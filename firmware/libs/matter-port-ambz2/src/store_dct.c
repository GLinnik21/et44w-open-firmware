/* The Matter store: Realtek DCT, second instance (dct2.h, closed lib_dct.a), in the `matter` flash region
 * (partitions.def), with store_kv on top.
 *
 * Geometry: 6 modules (boot, node, 4 fabric modules) x 4 KiB, each with a backup copy = 48 KiB = the region.
 * Variable name size 8 (names are <= 4 characters), value size 512: a module holds 4024 / 520 = 7 variables of up
 * to 508 bytes (dct_set_variable_new2 rejects len > value size - 4). Facts from disassembling lib_dct.a; a power cut
 * during a write has not been tested on the bench yet.
 *
 * Guard: the DCT library's flash helpers are wrapped (-Wl,--wrap in lib.mk), so any write or erase outside the
 * `matter` region is refused and logged; a Matter build therefore cannot touch kv, ota_state or the BT FTL. */
#include <stdio.h>
#include <string.h>

#include "dct.h"
#include "dct2.h"
#include "flash_map.h"

#include "flash_guard.h"
#include "port.h"

#define DCT_MODULE_SIZE 0x1000u
#define DCT_NAME_SIZE 8
_Static_assert(MTP_N_MODS * 2 * DCT_MODULE_SIZE == FLASH_matter_SIZE, "the matter region must hold 6 modules x 2");
_Static_assert(MTP_NAME_MAX < DCT_NAME_SIZE, "names must fit");
_Static_assert(MTP_VALUE_MAX == MTP_VALUE_SIZE - 4, "dct_set_variable_new2 limit");
/* What matter-fabric / matter-node store must fit store_kv. The ACL / META maxima (432 / 208 B) are private to
 * matter-fabric's fabric_store.c and are not checked here; both are below MTP_VALUE_MAX today. */
_Static_assert(MT_FABRIC_CERT_MAX <= MTP_VALUE_MAX, "certificate records must fit a DCT value");
_Static_assert(MT_FKIND_ACL <= MTP_FKIND_MAX, "fabric record kinds");
_Static_assert(MT_FABRIC_MAX <= MTP_FMODS - 1, "one fabric module stays free as the scratch");
_Static_assert(MT_NODE_KEY_BOOT == 0x0023u, "store_kv.c puts this key into the boot module");

static const char *const module_name[MTP_N_MODS] = { "mboot", "mnode", "mfab0", "mfab1", "mfab2", "mfab3" };

static bool ready;
static mtp_kv kv;
static uint8_t copy_buf[MTP_VALUE_MAX];   /* store_kv's tmp */
static uint8_t io_buf[MTP_VALUE_SIZE];    /* dct_get_variable_new2 target */

/* ---- flash guard ---- */

int32_t __real_dct_flash_write(uint32_t addr, uint8_t *data, uint32_t len);
int32_t __real_dct_flash_erase(uint32_t addr, uint32_t len);
int32_t __wrap_dct_flash_write(uint32_t addr, uint8_t *data, uint32_t len);
int32_t __wrap_dct_flash_erase(uint32_t addr, uint32_t len);

int32_t __wrap_dct_flash_write(uint32_t addr, uint8_t *data, uint32_t len)
{
    if (!mtp_guard_write_ok(addr, len, FLASH_matter_OFFSET, FLASH_matter_SIZE)) {
        MTP_LOG("REFUSED dct write 0x%lx+%lu outside the matter region\r\n", (unsigned long)addr, (unsigned long)len);
        return DCT_ERR_FLASH_RW;
    }
    return __real_dct_flash_write(addr, data, len);
}

int32_t __wrap_dct_flash_erase(uint32_t addr, uint32_t len)
{
    if (!mtp_guard_erase_ok(addr, len, FLASH_matter_OFFSET, FLASH_matter_SIZE)) {
        MTP_LOG("REFUSED dct erase 0x%lx+%lu outside the matter region\r\n", (unsigned long)addr, (unsigned long)len);
        return DCT_ERR_FLASH_RW;
    }
    return __real_dct_flash_erase(addr, len);
}

/* ---- mtp_mods over DCT2 ---- */

static mt_err open_mod(dct_handle_t *h, unsigned mod)
{
    int32_t r;
    if (!ready || mod >= MTP_N_MODS) return MT_ERR_IO;
    r = dct_open_module2(h, module_name[mod]);
    if (r != DCT_SUCCESS) {
        MTP_LOG("dct open %s: %ld\r\n", module_name[mod], (long)r);
        return MT_ERR_IO;
    }
    return MT_OK;
}

static mt_err close_mod(dct_handle_t *h, unsigned mod, mt_err e)
{
    int32_t r = dct_close_module2(h);
    if (r != DCT_SUCCESS) {
        MTP_LOG("dct close %s: %ld\r\n", module_name[mod], (long)r);
        if (!e) e = MT_ERR_IO;
    }
    return e;
}

static mt_err d_get(void *ctx, unsigned mod, const char *name, mt_buf out, size_t *len)
{
    dct_handle_t h;
    uint16_t size = sizeof io_buf;
    mt_err e = open_mod(&h, mod);
    int32_t r;
    (void)ctx;
    if (e) return e;
    r = dct_get_variable_new2(&h, name, (const char *)io_buf, &size);
    if (r == DCT_ERR_NOT_FIND) e = MT_ERR_NOT_FOUND;
    else if (r != DCT_SUCCESS || size > MTP_VALUE_MAX) e = MT_ERR_IO;
    else if (size > out.cap) e = MT_ERR_BUFFER_TOO_SMALL;
    else {
        memcpy(out.p, io_buf, size);
        *len = size;
    }
    return close_mod(&h, mod, e);
}

static mt_err d_set(void *ctx, unsigned mod, const char *name, mt_span val)
{
    dct_handle_t h;
    mt_err e;
    int32_t r;
    (void)ctx;
    if (val.len > MTP_VALUE_MAX || strlen(name) > MTP_NAME_MAX) return MT_ERR_INVALID;
    if ((e = open_mod(&h, mod))) return e;
    /* the closed API takes a non-const char *; a zero-length value still needs a valid pointer */
    r = dct_set_variable_new2(&h, name, val.len ? (const char *)val.p : "", (uint16_t)val.len);
    if (r != DCT_SUCCESS) {
        MTP_LOG("dct set %s/%s (%u B): %ld\r\n", module_name[mod], name, (unsigned)val.len, (long)r);
        e = MT_ERR_IO;
    }
    return close_mod(&h, mod, e);
}

static mt_err d_del(void *ctx, unsigned mod, const char *name)
{
    dct_handle_t h;
    mt_err e;
    int32_t r;
    (void)ctx;
    if ((e = open_mod(&h, mod))) return e;
    r = dct_delete_variable_new2(&h, name);
    if (r != DCT_SUCCESS && r != DCT_ERR_NOT_FIND) {
        MTP_LOG("dct del %s/%s: %ld\r\n", module_name[mod], name, (long)r);
        e = MT_ERR_IO;
    }
    return close_mod(&h, mod, e);
}

/* Empties a module: unregister + register, then checked, since the scratch scheme relies on it (a stale record
 * left behind would join the next fabric written there). Leftovers are deleted one by one. */
static mt_err d_reset(void *ctx, unsigned mod)
{
    dct_handle_t h;
    int32_t r;
    mt_err e;
    (void)ctx;
    if (!ready || mod >= MTP_N_MODS) return MT_ERR_IO;
    r = dct_unregister_module2(module_name[mod]);
    if (r != DCT_SUCCESS && r != DCT_ERR_NOT_FIND) {
        MTP_LOG("dct unregister %s: %ld\r\n", module_name[mod], (long)r);
        return MT_ERR_IO;
    }
    r = dct_register_module2(module_name[mod]);
    if (r != DCT_SUCCESS) {
        MTP_LOG("dct register %s: %ld\r\n", module_name[mod], (long)r);
        return MT_ERR_IO;
    }
    if ((e = open_mod(&h, mod))) return e;
    if (h.used_variable_num) {
        MTP_LOG("dct %s not empty after re-register (%u): deleting\r\n", module_name[mod], (unsigned)h.used_variable_num);
        for (unsigned kind = 1; kind <= MTP_FKIND_MAX; kind++) {
            char name[MTP_NAME_MAX + 1];
            mtp_kv_name((uint16_t)kind, name);
            r = dct_delete_variable_new2(&h, name);
            if (r != DCT_SUCCESS && r != DCT_ERR_NOT_FIND) e = MT_ERR_IO;
        }
        if (!e && h.used_variable_num) e = MT_ERR_IO;   /* a variable store_kv never writes */
    }
    return close_mod(&h, mod, e);
}

static const mtp_mods dct_mods = { NULL, d_get, d_set, d_del, d_reset };

mt_err mtp_store_init(void)
{
    int32_t r;
    if (ready) return MT_OK;
    r = dct_init2(FLASH_matter_OFFSET, MTP_N_MODS, DCT_NAME_SIZE, MTP_VALUE_SIZE, /*backup*/ 1, /*wear*/ 0);
    if (r != DCT_SUCCESS) {
        MTP_LOG("dct_init2: %ld\r\n", (long)r);
        return MT_ERR_IO;
    }
    for (unsigned i = 0; i < MTP_N_MODS; i++) {
        /* fails harmlessly when the module exists; a real problem shows at open */
        (void)dct_register_module2(module_name[i]);
    }
    ready = true;
    return MT_OK;
}

mt_err mtp_store_load(void)
{
    mt_err e;
    if (!ready) return MT_ERR_STATE;
    e = mtp_kv_init(&kv, &dct_mods, copy_buf);
    if (e) MTP_LOG("fabric index unreadable (%d): starting without fabrics\r\n", (int)e);
    MTP_LOG("store: %u fabric(s)\r\n", mtp_kv_fabrics(&kv));
    return e == MT_ERR_IO ? MT_ERR_IO : MT_OK;
}

mtp_kv *mtp_store(void) { return &kv; }

mt_err mtp_store_get(unsigned mod, const char *name, mt_buf out, size_t *len)
{
    return d_get(NULL, mod, name, out, len);
}

mt_err mtp_store_set(unsigned mod, const char *name, mt_span val) { return d_set(NULL, mod, name, val); }
mt_err mtp_store_del(unsigned mod, const char *name) { return d_del(NULL, mod, name); }
