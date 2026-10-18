// Order (each step crash-safe): check the signed header (length, serial, image hash) before touching flash,
// erase + write the image with its boot mark held back as 0xFF, check it hashes to the signed hash, re-read
// the slot and check it hashes the same, record the trial, then program the boot mark. A cut before the last
// step leaves the old slot as the only bootable one; an unsigned upload never erases anything.
#include "HAPBase.h" // first: defines what HAPCrypto.h needs, and must precede libc headers
#include "HAPCrypto.h"

#include "ota_receive.h"
#include "ota_flash.h"
#include "ota_state.h"

#include <stdbool.h>
#include <string.h>

#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "mbedtls/sha512.h"

#define HEADER_MAGIC "AOT2"
#define LEGACY_MAGIC "AOTA" // v1: signature over the whole image, checked only after the slot was overwritten
#define SIGN_DOMAIN  "ambz2-ota-v2"
#define SIGNED_SIZE  (4 + 4 + 64) // length, serial, SHA-512: the header bytes after the magic
#define UPLOAD_MS    (120u * 1000u) // whole upload (a full slot takes ~15 s); SO_RCVTIMEO only bounds each recv

typedef struct {
    uint8_t magic[4];
    uint8_t signedPart[SIGNED_SIZE];
    uint8_t sig[64];
} header_v2;
_Static_assert(sizeof(header_v2) == 140, "header_v2 is the wire layout");

static uint8_t chunk[OTA_SECTOR];
static u32_t uploadDeadline; // sys_now() at which a slow sender is dropped

static const char* RecvAll(int sock, uint8_t* buf, size_t n) {
    while (n) {
        if ((int32_t) (sys_now() - uploadDeadline) >= 0) {
            return "upload took too long";
        }
        int r = recv(sock, buf, n, 0);
        if (r <= 0) {
            return "connection lost"; // closed, error or SO_RCVTIMEO
        }
        buf += r;
        n -= (size_t) r;
    }
    return NULL;
}

/** Writes the image into slot, mark held back, and checks it hashes to digest. Fills mark. */
static const char* ReceiveImage(int sock, uint32_t slot, uint32_t length, uint32_t serial, const uint8_t digest[64],
                                uint8_t mark[OTA_MARK_SIZE]) {
    mbedtls_sha512_context sha;
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    const char* err = NULL;
    for (uint32_t off = 0; off < length; off += OTA_SECTOR) {
        size_t n = length - off < OTA_SECTOR ? length - off : OTA_SECTOR;
        if ((err = RecvAll(sock, chunk, n)) != NULL) {
            break;
        }
        mbedtls_sha512_update(&sha, chunk, n);
        if (off == 0) {
            if (memcmp(chunk + OTA_SERIAL_OFFSET, &serial, sizeof serial) != 0) { // before the first erase
                err = "image serial differs from the signed one";
                break;
            }
            memcpy(mark, chunk, OTA_MARK_SIZE);
            memset(chunk, 0xFF, OTA_MARK_SIZE);
        }
        ota_flash_erase(slot + off);
        ota_flash_write(slot + off, chunk, n);
    }
    uint8_t received[64];
    mbedtls_sha512_finish(&sha, received);
    mbedtls_sha512_free(&sha);
    if (!err && memcmp(received, digest, sizeof received) != 0) {
        err = "image does not match the signed hash";
    }
    return err;
}

/** Hashes the slot as written, with the held-back mark in place. */
static void HashSlot(uint32_t slot, uint32_t length, const uint8_t mark[OTA_MARK_SIZE], uint8_t digest[64]) {
    mbedtls_sha512_context sha;
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    for (uint32_t off = 0; off < length; off += OTA_SECTOR) {
        size_t n = length - off < OTA_SECTOR ? length - off : OTA_SECTOR;
        ota_flash_read(slot + off, chunk, n);
        if (off == 0) {
            memcpy(chunk, mark, OTA_MARK_SIZE);
        }
        mbedtls_sha512_update(&sha, chunk, n);
    }
    mbedtls_sha512_finish(&sha, digest);
    mbedtls_sha512_free(&sha);
}

static bool SignatureValid(const header_v2* h, const uint8_t key[32]) {
    uint8_t message[sizeof SIGN_DOMAIN - 1 + SIGNED_SIZE];
    memcpy(message, SIGN_DOMAIN, sizeof SIGN_DOMAIN - 1);
    memcpy(message + sizeof SIGN_DOMAIN - 1, h->signedPart, SIGNED_SIZE);
    return HAP_ed25519_verify(h->sig, message, sizeof message, key) == 0;
}

const char* ota_receive(int sock, const uint8_t publicKey[32]) {
    header_v2 h;
    uploadDeadline = sys_now() + UPLOAD_MS;
    if (RecvAll(sock, (uint8_t*) &h, sizeof h) != NULL) {
        return "bad header";
    }
    if (memcmp(h.magic, LEGACY_MAGIC, 4) == 0) {
        return "v1 upload format no longer accepted: push without --legacy";
    }
    if (memcmp(h.magic, HEADER_MAGIC, 4) != 0) {
        return "bad header";
    }
    uint32_t length, serial; // little-endian CPU, LE on the wire
    memcpy(&length, h.signedPart, 4);
    memcpy(&serial, h.signedPart + 4, 4);
    const uint8_t* digest = h.signedPart + 8;

    uint32_t running = ota_running_slot();
    if (!running) {
        return "running slot unknown";
    }
    if (ota_state_read().pending) {
        return "trial pending: confirm the running image first";
    }
    if (length <= OTA_SECTOR || length > ota_slot_size()) {
        return "bad length";
    }
    if (!SignatureValid(&h, publicKey)) {
        return "bad signature";
    }
    if (serial <= ota_slot_serial(running)) { // the bootloader would keep booting the running slot
        return "image not newer than the running one";
    }
    uint32_t slot = ota_other_slot(running);

    uint8_t mark[OTA_MARK_SIZE], written[64];
    const char* err = ReceiveImage(sock, slot, length, serial, digest, mark);
    if (err) {
        return err;
    }
    HashSlot(slot, length, mark, written);
    if (memcmp(digest, written, sizeof written) != 0) {
        return "flash verify failed";
    }

    ota_state_begin(slot);
    ota_flash_write(slot, mark, OTA_MARK_SIZE);
    uint8_t check[OTA_MARK_SIZE];
    ota_flash_read(slot, check, sizeof check);
    if (memcmp(check, mark, sizeof check) != 0) {
        ota_invalidate_slot(slot);
        ota_state_clear();
        return "boot mark write failed";
    }
    return NULL;
}
