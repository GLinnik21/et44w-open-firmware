/* ota_receive against headers made by tools/ota_push.py (vectors.h), on fake flash: nothing is erased until
 * the signed header checks out, and a bad image never gets its boot mark. */
#include "harness.h"
#include "fake.h"
#include "ota_flash.h"
#include "ota_receive.h"
#include "vectors.h"

static uint8_t stream[sizeof VEC_HEADER + VEC_LENGTH];

static void TestImage(uint8_t* img) /* same formula as gen_vectors.py */
{
    for (uint32_t i = 0; i < VEC_LENGTH; i++) {
        img[i] = (uint8_t) (i * 31 + 7);
    }
    uint32_t serial = VEC_SERIAL;
    memcpy(img + OTA_SERIAL_OFFSET, &serial, sizeof serial);
}

static const char* Push(const uint8_t* header, size_t headerLen, uint32_t runningSerial, const uint8_t* key)
{
    fake_reset(runningSerial);
    memmove(stream, header, headerLen);
    TestImage(stream + headerLen);
    fake_upload(stream, headerLen + VEC_LENGTH);
    return ota_receive(0, key);
}

static bool IdleSlotUntouched(void)
{
    for (uint32_t i = 0; i < FAKE_SLOT_SIZE; i++) {
        if (fake_flash[FAKE_SLOT_B + i] != 0x5A) {
            return false;
        }
    }
    return fake_erases == 0;
}

static void test_good_upload(void)
{
    const char* err = Push(VEC_HEADER, sizeof VEC_HEADER, VEC_SERIAL - 1, VEC_PK);
    CHECK(err == NULL);
    uint8_t img[VEC_LENGTH];
    TestImage(img);
    CHECK_MEM(fake_flash + FAKE_SLOT_B, img, VEC_LENGTH); /* boot mark included */
    CHECK(fake_trial_begun);
}

static void test_bad_signature_erases_nothing(void)
{
    uint8_t h[sizeof VEC_HEADER];
    memcpy(h, VEC_HEADER, sizeof h);
    h[20] ^= 1; /* in the signed hash */
    fake_reset(0);
    memcpy(stream, h, sizeof h);
    fake_upload(stream, sizeof stream); /* body irrelevant */
    const char* err = ota_receive(0, VEC_PK);
    CHECK(err && strcmp(err, "bad signature") == 0);
    CHECK(IdleSlotUntouched());

    static const uint8_t zeroKey[32];
    err = Push(VEC_HEADER, sizeof VEC_HEADER, 0, zeroKey);
    CHECK(err && strcmp(err, "bad signature") == 0);
    CHECK(IdleSlotUntouched());
}

static void test_v1_refused(void)
{
    const char* err = Push(VEC_HEADER_V1, sizeof VEC_HEADER_V1, 0, VEC_PK);
    CHECK(err && strstr(err, "v1") != NULL);
    CHECK(IdleSlotUntouched());
}

static void test_not_newer_erases_nothing(void)
{
    const char* err = Push(VEC_HEADER, sizeof VEC_HEADER, VEC_SERIAL, VEC_PK); /* a replayed current image */
    CHECK(err && strcmp(err, "image not newer than the running one") == 0);
    CHECK(IdleSlotUntouched());
}

static void test_serial_swap_erases_nothing(void)
{
    fake_reset(0);
    memcpy(stream, VEC_HEADER, sizeof VEC_HEADER);
    TestImage(stream + sizeof VEC_HEADER);
    stream[sizeof VEC_HEADER + OTA_SERIAL_OFFSET] ^= 0x80; /* image claims another serial */
    fake_upload(stream, sizeof stream);
    const char* err = ota_receive(0, VEC_PK);
    CHECK(err && strcmp(err, "image serial differs from the signed one") == 0);
    CHECK(IdleSlotUntouched());
}

static void test_tampered_body_not_armed(void)
{
    fake_reset(0);
    memcpy(stream, VEC_HEADER, sizeof VEC_HEADER);
    TestImage(stream + sizeof VEC_HEADER);
    stream[sizeof VEC_HEADER + 0x1800] ^= 1;
    fake_upload(stream, sizeof stream);
    const char* err = ota_receive(0, VEC_PK);
    CHECK(err && strcmp(err, "image does not match the signed hash") == 0);
    uint8_t erased[OTA_MARK_SIZE];
    memset(erased, 0xFF, sizeof erased);
    CHECK_MEM(fake_flash + FAKE_SLOT_B, erased, OTA_MARK_SIZE); /* no boot mark: never boots */
    CHECK(!fake_trial_begun);
}

static void test_truncated_not_armed(void)
{
    fake_reset(0);
    memcpy(stream, VEC_HEADER, sizeof VEC_HEADER);
    TestImage(stream + sizeof VEC_HEADER);
    fake_upload(stream, sizeof stream - 100);
    const char* err = ota_receive(0, VEC_PK);
    CHECK(err && strcmp(err, "connection lost") == 0);
    CHECK(fake_flash[FAKE_SLOT_B] == 0xFF);
    CHECK(!fake_trial_begun);
}

static void test_slow_sender_dropped(void)
{
    fake_reset(0);
    memcpy(stream, VEC_HEADER, sizeof VEC_HEADER);
    TestImage(stream + sizeof VEC_HEADER);
    fake_upload(stream, sizeof stream);
    fake_recv_ms = 20000; /* every recv within SO_RCVTIMEO, the whole upload far over the deadline */
    const char* err = ota_receive(0, VEC_PK);
    CHECK(err && strcmp(err, "upload took too long") == 0);
    CHECK(fake_flash[FAKE_SLOT_B] == 0xFF);
    CHECK(!fake_trial_begun);
}

void run_receive_tests(void)
{
    RUN(test_good_upload);
    RUN(test_bad_signature_erases_nothing);
    RUN(test_v1_refused);
    RUN(test_not_newer_erases_nothing);
    RUN(test_serial_swap_erases_nothing);
    RUN(test_tampered_body_not_armed);
    RUN(test_truncated_not_armed);
    RUN(test_slow_sender_dropped);
}
