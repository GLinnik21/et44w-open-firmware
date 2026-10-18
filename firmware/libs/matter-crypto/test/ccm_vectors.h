/* AES-128-CCM vectors with a 13-byte nonce and 16-byte tag, copied from connectedhomeip
 * src/crypto/tests/AES_CCM_128_test_vectors.h (Apache-2.0, Project CHIP Authors; the data are the
 * Wycheproof AES-CCM set). Hex strings; `valid` 0 means the tag/ciphertext must be rejected. */
#ifndef CCM_VECTORS_H
#define CCM_VECTORS_H

static const struct { unsigned tc; int valid; const char *key, *nonce, *aad, *pt, *ct, *tag; } CCM_VECTORS[] = {
    { 38, 1, "404142434445464748494a4b4c4d4e4f", "101112131415161718191a1b1c", "", "", "", "32d6f8243a26d0bd98d01b0f448e7773" },
    { 0, 1, "0953fa93e7caac9638f58820220a398e", "00800000011201000012345678", "", "fffd034b50057e400000010000", "b5e5bfdacbaf6cb7fb6bff871f", "b0d6dd827d35bf372fa6425dcd17d356" },
    { 1, 1, "0953fa93e7caac9638f58820220a398e", "00800148202345000012345678", "", "120104320308ba072f", "79d7dbc0c9b4d43eeb", "281508e50d58dbbd27c39597800f4733" },
    { 3, 1, "be635105434859f484fc798e043ce40e", "00800000021201000012345678", "", "23450100", "b0e5d0ad", "6078e0ddbb7cd43faea57c7051e5b4ae" },
    { 10, 1, "63964771734fbd76e3b40519d1d94a48", "010007080d1234973612345677", "f4a002c7fb1e4ca0a469a021de0db875", "ea0a00576f726c64", "de1547118463123e", "14604c1ddb4f5987064b1736f3923962" },
    { 11, 1, "08b0da255d2083808a1b4d367090bacc", "777828b13679a9e2ca89568233", "c5", "", "", "0a93ec4a8ff33964f58005868a868856" },
    { 12, 1, "08b0da255d2083808a1b4d367090bacc", "777828b13679a9e2ca89568233", "c5", "3a7f9b1d2e4c6a8f0b5d1c3e7a6d9f20", "c9d2fc9793b6f73a90d326816f52c16a", "e4e24567106d61bf5040b26fbaa68a58" },
    { 13, 1, "08b0da255d2083808a1b4d367090bacc", "777828b13679a9e2ca89568233", "c5", "e41a9f3c6d2b81745c0e3f1d89ab5d26f3c7e890bd12a45b", "17b7f8b6d0d11cc1c78005a29c94036ca9f376fb1b041005", "d0350a3c8db3cd8512f45f35432cb70d" },
};

#endif
