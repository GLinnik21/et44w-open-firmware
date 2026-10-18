// HomeKit ADK PAL for Realtek AmebaZ2: key-value store on Realtek DCT (device configuration table).
//
// Each ADK domain is one DCT module named "hapDD" (DD = domain in hex); each key is one DCT variable
// named by the key in hex ("KK"). Values are at most kHAPPlatformKeyValueStore_MaxValueBytes bytes.
// DCT has no iteration, so Enumerate probes all 256 keys of the module.
//
// **Example**
//
//   static HAPPlatformKeyValueStore keyValueStore;
//   HAPPlatformKeyValueStoreCreate(&keyValueStore, &(const HAPPlatformKeyValueStoreOptions) {
//       .baseAddress = FLASH_kv_OFFSET,       // config/flash_map.h (partitions.def: 0x1D1000)
//       .numModules = FLASH_KV_DCT_MODULES,   // the kv partition's size / 8 KiB (module + backup) = 12
//   });
//
// Create calls dct_init(), so other DCT users (Wi-Fi credentials, OTA state) register their modules
// after it. DCT serialises access per module itself (DCT_ERR_MODULE_BUSY on timeout).
#ifndef HAP_PLATFORM_KEY_VALUE_STORE_INIT_H
#define HAP_PLATFORM_KEY_VALUE_STORE_INIT_H

#include "HAPPlatform.h"

#include <stdint.h>

#define kHAPPlatformKeyValueStore_MaxValueBytes 128

typedef struct {
    uint32_t baseAddress; /**< Flash address of the DCT area. */
    uint16_t numModules;  /**< Total DCT modules: ADK domains in use plus other users. */
} HAPPlatformKeyValueStoreOptions;

struct HAPPlatformKeyValueStore {
    // Opaque type. Do not access the instance fields directly.
    /**@cond */
    bool initialized;
    /**@endcond */
};

/**
 * Initializes the key-value store and the underlying DCT.
 *
 * @param[out] keyValueStore        Pointer to an allocated but uninitialized HAPPlatformKeyValueStore structure.
 * @param      options              Initialization options.
 */
void HAPPlatformKeyValueStoreCreate(
        HAPPlatformKeyValueStoreRef keyValueStore,
        const HAPPlatformKeyValueStoreOptions* options);

#endif
