// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.
//
// Derived in structure from the Espressif ADK port (Apache-2.0).

#include "HAPPlatform+Init.h"
#include "HAPPlatformKeyValueStore+Init.h"
#include "dct.h"

#include <stdio.h>

static const HAPLogObject logObject = { .subsystem = kHAPPlatform_LogSubsystem, .category = "KeyValueStore" };

// DCT variable names are the 2-char hex key; the module name is "hap" + 2-char hex domain.
#define kNameSize  3
#define kModuleLen (3 + 2 + 1)

static void ModuleName(char name[kModuleLen], HAPPlatformKeyValueStoreDomain domain) {
    snprintf(name, kModuleLen, "hap%02X", domain);
}

static void VariableName(char name[kNameSize], HAPPlatformKeyValueStoreKey key) {
    snprintf(name, kNameSize, "%02X", key);
}

void HAPPlatformKeyValueStoreCreate(
        HAPPlatformKeyValueStoreRef keyValueStore,
        const HAPPlatformKeyValueStoreOptions* options) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(options);

    HAPRawBufferZero(keyValueStore, sizeof *keyValueStore);

    int32_t res = dct_init(
            options->baseAddress,
            options->numModules,
            kNameSize,
            kHAPPlatformKeyValueStore_MaxValueBytes,
            /* enable_backup: */ 1,
            /* enable_wear_leveling: */ 0);
    if (res != DCT_SUCCESS) {
        HAPLogError(&logObject, "dct_init failed: %d", (int) res);
        HAPFatalError();
    }
    keyValueStore->initialized = true;
}

/** Opens the domain's module. Returns kHAPError_None and sets *found=false if it does not exist. */
HAP_RESULT_USE_CHECK
static HAPError OpenModule(dct_handle_t* handle, HAPPlatformKeyValueStoreDomain domain, bool* found) {
    char name[kModuleLen];
    ModuleName(name, domain);
    int32_t res = dct_open_module(handle, name);
    *found = res == DCT_SUCCESS;
    if (res == DCT_SUCCESS || res == DCT_ERR_NOT_FIND) {
        return kHAPError_None;
    }
    HAPLogError(&logObject, "%s: dct_open_module %s failed: %d", __func__, name, (int) res);
    return kHAPError_Unknown;
}

/** Reads a variable into a MaxValueBytes buffer. *found=false if absent. */
HAP_RESULT_USE_CHECK
static HAPError ReadVariable(
        dct_handle_t* handle,
        HAPPlatformKeyValueStoreKey key,
        uint8_t buffer[kHAPPlatformKeyValueStore_MaxValueBytes],
        size_t* numBytes,
        bool* found) {
    char name[kNameSize];
    VariableName(name, key);
    uint16_t size = kHAPPlatformKeyValueStore_MaxValueBytes;
    int32_t res = dct_get_variable_new(handle, name, (const char*) buffer, &size);
    *found = res == DCT_SUCCESS;
    if (res == DCT_SUCCESS) {
        *numBytes = size;
        return kHAPError_None;
    }
    if (res == DCT_ERR_NOT_FIND) {
        return kHAPError_None;
    }
    HAPLogError(&logObject, "%s: dct_get_variable_new %s failed: %d", __func__, name, (int) res);
    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformKeyValueStoreGet(
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain,
        HAPPlatformKeyValueStoreKey key,
        void* _Nullable bytes,
        size_t maxBytes,
        size_t* _Nullable numBytes,
        bool* found) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(keyValueStore->initialized);
    HAPPrecondition((bytes && numBytes) || (!bytes && !maxBytes));
    HAPPrecondition(found);

    dct_handle_t handle;
    HAPError err = OpenModule(&handle, domain, found);
    if (err || !*found) {
        return err;
    }

    uint8_t buffer[kHAPPlatformKeyValueStore_MaxValueBytes];
    size_t size = 0;
    err = ReadVariable(&handle, key, buffer, &size, found);
    dct_close_module(&handle);
    if (err || !*found) {
        return err;
    }

    // ADK contract (and the POSIX PAL): a longer value is truncated to maxBytes, *numBytes = bytes copied.
    // Callers detect an oversized value by asking for one byte more than they expect.
    if (bytes) {
        if (size > maxBytes) {
            size = maxBytes;
        }
        HAPRawBufferCopyBytes(bytes, buffer, size);
    }
    if (numBytes) {
        *numBytes = size;
    }
    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformKeyValueStoreSet(
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain,
        HAPPlatformKeyValueStoreKey key,
        const void* bytes,
        size_t numBytes) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(keyValueStore->initialized);
    HAPPrecondition(bytes);

    if (numBytes > kHAPPlatformKeyValueStore_MaxValueBytes) {
        HAPLogError(&logObject, "Value too large: %zu bytes.", numBytes);
        return kHAPError_OutOfResources;
    }

    char module[kModuleLen];
    ModuleName(module, domain);
    // Fails if the module exists already, which is fine; a real failure shows up at open.
    (void) dct_register_module(module);

    dct_handle_t handle;
    int32_t res = dct_open_module(&handle, module);
    if (res != DCT_SUCCESS) {
        HAPLogError(&logObject, "%s: dct_open_module %s failed: %d", __func__, module, (int) res);
        return kHAPError_Unknown;
    }
    char name[kNameSize];
    VariableName(name, key);
    res = dct_set_variable_new(&handle, name, (const char*) bytes, (uint16_t) numBytes);
    dct_close_module(&handle);
    if (res != DCT_SUCCESS) {
        HAPLogError(&logObject, "%s: dct_set_variable_new %s failed: %d", __func__, name, (int) res);
        return kHAPError_Unknown;
    }
    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformKeyValueStoreRemove(
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain,
        HAPPlatformKeyValueStoreKey key) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(keyValueStore->initialized);

    dct_handle_t handle;
    bool found;
    HAPError err = OpenModule(&handle, domain, &found);
    if (err || !found) {
        return err;
    }
    char name[kNameSize];
    VariableName(name, key);
    int32_t res = dct_delete_variable_new(&handle, name);
    dct_close_module(&handle);
    if (res != DCT_SUCCESS && res != DCT_ERR_NOT_FIND) {
        HAPLogError(&logObject, "%s: dct_delete_variable_new %s failed: %d", __func__, name, (int) res);
        return kHAPError_Unknown;
    }
    return kHAPError_None;
}

/** Sets bit key in present[] for each key stored in the domain. */
HAP_RESULT_USE_CHECK
static HAPError CollectKeys(HAPPlatformKeyValueStoreDomain domain, uint8_t present[256 / 8]) {
    HAPRawBufferZero(present, 256 / 8);

    dct_handle_t handle;
    bool moduleFound;
    HAPError err = OpenModule(&handle, domain, &moduleFound);
    if (err || !moduleFound) {
        return err;
    }
    uint8_t buffer[kHAPPlatformKeyValueStore_MaxValueBytes];
    for (unsigned key = 0; key < 256 && !err; key++) {
        size_t size;
        bool found;
        err = ReadVariable(&handle, (HAPPlatformKeyValueStoreKey) key, buffer, &size, &found);
        if (found) {
            present[key / 8] |= (uint8_t)(1u << (key % 8));
        }
    }
    dct_close_module(&handle);
    return err;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformKeyValueStoreEnumerate(
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain,
        HAPPlatformKeyValueStoreEnumerateCallback callback,
        void* _Nullable context) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(keyValueStore->initialized);
    HAPPrecondition(callback);

    // The module is closed before calling back, so the callback may Set/Remove.
    uint8_t present[256 / 8];
    HAPError err = CollectKeys(domain, present);
    if (err) {
        return err;
    }
    for (unsigned key = 0; key < 256; key++) {
        if (!(present[key / 8] & (1u << (key % 8)))) {
            continue;
        }
        bool shouldContinue = true;
        err = callback(context, keyValueStore, domain, (HAPPlatformKeyValueStoreKey) key, &shouldContinue);
        if (err) {
            return err;
        }
        if (!shouldContinue) {
            break;
        }
    }
    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
HAPError HAPPlatformKeyValueStorePurgeDomain(
        HAPPlatformKeyValueStoreRef keyValueStore,
        HAPPlatformKeyValueStoreDomain domain) {
    HAPPrecondition(keyValueStore);
    HAPPrecondition(keyValueStore->initialized);

    char name[kModuleLen];
    ModuleName(name, domain);
    int32_t res = dct_unregister_module(name);
    if (res != DCT_SUCCESS && res != DCT_ERR_NOT_FIND) {
        HAPLogError(&logObject, "%s: dct_unregister_module %s failed: %d", __func__, name, (int) res);
        return kHAPError_Unknown;
    }
    return kHAPError_None;
}
