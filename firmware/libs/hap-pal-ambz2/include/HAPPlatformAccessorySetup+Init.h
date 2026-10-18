// HomeKit ADK PAL for Realtek AmebaZ2: accessory setup manager.
//
// Setup info (SRP salt + verifier) and setup ID are injected via options (they come from the factory
// record), not read from the key-value store. The setup code itself is never stored on the device
// (non-display accessory), so LoadSetupCode is a fatal error; the ADK only calls it for displays.
//
// **Example**
//
//   static HAPPlatformAccessorySetup accessorySetup;
//   HAPPlatformAccessorySetupCreate(&accessorySetup, &(const HAPPlatformAccessorySetupOptions) {
//       .setupInfo = &factory.setupInfo,
//       .setupID = "ABCD",
//   });
//
// The pointed-to data must outlive the accessory setup manager.
#ifndef HAP_PLATFORM_ACCESSORY_SETUP_INIT_H
#define HAP_PLATFORM_ACCESSORY_SETUP_INIT_H

#include "HAPPlatform.h"

typedef struct {
    const HAPSetupInfo* setupInfo; /**< SRP salt and verifier. */
    const char* _Nullable setupID; /**< 4 characters, or NULL if none (then no QR code / NFC). */
} HAPPlatformAccessorySetupOptions;

struct HAPPlatformAccessorySetup {
    // Opaque type. Do not access the instance fields directly.
    /**@cond */
    const HAPSetupInfo* setupInfo;
    HAPSetupID setupID;
    bool hasSetupID;
    /**@endcond */
};

/**
 * Initializes the accessory setup manager.
 *
 * @param[out] accessorySetup       Pointer to an allocated but uninitialized HAPPlatformAccessorySetup structure.
 * @param      options              Initialization options.
 */
void HAPPlatformAccessorySetupCreate(
        HAPPlatformAccessorySetupRef accessorySetup,
        const HAPPlatformAccessorySetupOptions* options);

#endif
