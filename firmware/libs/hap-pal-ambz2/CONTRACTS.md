# PAL internal contracts (for parallel authors)

Init APIs follow the Espressif port (`vendor/esp-apple-homekit-adk/port/include/*+Init.h`), with these changes:

| Header (include/) | Owner | API |
|---|---|---|
| `HAPPlatform+Init.h` | done | `HAVE_*`=0, session sizes, `HAPPlatformFreeSafe`, `HAPPlatformLogPOSIXError` (implemented in `HAPPlatformLog.c`) |
| `HAPPlatformRunLoop+Init.h` | runloop | `HAPPlatformRunLoopCreate(void)`, `HAPPlatformRunLoopRelease(void)`; `HAPPlatformRunLoopRun/Stop/ScheduleCallback` from ADK. Context ≤ 32 B |
| `HAPPlatformFileHandle.h` | runloop | as esp (Register/Update/Deregister on lwIP socket fds) |
| `HAPPlatformTCPStreamManager+Init.h` | net | as esp without `interfaceName` (`HAPPlatformTCPStreamManagerOptions{port, maxConcurrentTCPStreams}`) |
| `HAPPlatformServiceDiscovery+Init.h` | net | `struct HAPPlatformServiceDiscovery` + `HAPPlatformServiceDiscoveryCreate(sd, const HAPPlatformServiceDiscoveryOptions*)` (options may be empty: `hostName`, `netif`, both nullable) |
| `HAPPlatformKeyValueStore+Init.h` | storage | `HAPPlatformKeyValueStoreCreate(kvs, const HAPPlatformKeyValueStoreOptions* {uint32_t baseAddress; uint16_t numModules;})` on Realtek DCT. ADK domains 0x00-0xFF map to DCT modules; app domains 0x10–0x3F |
| `HAPPlatformAccessorySetup+Init.h` | storage | `HAPPlatformAccessorySetupCreate(setup, const HAPPlatformAccessorySetupOptions* { const HAPSetupInfo* setupInfo; const char* setupID /*4 chars*/; })` — setup info injected, not read from KV |
| `HAPPlatformRandomNumber` / Clock / Abort / Log | misc | no Init header needed beyond `HAPPlatformRandomNumberInit(void)` declared in `HAPPlatformRandomNumber+Init.h` (seeds DRBG; call once at boot after `crypto_init`) |
| `HAPPlatformMFiTokenAuth+Init.h`, BLE, MFiHW, NFC, Display | misc | stubs only as far as the linker needs; MFiTokenAuth: `HAPPlatformMFiTokenAuthCreate(auth, &(HAPPlatformMFiTokenAuthOptions){.keyValueStore=kvs})` that reports no token |

Threading: only the run-loop task touches HAP state. Other tasks use `HAPPlatformRunLoopScheduleCallback`.
Build: `make OUT=out/<yourname> -j6` (own OUT dir; never write `out/` directly). Our code compiles with `-Werror`.
