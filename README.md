# ET-44W open firmware

Replacement firmware for the Wi-Fi module of the **ET-44W floor thermostat** (sold as Warmee, EXTHERM
and others), a Tuya **WBR2** module with a Realtek **RTL8720CF** ("AmebaZ2"). It drops the Tuya cloud and
puts the thermostat straight into **Apple Home**, with no bridge and no hub.

The thermostat logic (relay, sensors, keys, display, weekly schedule) keeps running on the separate
thermostat MCU. This firmware only replaces the Wi-Fi side of the link, so the thermostat keeps heating
even when the network is down.

| | |
|---|---|
| **`thermostat`** (HomeKit, HAP over IP) | Thermostat tile (Off / Heat = manual / Auto = weekly program, 5–40 °C) + child lock switch. Uses Apple's HomeKit ADK. Pairs as an "uncertified accessory". Stable on two units |
| **`thermostat-matter`** (Matter, **experimental**) | Our own compact Matter 1.3 implementation in C: commissioning from an iPhone over Bluetooth with Wi-Fi provisioning, then control from Apple Home. Uncertified, uses the Matter test vendor ID. Young code: read the caveats below |
| Both | Local settings page on port 80 (every data point, decoded weekly schedule); signed over-the-air updates with automatic rollback; network log console on TCP 2323; watchdog |

Also useful on their own:
- `firmware/libs/tuyamcu`: a host-tested TuyaMCU protocol library (frame parser, DP codec, write allowlist).
- `firmware/libs/hap-pal-ambz2`: the HomeKit ADK platform layer for AmebaZ2 (FreeRTOS, lwIP, mbedtls 3).
- `scripts/ambz2_dump.py` / `ambz2_write.py`: reliable flash read/write through slow USB-UART bridges.
- `firmware/tools/pack_image.py`: builds flashable AmebaZ2 images without Realtek's x86-only tools, so
  everything builds natively on Apple Silicon and arm64 Linux.
- [`docs/thermostat-firmware.md`](docs/thermostat-firmware.md): what the stock Tuya firmware does (cloud
  endpoints, remote log streaming, Wi-Fi password in the boot log).
- [`docs/matter-apple-trace.md`](docs/matter-apple-trace.md): what Apple Home actually reads and writes when
  it commissions and controls a Matter thermostat.

## Hardware and first flash

See [`docs/hardware-and-flashing.md`](docs/hardware-and-flashing.md): board, pads, download mode, stock
backup, data-point map. The first flash needs a 3.3 V USB-serial adapter on two test pads; after that,
updates go over Wi-Fi.

## Build

Needs `make`, `git`, `curl`, a host C compiler (for the tests), Python 3.10+ and ~2 GB of disk. No root,
no Docker. All commands below run from `firmware/`.

```sh
cd firmware
tools/get-vendor.sh                  # Realtek SDK + Apple HomeKit ADK at the commits in vendor.lock
python3.12 -m venv ../.venv-flash    # any Python >= 3.10; make uses ../.venv-flash/bin/python (or PYTHON=...)
../.venv-flash/bin/pip install ltchiptool typer construct pycryptodomex pyserial cryptography
```

`ltchiptool` (plus `typer`, `construct` and `pycryptodomex`, which its AmbZ2 image code imports) packs the
flash images, `pyserial` is for the flashing scripts, `cryptography` signs OTA images. ltchiptool needs
Python 3.10 or newer: macOS's `/usr/bin/python3` is 3.9, so name a newer interpreter for the venv. The Arm
GNU toolchain is downloaded (SHA-pinned) on the first `make`.

### Per-device files

They are git-ignored; each `.example` file next to them describes its format.

```sh
# Wi-Fi network, per app (used until the device is provisioned): copy, then edit (the Matter build
# refuses the placeholder network)
cp apps/example-switch/wifi_credentials.h.example apps/example-switch/wifi_credentials.h
cp apps/thermostat/wifi_credentials.h.example apps/thermostat/wifi_credentials.h
cp apps/thermostat-matter/wifi_credentials.h.example apps/thermostat-matter/wifi_credentials.h

# OTA signing key, once: writes ../secrets/ota_signing.key (git-ignored) and apps/example-switch/ota_pubkey.h.
# Back the key up: without it, updates need the serial wires again.
../.venv-flash/bin/python tools/ota_keygen.py
../.venv-flash/bin/python tools/ota_keygen.py --header-only ../secrets/ota_signing.key apps/thermostat/ota_pubkey.h
../.venv-flash/bin/python tools/ota_keygen.py --header-only ../secrets/ota_signing.key apps/thermostat-matter/ota_pubkey.h

# HomeKit setup code (printed once, with the QR payload: note it)
python3 tools/hap_setup.py apps/example-switch/hap_setup_info.h
python3 tools/hap_setup.py apps/thermostat/units/example/hap_setup_info.h --category 9   # 9 = thermostat

# Matter setup: the passcode, QR payload and manual code go only to SETUP_TXT (keep it out of the repo)
make MATTER=1 APP=apps/thermostat-matter UNIT=example SERIAL=000000000001 \
     SETUP_TXT=../secrets/example_matter_setup.txt matter-unit
```

A unit is a folder under `apps/thermostat/units/` (`unit.h`: name, serial, POSIX time zone; the example
uses `UTC0`, set yours) plus its own `hap_setup_info.h`. For a second thermostat, copy
`units/example` to `units/<name>`, give it its own serial, and generate its setup files with
`UNIT=<name>`. The Matter build also reads `apps/thermostat/units/<name>/unit.h`.

### Firmware

```sh
make                                                                    # apps/example-switch -> out/
make APP=apps/thermostat UNIT=example                                   # HomeKit thermostat -> out/
make MATTER=1 APP=apps/thermostat-matter UNIT=example OUT=out-matter/example   # Matter (experimental)
```

make doesn't track flags: run `make clean` (or use another `OUT=`) when you switch `APP` or `UNIT`.
Outputs in the out dir: `image_flash_wipe.0x000000.bin` (first flash over UART, see
[`docs/hardware-and-flashing.md`](docs/hardware-and-flashing.md)) and `image_firmware_is.0x010000.bin`
(over-the-air update).

### Updates over Wi-Fi

```sh
../.venv-flash/bin/python tools/ota_push.py out/image_firmware_is.0x010000.bin --host <device-ip> \
    --key ../secrets/ota_signing.key
```

This speaks OTA format v2 (the signed header is checked before the module erases anything), which is
what this firmware accepts. `--legacy` sends the old v1 format, only for a unit still running firmware
from before OTA v2; v2 firmware refuses it. A new image runs on trial and rolls back unless it comes
up healthy.

### Tests

```sh
for t in libs/*/test; do make -C "$t" || break; done          # pure C libraries (host compiler)
make -C tools/matter-host test                                # Matter node on the host, loopback client
../.venv-flash/bin/python -m unittest tools/test_pack_image.py tools/test_matter_setup.py
../.venv-flash/bin/python tools/ota_push.py --self-test
```

`libs/ota/test` builds the ADK's Ed25519, so run `tools/get-vendor.sh` first. The optional matter.js
end-to-end test (`make -C tools/matter-host e2e`) needs Node.js and matter.js installed once with
`npm install --prefix out-host/matterjs @matter/nodejs-shell@0.17.9` (or point `MATTERJS_CTL_DIR` at an
existing install). Layering rules and design decisions:
[`firmware/ARCHITECTURE.md`](firmware/ARCHITECTURE.md).

## Caveats

- **Not certified by Apple or the CSA.** Apple Home shows an "Uncertified Accessory" prompt. The Matter
  build uses the official *test* vendor ID and test attestation certificates, which is fine for your own
  home and not for a product.
- **The Matter stack is experimental.** It's a new, compact implementation of a security protocol. It works
  with Apple Home on iOS, but hasn't had an independent security review.
- **No login on the settings page.** It's meant for a trusted LAN. It refuses foreign `Host` headers and
  cross-site POSTs, but anyone on your network can change settings. Put IoT devices on their own network.
- The network log on port 2323 is unauthenticated, for the same reason.
- Flashing replaces the Tuya firmware. Keep your stock dump to go back.

## Licence

MIT, see [`LICENSE`](LICENSE). Files derived from Apache-2.0 sources keep their headers and stay under
the Apache License 2.0 ([`LICENSE-APACHE-2.0`](LICENSE-APACHE-2.0)): the HomeKit ADK platform layer
(`firmware/libs/hap-pal-ambz2/`), the accessory database code derived from the ADK and Espressif
(`hap_db.h`, `db_*.c` and `hap_app.c` in `firmware/libs/hap-app/`, `thermostat_db.c`, the example's `switch.c`) and Matter test vectors and test credentials
from connectedhomeip and rs-matter. [`NOTICE`](NOTICE) lists every such file.

The build downloads Apple's HomeKit ADK (Apache-2.0) and Realtek's ameba-rtos-z2 SDK under their own
licences; neither is redistributed here.
