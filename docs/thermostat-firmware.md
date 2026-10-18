# Warmee / ET-44W thermostat — stock WBR2 firmware findings

Source: a full flash dump of one unit (2026-10-16), running image FW2 (Tuya SDK, built May 23 2023,
product `gc1bxoq2hafxpa35`). Static analysis of strings so far; behaviour not yet confirmed
with a traffic capture. Dumps are not published: they hold the
owner's Wi-Fi credentials and the device's Tuya keys.

## Cloud endpoints compiled in

| Host | Use (from SDK naming) |
|---|---|
| `a.tuyacn.com:80/d.json` (plain HTTP), `a2.tuyacn.com:443`, `a3.tuyacn.com:443` | region / endpoint bootstrap |
| `https://%s/v2/url_config`, `/v1/dns_query`, `/device/dns_query` | fetch per-region API/MQTT hosts at runtime (EU hosts are not hard-coded) |
| `h3.iot-dns.com`, `h3-we.iot-dns.com` | Tuya's own DNS-over-HTTPS-style resolver |
| `m2.tuyacn.com`, `mq.gw.tuyacn.com` | MQTT gateway (China defaults) |
| `aispeech-cn.wgine.com:443` | Tuya voice SDK endpoint, linked in by the generic SDK; device has no microphone |

## What the cloud can make the device do (API names in the binary)

- `tuya.device.upgrade.get` / **`tuya.device.upgrade.silent.get`**: firmware OTA, including silent updates.
- `tuya.device.reset`: remote reset/unbind.
- **`atop.online.debug.log`** plus a `log/log_seq` store: upload of device logs on cloud request.
- `tuya.device.dynamic.config.get` ("use dynamic dns ip … for domain"): cloud can override DNS answers for its own domains.
- `tuya.device.file.get` / `file.notice`: file push.
- Timers, timezone, astronomical timers, schema/property sync and DP reporting (normal function).

## Credentials and leaks

- The Wi-Fi SSID **and password** are formatted into log lines in at least 4 places
  (`fast connect ssid %s,passwd:%s`, `Netcfg Finish … passwd:%s`, BLE provisioning, AP provisioning).
  Seen live on the `Log_Tx` UART at every boot. Whether the cloud log upload (`atop.online.debug.log`)
  includes these lines is **not yet known** (next step: decompile the log uploader in Ghidra).
- A UDP log channel exists (`open udp log fd`, `udp log port:%d`), and the firmware does Wi-Fi scans
  (`ssid list` with RSSI). Destination and trigger not yet determined.

## Remote logging (decompiled 2026-10-16)

`FUN_9b0747dc` registers one handler (`FUN_9b0744a0`) as an "ext_mq_pro" **cloud MQTT command**
for four `reqType`s; replies go back over MQTT protocol 0x37 (55). Each mode carries an expiry
timestamp `ts` and turns itself off afterwards (timer = `ts - now`).

| reqType | Payload | Effect |
|---|---|---|
| `localLog` | `level`, `ts` | raise the log verbosity until `ts` |
| `lanLog` | `port`, `ts` | opens a UDP socket and sends every log line to **255.255.255.255:`port`** (LAN broadcast, plaintext) until `ts` |
| `mqttRLog` | `ts` | sends every log line **to the Tuya cloud over MQTT** until `ts` |
| `enable_test` | `status` | toggles a test mode |

So Tuya (or anyone with control of the cloud account/MQTT session) can switch on live log
streaming to the cloud or the LAN. Logs include the lines that format the Wi-Fi password, but
those are printed while (re)connecting to Wi-Fi, before the MQTT/UDP sinks can send. They would
only leak if a reconnect path logged them while a sink is open; not verified either way.

`atop.online.debug.log` is **not** a log upload: it posts only `{"data":"<int>"[, "exp":"…"]}`.
`log_seq` / `netcfg_log` is a small typed event log (ints/strings with numeric ids) for
network-provisioning diagnostics, stored in flash and uploaded after pairing ("upolad %s").

## TuyaMCU link to the CBM7326 (decompiled 2026-10-17)

- UART0 (A13 RX / A14 TX). Baud table at `0x9b0be278` = {9600, 115200}. The firmware tries each rate
  until a frame passes the checksum, then saves the result as KV `baud_cfg`. Tuya's KV store
  (0x1D4000–0x1E4FFF) is encrypted, so the saved value is not readable from the dump; the boot log shows it.
- Frame `55 AA ver cmd len_hi len_lo data… sum`, where sum = sum of all preceding bytes mod 256 and the total length = len + 7.
  Parser `FUN_9b01f590`, dispatcher `FUN_9b01fc44`.
- The handler table at SRAM `0x10000bf8` handles MCU→module commands 0x02, 0x04, 0x05, 0x07,
  0x0A/0x0B (MCU OTA), 0x0C (GMT time), 0x0E, 0x0F, 0x1C (local time), 0x22, 0x24, 0x25, 0x2A,
  0x2B, 0x2C, 0x2D, 0x34 (7 subcommands), 0x37. 0xF0 is the production-test path (`FUN_9b06be00`).
- Wi-Fi reset (0x04/0x05, `FUN_9b056a78`) clears the stored SSID/password and enters pairing mode.
  It never sends DP 115.
- Net-state table at `0x10000b34` (internal state → code reported to the MCU): 0→0x05, 1→0x00,
  2 (AP, unconfigured)→0x01, 3/5 (disconnected)→0x02, 4/6 (on router)→0x03, 7/8/14 (cloud)→0x04,
  13→0x06. If the MCU's protocol version is below 3, cloud states are reported as 0x03 and state 0 as 0x02.
  The extra bytes 250/1500 in the table are LED blink periods.
- Per Tuya's serial protocol doc, the MCU asks for the time only after the module reports 0x04.

## Local interface

- Tuya LAN protocol 3.4 (encrypted, `ENABLE_LAN_ENCRYPTION:1`) on TCP 6668, UDP broadcast discovery.
- No telnet, shell or remote-command strings found.

## Observed traffic (router capture, 2026-10-16, 5 min incl. a reboot)

Captured on the router's IoT segment, filtered to the thermostat. Everything the device sent:

| Destination | Proto | What |
|---|---|---|
| 18.153.246.219:8883 (AWS eu-central-1) | TLS | MQTT to Tuya cloud; one persistent session, keepalive every 60 s; reconnected immediately after reboot |
| 18.198.62.99:443 (AWS eu-central-1) | TLS-PSK | Tuya HTTPS API, 6 short sessions in the first 90 s after boot, then idle |
| 255.255.255.255:6667 | UDP | Tuya LAN discovery broadcast every ~5 s |
| router | DHCP | lease renew at boot |

- **No DNS at all**, even after reboot: it connects to IPs it cached from Tuya's dynamic config
  (current DNS for `a1/m1.tuyaeu.com` returns different AWS IPs). So DNS-based blocking won't
  catch it; blocking needs an IP/firewall rule for the whole IoT segment.
- No plain HTTP (the `a.tuyacn.com:80` fallback was not used), no NTP, no traffic to China, nothing
  to other LAN hosts except a local controller's polls on 6668.
- HTTPS uses TLS-PSK only (ciphers `c0a5`, `008d`, … `00ff`; no SNI, no certificates), keyed from
  the device's auth key in flash; content is not readable without extracting that key.

## Open questions

1. ~~Confirm the actual hosts contacted~~ Done (above). Longer captures could still show periodic jobs (OTA checks, timer sync) that run less than every 5 min.
2. ~~Does the uploaded debug log contain the Wi-Fi password?~~ No: `atop.online.debug.log` sends one int; live log streaming is the `mqttRLog` command (above).
3. ~~Where does the UDP log go?~~ LAN broadcast on a cloud-chosen port, enabled by the `lanLog` MQTT command.
4. Which string ids `log_seq` records (callers of the thin wrappers `FUN_9b0549d0`/`FUN_9b0549de` are indirect, so not resolved yet).
