# What Apple Home does with a Matter thermostat

Run 2026-10-17/18. iPhone on iOS 27; the node ran on a Mac on the same LAN. No HomePod/Apple TV. Node: rs-matter 0.4.1 `thermostat` example
(commit c69916a), `--features astro-dnssd`, log level `rs_matter=debug`. Paths and command IDs
below come from that log.

## G0 result: passed

- iOS 27 accepts a test-certified device (VID 0xFFF1, rs-matter's test DAC/PAI/CD). It shows an
  **"Uncertified Accessory"** prompt and then continues. No hub needed.
- Scanning the QR was enough; the pairing code wasn't asked for separately.
- Commissioning, control (Off / Heat + setpoint) and Remove Accessory all worked.
- The macOS app firewall blocked the node until it was set to Allow. Not relevant on-device, but
  any Mac-hosted test node needs that.

## Commissioning sequence (as seen by the node)

PASE (BLE is not used here; the Mac node was discovered via `_matterc._udp` on IP), then:

| Order | Cluster / command | Notes |
|---|---|---|
| 1 | GeneralCommissioning (0x30) ArmFailSafe (0) | ×2 in total |
| 2 | GeneralCommissioning SetRegulatoryConfig (2) | |
| 3 | OperationalCredentials (0x3E) CertificateChainRequest (2) | DAC and PAI |
| 4 | OperationalCredentials AttestationRequest (0) | |
| 5 | OperationalCredentials CSRRequest (4) | ×2 (one per fabric) |
| 6 | OperationalCredentials AddTrustedRootCertificate (11) | ×2 |
| 7 | OperationalCredentials AddNOC (6) | ×2 → fabric indices 1 and 2, **no ICAC** |
| 8 | OperationalCredentials UpdateFabricLabel (9) | label "Home"; ×3 |
| 9 | AccessControl (0x1F) ACL write (attr 0) | |
| 10 | TimeSynchronization (0x38) SetUTCTime (0) | sent even though the cluster is optional |
| 11 | GeneralCommissioning CommissioningComplete (4) | ×2, over CASE |

So Apple adds **two fabrics** per device (both labelled "Home").
(Correction, checked 2026-10-18: the rs-matter commit of the trace, c69916a, `Fabrics::update_label`, already
rejects a label that another fabric uses, with NOCResponse LabelConflict(10). The node log only shows the requests,
not their answers, so "accepted" was an assumption. Apple finished commissioning anyway, i.e. it tolerates
LabelConflict on the second UpdateFabricLabel. Our firmware keeps the strict rule, matching rs-matter, matter.js
and the spec text; see `operational_credentials.c`.) With the planned 3-fabric limit that
leaves one slot for another ecosystem.

Also read during/after commissioning: Basic Information (0x28) attrs 2, 4, 15; GeneralCommissioning
attrs 0–4 and **12** (not implemented by rs-matter, Home didn't mind); GeneralDiagnostics (0x33)
attr 0; OperationalCredentials attrs 0, 1, 4, 5 (Fabrics/NOCs are re-read often); Descriptor (0x1D)
on EP0/EP1 including the global attrs (0xFFF8/9/B/C/D); a vendor cluster 0x134A0000 (rs-matter's
own) attr 1; ElectricalEnergyMeasurement (0x90) attr 8 (EP1 in the example, not in our device).

## Steady state

- **Subscriptions:** wildcard attribute paths, `keep_subs = true`, `min_int_floor = 0`,
  `max_int_ceil = 600`. One per controller session; the Mac's Home app subscribes too (5 subscribe
  requests seen in total, incl. re-subscribes after session drops).
- **Control is plain attribute writes**, no commands, `timed_request = false` on all 7 writes:
  - Thermostat (0x201) **SystemMode** (attr 28): Off / Heat.
  - Thermostat **OccupiedHeatingSetpoint** (attr 18), same write request as SystemMode when both
    change.
  - No SetpointRaiseLower. So the device side needs write handlers for attrs 18 and 28, not commands.
- **Reconnect:** the node's sends to the phone's link-local address failed ("No route to host")
  after the phone slept, and the sessions expired. When Home was reopened the phone set up a new
  CASE session and replayed the queued writes (Heat 21.5, 23.0, Off). Home doesn't report a failure
  while it's queuing.
- **Removal:** RemoveFabric (OperationalCredentials cmd 10) for fabric 1 → subscriptions of that
  fabric dropped, then the node deregistered its `_matter._tcp` record.

## Differences from the firmware we will build

The trace used the stock example, so these are not yet checked against our config:

- Setpoint limits 7.0–30.0 °C (700/3000); the thermostat needs 5.0–40.0 °C, step 0.5.
- EP1 also carried an energy-meter device type.
- PID 0x8001, product name "MyTest".
- rs-matter's test DAC/PAI/CD, not ours.
- mDNS queries from the phone weren't captured (no tcpdump without sudo on the Mac).
- Commissioning was over IP on the same LAN. BLE commissioning (with Wi-Fi provisioned from iOS)
  was tested later on the device itself and works; it isn't part of this trace.
