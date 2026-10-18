#!/usr/bin/env node
/* matter-ctl: a small Matter controller (matter.js CommissioningController) for testing our device stack.
 *
 *   node matter-ctl.cjs [global options] <command> [command options]
 *
 * Commands
 *   discover                         list commissionable devices found over mDNS (--timeout s)
 *   commission                       commission an on-network device. Target: --ip A --port P, or discovery
 *                                    by --discriminator D / --short-discriminator S. Credentials:
 *                                    --pairing-code 11/21-digit manual code, --qr MT:..., or --passcode N
 *   info                             Basic Information of the node (+ device types, root server list)
 *   read [--endpoint E] [--cluster C] [--attribute A]
 *                                    wildcard read, printed as endpoint/cluster/attribute = value
 *   subscribe [--seconds N] [--poke PID]
 *                                    subscribe to all attributes and events (MinIntervalFloor 1 s, MaxIntervalCeiling
 *                                    60 s), print reports (default 60 s). --poke: once subscribed, send SIGUSR1 to
 *                                    PID (matter-host: room +0.5 C) and exit 0 as soon as a LocalTemperature report
 *                                    with the new value arrives (exit 4 if none within --seconds)
 *   write-setpoint <degC>            write Thermostat.OccupiedHeatingSetpoint (hundredths of a degree on the wire)
 *   write-mode <Off|Auto|Heat|...>   write Thermostat.SystemMode (name or number)
 *   onoff <on|off|toggle>            invoke OnOff.On/Off/Toggle on --endpoint (default 2, the thermostat's Schedule
 *                                    switch), then read OnOff back
 *   remove-fabric                    invoke OperationalCredentials.RemoveFabric for our own fabric, then
 *                                    forget the node locally
 *   open-window [--enhanced] [--window s]
 *                                    open a second commissioning window. Default: basic window (the device's
 *                                    own setup code stays valid, OpenBasicCommissioningWindow). --enhanced:
 *                                    OpenCommissioningWindow with a fresh random passcode, printed here.
 *   set-utc                          invoke TimeSynchronization.SetUTCTime with this Mac's clock (granularity ms, source
 *                                    Admin), then read UTCTime/Granularity/TimeSource back (matter.js itself does not
 *                                    send SetUTCTime; Apple does during commissioning)
 *   nodes                            list commissioned nodes in this storage
 *
 * Global options
 *   --storage DIR     fabric/controller storage (default <repo>/firmware/out-host/matter-ctl, git-ignored)
 *   --node ID         node id to act on (default: first commissioned node)
 *   --endpoint E      endpoint for write-* commands (default 1)
 *   --iface NAME      network interface for mDNS (e.g. en0)
 *   --label TEXT      adminFabricLabel of this controller (default matter-ctl); distinct per storage, or AddNOC/
 *                     UpdateFabricLabel on a second fabric hits LabelConflict
 *   --ip A --port P   (any command) operational address to use for a node whose address matter.js does not know
 *                     yet (its own mDNS cannot send on this Mac, see --dns-sd)
 *   --dns-sd          discover through macOS mDNSResponder (dns-sd -B/-L/-G) instead of matter.js's own mDNS:
 *                     commissionable records for 'commission' (by --discriminator / pairing code), operational
 *                     records (_matter._tcp, <CFID>-<NodeID>) to find a commissioned node's address. Needed when
 *                     matter.js's multicast sends fail with EHOSTUNREACH (macOS Local Network privacy for node)
 *   --dns-sd-loopback with --dns-sd: keep the discovered port but connect to ::1 (the macOS app firewall blocks
 *                     unsigned binaries on the LAN address)
 *   --timeout S       overall command timeout in seconds (default 60; commission 120)
 *   --strict-attestation   refuse commissioning when attestation has error-level findings
 *   --verbose         matter.js debug logging (default: warnings only)
 *
 * Attestation: without a DclCertificateService in the environment (this tool never creates one, so no DCL or
 * GitHub traffic) matter.js checks only the nonce, the attestation signature with the DAC key, VID/PID against
 * the Certification Declaration and the CD's product list; PAA/chain/revocation/CD-signer checks are skipped
 * with warnings. Findings are printed and, unless --strict-attestation, accepted.
 *
 * matter.js is loaded from MATTERJS_CTL_DIR (default <repo>/firmware/out-host/matterjs, git-ignored). Install it
 * there once, from the repo root: npm install --prefix firmware/out-host/matterjs @matter/nodejs-shell@0.17.9
 * Storage contains the controller's fabric root key: it stays out of the repo (firmware/out-host is ignored).
 */
"use strict";

const path = require("node:path");
const { createRequire } = require("node:module");
const { parseArgs } = require("node:util");

const LIB_DIR = process.env.MATTERJS_CTL_DIR || path.resolve(__dirname, "..", "..", "..", "out-host", "matterjs");
let lib;
try {
    lib = createRequire(path.join(LIB_DIR, "package.json"));
    lib.resolve("@project-chip/matter.js");
} catch (e) {
    console.error(`matter.js not found under ${LIB_DIR} (set MATTERJS_CTL_DIR): ${e.message}`);
    process.exit(2);
}

const DEFAULT_STORAGE = path.resolve(__dirname, "..", "..", "..", "out-host", "matter-ctl");

const { values: opt, positionals } = parseArgs({
    allowPositionals: true,
    options: {
        storage: { type: "string", default: DEFAULT_STORAGE },
        node: { type: "string" },
        endpoint: { type: "string" },
        cluster: { type: "string" },
        attribute: { type: "string" },
        iface: { type: "string" },
        timeout: { type: "string" },
        ip: { type: "string" },
        port: { type: "string" },
        discriminator: { type: "string" },
        "short-discriminator": { type: "string" },
        "pairing-code": { type: "string" },
        qr: { type: "string" },
        passcode: { type: "string" },
        seconds: { type: "string" },
        window: { type: "string" },
        enhanced: { type: "boolean", default: false },
        label: { type: "string" },
        poke: { type: "string" },
        "dns-sd": { type: "boolean", default: false },
        "dns-sd-loopback": { type: "boolean", default: false },
        "strict-attestation": { type: "boolean", default: false },
        verbose: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
    },
});

// matter.js turns every `--name value` in process.argv into an environment variable (e.g. --storage collides
// with storage.path), so hide our options from it.
process.argv.length = 2;

const cmd = positionals[0];
if (opt.help || !cmd) {
    const src = require("node:fs").readFileSync(__filename, "utf8");
    console.log(src.slice(src.indexOf("/*") + 3, src.indexOf("*/")).replace(/^ \* ?/gm, ""));
    process.exit(cmd || opt.help ? 0 : 2);
}

const num = (s, what) => {
    const n = Number(s);
    if (!Number.isFinite(n)) throw new Error(`${what}: not a number: ${s}`);
    return n;
};
const jsonSafe = (v) =>
    JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x instanceof Uint8Array ? Buffer.from(x).toString("hex") : x));

class Done extends Error {}

// ---- discovery through macOS mDNSResponder (dns-sd) ----
const { spawn } = require("node:child_process");

/* Run `dns-sd args...` until `done(line)` returns a value or `ms` passes. */
function dnssd(args, done, ms = 8000) {
    return new Promise((resolve) => {
        const p = spawn("dns-sd", args, { stdio: ["ignore", "pipe", "ignore"] });
        let buf = "", result;
        const finish = (v) => { if (result === undefined) { result = v; p.kill(); clearTimeout(t); resolve(v); } };
        const t = setTimeout(() => finish(null), ms);
        p.stdout.on("data", (d) => {
            buf += d.toString();
            let i;
            while ((i = buf.indexOf("\n")) >= 0) {
                const line = buf.slice(0, i);
                buf = buf.slice(i + 1);
                const v = done(line);
                if (v !== undefined && v !== null) finish(v);
            }
        });
        p.on("exit", () => finish(null));
    });
}

/* Browse `type` (may carry a subtype: _matterc._udp,_L3840) for an instance accepted by `want`, resolve it to
 * host, port and TXT, and the host to an address. */
async function dnssdFind(type, want, ms) {
    const base = type.split(",")[0];
    const inst = await dnssd(["-B", type, "local."], (line) => {
        const m = line.match(/\s+Add\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$/);
        return m && want(m[1]) ? m[1] : undefined;
    }, ms);
    if (!inst) return null;
    let host, port, txt = "";
    await dnssd(["-L", inst, base, "local."], (line) => {
        const m = line.match(/can be reached at (\S+?)\.?:(\d+)/);
        if (m) { host = m[1]; port = Number(m[2]); return undefined; }
        if (host && line.trim()) { txt = line.trim(); return true; }
        return undefined;
    }, 5000);
    if (!host) return null;
    let ip = null;
    if (opt["dns-sd-loopback"]) ip = "::1";
    else {
        const seen = [];
        ip = await dnssd(["-G", "v4v6", host], (line) => {
            const m = line.match(/\s(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+:[0-9a-fA-F:]*(?:%\S+)?)\s+\d+\s*$/);
            if (m) seen.push(m[1]);
            return seen.find((a) => a.includes(".")) ?? undefined;
        }, 3000) ?? null;
    }
    console.log(`dns-sd: ${inst}.${base} -> ${host}:${port} (${ip}) TXT ${txt}`);
    return ip ? { instance: inst, ip, port, txt } : null;
}

/* Operational addresses matter.js cannot find itself: while commissioning, the commissioning address; else
 * --ip/--port for a peer without one, or (--dns-sd) the peer's _matter._tcp record, always re-resolved. */
let commissionAddress;
async function hookPeers(ctl, types) {
    const { PeerSet } = lib("@matter/protocol");
    const peers = ctl.node.env.get(PeerSet);
    const fill = async (peer) => {
        if (cmd === "commission") {
            // The new node answers on the address it was commissioned on; matter.js only falls back to a known
            // operational address, so it must be there before the CASE attempt starts (synchronously).
            if (commissionAddress && !peer.descriptor.operationalAddress) peer.descriptor.operationalAddress = commissionAddress;
            return;
        }
        if (peer.descriptor.operationalAddress && !opt["dns-sd"]) return;
        if (opt.ip) {
            peer.descriptor.operationalAddress = { type: "udp", ip: opt.ip, port: num(opt.port ?? "5540", "port") };
        } else if (opt["dns-sd"]) {
            const hex16 = (v) => BigInt(v).toString(16).toUpperCase().padStart(16, "0");
            const name = `${hex16(ctl.fabric.globalId)}-${hex16(peer.address.nodeId)}`;   // <CFID>-<NodeID>
            const r = await dnssdFind(`_matter._tcp,_I${hex16(ctl.fabric.globalId)}`, (inst) => inst.toUpperCase() === name, 10000);
            if (!r) throw new Error(`dns-sd: no operational record ${name}`);
            peer.descriptor.operationalAddress = { type: "udp", ip: r.ip, port: r.port };
        }
    };
    peers.added.on((peer) => { fill(peer).catch((e) => console.log("address lookup:", e.message)); });
    for (const peer of peers) await fill(peer);
}

async function main() {
    const general = lib("@matter/general");
    const types = lib("@matter/types");
    const clusters = lib("@matter/types/clusters");
    const { CommissioningController } = lib("@project-chip/matter.js");
    require("node:fs").mkdirSync(opt.storage, { recursive: true });
    lib("@matter/nodejs"); // registers the Node.js environment (file storage, UDP, mDNS)

    const { Environment, Logger, LogLevel, Seconds } = general;
    Logger.level = opt.verbose ? LogLevel.DEBUG : LogLevel.WARN;
    const env = Environment.default;
    env.vars.set("storage.path", opt.storage);
    env.vars.set("storage.driver", "file");
    if (opt.iface) env.vars.set("mdns.networkinterface", opt.iface);

    const ctl = new CommissioningController({
        environment: { environment: env, id: "ctl" },
        autoConnect: false,
        adminFabricLabel: opt.label ?? "matter-ctl",
        // No OTA provider endpoint, no TCP: keep the controller's own surface minimal.
    });
    const limit = Number(opt.timeout ?? (cmd === "commission" ? 120 : 60)) * 1000;
    const timer = setTimeout(() => {
        console.error(`timeout after ${limit / 1000} s`);
        process.exit(3);
    }, limit);

    try {
        await ctl.start();
        await hookPeers(ctl, types);
        await run(ctl, { general, types, clusters, Seconds });
    } finally {
        clearTimeout(timer);
        await Promise.race([ctl.close(), new Promise((r) => setTimeout(r, 5000))]).catch(() => {});
    }
}

async function pickNode(ctl, { types }) {
    const ids = ctl.getCommissionedNodes();
    if (ids.length === 0) throw new Error("no commissioned node in this storage (run 'commission' first)");
    const id = opt.node !== undefined ? types.NodeId(BigInt(opt.node)) : ids[0];
    if (!ctl.isNodeCommissioned(id)) throw new Error(`node ${id} is not commissioned here (have: ${ids.join(", ")})`);
    const node = await ctl.connectNode(id, { autoSubscribe: false });
    if (!node.initialized) await node.events.initialized;
    return node;
}

async function run(ctl, m) {
    const { types, clusters, Seconds } = m;
    switch (cmd) {
        case "nodes": {
            console.log(jsonSafe(ctl.getCommissionedNodesDetails()));
            return;
        }
        case "discover": {
            const found = await ctl.discoverCommissionableDevices(
                {},
                { onIpNetwork: true },
                (d) => console.log("found", jsonSafe(d)),
                Seconds(Number(opt.timeout ?? 10)),
            );
            console.log(`${found.length} commissionable device(s)`);
            return;
        }
        case "commission":
            return commission(ctl, m);
        case "info": {
            const node = await pickNode(ctl, m);
            console.log(jsonSafe(node.basicInformation));
            const d = node.getRootClusterClient(clusters.Descriptor);
            if (d) {
                console.log("root device types:", jsonSafe(await d.attributes.deviceTypeList.get()));
                console.log("root server list:", jsonSafe(await d.attributes.serverList.get()));
                console.log("parts:", jsonSafe(await d.attributes.partsList.get()));
            }
            return;
        }
        case "read": {
            const node = await pickNode(ctl, m);
            const attrs = [{}];
            if (opt.endpoint || opt.cluster || opt.attribute) {
                attrs[0] = {
                    endpointId: opt.endpoint !== undefined ? types.EndpointNumber(num(opt.endpoint, "endpoint")) : undefined,
                    clusterId: opt.cluster !== undefined ? types.ClusterId(num(opt.cluster, "cluster")) : undefined,
                    attributeId: opt.attribute !== undefined ? types.AttributeId(num(opt.attribute, "attribute")) : undefined,
                };
            }
            const reports = await node.getInteractionClient().getMultipleAttributes({ attributes: attrs });
            for (const r of reports) {
                const p = r.path;
                const hex = (n) => "0x" + Number(n).toString(16);
                console.log(`${p.endpointId}/${hex(p.clusterId)}/${hex(p.attributeId)}${p.attributeName ? " " + p.attributeName : ""} = ${jsonSafe(r.value)}`);
            }
            console.log(`${reports.length} attribute(s)`);
            return;
        }
        case "subscribe": {
            const node = await pickNode(ctl, m);
            const secs = Number(opt.seconds ?? 60);
            const hex = (n) => "0x" + Number(n).toString(16);
            let primed = false, before, resolveSeen;
            const seen = new Promise((r) => (resolveSeen = r));
            const ic = node.getInteractionClient();
            await ic.subscribeAllAttributesAndEvents({
                minIntervalFloorSeconds: 1,
                maxIntervalCeilingSeconds: 60,
                keepSubscriptions: false,
                attributeListener: ({ path: p, value }) => {
                    console.log(`attr ${p.endpointId}/${hex(p.clusterId)}/${p.attributeName ?? hex(p.attributeId)} = ${jsonSafe(value)}`);
                    if (p.endpointId === 1 && p.clusterId === 0x201 && p.attributeId === 0) {
                        if (!primed) before = value;
                        else if (value !== before) resolveSeen(value);
                    }
                },
                eventListener: ({ path: p, events }) =>
                    console.log(`event ${p.endpointId}/${hex(p.clusterId)}/${p.eventName ?? hex(p.eventId)} ${jsonSafe(events)}`),
            });
            primed = true;
            if (before === undefined) {
                const r = await ic.getMultipleAttributes({ attributes: [{ endpointId: types.EndpointNumber(1), clusterId: types.ClusterId(0x201), attributeId: types.AttributeId(0) }] });
                before = r[0]?.value;
            }
            console.log(`subscribed (LocalTemperature ${before}); listening for ${secs} s`);
            if (opt.poke) {
                process.kill(num(opt.poke, "poke"), "SIGUSR1");
                const t0 = Date.now();
                const v = await Promise.race([seen, new Promise((r) => setTimeout(() => r(undefined), secs * 1000))]);
                if (v === undefined) {
                    console.log("no LocalTemperature report after the poke");
                    process.exitCode = 4;
                } else console.log(`report: LocalTemperature ${before} -> ${v} after ${Date.now() - t0} ms`);
                return;
            }
            await new Promise((r) => setTimeout(r, secs * 1000));
            return;
        }
        case "write-setpoint": {
            const deg = num(positionals[1], "degC");
            await writeThermostat(ctl, m, "occupiedHeatingSetpoint", Math.round(deg * 100));
            return;
        }
        case "write-mode": {
            const arg = positionals[1];
            if (arg === undefined) throw new Error("write-mode <name|number>");
            const modes = clusters.Thermostat.SystemMode;
            const v = /^\d+$/.test(arg) ? Number(arg) : modes[arg[0].toUpperCase() + arg.slice(1)];
            if (v === undefined) throw new Error(`unknown SystemMode '${arg}' (have: ${Object.keys(modes).filter((k) => isNaN(k)).join(", ")})`);
            await writeThermostat(ctl, m, "systemMode", v);
            return;
        }
        case "onoff": {
            const what = positionals[1];
            if (!["on", "off", "toggle"].includes(what)) throw new Error("onoff <on|off|toggle>");
            const node = await pickNode(ctl, m);
            const ep = num(opt.endpoint ?? "2", "endpoint");
            const dev = node.getDeviceById(ep);
            const oo = dev?.getClusterClient(clusters.OnOff.Complete) ?? dev?.getClusterClient(clusters.OnOff);
            if (!oo) throw new Error(`no OnOff cluster on endpoint ${ep}`);
            await oo.commands[what]();
            console.log(`${what} sent to endpoint ${ep}`);
            console.log(`read back onOff = ${jsonSafe(await oo.attributes.onOff.get(true))}`);
            return;
        }
        case "remove-fabric": {
            const node = await pickNode(ctl, m);
            const oc = node.getRootClusterClient(clusters.OperationalCredentials);
            if (!oc) throw new Error("no OperationalCredentials cluster on root endpoint");
            const idx = await oc.attributes.currentFabricIndex.get(true);
            console.log(`current fabric index ${idx}; invoking RemoveFabric`);
            try {
                const r = await oc.commands.removeFabric({ fabricIndex: idx });
                console.log("RemoveFabric response:", jsonSafe(r));
            } catch (e) {
                console.log("RemoveFabric failed:", e.message);
                throw e;
            }
            await ctl.removeNode(node.nodeId, false).catch((e) => console.log("local removeNode:", e.message));
            console.log("node forgotten locally");
            return;
        }
        case "set-utc": {
            const node = await pickNode(ctl, m);
            const ts = node.getRootClusterClient(clusters.TimeSynchronization);
            if (!ts) throw new Error("no TimeSynchronization cluster on root endpoint");
            const unixUs = Date.now() * 1000;   // matter.js's epoch-us fields take unix microseconds and convert to the Matter epoch
            await ts.commands.setUtcTime({
                utcTime: unixUs,
                granularity: clusters.TimeSynchronization.Granularity.MillisecondsGranularity,
                timeSource: clusters.TimeSynchronization.TimeSource.Admin,
            });
            console.log(`SetUTCTime sent: unix us ${unixUs}`);
            console.log(`utcTime = ${jsonSafe(await ts.attributes.utcTime.get(true))}`);
            console.log(`granularity = ${jsonSafe(await ts.attributes.granularity.get(true))}`);
            console.log(`timeSource = ${jsonSafe(await ts.attributes.timeSource.get(true))}`);
            return;
        }
        case "open-window": {
            const node = await pickNode(ctl, m);
            const secs = Number(opt.window ?? 300);
            if (opt.enhanced) {
                const r = await node.openEnhancedCommissioningWindow(secs);
                console.log("enhanced window open:", jsonSafe(r));
            } else {
                await node.openBasicCommissioningWindow(secs);
                console.log(`basic window open for ${secs} s (use the device's own setup code)`);
            }
            return;
        }
        default:
            throw new Error(`unknown command '${cmd}' (try --help)`);
    }
}

async function writeThermostat(ctl, m, attrName, value) {
    const { types, clusters } = m;
    const node = await pickNode(ctl, m);
    const ep = types.EndpointNumber(num(opt.endpoint ?? "1", "endpoint"));
    const attribute = clusters.Thermostat.Complete.attributes[attrName];
    if (!attribute) throw new Error(`Thermostat has no attribute ${attrName}`);
    const res = await node.getInteractionClient().setMultipleAttributes({
        attributes: [{ endpointId: ep, clusterId: clusters.Thermostat.Complete.id, attribute, value }],
    });
    console.log(`write ${attrName}=${value} on endpoint ${ep}:`, res.length ? jsonSafe(res) : "ok (no per-attribute status)");
    const back = await node.getInteractionClient().getMultipleAttributes({
        attributes: [{ endpointId: ep, clusterId: clusters.Thermostat.Complete.id, attributeId: attribute.id }],
    });
    for (const r of back) console.log(`read back ${r.path.attributeName ?? attrName} = ${jsonSafe(r.value)}`);
}

async function commission(ctl, { types, clusters, general }) {
    let passcode;
    let longD = opt.discriminator !== undefined ? num(opt.discriminator, "discriminator") : undefined;
    let shortD = opt["short-discriminator"] !== undefined ? num(opt["short-discriminator"], "short-discriminator") : undefined;
    if (opt["pairing-code"]) {
        const r = types.ManualPairingCodeCodec.decode(opt["pairing-code"]);
        passcode = r.passcode;
        shortD = r.shortDiscriminator;
        longD = undefined;
    } else if (opt.qr) {
        const r = types.QrPairingCodeCodec.decode(opt.qr)[0];
        passcode = r.passcode;
        longD = r.discriminator;
        shortD = undefined;
    } else if (opt.passcode) {
        passcode = num(opt.passcode, "passcode");
    } else {
        throw new Error("need --pairing-code, --qr or --passcode");
    }
    const identifierData = longD !== undefined ? { longDiscriminator: longD } : shortD !== undefined ? { shortDiscriminator: shortD } : {};
    let knownAddress = opt.ip ? { type: "udp", ip: opt.ip, port: num(opt.port ?? "5540", "port") } : undefined;
    if (!knownAddress && opt["dns-sd"]) {
        const sub = longD !== undefined ? `_L${longD}` : shortD !== undefined ? `_S${shortD}` : "_CM";
        const r = await dnssdFind(`_matterc._udp,${sub}`, () => true, 15000);
        if (!r) throw new Error(`dns-sd: no commissionable node with subtype ${sub}`);
        knownAddress = { type: "udp", ip: r.ip, port: r.port };
    }
    commissionAddress = knownAddress;
    console.log(`commissioning: ${knownAddress ? `address ${knownAddress.ip}:${knownAddress.port}` : "mDNS discovery"}, ${jsonSafe(identifierData)}`);

    const nodeId = await ctl.commissionNode({
        discovery: { knownAddress, identifierData, discoveryCapabilities: { onIpNetwork: true }, timeout: general.Seconds(60) },
        passcode,
        autoSubscribe: false,
        commissioning: {
            regulatoryLocation: clusters.GeneralCommissioning.RegulatoryLocationType.IndoorOutdoor,
            regulatoryCountryCode: "XX",
            onAttestationFailure: (findings) => {
                const ok = opt["strict-attestation"] ? findings.every((f) => f.level !== "error") : true;
                for (const f of findings) console.log(`attestation ${ok ? "accepted" : "REJECTED"} [${f.level}] ${f.type}: ${f.message}`);
                return ok;
            },
        },
    });
    console.log("commissioned, node id", nodeId.toString());
    const node = ctl.getPairedNode(nodeId);
    if (node) {
        if (!node.initialized) await node.events.initialized;
        console.log(jsonSafe(node.basicInformation));
    }
}

main().then(
    () => process.exit(0),
    (e) => {
        console.error(`error: ${e && e.message ? e.message : e}`);
        if (opt.verbose && e && e.stack) console.error(e.stack);
        process.exit(1);
    },
);
