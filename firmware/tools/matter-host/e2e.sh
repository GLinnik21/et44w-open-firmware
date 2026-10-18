#!/bin/sh
# make e2e: the matter.js scenario against matter-host (needs NODE_BIN and matter.js in MATTERJS_CTL_DIR, see
# ctl/matter-ctl.cjs). Everything stays on this Mac: the node answers on ::1 / 127.0.0.1, records go through
# mDNSResponder (dns-sd). Steps:
#   1 commission fabric 1 by IP (::1, manual pairing code)      2 chunked wildcard read of endpoints 0, 1 and 2
#   3 subscribe (1/60 s), room +0.5 C (SIGUSR1) -> report         4 write setpoint 23.5 C, SystemMode Off, Heat
#   4b Schedule switch (endpoint 2 OnOff) on, toggle -> DP2 smart, hold
#   5 restart the node, read over a new CASE session (persisted fabric, RebootCount 1)
#   6 OpenCommissioningWindow (ECM) -> fabric 2 by mDNS discovery (_matterc._udp), second storage, own label;
#     its operational record (_matter._tcp) found through dns-sd    7 RemoveFabric 2, then 1 -> boot window again
# KEEP=1 keeps the work dir (logs) for inspection.
NODE_HOST=$1
NODE_BIN=${NODE_BIN:-node}
HERE=$(cd "$(dirname "$0")" && pwd)
CTL="$HERE/ctl/matter-ctl.cjs"
DIR=$(mktemp -d "${TMPDIR:-/tmp}/matter-e2e.XXXXXX") || exit 1
NPID=
PORT=
STEP=0
cleanup() {
    [ -n "$NPID" ] && kill "$NPID" 2>/dev/null && wait "$NPID" 2>/dev/null
    if [ "${KEEP:-0}" = 1 ]; then echo "logs kept in $DIR"; else rm -rf "$DIR"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fail() {
    echo "e2e FAIL at step $STEP: $*"
    echo "---- node log (tail)"; tail -n 30 "$DIR/node.log"
    echo "---- last ctl output (tail)"; tail -n 30 "$DIR/ctl.out"
    exit 1
}
step() { STEP=$((STEP + 1)); echo "-- $STEP. $*"; }

start_node() {   # [--reset]
    : >"$DIR/node.log"
    "$NODE_HOST" --port "${PORT:-0}" --kv-dir "$DIR/kv" --im-buf 900 "$@" >>"$DIR/node.log" 2>&1 &
    NPID=$!
    i=0
    while [ $i -lt 100 ]; do
        P=$(sed -n 's/^PORT=//p' "$DIR/node.log" | head -n 1)
        [ -n "$P" ] && { PORT=$P; return 0; }
        kill -0 "$NPID" 2>/dev/null || fail "node exited"
        sleep 0.1
        i=$((i + 1))
    done
    fail "node did not report a port"
}
stop_node() { kill "$NPID"; wait "$NPID" 2>/dev/null; NPID=; }

ctl() {          # <storage> args...  (output in $DIR/ctl.out, echoed through the filter below)
    s=$1; shift
    "$NODE_BIN" "$CTL" --storage "$DIR/$s" "$@" >"$DIR/ctl.out" 2>&1
}
expect() { grep -q -- "$1" "$DIR/ctl.out" || fail "expected '$1'"; }
show() { grep -E -- "$1" "$DIR/ctl.out" | cut -c1-160; }

"$NODE_BIN" --version >/dev/null 2>&1 || { echo "e2e: node.js not found ($NODE_BIN; set NODE_BIN)"; exit 2; }
"$NODE_BIN" "$CTL" --help >"$DIR/ctl.out" 2>&1 || { cat "$DIR/ctl.out"; echo "e2e: matter.js missing: npm install --prefix firmware/out-host/matterjs @matter/nodejs-shell@0.17.9 (or set MATTERJS_CTL_DIR)"; exit 2; }
start_node --reset
grep -q "fabrics=0 reboot_count=0 window=open" "$DIR/node.log" || fail "fresh node state"
echo "node on port $PORT (pid $NPID)"

step "commission fabric 1 by IP [::1]:$PORT"
ctl ctl1 --label ctl-one --timeout 120 commission --ip ::1 --port "$PORT" --pairing-code 34970112332 || fail "commission rc"
expect "commissioned, node id"
grep -q "fabrics=1 (+0 pending) window=closed" "$DIR/node.log" || fail "node did not commit fabric 1 / close the window"

step "chunked wildcard read of both endpoints"
ctl ctl1 --ip ::1 --port "$PORT" --verbose read || fail "read rc"
E0=$(grep -c '^0/' "$DIR/ctl.out"); E1=$(grep -c '^1/' "$DIR/ctl.out")
CH=$(sed 's/\x1b\[[0-9;]*m//g' "$DIR/ctl.out" | grep -c 'I/ReportData')
echo "   endpoint 0: $E0 attributes, endpoint 1: $E1 attributes, $CH ReportData messages"
E2=$(grep -c '^2/' "$DIR/ctl.out")
echo "   endpoint 2: $E2 attributes"
[ "$E0" -gt 50 ] && [ "$E1" -gt 20 ] && [ "$E2" -ge 6 ] && [ "$CH" -ge 2 ] || fail "wildcard read incomplete or not chunked"
expect "1/0x201/0x12 occupiedHeatingSetpoint = 2100"

step "TimeSynchronization: UTCTime null, SetUTCTime, read back"
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 0 --cluster 0x38 || fail "time read rc"
expect "0/0x38/0x0 utcTime = null"
expect "0/0x38/0x1 granularity = 0"
ctl ctl1 --ip ::1 --port "$PORT" set-utc || fail "set-utc rc"
expect "SetUTCTime sent"
expect "granularity = 3"
expect "timeSource = 2"
grep -q "^utc_set: .* granularity=3 source=2" "$DIR/node.log" || fail "the port did not see SetUTCTime"
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 0 --cluster 0x38 --attribute 0 || fail "time read 2 rc"
grep -Eq "utcTime = \"?[0-9]{15,}" "$DIR/ctl.out" || fail "UTCTime not set after SetUTCTime"

step "subscribe (min 1 s, max 60 s), room +0.5 C"
ctl ctl1 --ip ::1 --port "$PORT" subscribe --poke "$NPID" --seconds 20 || fail "no report after the temperature change"
show "^subscribed|^report:"

step "write setpoint and SystemMode"
ctl ctl1 --ip ::1 --port "$PORT" write-setpoint 23.5 || fail "write-setpoint rc"
expect "read back occupiedHeatingSetpoint = 2350"
ctl ctl1 --ip ::1 --port "$PORT" write-mode Off || fail "write-mode Off rc"
expect "read back systemMode = 0"
ctl ctl1 --ip ::1 --port "$PORT" write-mode Heat || fail "write-mode Heat rc"
expect "read back systemMode = 4"
grep -q "sim: DP16 <- 235" "$DIR/node.log" && grep -q "sim: DP1 <- 0" "$DIR/node.log" &&
    grep -q "sim: DP1 <- 1" "$DIR/node.log" || fail "the simulated MCU did not get the DPs"

step "Schedule switch (endpoint 2 OnOff): on, toggle off"
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 2 || fail "read endpoint 2 rc"
expect "2/0x6/0x0 onOff = false"
ctl ctl1 --ip ::1 --port "$PORT" onoff on || fail "onoff on rc"
expect "read back onOff = true"
ctl ctl1 --ip ::1 --port "$PORT" onoff toggle || fail "onoff toggle rc"
expect "read back onOff = false"
grep -q "sim: DP2 <- 1" "$DIR/node.log" && grep -q "sim: DP2 <- 2" "$DIR/node.log" ||
    fail "the simulated MCU did not get DP2 smart then hold"

step "restart the node, read over a new CASE session"
stop_node
start_node
grep -q "fabrics=1 reboot_count=1 window=closed" "$DIR/node.log" || fail "state after restart"
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 0 --cluster 0x33 --attribute 1 || fail "read after restart rc"
expect "rebootCount = 1"

step "OpenCommissioningWindow (ECM), fabric 2 by mDNS discovery (the node's clock set: AddNOC and CASE check validity)"
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 0 --cluster 0x38 --attribute 0 || fail "time read after restart rc"
expect "utcTime = null"                      # RAM only: unknown again after a reboot
ctl ctl1 --ip ::1 --port "$PORT" set-utc || fail "set-utc after restart rc"
ctl ctl1 --ip ::1 --port "$PORT" open-window --enhanced --window 300 || fail "open-window rc"
CODE=$(sed -n 's/.*"manualPairingCode":"\([0-9]*\)".*/\1/p' "$DIR/ctl.out")
[ -n "$CODE" ] || fail "no pairing code from open-window"
grep -q "CM=2" "$DIR/node.log" || fail "no enhanced commissionable record"
ctl ctl2 --label ctl-two --dns-sd --timeout 120 commission --pairing-code "$CODE" || fail "commission by discovery rc"
expect "commissioned, node id"
show "^dns-sd:"
ctl ctl2 --dns-sd read --endpoint 0 --cluster 0x3e --attribute 3 || fail "read on fabric 2 rc"
expect "commissionedFabrics = 2"
show "^dns-sd:"

step "RemoveFabric: fabric 2, then fabric 1"
ctl ctl2 --dns-sd remove-fabric || fail "remove-fabric 2 rc"
expect '"statusCode":0'
ctl ctl1 --ip ::1 --port "$PORT" read --endpoint 0 --cluster 0x3e --attribute 3 || fail "read on fabric 1 rc"
expect "commissionedFabrics = 1"
ctl ctl1 --ip ::1 --port "$PORT" remove-fabric || fail "remove-fabric 1 rc"
expect '"statusCode":0'
sleep 1
tail -n 3 "$DIR/node.log" | grep -q "_matterc._udp,_L3840" || grep -q "fabrics=0 (+0 pending) window=open" "$DIR/node.log" || fail "boot window did not reopen"
echo "matter-host e2e (matter.js): PASS"
