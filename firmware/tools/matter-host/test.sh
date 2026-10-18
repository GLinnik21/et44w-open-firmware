#!/bin/sh
# make test: start the node on a free port (--port 0 -> it prints PORT=n), run the loopback client, stop the node.
# The node runs with a 128-byte IM buffer so the wildcard read must be chunked.
NODE=$1
CLIENT=$2
DIR=$(mktemp -d "${TMPDIR:-/tmp}/matter-host-test.XXXXXX") || exit 1
LOG=$DIR/node.log
NPID=
cleanup() {
    [ -n "$NPID" ] && kill "$NPID" 2>/dev/null
    [ -n "$NPID" ] && wait "$NPID" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT INT TERM

"$NODE" --port 0 --kv-dir "$DIR/kv" --im-buf 128 --no-mdns >"$LOG" 2>&1 &
NPID=$!
PORT=
i=0
while [ $i -lt 100 ]; do
    PORT=$(sed -n 's/^PORT=//p' "$LOG" | head -n 1)
    [ -n "$PORT" ] && break
    kill -0 "$NPID" 2>/dev/null || { echo "node exited early:"; cat "$LOG"; exit 1; }
    sleep 0.1
    i=$((i + 1))
done
[ -n "$PORT" ] || { echo "node did not report a port:"; cat "$LOG"; exit 1; }
grep -E '^(qr|manual code)' "$LOG"
echo "node on port $PORT"
"$CLIENT" --port "$PORT" --host ::1 --expect-chunks 4
RC=$?
if [ $RC -eq 0 ]; then
    echo "same node over IPv4 (v4-mapped peer addresses)"
    "$CLIENT" --port "$PORT" --host 127.0.0.1 --expect-chunks 4
    RC=$?
fi
[ $RC -eq 0 ] && echo "matter-host loopback test: PASS" || { echo "matter-host loopback test: FAIL (rc=$RC)"; cat "$LOG"; }
exit $RC
