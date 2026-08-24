#!/bin/bash
# Cross-implementation test for the SIP-2 peer-key accessor.
#
# For each (server, client) pairing across the Rust and Go implementations,
# assert that the peer key the server verified and exposes (PEERKEY) equals the
# X25519 key the client advertises it will send (CLIENTX). The two mixed
# pairings are the point: they prove the DCID join and key extraction agree on
# the wire between implementations.
#
# Needs squic-rust checked out as a sibling of squic-go by default; override
# with SQUIC_RUST_DIR. Builds both probes, then runs the 4x matrix.
set -u
GO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SQUIC_RUST_DIR="${SQUIC_RUST_DIR:-$(cd "$GO_DIR/../squic-rust" && pwd)}"

echo "building probes..."
( cd "$SQUIC_RUST_DIR" && cargo build --release --example peerkey_probe ) || exit 2
RUST="$SQUIC_RUST_DIR/target/release/examples/peerkey_probe"
GO="$(mktemp -d)/peerkeyprobe"
( cd "$GO_DIR" && go build -o "$GO" ./examples/peerkeyprobe/ ) || exit 2

WORK="$(mktemp -d)"
SERVER_SEED="1111111111111111111111111111111111111111111111111111111111111111"
CLIENT_SEED="2222222222222222222222222222222222222222222222222222222222222222"
pass=0; fail=0; port=5300

run() { # $1=server label $2=server bin  $3=client label $4=client bin
  port=$((port+1))
  local so="$WORK/s_$1_$3.out" co="$WORK/c_$1_$3.out"
  "$2" --server --port "$port" --server-key "$SERVER_SEED" >"$so" 2>"$so.err" &
  local spid=$!
  local pub=""
  for _ in $(seq 1 50); do
    pub=$(grep -oE 'SERVERPUB=[0-9a-f]+' "$so" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$pub" ] && break
    sleep 0.1
  done
  if [ -z "$pub" ]; then
    echo "  [$1 server / $3 client] FAIL: no SERVERPUB"; sed 's/^/    /' "$so.err" | head -3
    kill "$spid" 2>/dev/null; fail=$((fail+1)); return
  fi
  "$4" --client --host 127.0.0.1 --port "$port" --server-pub "$pub" --client-key "$CLIENT_SEED" >"$co" 2>"$co.err"
  for _ in $(seq 1 30); do grep -q PEERKEY "$so" && break; sleep 0.1; done
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local pk cx
  pk=$(grep -oE 'PEERKEY=[0-9a-f]+|PEERKEY=none' "$so" | head -1 | cut -d= -f2)
  cx=$(grep -oE 'CLIENTX=[0-9a-f]+' "$co" | head -1 | cut -d= -f2)
  if [ -n "$pk" ] && [ "$pk" = "$cx" ]; then
    echo "  [$1 server / $3 client] PASS  peer=$pk"; pass=$((pass+1))
  else
    echo "  [$1 server / $3 client] FAIL  PEERKEY=$pk CLIENTX=$cx"
    [ -s "$so.err" ] && sed 's/^/    s.err: /' "$so.err" | head -3
    [ -s "$co.err" ] && sed 's/^/    c.err: /' "$co.err" | head -3
    fail=$((fail+1))
  fi
}

echo "=== cross-implementation SIP-2 peer-key test ==="
run rust "$RUST" rust "$RUST"
run rust "$RUST" go   "$GO"
run go   "$GO"   rust "$RUST"
run go   "$GO"   go   "$GO"
echo "=== pass=$pass fail=$fail ==="
rm -rf "$WORK"
exit "$fail"
