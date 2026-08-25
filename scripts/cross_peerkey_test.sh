#!/bin/bash
# Cross-implementation test for the SIP-2 peer-key and SIP-3 peer-identity
# accessors.
#
# For each (server, client) pairing across the Rust and Go implementations,
# assert that:
#   * the peer key the server verified and exposes (PEERKEY) equals the X25519
#     key the client says it will send (CLIENTX), and
#   * the Ed25519 identity the server bound (PEERID) equals the one the client
#     says it advertises (CLIENTED) — which is the literal string "none" when
#     the client does not advertise, so one comparison covers the advertised
#     and the anonymous case.
#
# Every pairing is run twice, with and without --advertise. The mixed pairings
# are the point: they prove the envelope layout, the MAC1 input ordering, the
# derivation check and the DCID join all agree on the wire between the two
# implementations.
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

run() { # $1=server label $2=server bin  $3=client label $4=client bin  $5=advertise(0|1)
  port=$((port+1))
  local adv_flag="" adv_label="anon"
  if [ "$5" = "1" ]; then adv_flag="--advertise"; adv_label="advertised"; fi
  local so="$WORK/s_$1_$3_$5.out" co="$WORK/c_$1_$3_$5.out"
  "$2" --server --port "$port" --server-key "$SERVER_SEED" >"$so" 2>"$so.err" &
  local spid=$!
  local pub=""
  for _ in $(seq 1 50); do
    pub=$(grep -oE 'SERVERPUB=[0-9a-f]+' "$so" 2>/dev/null | head -1 | cut -d= -f2)
    [ -n "$pub" ] && break
    sleep 0.1
  done
  if [ -z "$pub" ]; then
    echo "  [$1 server / $3 client / $adv_label] FAIL: no SERVERPUB"; sed 's/^/    /' "$so.err" | head -3
    kill "$spid" 2>/dev/null; fail=$((fail+1)); return
  fi
  # shellcheck disable=SC2086 # adv_flag is one optional literal flag
  "$4" --client --host 127.0.0.1 --port "$port" --server-pub "$pub" --client-key "$CLIENT_SEED" $adv_flag >"$co" 2>"$co.err"
  for _ in $(seq 1 30); do grep -q PEERID "$so" && break; sleep 0.1; done
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  local pk cx pid ced
  pk=$(grep -oE 'PEERKEY=[0-9a-f]+|PEERKEY=none' "$so" | head -1 | cut -d= -f2)
  cx=$(grep -oE 'CLIENTX=[0-9a-f]+' "$co" | head -1 | cut -d= -f2)
  pid=$(grep -oE 'PEERID=[0-9a-f]+|PEERID=none' "$so" | head -1 | cut -d= -f2)
  ced=$(grep -oE 'CLIENTED=[0-9a-f]+|CLIENTED=none' "$co" | head -1 | cut -d= -f2)
  if [ -n "$pk" ] && [ "$pk" = "$cx" ] && [ -n "$pid" ] && [ "$pid" = "$ced" ]; then
    echo "  [$1 server / $3 client / $adv_label] PASS  peer=${pk:0:16}… id=${pid:0:16}…"
    pass=$((pass+1))
  else
    echo "  [$1 server / $3 client / $adv_label] FAIL"
    echo "      PEERKEY=$pk CLIENTX=$cx"
    echo "      PEERID=$pid CLIENTED=$ced"
    [ -s "$so.err" ] && sed 's/^/    s.err: /' "$so.err" | head -3
    [ -s "$co.err" ] && sed 's/^/    c.err: /' "$co.err" | head -3
    fail=$((fail+1))
  fi
}

echo "=== cross-implementation SIP-2 peer-key / SIP-3 peer-identity test ==="
for adv in 0 1; do
  run rust "$RUST" rust "$RUST" "$adv"
  run rust "$RUST" go   "$GO"   "$adv"
  run go   "$GO"   rust "$RUST" "$adv"
  run go   "$GO"   go   "$GO"   "$adv"
done
echo "=== pass=$pass fail=$fail ==="
rm -rf "$WORK"
exit "$fail"
