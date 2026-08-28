#!/bin/bash
# Cross-implementation test for the SIP-7 cookie defence.
#
# The peer-key test proves the two implementations agree on the Initial
# envelope and MAC1. Nothing proved they agree on the cookie path, which has
# four constructions that both ends have to compute identically and that had
# only ever been exercised inside one implementation at a time:
#
#   * cookie      = HMAC-SHA256(secret, ip)[:16], with the IP normalised to 16
#   * MAC2        = HMAC-SHA256(cookie, envelope-before-mac1 || mac1)[:16]
#   * cookie_key  = SHA-256("squic-cookie-v1" || server X25519 pub)
#   * the reply packet: 0x01 || nonce(24) || XChaCha20-Poly1305(cookie)
#
# A server started with --under-load challenges every caller before doing any
# key agreement, so a connection completes only if the client opened the reply,
# recomputed the cookie's MAC2 over exactly the right range, and the server
# verified it. Each pairing asserts the handshake succeeded AND that the server
# reports at least one challenge issued and one MAC2 verified — otherwise a run
# that quietly skipped the cookie path would pass.
#
# Needs squic-rust checked out as a sibling of squic-go by default; override
# with SQUIC_RUST_DIR.
set -u
GO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SQUIC_RUST_DIR="${SQUIC_RUST_DIR:-$(cd "$GO_DIR/../squic-rust" && pwd)}"

echo "building probes..."
( cd "$SQUIC_RUST_DIR" && cargo build --release --example peerkey_probe ) || exit 2
RUST="$SQUIC_RUST_DIR/target/release/examples/peerkey_probe"
GO="$(mktemp -d)/peerkeyprobe"
( cd "$GO_DIR" && go build -o "$GO" ./examples/peerkeyprobe/ ) || exit 2

WORK="$(mktemp -d)"
SERVER_SEED="3333333333333333333333333333333333333333333333333333333333333333"
CLIENT_SEED="4444444444444444444444444444444444444444444444444444444444444444"
pass=0; fail=0; port=5400

run() { # $1=server label $2=server bin  $3=client label $4=client bin
  port=$((port+1))
  local so="$WORK/s_$1_$3.out" co="$WORK/c_$1_$3.out"
  "$2" --server --port "$port" --server-key "$SERVER_SEED" --under-load >"$so" 2>"$so.err" &
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

  "$4" --client --host 127.0.0.1 --port "$port" --server-pub "$pub" --client-key "$CLIENT_SEED" \
    >"$co" 2>"$co.err"
  local dialed=$?
  for _ in $(seq 1 30); do grep -q COOKIES "$so" && break; sleep 0.1; done
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null

  local pk cx cookies replies verified
  pk=$(grep -oE 'PEERKEY=[0-9a-f]+|PEERKEY=none' "$so" | head -1 | cut -d= -f2)
  cx=$(grep -oE 'CLIENTX=[0-9a-f]+' "$co" | head -1 | cut -d= -f2)
  cookies=$(grep -oE 'COOKIES=[0-9]+,[0-9]+' "$so" | head -1 | cut -d= -f2)
  replies=${cookies%%,*}
  verified=${cookies##*,}

  if [ "$dialed" -eq 0 ] && [ -n "$pk" ] && [ "$pk" = "$cx" ] \
     && [ -n "$replies" ] && [ "$replies" -ge 1 ] && [ "$verified" -ge 1 ]; then
    echo "  [$1 server / $3 client] PASS  challenges=$replies mac2_verified=$verified"
    pass=$((pass+1))
  else
    echo "  [$1 server / $3 client] FAIL"
    echo "      dial exit=$dialed PEERKEY=$pk CLIENTX=$cx COOKIES=$cookies"
    [ -s "$so.err" ] && sed 's/^/    s.err: /' "$so.err" | head -3
    [ -s "$co.err" ] && sed 's/^/    c.err: /' "$co.err" | head -3
    fail=$((fail+1))
  fi
}

echo "=== cross-implementation SIP-7 cookie test ==="
run rust "$RUST" rust "$RUST"
run rust "$RUST" go   "$GO"
run go   "$GO"   rust "$RUST"
run go   "$GO"   go   "$GO"
echo "=== pass=$pass fail=$fail ==="
rm -rf "$WORK"
exit "$fail"
