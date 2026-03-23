# sQUIC — Sovereign QUIC

sQUIC is an extension of QUIC that adds three features:

1. **Silent server** — the server is invisible to port scanners. Only clients that possess the server's public key can elicit a response.
2. **No CA/PKI** — identity is a pinned Ed25519 public key (32 bytes), not a certificate chain. No certificate authorities.
3. **Client whitelisting** — optionally restrict connections to a set of known client public keys, manageable at runtime. Add, remove, and query keys without restarting the server. Non-whitelisted clients are silently dropped at the MAC layer — no handshake, no state, no response.

Everything else is standard QUIC — streams, flow control, congestion control, connection migration, 0-RTT — all provided by quic-go with zero modifications.

## Rationale

Standard QUIC servers respond to every incoming packet, making them trivially discoverable by port scanners. TLS certificate chains leak server identity and depend on certificate authorities. There is no built-in mechanism to restrict which clients can even attempt a connection.

sQUIC addresses this by borrowing ideas from WireGuard: the server is silent until a client proves knowledge of the server's public key via a DH-based MAC. No valid MAC, no response — the server is indistinguishable from a closed port. Identity is a single 32-byte key, not a certificate. Optional whitelisting lets the server restrict access to known clients at the MAC layer, before any QUIC state is allocated.

The implementation wraps quic-go as an unmodified dependency rather than forking it. Upstream improvements — performance, security fixes, new RFCs — arrive via `go get -u`. The wrapper touches only the UDP socket layer, preserving quic-go's full fast path (GSO, sendmmsg/recvmmsg, ECN) with near-zero overhead.

## Install

```
go get github.com/lyowhs/squic-go
```

## Usage

### Server

```go
// Generate a new key pair (first run)
cert, pubKey, _ := squic.GenerateKeyPair()

// Or load an existing private key (persistent server identity)
cert, pubKey, _ := squic.LoadKeyPair("a1b2c3d4...64 hex chars...")

// Listen — server is silent to anyone without pubKey
ln, _ := squic.Listen("udp", ":443", cert, pubKey, nil)

conn, _ := ln.Accept(ctx)
stream, _ := conn.AcceptStream(ctx)
// ... use stream like any quic-go stream
```

### Client

```go
// serverPubKey is the 32-byte Ed25519 key, known out-of-band
conn, _ := squic.Dial(ctx, "server:4433", serverPubKey, nil)

stream, _ := conn.OpenStreamSync(ctx)
stream.Write([]byte("hello"))
```

## How it works

sQUIC wraps the UDP socket (`net.PacketConn`) that quic-go uses:

- **Client side**: Each connection generates an ephemeral X25519 key pair. Outgoing QUIC Initial packets get a 32-byte client public key + 16-byte MAC1 appended. MAC1 is computed using a DH shared secret (`X25519(clientPriv, serverPub)`), proving the client knows the server's public key.
- **Server side**: Validates MAC1 on incoming Initial packets via DH (`X25519(serverPriv, clientPub)`). Invalid MAC1 → silently dropped (no response). Valid MAC1 → stripped and passed to quic-go.
- **Client key whitelisting** (optional): The server can restrict connections to a set of known client X25519 public keys. Non-whitelisted clients are silently dropped — the server remains fully invisible to them.

After the handshake, all packets flow through unmodified. The wrapper implements quic-go's `OOBCapablePacketConn` and `batchConn` interfaces, preserving the full fast path (recvmmsg, sendmmsg, GSO, ECN) with near-zero overhead.

TLS is used internally with self-signed certificates. The client verifies the server owns the private key by pinning the Ed25519 public key in `VerifyPeerCertificate`.

## Key format

Keys are 32-byte Ed25519 public keys (64 hex characters):

```
c0624ec327d4a18fb904da967dc0f4901433137c32c2ee459f4235d205626ca5
```

## Client key whitelisting

```go
// At startup: pre-populate whitelist via config
ln, _ := squic.Listen("udp", ":4433", cert, pubKey, &squic.Config{
    AllowedKeys: [][]byte{clientKey1, clientKey2},
})

// Or enable at runtime with initial keys
ln.EnableWhitelist(clientKey1, clientKey2)

// Add/remove keys at runtime (thread-safe, no restart needed)
ln.AllowKey(newClientKey)
ln.RemoveKey(revokedClientKey)

// Query the whitelist
if ln.HasKey(someKey) { /* allowed */ }
keys := ln.AllowedKeys() // returns a copy of all keys

// Disable whitelisting entirely (allow any valid MAC1 client)
ln.DisableWhitelist()
```

Non-whitelisted clients are silently dropped at the MAC1 layer — no TLS handshake, no state allocation, no response. The server remains fully invisible.

## Performance

sQUIC adds near-zero overhead to quic-go's fast path:

| Mode | macOS M4 Pro (loopback) | Cheapest Linux VPS (loopback) |
|------|------------------------|---------------------|
| Upload | 1,479 Mbps | 1,417 Mbps |
| Download | 1,457 Mbps | 1,437 Mbps |
| Bidirectional | 2,080 Mbps total | 1,683 Mbps total |

Measured with the included sqperf tool over loopback, 30-second runs.

## Examples

### sqperf

A throughput benchmarking tool:

```bash
cd examples/sqperf

# Server (prints public key on startup)
go run . -s -p 4433

# Client
go run . -c 127.0.0.1 -p 4433 --key <server-pub-hex> -t 30

# Download mode (server sends)
go run . -c 127.0.0.1 -p 4433 --key <server-pub-hex> -t 30 -R

# Bidirectional
go run . -c 127.0.0.1 -p 4433 --key <server-pub-hex> -t 30 -d
```

## License

MIT
