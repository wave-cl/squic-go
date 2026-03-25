# sQUIC — Shielded QUIC

## Features

1. **Pre-handshake authentication** — clients must prove knowledge of the server's public key before the QUIC handshake begins. Invalid packets are silently discarded.
2. **No CA/PKI** — identity is a pinned Ed25519 public key (32 bytes). No certificate authorities.
3. **Client whitelisting** — runtime-manageable set of allowed client keys. Non-whitelisted clients are silently dropped at the MAC layer.
4. **Persistent client identity** — optional `ClientKey` config for stable client identity across reconnects, enabling server-side whitelisting.
5. **Replay protection** — 120-second timestamp window + 8-byte cryptographic nonce per packet.
6. **DDoS resistance** — WireGuard-style MAC2 + cookie mechanism. Under load, the server requires proof-of-address before performing expensive DH operations.
7. **Interoperable** — same wire format as squic-rust. Go server + Rust client (and vice versa) work together.

### Connection Modes

| Mode | Server config | Client config | Behaviour |
|------|--------------|---------------|-----------|
| **Open** | No `AllowedKeys` | No `ClientKey` | Any client with the server's public key can connect. Default. |
| **Whitelisted** | `AllowedKeys` set | `ClientKey` set | Only clients whose keys are in the whitelist can connect. Silently dropped before any QUIC processing. |

In all three modes, the server is silent to anyone who does not possess the server's public key.

### Connection String

A server's address and public key can be shared as a single string, for example:

```
sqc://example.com:443/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
```

## Install

```
go get github.com/wave-cl/squic-go
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

- **Client side**: Each connection uses an ephemeral or persistent X25519 key pair. Outgoing QUIC Initial packets get a 32-byte client public key + 4-byte timestamp + 16-byte MAC1 appended. MAC1 is computed using a DH shared secret (`X25519(clientPriv, serverPub)`), proving the client knows the server's public key. Set `Config.ClientKey` (hex Ed25519 seed) for a persistent identity that survives reconnects.
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

## Persistent client identity

By default, clients generate an ephemeral key pair per connection. To use a stable identity (required for server-side whitelisting):

```go
// Generate a client key pair (once, save the seed)
_, clientPub, _ := squic.GenerateKeyPair()
clientSeed := hex.EncodeToString(clientPrivateKeySeed) // 64 hex chars

// Connect with persistent identity
conn, _ := squic.Dial(ctx, "server:4433", serverPubKey, &squic.Config{
    ClientKey: clientSeed, // same X25519 pubkey every connection
})
```

The server can then whitelist this client's X25519 public key (derived from the Ed25519 key).

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

### http3

An HTTP/3 server and client over sQUIC:

```bash
cd examples/http3

# Server (prints public key on startup)
go run . -s -p 443

# Client
go run . -c 127.0.0.1 -p 443 --key <server-pub-hex>
go run . -c 127.0.0.1 -p 443 --key <server-pub-hex> /health
```

The server is invisible to port scanners — only clients with the server's public key receive HTTP/3 responses.

## License

MIT
