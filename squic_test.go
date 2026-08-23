package squic_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	squic "github.com/wave-cl/squic-go"
)

func TestMAC1RoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	data := []byte("test packet data")
	ts := squic.NowTimestamp()
	nonce, _ := squic.GenerateNonce()
	mac := squic.ComputeMAC1(sharedSecret, data, ts, nonce)

	if len(mac) != squic.MACSize {
		t.Fatalf("MAC1 length = %d, want %d", len(mac), squic.MACSize)
	}

	// Verify MAC1
	if !squic.VerifyMAC1(sharedSecret, data, ts, nonce, mac) {
		t.Error("valid MAC1 failed verification")
	}

	// Wrong key should fail
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	if squic.VerifyMAC1(wrongKey, data, ts, nonce, mac) {
		t.Error("MAC1 should fail with wrong key")
	}

	// Tampered data should fail
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0xFF
	if squic.VerifyMAC1(sharedSecret, tampered, ts, nonce, mac) {
		t.Error("MAC1 should fail with tampered data")
	}

	// Wrong timestamp should fail
	if squic.VerifyMAC1(sharedSecret, data, ts+1, nonce, mac) {
		t.Error("MAC1 should fail with different timestamp")
	}

	// Wrong nonce should fail
	wrongNonce := make([]byte, squic.NonceSize)
	rand.Read(wrongNonce)
	if squic.VerifyMAC1(sharedSecret, data, ts, wrongNonce, mac) {
		t.Error("MAC1 should fail with different nonce")
	}
}

func TestTimestampReplayWindow(t *testing.T) {
	now := squic.NowTimestamp()

	// Current time: valid
	if !squic.TimestampInWindow(now, now) {
		t.Error("current timestamp should be valid")
	}

	// 60 seconds ago: valid
	if !squic.TimestampInWindow(now-60, now) {
		t.Error("60s old timestamp should be valid")
	}

	// 119 seconds ago: valid (within 120s window)
	if !squic.TimestampInWindow(now-119, now) {
		t.Error("119s old timestamp should be valid")
	}

	// 121 seconds ago: invalid (outside 120s window)
	if squic.TimestampInWindow(now-121, now) {
		t.Error("121s old timestamp should be rejected")
	}

	// 60 seconds in the future: valid (clock skew tolerance)
	if !squic.TimestampInWindow(now+60, now) {
		t.Error("60s future timestamp should be valid")
	}

	// 121 seconds in the future: invalid
	if squic.TimestampInWindow(now+121, now) {
		t.Error("121s future timestamp should be rejected")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("empty certificate")
	}
	if len(pubKey) == 0 {
		t.Error("empty public key")
	}
}

func TestLoadKeyPair(t *testing.T) {
	// Generate a key pair, extract the seed, reload it
	cert1, pubKey1, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Extract the 32-byte seed from the Ed25519 private key
	priv := cert1.PrivateKey.(crypto.Signer)
	edPriv := priv.(interface{ Seed() []byte })
	seedHex := fmt.Sprintf("%x", edPriv.Seed())

	// Reload from hex
	cert2, pubKey2, err := squic.LoadKeyPair(seedHex)
	if err != nil {
		t.Fatalf("LoadKeyPair: %v", err)
	}

	if !bytes.Equal(pubKey1, pubKey2) {
		t.Error("public keys should match after reload")
	}
	if len(cert2.Certificate) == 0 {
		t.Error("empty certificate from LoadKeyPair")
	}
}

func TestLoadKeyPairInvalid(t *testing.T) {
	_, _, err := squic.LoadKeyPair("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}

	_, _, err = squic.LoadKeyPair("aabb") // too short
	if err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestClientServerConnection(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Start server
	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Server goroutine: accept one connection, echo data
	serverDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}

		// Echo: read all data, write it back
		data, err := io.ReadAll(stream)
		if err != nil {
			serverDone <- err
			return
		}

		_, err = stream.Write(data)
		if err != nil {
			serverDone <- err
			return
		}
		stream.Close()
		serverDone <- nil
	}()

	// Client: connect, send data, read echo
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := squic.Dial(ctx, serverAddr, pubKey, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	testData := []byte("Hello, sQUIC!")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	stream.Close()

	echo, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(echo) != string(testData) {
		t.Errorf("echo = %q, want %q", echo, testData)
	}

	conn.CloseWithError(0, "")

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestSilentServerDropsInvalidMAC(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Send garbage UDP packet (no MAC1)
	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer rawConn.Close()

	// Send fake Initial packet (long header, type Initial)
	garbage := make([]byte, 1200)
	garbage[0] = 0xC0 // long header, Initial type
	garbage[1] = 0x01 // version
	rawConn.Write(garbage)

	// Send another with random client key + wrong MAC1
	fakeClientPub := make([]byte, 32)
	rand.Read(fakeClientPub)
	fakeMAC := make([]byte, squic.MACSize)
	rand.Read(fakeMAC)
	buf := make([]byte, len(garbage)+squic.MACOverhead)
	copy(buf, garbage)
	copy(buf[len(garbage):], fakeClientPub)
	copy(buf[len(garbage)+squic.ClientKeySize:], fakeMAC)
	rawConn.Write(buf)

	// Server should accept with timeout — no connection established
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = ln.Accept(ctx)
	if err == nil {
		t.Error("server should not accept connection from invalid MAC1")
	}
	// Expected: context deadline exceeded (no valid client connected)
}

func TestSilentServerRejectsWrongKey(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Client tries to connect with wrong server public key
	wrongKey := make([]byte, len(pubKey))
	rand.Read(wrongKey)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = squic.Dial(ctx, serverAddr, wrongKey, nil)
	if err == nil {
		t.Error("Dial should fail with wrong server key")
	}
}

// clientX25519PubFromDial extracts the X25519 public key that Dial() would generate.
// For testing, we generate a key pair and convert to X25519.
func generateClientX25519Pub(t *testing.T) []byte {
	t.Helper()
	_, pub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	x25519Pub, err := squic.Ed25519PublicToX25519(pub)
	if err != nil {
		t.Fatalf("Ed25519PublicToX25519: %v", err)
	}
	return x25519Pub
}

func TestWhitelistAllowsKnownClient(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// A client with a stable identity, so its key can be whitelisted before it
	// ever connects. Without ClientKey the client mints an ephemeral X25519
	// pair per Dial, which is why this test used to settle for connecting with
	// no whitelist at all and never checked the thing its name describes.
	clientSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(clientSeed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	clientEd := ed25519.NewKeyFromSeed(clientSeed)
	clientKey, err := squic.Ed25519PublicToX25519(clientEd.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("Ed25519PublicToX25519: %v", err)
	}

	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	ln.EnableWhitelist(clientKey)

	serverAddr := ln.Addr().String()

	// Report why the accept gave up rather than swallowing the error, so a
	// failure names the cause instead of only the symptom.
	accepted := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			accepted <- err
			return
		}
		conn.CloseWithError(0, "")
		accepted <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := squic.Dial(ctx, serverAddr, serverPub, &squic.Config{
		ClientKey: hex.EncodeToString(clientSeed),
	})
	if err != nil {
		t.Fatalf("whitelisted client should be admitted: %v", err)
	}
	// Hold the connection open until the server has accepted it. Closing
	// straight after Dial races the server: a connection the client has
	// already torn down is discarded before it ever reaches Accept.
	defer conn.CloseWithError(0, "")

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("server did not accept the whitelisted client: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept the whitelisted client: Accept never returned")
	}

	// The other half of the claim: admitting this client has to mean the
	// whitelist is enforced, not that the server is letting everyone in. An
	// ephemeral client is not on the list and must be dropped in silence.
	strangerCtx, strangerCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer strangerCancel()
	if _, err := squic.Dial(strangerCtx, serverAddr, serverPub, nil); err == nil {
		t.Fatal("a client absent from the whitelist was admitted")
	}
}

func TestWhitelistRejectsUnknownClient(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Create a whitelist with a random key that won't match the client's ephemeral key
	randomAllowedKey := make([]byte, 32)
	rand.Read(randomAllowedKey)

	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, &squic.Config{
		AllowedKeys: [][]byte{randomAllowedKey},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Server: try to accept — should timeout (client silently dropped)
	serverDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_, err := ln.Accept(ctx)
		serverDone <- err
	}()

	// Client: try to connect — will timeout because server silently drops
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = squic.Dial(ctx, serverAddr, serverPub, nil)
	if err == nil {
		t.Error("Dial should fail when client is not whitelisted")
	}

	// Server should also timeout (no valid connection accepted)
	if err := <-serverDone; err == nil {
		t.Error("server Accept should timeout when client is not whitelisted")
	}
}

func TestWhitelistDHCannotBeForged(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Generate a "victim" client key that IS in the whitelist
	victimPub := make([]byte, 32)
	rand.Read(victimPub)

	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, &squic.Config{
		AllowedKeys: [][]byte{victimPub},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Attacker sends a packet claiming to be the victim (victim's pubkey)
	// but uses a random MAC1 (can't compute correct DH shared secret without victim's private key)
	udpAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	rawConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer rawConn.Close()

	// Craft fake Initial packet with victim's pubkey but wrong MAC
	fakePacket := make([]byte, 1200)
	fakePacket[0] = 0xC0 // Initial packet header
	fakePacket[1] = 0x01

	fakeMAC := make([]byte, squic.MACSize)
	rand.Read(fakeMAC)

	buf := make([]byte, len(fakePacket)+squic.MACOverhead)
	copy(buf, fakePacket)
	copy(buf[len(fakePacket):], victimPub)
	copy(buf[len(fakePacket)+squic.ClientKeySize:], fakeMAC)
	rawConn.Write(buf)

	// Server should not accept — MAC1 verification fails
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = ln.Accept(ctx)
	if err == nil {
		t.Error("server should not accept forged client identity")
	}
}

func TestRuntimeAllowKey(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Start with whitelist enabled but empty — blocks all clients
	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	ln.EnableWhitelist() // empty whitelist = block all

	serverAddr := ln.Addr().String()

	// Attempt 1: should fail (empty whitelist)
	ctx1, cancel1 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel1()
	_, err = squic.Dial(ctx1, serverAddr, serverPub, nil)
	if err == nil {
		t.Fatal("expected dial to fail with empty whitelist")
	}

	// Now disable whitelist — should allow any valid MAC1 client
	ln.DisableWhitelist()

	// Accept goroutine. It reports why it gave up rather than swallowing the
	// error, so a failure here says what went wrong instead of only that
	// nothing arrived.
	accepted := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			accepted <- err
			return
		}
		conn.CloseWithError(0, "")
		accepted <- nil
	}()

	// Attempt 2: should succeed
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn, err := squic.Dial(ctx2, serverAddr, serverPub, nil)
	if err != nil {
		t.Fatalf("Dial after DisableWhitelist should succeed: %v", err)
	}
	// Hold the connection open until the server has accepted it. Closing
	// straight after Dial races the server: a connection the client has
	// already torn down is discarded before it ever reaches Accept, and the
	// test then reports a whitelist failure for a teardown it caused itself.
	defer conn.CloseWithError(0, "")

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("server did not accept connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not accept connection: Accept never returned")
	}
}

func TestRuntimeRemoveKey(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Verify HasKey returns false for non-existent key
	fakeKey := make([]byte, 32)
	rand.Read(fakeKey)
	if ln.HasKey(fakeKey) {
		t.Fatal("HasKey should return false for unknown key")
	}

	// Verify AllowedKeys returns nil when whitelist is disabled
	if keys := ln.AllowedKeys(); keys != nil {
		t.Fatalf("AllowedKeys should be nil when whitelist disabled, got %d keys", len(keys))
	}

	// Enable whitelist with a key, then remove it
	ln.EnableWhitelist(fakeKey)
	if !ln.HasKey(fakeKey) {
		t.Fatal("HasKey should return true after EnableWhitelist with key")
	}
	if keys := ln.AllowedKeys(); len(keys) != 1 {
		t.Fatalf("expected 1 allowed key, got %d", len(keys))
	}

	ln.RemoveKey(fakeKey)
	if ln.HasKey(fakeKey) {
		t.Fatal("HasKey should return false after RemoveKey")
	}

	// Whitelist is now enabled but empty — connection should fail
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = squic.Dial(ctx, serverAddr, serverPub, nil)
	if err == nil {
		t.Fatal("expected dial to fail after key removed from whitelist")
	}
}

func TestEnableWhitelistWithKeys(t *testing.T) {
	serverCert, serverPub, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Enable with multiple keys
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ln.EnableWhitelist(key1, key2)

	if !ln.HasKey(key1) || !ln.HasKey(key2) {
		t.Fatal("both keys should be in whitelist")
	}
	if keys := ln.AllowedKeys(); len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Add a third key at runtime
	key3 := make([]byte, 32)
	rand.Read(key3)
	ln.AllowKey(key3)

	if !ln.HasKey(key3) {
		t.Fatal("key3 should be in whitelist after AllowKey")
	}
	if keys := ln.AllowedKeys(); len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Disable entirely
	ln.DisableWhitelist()
	if keys := ln.AllowedKeys(); keys != nil {
		t.Fatal("AllowedKeys should be nil after DisableWhitelist")
	}
}

// lossyRelay forwards UDP between a client and server, blackholing the first
// dropFirst datagrams travelling client -> server. Returns the address the
// client should dial.
func lossyRelay(t *testing.T, server string, dropFirst int) string {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("front ListenUDP: %v", err)
	}
	back, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("back DialUDP: %v", err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })

	var mu sync.Mutex
	var client *net.UDPAddr

	go func() {
		buf := make([]byte, 65536)
		dropped := 0
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			if dropped < dropFirst {
				dropped++
				continue
			}
			back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			to := client
			mu.Unlock()
			if to != nil {
				front.WriteToUDP(buf[:n], to)
			}
		}
	}()

	return front.LocalAddr().String()
}

func assertHandshakeSurvivesLosing(t *testing.T, lost int) {
	t.Helper()
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	// Blackhole the client's first datagrams. QUIC must retransmit the
	// Initial, and every retransmission has to carry a valid MAC or the silent
	// server drops it too.
	relay := lossyRelay(t, ln.Addr().String(), lost)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	started := time.Now()
	conn, err := squic.Dial(ctx, relay, pubKey, nil)
	if err != nil {
		t.Fatalf("handshake failed after losing %d Initial(s) in %v: %v", lost, time.Since(started), err)
	}
	conn.CloseWithError(0, "")
}

func TestHandshakeSurvivesInitialPacketLoss(t *testing.T) {
	assertHandshakeSurvivesLosing(t, 1)
}

// Several PTOs deep, the envelope must still be there.
func TestHandshakeSurvivesRepeatedInitialLoss(t *testing.T) {
	assertHandshakeSurvivesLosing(t, 3)
}

// The cookie defence has to admit legitimate clients, not just reject
// attackers: challenge, decrypt, retransmit carrying MAC2, accept.
func TestCookieChallengeAdmitsALegitimateClient(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Under load before the first packet arrives. The load monitor re-evaluates
	// once a second, so the client's retransmission — the packet that actually
	// carries MAC2 — has to get there inside that window.
	ln.SetUnderLoad(true)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := squic.Dial(ctx, ln.Addr().String(), pubKey, nil)
	if err != nil {
		t.Fatalf("cookie challenge locked out a legitimate client: %v", err)
	}
	conn.CloseWithError(0, "")

	stats := ln.LoadStats()
	if stats.CookieRepliesSent < 1 {
		t.Fatalf("server never issued a challenge: %+v", stats)
	}
	if stats.MAC2Verified < 1 {
		t.Fatalf("client's MAC2 never verified — the exchange did not complete: %+v", stats)
	}
}
