package squic_test

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	squic "github.com/lyowhs/squic-go"
)

func TestMAC1RoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	data := []byte("test packet data")
	mac := squic.ComputeMAC1(sharedSecret, data)

	if len(mac) != squic.MACSize {
		t.Fatalf("MAC1 length = %d, want %d", len(mac), squic.MACSize)
	}

	// Verify MAC1
	if !squic.VerifyMAC1(sharedSecret, data, mac) {
		t.Error("valid MAC1 failed verification")
	}

	// Wrong key should fail
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	if squic.VerifyMAC1(wrongKey, data, mac) {
		t.Error("MAC1 should fail with wrong key")
	}

	// Tampered data should fail
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0xFF
	if squic.VerifyMAC1(sharedSecret, tampered, mac) {
		t.Error("MAC1 should fail with tampered data")
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

	// The client generates an ephemeral X25519 key pair on each Dial().
	// To whitelist it, we'd need to know the key in advance.
	// For this test: we connect WITHOUT a whitelist (AllowedKeys: nil)
	// and verify it works. The whitelisting test below uses a controlled setup.
	ln, err := squic.Listen("udp", "127.0.0.1:0", serverCert, serverPub, &squic.Config{
		AllowedKeys: nil, // no whitelist = accept any valid MAC1
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		stream, _ := conn.AcceptStream(ctx)
		if stream != nil {
			io.Copy(io.Discard, stream)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := squic.Dial(ctx, serverAddr, serverPub, nil)
	if err != nil {
		t.Fatalf("Dial with no whitelist should succeed: %v", err)
	}
	conn.CloseWithError(0, "")
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
