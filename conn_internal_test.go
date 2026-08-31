package squic

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// probe builds a long-header packet of the given type carrying a QUIC version
// nobody supports — the packet that draws a Version Negotiation reply out of a
// stack that has not been told to keep quiet.
func probe(firstByte byte, version uint32, n int) []byte {
	p := make([]byte, n)
	p[0] = firstByte
	binary.BigEndian.PutUint32(p[1:5], version)
	p[5] = 0 // DCID length
	p[6] = 0 // SCID length
	return p
}

func testServerConn(t *testing.T) (*serverConn, *net.UDPConn) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	return newServerConn(conn, Ed25519PrivateToX25519(priv), nil, 1000, []uint8{EnvelopeV1, EnvelopeV2}), conn
}

// A long header carrying a version quic-go does not parse must be dropped by
// sQUIC, because quic-go would answer it with a Version Negotiation packet
// before looking at the connection at all — a reply to a caller holding no key.
//
// Every packet type, including the Initial: the version gate runs ahead of the
// envelope, so a bad version is refused whatever the type claims to be.
func TestUnsupportedVersionLongHeaderIsDropped(t *testing.T) {
	sc, conn := testServerConn(t)
	defer conn.Close()

	for _, first := range []byte{0xE0, 0xD0, 0xF0, 0xC0} {
		p := probe(first, 0xDEADBEEF, 1200)
		if ok, _ := sc.validateAndStrip(p, len(p), nil); ok {
			t.Errorf("a %#02x long header with an unsupported version was admitted", first)
		}
	}
}

// The other half, and the reason the gate is on the version and not the packet
// type: a client's Handshake and 0-RTT packets are long-headed too. Dropping
// every non-Initial long header would break each connection at the second
// flight, so a recognised version must still pass straight through.
func TestSupportedVersionNonInitialPassesThrough(t *testing.T) {
	sc, conn := testServerConn(t)
	defer conn.Close()

	// Driven off the declared set, so the gate and the set cannot drift apart.
	for _, sv := range supportedVersions {
		v := uint32(sv)
		for _, first := range []byte{0xE0, 0xD0, 0xF0} { // Handshake, 0-RTT, Retry
			p := probe(first, v, 1200)
			ok, n := sc.validateAndStrip(p, len(p), nil)
			if !ok {
				t.Errorf("a %#02x long header at version %#x was dropped; the handshake needs it", first, v)
			}
			if n != len(p) {
				t.Errorf("a pass-through packet was resized from %d to %d", len(p), n)
			}
		}
	}
	// And a short header — the 1-RTT data path — is untouched.
	short := []byte{0x40, 1, 2, 3, 4, 5}
	if ok, n := sc.validateAndStrip(short, len(short), nil); !ok || n != len(short) {
		t.Errorf("short header not passed through: ok=%v n=%d", ok, n)
	}
}

// Dropping a whole batch is the *expected* outcome under the flood this server
// exists to discard cheaply. Recursing once per dropped batch never unwinds:
// the stack grows until Go aborts the process with "goroutine stack exceeds",
// which recover() cannot catch, so the only way to observe it is from outside.
//
// The child lowers its own stack limit so the failure, if present, arrives in
// seconds rather than after a gigabyte.
func TestReadBatchDoesNotRecurseUnderAFlood(t *testing.T) {
	if os.Getenv("SQUIC_FLOOD_CHILD") == "1" {
		floodChild()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadBatchDoesNotRecurseUnderAFlood", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "SQUIC_FLOOD_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the read path did not survive a flood of dropped packets: %v\n%s", err, out)
	}
}

func floodChild() {
	// Small enough that recursion reaches it in a few thousand frames, large
	// enough that the runtime is comfortable.
	debug.SetMaxStack(1 << 20)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	sc := newServerConn(conn, Ed25519PrivateToX25519(priv), nil, 1000, []uint8{EnvelopeV1, EnvelopeV2})

	sender, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		panic(err)
	}
	defer sender.Close()

	done := make(chan struct{})
	go func() {
		// Packets that are always dropped, so every batch is an empty one.
		junk := probe(0xE0, 0xDEADBEEF, 1200)
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				// One short header, so the reader has something to return.
				sender.Write([]byte{0x40, 1, 2, 3, 4, 5})
				return
			default:
			}
			sender.Write(junk)
		}
	}()

	ms := make([]ipv4.Message, 8)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 1500)}
	}

	// Give the flood time to drive several thousand dropped batches through the
	// read path, then release the reader with a packet it will accept.
	go func() {
		time.Sleep(6 * time.Second)
		close(done)
	}()

	if _, err := sc.ReadBatch(ms, 0); err != nil {
		panic(err)
	}
}
