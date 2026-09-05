package squic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"github.com/quic-go/quic-go"
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
	return newServerConn(conn, Ed25519PrivateToX25519(priv), nil, 1000, []uint8{EnvelopeV4}), conn
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
	sc := newServerConn(conn, Ed25519PrivateToX25519(priv), nil, 1000, []uint8{EnvelopeV4})

	sender, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		panic(err)
	}
	defer sender.Close()

	stopFlood := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		// Packets that are always dropped, so every batch is an empty one.
		junk := probe(0xE0, 0xDEADBEEF, 1200)
		for {
			select {
			case <-stopFlood:
				// Release the reader with something it will accept. Offer it
				// repeatedly rather than once: a single packet is easily lost
				// in the backlog the flood just built, and a test that hangs
				// when the release is dropped is a test that fails at random.
				short := []byte{0x40, 1, 2, 3, 4, 5}
				for {
					select {
					case <-readerDone:
						return
					default:
					}
					sender.Write(short)
					time.Sleep(20 * time.Millisecond)
				}
			default:
			}
			sender.Write(junk)
		}
	}()

	// Long enough to drive several thousand dropped batches through the read
	// path. With the recursion present the stack limit is reached in well
	// under a second, so this only bounds the healthy case.
	go func() {
		time.Sleep(6 * time.Second)
		close(stopFlood)
	}()

	ms := make([]ipv4.Message, 8)
	for i := range ms {
		ms[i].Buffers = [][]byte{make([]byte, 1500)}
	}

	if _, err := sc.ReadBatch(ms, 0); err != nil {
		panic(err)
	}
	close(readerDone)
}

// buildStrangerEnvelope produces everything an attacker can make without the
// server's public key: a real QUIC v1 header, a timestamp inside the window,
// and noise for the rest of the envelope. The gate is the field they cannot
// produce, which is the whole point of it.
func buildStrangerEnvelope() []byte {
	p := probe(0xC0, uint32(quic.Version1), 1200)
	p[5] = 8 // DCID length
	hdr := Hdr(EnvelopeV4, false)
	buf := append([]byte(nil), p...)
	buf = append(buf, bytes.Repeat([]byte{0x42}, ClientKeySize)...)
	var ts [4]byte
	binary.BigEndian.PutUint32(ts[:], NowTimestamp())
	buf = append(buf, ts[:]...)
	buf = append(buf, bytes.Repeat([]byte{0x11}, GateSize)...) // guessed
	buf = append(buf, bytes.Repeat([]byte{0x22}, MACSize)...)
	buf = append(buf, hdr)
	return buf
}

// The S8 finding, and the reason the gate exists.
//
// Under load a server without a cheap check challenges before it knows who is
// calling, because MAC1 is a Diffie-Hellman and there is nothing cheaper in
// front of it. So a stranger — no key, no captured traffic — sends something
// Initial-shaped with a plausible timestamp and gets a cookie reply, which is a
// server that is supposed to be silent telling them it exists.
//
// With the gate the same stranger is dropped before the challenge. There is no
// longer a version that skips it: that was the honest limit of the v3 fix, and
// removing versions 1 and 2 is what finally closed it.
func TestUnderLoadAStrangerIsDroppedNotChallenged(t *testing.T) {
	sc, conn := testServerConn(t)
	defer conn.Close()
	sc.acceptedVersions = []uint8{EnvelopeV4}
	sc.underLoad.Store(true)

	buf := buildStrangerEnvelope()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40501}
	if ok, _ := sc.validateAndStrip(buf, len(buf), addr); ok {
		t.Fatal("a stranger's envelope was admitted")
	}
	if n := sc.cookieReplies.Load(); n != 0 {
		t.Errorf("a stranger drew %d cookie replies out of a server that is supposed to be silent", n)
	}
}

// An envelope whose gate tag does not verify is dropped even when the server is
// not under load — the gate is unconditional, so rubbish costs one HMAC rather
// than a curve operation.
func TestABadGateIsDroppedWithoutADiffieHellman(t *testing.T) {
	sc, conn := testServerConn(t)
	defer conn.Close()
	sc.acceptedVersions = []uint8{EnvelopeV4}

	buf := buildStrangerEnvelope()
	before := sc.dhCount.Load()
	if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
		t.Fatal("an envelope with a bad gate tag was admitted")
	}
	if sc.dhCount.Load() != before {
		t.Error("a Diffie-Hellman was performed for an envelope that failed the gate")
	}
}

// The counter that turns retiring a version from nerve into arithmetic.
//
// A server that drops an envelope does so in silence, so retiring one that
// clients are still sending locks them out with nothing in any log on either
// side. Before this there was no way to ask "is anything still arriving on
// version 2" — the question the decision rests on.
func TestAcceptedInitialsAreCountedPerEnvelopeVersion(t *testing.T) {
	sc, conn := testServerConn(t)
	defer conn.Close()
	sc.acceptedVersions = []uint8{EnvelopeV4}

	// A rejected envelope must not be counted as an arrival on the version it
	// claims, or the number says the opposite of what a reader needs.
	for _, v := range EnvelopeVersions {
		buf := buildStrangerEnvelope()
		buf[len(buf)-1] = Hdr(v, false)
		if ok, _ := sc.validateAndStrip(buf, len(buf), nil); ok {
			t.Fatalf("a stranger's version %d envelope was admitted", v)
		}
	}
	for v, n := range sc.loadStats().AcceptedByVersion {
		if n != 0 {
			t.Errorf("version %d counted %d rejected envelopes", v, n)
		}
	}

	// Every known version is reported, present or not, so a reader can tell
	// "nothing arrived on version 1" from "version 1 is not a thing here".
	stats := sc.loadStats()
	if len(stats.AcceptedByVersion) != len(EnvelopeVersions) {
		t.Fatalf("reported %d versions, want %d", len(stats.AcceptedByVersion), len(EnvelopeVersions))
	}
	for _, v := range EnvelopeVersions {
		if _, ok := stats.AcceptedByVersion[v]; !ok {
			t.Errorf("version %d missing from the report", v)
		}
	}

	// And the half that actually needs the counter to exist. Asserting only
	// that rejected envelopes count zero passes just as well with no counter at
	// all — measured, not assumed: without this the whole test survives
	// deleting the increment.
	srv, cli := pair(t, EnvelopeV4, []uint8{EnvelopeV4})
	for i := 0; i < 3; i++ {
		env := cli.buildInitial(initialDatagram())
		if ok, _ := srv.validateAndStrip(env, len(env), nil); !ok {
			t.Fatalf("the matched client's envelope %d was refused", i)
		}
	}
	if got := srv.loadStats().AcceptedByVersion[EnvelopeV4]; got != 3 {
		t.Errorf("version %d counted %d accepted Initials, want 3", EnvelopeV4, got)
	}

	// A stranger's envelope is refused, and must not move the counter — a
	// rejected Initial counted as an arrival says the opposite of what a reader
	// needs.
	stranger := buildStrangerEnvelope()
	if ok, _ := srv.validateAndStrip(stranger, len(stranger), nil); ok {
		t.Fatal("a stranger's envelope was admitted")
	}
	if got := srv.loadStats().AcceptedByVersion[EnvelopeV4]; got != 3 {
		t.Errorf("a refused Initial was counted: %d, want 3", got)
	}
}

// S12: compacting a batch must not move buffers between slots.
//
// quic-go keeps a parallel array of packet buffers and pairs it with the
// messages **by index** (sys_conn_oob.go, ReadPacket), refreshing that pairing
// itself for the slots it has consumed. squic used to compact with
// `ms[dst] = ms[src]`, which copies the whole ipv4.Message including Buffers,
// so quic-go was handed one packet's bytes paired with another's buffer handle:
// releasing it returned the wrong buffer to the pool while the memory holding
// the live data was overwritten by the next recvmmsg. Data corruption, not a
// leak.
//
// This asserts the contract directly — ReadBatch may fill messages, it must not
// reorder their buffers — rather than through ReadBatch itself. A batch test
// would be unreliable: without recvmmsg, x/net reads one message per call, so
// compaction would never trigger and the test would pass without exercising
// anything, which is worse than no test at all.
func TestCompactionKeepsEachSlotsOwnBuffer(t *testing.T) {
	const size = 1500
	ms := make([]ipv4.Message, 3)
	spine := make([]*byte, len(ms))
	for i := range ms {
		buf := make([]byte, size)
		// Fill each buffer with its own index so a swapped buffer is visible.
		for j := range buf {
			buf[j] = byte(i)
		}
		ms[i].Buffers = [][]byte{buf}
		ms[i].OOB = make([]byte, 64)
		ms[i].N = size
		// Identity of the backing array, which is what quic-go pairs on.
		spine[i] = &ms[i].Buffers[0][0]
	}

	src, dst, n := 2, 0, 42
	ms[src].Addr = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}
	ms[src].OOB[0] = 0xAB
	ms[src].NN = 1

	if !moveMessage(ms, dst, src, n) {
		t.Fatal("moveMessage refused a destination that is plainly big enough")
	}

	// The invariant. With `ms[dst] = ms[src]` this is where it fails.
	for i := range ms {
		if got := &ms[i].Buffers[0][0]; got != spine[i] {
			t.Errorf("slot %d no longer owns its original buffer: quic-go pairs "+
				"messages and buffers by index, so it would now hand the "+
				"application one packet's bytes with another's buffer handle", i)
		}
	}

	// And the move actually moved something.
	if ms[dst].N != n {
		t.Errorf("N = %d, want %d", ms[dst].N, n)
	}
	for j := 0; j < n; j++ {
		if ms[dst].Buffers[0][j] != byte(src) {
			t.Fatalf("payload not copied: byte %d is %d, want %d",
				j, ms[dst].Buffers[0][j], src)
		}
	}
	// Byte n is past what was copied, so it must still be the destination's own.
	if ms[dst].Buffers[0][n] != byte(dst) {
		t.Errorf("copied past N: byte %d is %d, want the destination's own %d",
			n, ms[dst].Buffers[0][n], dst)
	}
	if ms[dst].NN != 1 || ms[dst].OOB[0] != 0xAB {
		t.Errorf("OOB not carried: NN=%d OOB[0]=%#02x", ms[dst].NN, ms[dst].OOB[0])
	}
	if ms[dst].Addr == nil || ms[dst].Addr.String() != "10.0.0.1:9999" {
		t.Errorf("Addr not carried: %v", ms[dst].Addr)
	}
}

// A destination too small is refused rather than silently truncated — the
// caller drops the packet instead of forwarding a short one.
func TestCompactionRefusesATooSmallDestination(t *testing.T) {
	ms := make([]ipv4.Message, 2)
	ms[0].Buffers = [][]byte{make([]byte, 10)}
	ms[1].Buffers = [][]byte{make([]byte, 1500)}
	ms[1].N = 1200

	if moveMessage(ms, 0, 1, 1200) {
		t.Fatal("moveMessage claimed success writing 1200 bytes into a 10-byte buffer")
	}
	if ms[0].N != 0 {
		t.Errorf("a refused move still wrote N = %d", ms[0].N)
	}
}
