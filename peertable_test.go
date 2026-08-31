package squic

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestPeerTableSameKeyIdempotent(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	k := [32]byte{1}
	id := [32]byte{9}
	pt.record([]byte("cid1"), k, id, true, now)
	pt.record([]byte("cid1"), k, id, true, now) // retransmission
	got, gotID, hasID, ok := pt.take([]byte("cid1"), now)
	if !ok || got != k || !hasID || gotID != id {
		t.Fatalf("take = %x id=%x has=%v ok=%v; want key %x id %x", got, gotID, hasID, ok, k, id)
	}
}

func TestPeerTableContestedIsPoisoned(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{}, false, now)
	pt.record([]byte("cid1"), [32]byte{2}, [32]byte{}, false, now) // different key, same DCID
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("poisoned entry must not resolve")
	}
}

func TestPeerTableContestedIdentityIsPoisoned(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{9}, true, now)
	pt.record([]byte("cid1"), [32]byte{1}, [32]byte{8}, true, now) // same key, different identity
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("contested identity must poison the entry")
	}
}

func TestPeerTableTakeDrains(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{7}, [32]byte{}, false, now)
	if _, _, _, ok := pt.take([]byte("cid1"), now); !ok {
		t.Fatal("first take should succeed")
	}
	if _, _, _, ok := pt.take([]byte("cid1"), now); ok {
		t.Fatal("second take should find nothing")
	}
}

func TestPeerTableAnonymousHasNoIdentity(t *testing.T) {
	pt := newPeerTable()
	now := time.Now()
	pt.record([]byte("cid1"), [32]byte{7}, [32]byte{}, false, now)
	_, _, hasID, ok := pt.take([]byte("cid1"), now)
	if !ok || hasID {
		t.Fatalf("anonymous entry: ok=%v hasIdentity=%v; want ok=true hasIdentity=false", ok, hasID)
	}
}

func TestPeerTableExpiry(t *testing.T) {
	pt := newPeerTable()
	start := time.Now()
	pt.record([]byte("cid1"), [32]byte{9}, [32]byte{}, false, start)
	later := start.Add(peerKeyTTL + time.Second)
	if _, _, _, ok := pt.take([]byte("cid1"), later); ok {
		t.Fatal("expired entry must not resolve")
	}
}

// The finding this replaces: the old prune dropped only *expired* entries and
// then inserted regardless, so when arrivals outran the TTL it freed nothing
// and the table grew without limit — while every insert past the threshold paid
// for a full map scan that reclaimed nothing, under the lock, on the receive
// path. A peer that can pass MAC1 could drive both.
func TestPeerTableIsBoundedByAFloodOfFreshEntries(t *testing.T) {
	tbl := newPeerTable()
	now := time.Now()
	dcid := make([]byte, 8)
	for i := 0; i < peerTableMax*3; i++ {
		// Every one distinct, every one fresh: nothing is ever expired, so the
		// old prune would have reclaimed nothing on any of these.
		binary.BigEndian.PutUint64(dcid, uint64(i))
		tbl.record(dcid, [32]byte{1}, [32]byte{}, false, now)
	}
	if len(tbl.entries) > peerTableMax {
		t.Fatalf("table grew to %d entries, past the %d bound", len(tbl.entries), peerTableMax)
	}
	if len(tbl.order) > peerTableMax {
		t.Fatalf("order queue grew to %d records, past the %d bound", len(tbl.order), peerTableMax)
	}
}

// Eviction takes from the oldest end, so the caller that just arrived — whose
// key is read within milliseconds — is the last thing to go.
func TestPeerTableNewestEntrySurvivesAFlood(t *testing.T) {
	tbl := newPeerTable()
	now := time.Now()
	dcid := make([]byte, 8)
	for i := 0; i < peerTableMax*2; i++ {
		binary.BigEndian.PutUint64(dcid, uint64(i))
		tbl.record(dcid, [32]byte{1}, [32]byte{}, false, now)
	}
	tbl.record([]byte("mine"), [32]byte{7}, [32]byte{8}, true, now)

	key, id, hasID, ok := tbl.take([]byte("mine"), now)
	if !ok || key != [32]byte{7} || !hasID || id != [32]byte{8} {
		t.Fatalf("the newest entry did not survive: ok=%v key=%v hasID=%v", ok, key[0], hasID)
	}
}

// Expiry runs off the queue front rather than a scan, so it must still be
// exact: everything past the TTL goes, everything inside it stays.
func TestPeerTableExpiryTakesTheOldAndLeavesTheNew(t *testing.T) {
	tbl := newPeerTable()
	start := time.Now()
	tbl.record([]byte("old"), [32]byte{1}, [32]byte{}, false, start)
	later := start.Add(peerKeyTTL + time.Second)
	tbl.record([]byte("new"), [32]byte{2}, [32]byte{}, false, later)

	if _, _, _, ok := tbl.take([]byte("old"), later); ok {
		t.Error("an entry past its TTL still resolved")
	}
	if _, _, _, ok := tbl.take([]byte("new"), later); !ok {
		t.Error("the fresh entry did not resolve")
	}
	if len(tbl.entries) != 0 {
		t.Errorf("expired entry was not reclaimed: %d left", len(tbl.entries))
	}
}

// A retransmission no longer extends the entry — it lives its TTL from first
// sight. That is what keeps the order queue exact, and it stops a peer holding
// an entry open forever by retransmitting. 30s of TTL against a 10s handshake
// timeout leaves the handshake covered either way.
func TestPeerTableRetransmissionDoesNotExtendTheEntry(t *testing.T) {
	tbl := newPeerTable()
	start := time.Now()
	tbl.record([]byte("cid1"), [32]byte{1}, [32]byte{}, false, start)
	midway := start.Add(25 * time.Second)
	tbl.record([]byte("cid1"), [32]byte{1}, [32]byte{}, false, midway)

	// Expiry is measured from the first sighting, not the last.
	past := start.Add(peerKeyTTL + time.Second)
	if _, _, _, ok := tbl.take([]byte("cid1"), past); ok {
		t.Error("a retransmission extended the entry past its TTL")
	}
}

func TestInitialDCID(t *testing.T) {
	pkt := []byte{0xC0, 0, 0, 0, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD, 0x99}
	dcid, ok := initialDCID(pkt)
	if !ok || string(dcid) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("dcid = %x, %v", dcid, ok)
	}
	if _, ok := initialDCID([]byte{0xC0, 0, 0, 0, 1, 21}); ok {
		t.Fatal("over-long DCID length must be rejected")
	}
}
