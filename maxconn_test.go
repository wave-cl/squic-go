package squic_test

import (
	"context"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	squic "github.com/wave-cl/squic-go"
)

// A server with MaxConnections set refuses connections once that many are
// established — the memory bound iteration-2 testing showed was missing (N held
// connections each cost their receive window). Two fit; the third is refused;
// freeing one lets a new one in.
func TestMaxConnectionsCap(t *testing.T) {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ln, err := squic.Listen("udp", "127.0.0.1:0", cert, pubKey, &squic.Config{MaxConnections: 2})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Server holds every connection it accepts so the count stays up.
	var mu sync.Mutex
	var held []*quic.Conn
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()

	dial := func() (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return squic.Dial(ctx, addr, pubKey, nil)
	}

	c1, err := dial()
	if err != nil {
		t.Fatalf("conn 1: %v", err)
	}
	if _, err := dial(); err != nil {
		t.Fatalf("conn 2: %v", err)
	}
	// Let the server register both as established before probing the cap.
	time.Sleep(300 * time.Millisecond)

	if _, err := dial(); err == nil {
		t.Fatal("a third connection was admitted past a cap of 2")
	}

	// Free one and a new connection is admitted again.
	c1.CloseWithError(0, "done")
	time.Sleep(500 * time.Millisecond)
	if _, err := dial(); err != nil {
		t.Fatalf("no connection admitted after one was freed below the cap: %v", err)
	}
}
