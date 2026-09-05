// Cross-implementation probe for the SIP-2 peer-key and SIP-3 peer-identity
// accessors.
//
// server: load a fixed keypair, accept one connection, print the peer key the
//
//	transport verified as PEERKEY=<hex> and the Ed25519 identity it bound
//	as PEERID=<hex> (or PEERID=none), then complete the handshake.
//
// client: dial with a fixed client key and print the X25519 key it will send
//
//	as CLIENTX=<hex>, plus the Ed25519 identity it advertises as
//	CLIENTED=<hex> — or CLIENTED=none without -advertise.
//
// With -under-load the server demands a cookie (SIP-7) from every caller before
// doing any key agreement, and reports the defence's counters as
// COOKIES=<replies sent>,<MAC2 verified>, so a harness can tell a connection
// that went through the cookie exchange from one that merely succeeded.
//
// A harness runs this against the Rust probe in every client/server
// combination and asserts every PEERKEY equals every CLIENTX, and every PEERID
// equals every CLIENTED (covering both the advertised and anonymous cases).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/wave-cl/squic-go"
)

func main() {
	server := flag.Bool("server", false, "run as server")
	client := flag.Bool("client", false, "run as client")
	host := flag.String("host", "127.0.0.1", "host")
	port := flag.Int("port", 5060, "port")
	serverKey := flag.String("server-key", "", "server Ed25519 seed (hex), server mode")
	serverPub := flag.String("server-pub", "", "server Ed25519 public key (hex), client mode")
	clientKey := flag.String("client-key", "", "client Ed25519 seed (hex), client mode")
	advertise := flag.Bool("advertise", false, "advertise the client Ed25519 identity (SIP-3)")
	underLoad := flag.Bool("under-load", false, "server: demand a cookie from every caller (SIP-7)")
	envelopeVersion := flag.Int("envelope-version", 4, "client: envelope version to emit (SIP-29)")
	flag.Parse()

	switch {
	case *server:
		runServer(*port, *serverKey, *underLoad)
	case *client:
		runClient(*host, *port, *serverPub, *clientKey, *advertise, uint8(*envelopeVersion))
	default:
		fmt.Fprintln(os.Stderr, "specify -server or -client")
		os.Exit(2)
	}
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}

func runServer(port int, serverKeyHex string, underLoad bool) {
	cert, pubKey, err := squic.LoadKeyPair(serverKeyHex)
	if err != nil {
		fail("load server key", err)
	}
	fmt.Printf("SERVERPUB=%s\n", hex.EncodeToString(pubKey))
	ln, err := squic.Listen("udp", fmt.Sprintf("127.0.0.1:%d", port), cert, pubKey, nil)
	if err != nil {
		fail("listen", err)
	}
	defer ln.Close()
	if underLoad {
		ln.SetUnderLoad(true)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := ln.Accept(ctx)
	if err != nil {
		fail("accept", err)
	}
	if key, ok := ln.PeerKey(conn); ok {
		fmt.Printf("PEERKEY=%s\n", hex.EncodeToString(key[:]))
	} else {
		fmt.Println("PEERKEY=none")
	}
	if id, ok := ln.PeerIdentity(conn); ok {
		fmt.Printf("PEERID=%s\n", hex.EncodeToString(id[:]))
	} else {
		fmt.Println("PEERID=none")
	}
	stats := ln.LoadStats()
	fmt.Printf("COOKIES=%d,%d\n", stats.CookieRepliesSent, stats.MAC2Verified)
	// Complete the exchange so the client does not error.
	stream, err := conn.AcceptStream(ctx)
	if err == nil {
		buf := make([]byte, 8)
		_, _ = stream.Read(buf)
		_, _ = stream.Write([]byte("ok"))
		stream.Close()
	}
	// Tell the client we are done. Without this the process just exits, the
	// client never sees a CONNECTION_CLOSE, and it waits out the full 30s idle
	// timeout on a probe that has already succeeded — which is what made the
	// go-server rows of scripts/cross_peerkey_test.sh dominate its wall time.
	conn.CloseWithError(0, "")
}

func runClient(host string, port int, serverPubHex, clientKeyHex string, advertise bool, envelopeVersion uint8) {
	serverPub, err := hex.DecodeString(serverPubHex)
	if err != nil {
		fail("decode server-pub", err)
	}
	// Print the X25519 key this client will stamp into its Initial.
	seed, err := hex.DecodeString(clientKeyHex)
	if err != nil {
		fail("decode client-key", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	edPub := priv.Public().(ed25519.PublicKey)
	x, err := squic.Ed25519PublicToX25519(edPub)
	if err != nil {
		fail("convert client key", err)
	}
	fmt.Printf("CLIENTX=%s\n", hex.EncodeToString(x))
	fmt.Printf("CLIENTVER=%d\n", envelopeVersion)
	if advertise {
		fmt.Printf("CLIENTED=%s\n", hex.EncodeToString(edPub))
	} else {
		fmt.Println("CLIENTED=none")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := squic.Dial(ctx, fmt.Sprintf("%s:%d", host, port), serverPub, &squic.Config{
		ClientKey:         clientKeyHex,
		AdvertiseIdentity: advertise,
		EnvelopeVersion:   envelopeVersion,
	})
	if err != nil {
		fail("dial", err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fail("open stream", err)
	}
	_, _ = stream.Write([]byte("hi"))
	stream.Close()
	_, _ = io.ReadAll(stream)
	conn.CloseWithError(0, "")
}
