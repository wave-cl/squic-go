// Cross-implementation probe for the SIP-2 peer-key accessor.
//
// server: load a fixed keypair, accept one connection, print the peer key the
//
//	transport verified as PEERKEY=<hex>, then complete the handshake.
//
// client: dial with a fixed client key and print the X25519 key it will send
//
//	as CLIENTX=<hex>.
//
// A harness runs this against the Rust probe in every client/server
// combination and asserts every PEERKEY equals every CLIENTX.
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
	flag.Parse()

	switch {
	case *server:
		runServer(*port, *serverKey)
	case *client:
		runClient(*host, *port, *serverPub, *clientKey)
	default:
		fmt.Fprintln(os.Stderr, "specify -server or -client")
		os.Exit(2)
	}
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}

func runServer(port int, serverKeyHex string) {
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
	// Complete the exchange so the client does not error.
	stream, err := conn.AcceptStream(ctx)
	if err == nil {
		buf := make([]byte, 8)
		_, _ = stream.Read(buf)
		_, _ = stream.Write([]byte("ok"))
		stream.Close()
	}
}

func runClient(host string, port int, serverPubHex, clientKeyHex string) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := squic.Dial(ctx, fmt.Sprintf("%s:%d", host, port), serverPub, &squic.Config{
		ClientKey: clientKeyHex,
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
