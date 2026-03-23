// HTTP/3 server and client over sQUIC.
//
// Server: invisible to port scanners, responds only to clients with the server's public key.
// Client: pins the server's Ed25519 public key — no certificate authorities.
//
// Usage:
//
//	go run . -s [-p port]
//	go run . -c <host> -p <port> --key <server-pub-hex> [path]
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	squic "github.com/wave-cl/squic-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	server := flag.Bool("s", false, "run as server")
	client := flag.String("c", "", "connect to server (host)")
	port := flag.Int("p", 443, "port")
	key := flag.String("key", "", "server public key (hex)")
	flag.Parse()

	if *server {
		if err := runServer(*port); err != nil {
			log.Fatal(err)
		}
	} else if *client != "" {
		path := "/"
		if flag.NArg() > 0 {
			path = flag.Arg(0)
		}
		if err := runClient(*client, *port, *key, path); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("  go run . -s [-p port]")
		fmt.Println("  go run . -c <host> -p <port> --key <server-pub-hex> [path]")
		os.Exit(1)
	}
}

func runServer(port int) error {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		return err
	}

	fmt.Printf("Server public key: %x\n", pubKey)
	fmt.Printf("Listening on :%d (HTTP/3)\n", port)

	addr := fmt.Sprintf(":%d", port)
	ln, err := squic.Listen("udp4", addr, cert, pubKey, &squic.Config{
		NextProtos: []string{"h3"},
	})
	if err != nil {
		return err
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Hello from sQUIC HTTP/3!")
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "ok",
			"protocol": "h3",
			"server":   "squic",
		})
	})

	h3srv := &http3.Server{Handler: mux}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		fmt.Println("\nShutting down...")
		h3srv.Close()
	}()

	return h3srv.ServeListener(ln)
}

func runClient(host string, port int, keyHex string, path string) error {
	if keyHex == "" {
		return fmt.Errorf("--key is required")
	}

	serverPubKey, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("parse server key: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	url := fmt.Sprintf("https://%s%s", addr, path)

	tr := &http3.Transport{
		Dial: func(ctx context.Context, dialAddr string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			return squic.Dial(ctx, dialAddr, serverPubKey, &squic.Config{
				NextProtos: []string{"h3"},
			})
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP/3 %s\n", resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, v[0])
	}
	fmt.Println()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Print(string(body))
	return nil
}
