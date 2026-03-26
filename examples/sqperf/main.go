package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	squic "github.com/wave-cl/squic-go"
	"github.com/quic-go/quic-go"
)

var (
	serverMode = flag.Bool("s", false, "Server mode")
	clientAddr = flag.String("c", "", "Client mode: connect to address")
	port       = flag.Int("p", 5000, "Port")
	duration   = flag.Int("t", 10, "Test duration in seconds")
	reverse    = flag.Bool("R", false, "Reverse mode (server sends)")
	bidir      = flag.Bool("d", false, "Bidirectional mode")
	genKey     = flag.Bool("genkey", false, "Generate key pair and exit")
	keyFile    = flag.String("key", "", "Hex-encoded server public key (client) or key file (server)")
)

func main() {
	flag.Parse()

	if *genKey {
		cert, pubKey, err := squic.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("public: %s\n", hex.EncodeToString(pubKey))
		// Store cert for server use (in real usage, persist to disk)
		_ = cert
		os.Exit(0)
	}

	if *serverMode {
		if err := runServer(*port); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
	} else if *clientAddr != "" {
		mode := "upload"
		if *reverse {
			mode = "download"
		}
		if *bidir {
			mode = "bidir"
		}
		if *keyFile == "" {
			fmt.Fprintf(os.Stderr, "Client requires --key <server-public-key-hex>\n")
			os.Exit(1)
		}
		addr := fmt.Sprintf("%s:%d", *clientAddr, *port)
		if err := runClient(addr, mode, time.Duration(*duration)*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "Client error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("  sqperf --genkey")
		fmt.Println("  sqperf -s [-p port]")
		fmt.Println("  sqperf -c <addr> --key <server-pub-hex> [-p port] [-t secs] [-R] [-d]")
		os.Exit(1)
	}
}

func runServer(port int) error {
	cert, pubKey, err := squic.GenerateKeyPair()
	if err != nil {
		return err
	}

	fmt.Printf("Server public key: %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Listening on :%d\n", port)

	addr := fmt.Sprintf(":%d", port)
	ln, err := squic.Listen("udp", addr, cert, pubKey, &squic.Config{
		MaxIdleTimeout:    60 * time.Second,
		MaxIncomingStreams: 200,
	})
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn *quic.Conn) {
	fmt.Println("Connection accepted")
	defer conn.CloseWithError(0, "done")

	for {
		ctx := context.Background()
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	// Read first byte to determine mode
	modeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, modeBuf); err != nil {
		return
	}

	switch modeBuf[0] {
	case 'U': // Upload: client sends, server receives
		var total int64
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		// Send back total received
		fmt.Fprintf(stream, "%d", total)

	case 'D': // Download: server sends
		sendData(stream, 0) // send forever until client closes

	default:
		return
	}
}

func sendData(stream *quic.Stream, duration time.Duration) {
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = byte(i % 251)
	}

	deadline := time.Now().Add(100 * 365 * 24 * time.Hour) // effectively forever
	if duration > 0 {
		deadline = time.Now().Add(duration)
	}

	for time.Now().Before(deadline) {
		if _, err := stream.Write(buf); err != nil {
			return
		}
	}
}

func runClient(addr string, mode string, dur time.Duration) error {
	pubKey, err := hex.DecodeString(*keyFile)
	if err != nil {
		return fmt.Errorf("invalid server public key hex: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := squic.Dial(ctx, addr, pubKey, &squic.Config{
		MaxIdleTimeout:    60 * time.Second,
		MaxIncomingStreams: 200,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseWithError(0, "done")

	fmt.Printf("Connected to %s\n", addr)

	switch mode {
	case "upload":
		return runUpload(conn, dur)
	case "download":
		return runDownload(conn, dur)
	case "bidir":
		return runBidir(conn, dur)
	}
	return nil
}

func runUpload(conn *quic.Conn, dur time.Duration) error {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	// Signal upload mode
	if _, err := stream.Write([]byte("U")); err != nil {
		return err
	}

	var totalBytes atomic.Int64
	buf := make([]byte, 32*1024)
	for i := range buf {
		buf[i] = byte(i % 251)
	}

	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		var lastTotal int64
		for range ticker.C {
			elapsed := time.Since(start)
			total := totalBytes.Load()
			delta := total - lastTotal
			lastTotal = total
			mbps := float64(delta) * 8 / 1e6
			fmt.Printf("[  0]  %.0f-%.0fs  %d MB  %.1f Mbits/sec\n",
				elapsed.Seconds()-1, elapsed.Seconds(),
				delta/(1<<20), mbps)
		}
	}()

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		n, err := stream.Write(buf)
		if err != nil {
			break
		}
		totalBytes.Add(int64(n))
	}
	stream.Close()

	elapsed := time.Since(start)
	total := totalBytes.Load()
	avgMbps := float64(total) * 8 / elapsed.Seconds() / 1e6

	fmt.Printf("\n[SUM]  0.00-%.2f sec  %d MB  %.1f Mbits/sec  sender\n",
		elapsed.Seconds(), total/(1<<20), avgMbps)

	// Read server's confirmed byte count
	resp := make([]byte, 64)
	n, _ := stream.Read(resp)
	if n > 0 {
		fmt.Printf("[SUM]  server confirmed: %s bytes\n", string(resp[:n]))
	}

	return nil
}

func runDownload(conn *quic.Conn, dur time.Duration) error {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	// Signal download mode
	if _, err := stream.Write([]byte("D")); err != nil {
		return err
	}

	var totalBytes atomic.Int64
	buf := make([]byte, 32*1024)

	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		var lastTotal int64
		for range ticker.C {
			elapsed := time.Since(start)
			total := totalBytes.Load()
			delta := total - lastTotal
			lastTotal = total
			mbps := float64(delta) * 8 / 1e6
			fmt.Printf("[  0]  %.0f-%.0fs  %d MB  %.1f Mbits/sec  recv\n",
				elapsed.Seconds()-1, elapsed.Seconds(),
				delta/(1<<20), mbps)
		}
	}()

	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		n, err := stream.Read(buf)
		totalBytes.Add(int64(n))
		if err != nil {
			break
		}
	}
	stream.Close()

	elapsed := time.Since(start)
	total := totalBytes.Load()
	avgMbps := float64(total) * 8 / elapsed.Seconds() / 1e6

	fmt.Printf("\n[SUM]  0.00-%.2f sec  %d MB  %.1f Mbits/sec  receiver\n",
		elapsed.Seconds(), total/(1<<20), avgMbps)

	return nil
}

func runBidir(conn *quic.Conn, dur time.Duration) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// Upload stream
	go func() {
		defer wg.Done()
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "upload stream: %v\n", err)
			return
		}
		if _, err := stream.Write([]byte("U")); err != nil {
			fmt.Fprintf(os.Stderr, "upload mode write: %v\n", err)
			return
		}

		var total int64
		buf := make([]byte, 32*1024)
		deadline := time.Now().Add(dur)
		for time.Now().Before(deadline) {
			n, err := stream.Write(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		stream.Close()

		mbps := float64(total) * 8 / dur.Seconds() / 1e6
		fmt.Printf("[UP]   %d MB  %.1f Mbits/sec  sender\n", total/(1<<20), mbps)
	}()

	// Download stream
	go func() {
		defer wg.Done()
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "download stream: %v\n", err)
			return
		}
		if _, err := stream.Write([]byte("D")); err != nil {
			fmt.Fprintf(os.Stderr, "download mode write: %v\n", err)
			return
		}

		var total int64
		buf := make([]byte, 32*1024)
		deadline := time.Now().Add(dur)
		for time.Now().Before(deadline) {
			n, err := stream.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		stream.Close()

		mbps := float64(total) * 8 / dur.Seconds() / 1e6
		fmt.Printf("[DOWN] %d MB  %.1f Mbits/sec  receiver\n", total/(1<<20), mbps)
	}()

	wg.Wait()
	return nil
}

