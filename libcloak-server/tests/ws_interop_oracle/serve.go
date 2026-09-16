package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// The mirror image of decode.go: gorilla on the SERVER side of the
// upgrade, so the negative control that bites here is the other one --
// an UNMASKED client-to-server frame, which RFC 6455 section 5.1 forbids
// and which gorilla reports as the same "bad MASK".
//
// It earns its place twice over. Besides the control, this is the only
// place in this tree where a real gorilla Upgrader computes a
// Sec-WebSocket-Accept over a key the C side chose: the C test compares
// gorilla's answer to cloak_ws_handshake_parse's, so the accept
// computation is checked against an implementation that is not ours,
// rather than against the RFC vector alone.

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	expect := fs.String("expect", "ok", "ok | badmask")
	sizes := fs.String("sizes", "1,125,126,16000", "message payload sizes, in order")
	timeout := fs.Duration("timeout", 8*time.Second, "overall bound")
	_ = fs.Parse(args)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
	}
	// The C side reads this line to learn the port, so it must be flushed
	// before anything can connect -- stdout is unbuffered in Go.
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)

	want := parseSizes(*sizes)
	done := make(chan error, 1)
	up := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			done <- fmt.Errorf("upgrade: %w", err)
			return
		}
		fmt.Printf("UPGRADE ok\n")
		done <- readAndCheck(c, want)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	select {
	case err := <-done:
		report("server", *expect, err)
	case <-time.After(*timeout):
		fail("no connection completed within %s", *timeout)
	}
}
