// ws_interop_oracle -- the outside implementations libcloak-server's CDN
// transport is measured against.
//
// Every test in this port's first seven modules had our code on both ends,
// which is how it once shipped a data path carrying a two-byte length
// prefix where Go writes a five-byte TLS record header: the disguise
// applied for one round trip and then dropped, and five modules of
// round-trip tests could not see it because both ends agreed. This program
// is the other end that does not agree by construction.
//
// It has four modes, and each one is a different kind of outside opinion:
//
//	client  A real Cloak client: gorilla/websocket does the upgrade and
//	        the framing, and the Cloak layers above it (the authentication
//	        payload, the frame obfuscator, Salsa20) are the Go original's
//	        own source, copied in cloak_upstream.go. What it proves is not
//	        "a session was established" but "these exact bytes came back",
//	        through a proxy that transforms them, so a session built on a
//	        wrong key or a wrong framing mode cannot pass.
//	        -fragment additionally routes the whole connection through the
//	        hand-written fragmenting proxy in fragproxy.go.
//	        -ping instead sends a WebSocket ping and requires a pong.
//	decode  gorilla as a DECODER: it validates the C server's 101 (its own
//	        Sec-WebSocket-Accept check) and then reads frames the C side
//	        produced, reporting exactly what its advanceFrame said.
//	serve   gorilla as a SERVER-side decoder, for the mirror-image
//	        negative control: a server rejects an unmasked client frame.
//
// Output discipline: every mode prints machine-readable lines to stdout
// and exits 0 only if what happened is what -expect said should happen.
// The C test asserts on the exit status AND on those lines, because a
// program that fails to start also "produces no error output".
package main

import (
	"fmt"
	"os"
)

func fail(format string, args ...interface{}) {
	fmt.Printf("FAIL "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: ws_interop_oracle <client|decode|serve> [flags]")
	}
	mode := os.Args[1]
	args := os.Args[2:]
	switch mode {
	case "client":
		runClient(args)
	case "decode":
		runDecode(args)
	case "serve":
		runServe(args)
	default:
		fail("unknown mode %q", mode)
	}
}
