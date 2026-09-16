package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// GORILLA AS A DECODER ORACLE.
//
// gorilla's advanceFrame is a fussy, independently written RFC 6455
// validator: it refuses RSV bits, unknown opcodes, over-long control
// frames, a CONTINUATION with no message open, and -- the one that
// matters most here -- a frame masked the wrong way for its direction
// ("bad MASK", conn.go:862, `mask != c.isServer`). Feeding it the bytes
// the C conn layer actually put on a socket is the only check in this
// tree that is not ultimately our own opinion of our own output.
//
// A positive result here is worth nothing without the negative controls,
// so both modes take an -expect and both are run: `ok` requires every
// message to arrive intact, `badmask` requires gorilla to refuse the very
// first frame with "bad MASK". If the second did not fail, the first
// would not be evidence of anything.

// The payload the C side writes and this side re-derives. Deliberately
// index-dependent in BOTH the byte offset and the message number, so that
// a reassembly that dropped, duplicated or reordered a fragment shows up
// as a content mismatch and not merely as a length mismatch.
func oraclePayload(msg, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*5 + 1 + msg*97)
	}
	return out
}

func parseSizes(s string) []int {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.Atoi(f)
		if err != nil {
			fail("bad -sizes %q", s)
		}
		out = append(out, v)
	}
	return out
}

// readAndCheck consumes len(sizes) binary messages and verifies each one,
// or reports the error gorilla produced. Returns the error, if any.
func readAndCheck(c *websocket.Conn, sizes []int) error {
	for i, want := range sizes {
		mt, r, err := c.NextReader()
		if err != nil {
			return err
		}
		if mt != websocket.BinaryMessage {
			return fmt.Errorf("message %d has type %d, want binary", i, mt)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if len(got) != want {
			return fmt.Errorf("message %d is %d bytes, want %d", i, len(got), want)
		}
		expect := oraclePayload(i, want)
		for j := range got {
			if got[j] != expect[j] {
				return fmt.Errorf("message %d byte %d is %02x, want %02x", i, j, got[j], expect[j])
			}
		}
		fmt.Printf("MSG %d len=%d ok\n", i, len(got))
	}
	return nil
}

// report turns "what gorilla said" into an exit status against -expect.
func report(where string, expect string, err error) {
	switch expect {
	case "ok":
		if err != nil {
			fail("%s: expected clean decode, got: %v", where, err)
		}
		fmt.Printf("DECODE ok side=%s\n", where)
	case "badmask":
		if err == nil {
			fail("%s: expected gorilla to refuse the frame, it accepted it", where)
		}
		fmt.Printf("DECODE error side=%s text=%q\n", where, err.Error())
		if !strings.Contains(err.Error(), "bad MASK") {
			fail("%s: expected \"bad MASK\", got: %v", where, err)
		}
	default:
		fail("unknown -expect %q", expect)
	}
	os.Exit(0)
}

func runDecode(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port that speaks the server half of the upgrade")
	expect := fs.String("expect", "ok", "ok | badmask")
	sizes := fs.String("sizes", "1,125,126,16000", "message payload sizes, in order")
	hidden := fs.String("hidden", "", "value for the Cloak `Hidden` request header")
	timeout := fs.Duration("timeout", 8*time.Second, "overall bound")
	_ = fs.Parse(args)

	raw, err := net.DialTimeout("tcp", *addr, *timeout)
	if err != nil {
		fail("dial: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(*timeout))

	u, err := url.Parse("ws://" + *addr + "/ws/path")
	if err != nil {
		fail("%v", err)
	}
	// The `Hidden` header the C side needs in order to run this request
	// through cloak_ws_handshake_parse -- which is the point: the accept
	// this client then validates was computed by the production parser
	// over a request gorilla itself composed, not over a fixture.
	header := http.Header{}
	if *hidden != "" {
		header.Add("hidden", *hidden)
	}
	// Small buffers on purpose: a 16000-byte message therefore cannot be
	// served out of one buffered read, so gorilla's streaming reassembly
	// runs rather than being bypassed.
	c, _, err := websocket.NewClient(raw, u, header, 4096, 4096)
	if err != nil {
		fail("upgrade: %v", err)
	}
	fmt.Printf("UPGRADE ok\n")
	report("client", *expect, readAndCheck(c, parseSizes(*sizes)))
}
