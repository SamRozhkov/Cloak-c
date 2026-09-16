package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// A HAND-WRITTEN FRAGMENTING PROXY, and the reason it is hand-written.
//
// Neither end of a C-to-C test produces a fragmented WebSocket message,
// and neither does a Go peer: gorilla's writer emits one frame per
// message unless the application asks otherwise, and Cloak's own client
// never asks. So the only way this port ever meets RFC 6455 section 5.4
// on the wire is if something in the middle re-frames -- which is exactly
// what a CDN is entitled to do, and what this project cannot control in
// production. Every bug in that class passes the whole suite and fails
// behind the intermediary.
//
// This file therefore uses NO WebSocket library at all. It reads the two
// header bytes, the extended length and the 4-byte mask key by hand,
// unmasks the payload by hand, and re-emits the message as 2-3 frames of
// its own with fresh mask keys -- a BINARY frame with FIN clear, zero or
// one CONTINUATION frames with FIN clear, and a final CONTINUATION with
// FIN set -- with a PING interleaved between the fragments, which section
// 5.4 explicitly permits and which a real CDN really does send.
//
// Only the client-to-server direction is re-framed. The other direction
// is copied through untouched: fragmenting it would be a test of
// gorilla's reassembly, not of ours.

const (
	opContinuation = 0x0
	opBinary       = 0x2
	opPing         = 0x9
)

type fragProxy struct {
	addr string

	mu        sync.Mutex
	framesOut int
	pings     int
}

func (p *fragProxy) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.framesOut, p.pings
}

func startFragProxy(target string) (*fragProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &fragProxy{addr: ln.Addr().String()}
	go func() {
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c, target)
		}
	}()
	return p, nil
}

func (p *fragProxy) serve(client net.Conn, target string) {
	defer client.Close()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()

	br := bufio.NewReaderSize(client, 65536)

	// The upgrade request goes through verbatim: this proxy re-frames
	// WebSocket messages and rewrites no HTTP. (A CDN does rewrite
	// headers, and test_dispatcher_ws.c is where that is covered; here,
	// changing the request would only move the failure earlier.)
	if err := copyHeaderBlock(br, server); err != nil {
		return
	}

	go func() {
		// Server to client, untouched.
		_, _ = io.Copy(client, server)
		client.Close()
	}()

	for {
		fin, opcode, payload, err := readFrame(br)
		if err != nil {
			return
		}
		if opcode != opBinary && opcode != opContinuation {
			// Control frames (and anything else) pass through unchanged
			// except for a fresh mask, which RFC 6455 section 5.3
			// requires of every client-to-server frame.
			if err := writeMaskedFrame(server, fin, opcode, payload); err != nil {
				return
			}
			continue
		}
		if !fin {
			// Our own client never fragments; if it started to, the
			// splitting below would have to track message state, and
			// silently forwarding instead would make this case a no-op.
			return
		}
		if err := p.splitAndForward(server, payload); err != nil {
			return
		}
	}
}

// splitAndForward turns one message into 2-3 frames with a ping wedged
// between the first and the second.
func (p *fragProxy) splitAndForward(w io.Writer, payload []byte) error {
	parts := 3
	if len(payload) < 3 {
		parts = 1
	} else if len(payload) < 64 {
		parts = 2
	}
	size := len(payload) / parts

	for i := 0; i < parts; i++ {
		start := i * size
		end := start + size
		if i == parts-1 {
			end = len(payload)
		}
		op := opContinuation
		if i == 0 {
			op = opBinary
		}
		last := i == parts-1
		if err := writeMaskedFrame(w, last, op, payload[start:end]); err != nil {
			return err
		}
		p.mu.Lock()
		p.framesOut++
		p.mu.Unlock()

		if i == 0 && parts > 1 {
			// RFC 6455 section 5.4: "control frames MAY be injected in
			// the middle of a fragmented message". A CDN's keepalive
			// lands here, and a server that keeps one reassembly buffer
			// for everything corrupts the message on it.
			if err := writeMaskedFrame(w, true, opPing, []byte("cdn-keepalive")); err != nil {
				return err
			}
			p.mu.Lock()
			p.pings++
			p.mu.Unlock()
		}
	}
	return nil
}

// copyHeaderBlock forwards bytes until CRLFCRLF, inclusive.
func copyHeaderBlock(br *bufio.Reader, w io.Writer) error {
	var seen []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		seen = append(seen, b)
		if _, err := w.Write([]byte{b}); err != nil {
			return err
		}
		n := len(seen)
		if n >= 4 && seen[n-4] == '\r' && seen[n-3] == '\n' && seen[n-2] == '\r' && seen[n-1] == '\n' {
			return nil
		}
		if n > 1<<16 {
			return fmt.Errorf("header block too long")
		}
	}
}

// readFrame reads one RFC 6455 frame from a client, by hand, and returns
// its unmasked payload.
func readFrame(br *bufio.Reader) (fin bool, opcode int, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(br, h[:]); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	opcode = int(h[0] & 0x0f)
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(br, ext[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(br, ext[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	var key [4]byte
	if masked {
		if _, err = io.ReadFull(br, key[:]); err != nil {
			return
		}
	}
	if n > 1<<20 {
		err = fmt.Errorf("frame of %d bytes is not something this proxy expects", n)
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	return
}

// writeMaskedFrame emits one frame towards the server, masked as RFC 6455
// section 5.3 requires of a client.
func writeMaskedFrame(w io.Writer, fin bool, opcode int, payload []byte) error {
	var hdr []byte
	b0 := byte(opcode)
	if fin {
		b0 |= 0x80
	}
	hdr = append(hdr, b0)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n < 1<<16:
		hdr = append(hdr, 126|0x80)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		hdr = append(hdr, ext[:]...)
	default:
		hdr = append(hdr, 127|0x80)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	hdr = append(hdr, key[:]...)

	body := make([]byte, n)
	for i := range payload {
		body[i] = payload[i] ^ key[i&3]
	}
	if _, err := w.Write(append(hdr, body...)); err != nil {
		return err
	}
	return nil
}
