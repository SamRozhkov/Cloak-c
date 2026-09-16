package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// The full CDN session, as a real Cloak client drives it.
//
// The handshake below is internal/client/websocket.go's WSOverTLS.Handshake
// with the uTLS leg removed: this oracle talks to the origin directly,
// which is what a CDN's own back end does, and the TLS the real client
// speaks is between it and the CDN and carries none of the bytes under
// test. What is kept is the part the C server sees -- the `hidden` header,
// gorilla's own upgrade, and the 60-byte reply split as
// [12-byte nonce][48 bytes AES-GCM].

const (
	// What Go's client passes to websocket.NewClient
	// (internal/client/websocket.go:52).
	goReadBufSize  = 16480
	goWriteBufSize = 16480
)

type session struct {
	ws   *WebSocketConn
	obfs Obfuscator
}

func handshake(addr string, uid []byte, serverPub []byte, method byte, sessionID uint32) (*session, error) {
	raw, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	payload, sharedSecret := makeAuthenticationPayload(uid, "shadowsocks", method, sessionID, false,
		serverPub, time.Now())

	// internal/client/websocket.go:50-51, byte for byte: the header name
	// is lowercase on the wire only because net/http canonicalises it,
	// and the value is unpadded-free standard base64 of 96 bytes.
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(append(payload.randPubKey[:], payload.ciphertextWithTag[:]...)))

	u, err := url.Parse("ws://" + addr + "/ws/path")
	if err != nil {
		return nil, err
	}
	c, _, err := websocket.NewClient(raw, u, header, goReadBufSize, goWriteBufSize)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("upgrade: %w", err)
	}

	ws := &WebSocketConn{Conn: c}
	buf := make([]byte, 128)
	if err := ws.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	n, err := ws.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read reply: %w", err)
	}
	if n != 60 {
		return nil, fmt.Errorf("reply must be 60 bytes, got %d", n)
	}
	reply := buf[:60]
	sessionKeySlice, err := AESGCMDecrypt(reply[:12], sharedSecret[:], reply[12:])
	if err != nil {
		return nil, fmt.Errorf("decrypt reply: %w", err)
	}
	if len(sessionKeySlice) != 32 {
		return nil, fmt.Errorf("session key must be 32 bytes, got %d", len(sessionKeySlice))
	}
	var sessionKey [32]byte
	copy(sessionKey[:], sessionKeySlice)
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	o, err := MakeObfuscator(method, sessionKey)
	if err != nil {
		return nil, err
	}
	fmt.Printf("HANDSHAKE ok sessionkey=%x\n", sessionKey[:4])
	return &session{ws: ws, obfs: o}, nil
}

// sendFrame puts exactly one Cloak mux frame into exactly one WebSocket
// binary message, which is the invariant the C conn layer is written to.
func (s *session) sendFrame(f *Frame) error {
	buf := make([]byte, frameHeaderLength+len(f.Payload)+maxExtraLen)
	n, err := s.obfs.obfuscate(f, buf, 0)
	if err != nil {
		return err
	}
	_, err = s.ws.Write(buf[:n])
	return err
}

// recvFrame reads one message and deobfuscates it in place.
func (s *session) recvFrame(buf []byte) (*Frame, error) {
	n, err := s.ws.Read(buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("empty websocket message")
	}
	var f Frame
	if err := s.obfs.deobfuscate(&f, buf[:n]); err != nil {
		return nil, fmt.Errorf("deobfuscate (%d bytes): %w", n, err)
	}
	return &f, nil
}

// The payload the exchange sends. Deterministic from the seed so the C
// side can rebuild it and assert on what the upstream saw, and NOT
// constant, so that a server which echoed a buffer back instead of
// relaying it would be caught.
func makePayload(n int, seed uint64) []byte {
	out := make([]byte, n)
	x := seed | 1
	for i := range out {
		// xorshift64*, written out rather than imported so the C side can
		// mirror it in six lines.
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x >> 24)
	}
	return out
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port of the Cloak server")
	uidB64 := fs.String("uid", "", "base64 UID")
	pubB64 := fs.String("pub", "", "base64 server public key")
	nbytes := fs.Int("bytes", 70000, "payload bytes to send")
	chunk := fs.Int("chunk", 4096, "payload bytes per mux frame")
	xorMask := fs.Int("xor", 0x5a, "the byte the upstream XORs with")
	seed := fs.Uint64("seed", 0x9e3779b97f4a7c15, "payload seed")
	fragment := fs.Bool("fragment", false, "route through the fragmenting proxy")
	ping := fs.Bool("ping", false, "do the ping/pong check instead of an exchange")
	timeout := fs.Duration("timeout", 8*time.Second, "overall bound")
	_ = fs.Parse(args)

	uid, err := base64.StdEncoding.DecodeString(*uidB64)
	if err != nil || len(uid) != 16 {
		fail("bad -uid %q", *uidB64)
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil || len(pub) != 32 {
		fail("bad -pub %q", *pubB64)
	}

	target := *addr
	var proxy *fragProxy
	if *fragment {
		proxy, err = startFragProxy(*addr)
		if err != nil {
			fail("fragproxy: %v", err)
		}
		target = proxy.addr
		fmt.Printf("PROXY listening=%s target=%s\n", proxy.addr, *addr)
	}

	deadline := time.Now().Add(*timeout)
	s, err := handshake(target, uid, pub, EncryptionMethodAES256GCM, 1)
	if err != nil {
		fail("%v", err)
	}
	defer s.ws.Close()

	if *ping {
		runPing(s, deadline)
		return
	}
	runExchange(s, *nbytes, *chunk, byte(*xorMask), *seed, deadline)
	if proxy != nil {
		f, p := proxy.counts()
		fmt.Printf("PROXY frames_out=%d pings=%d\n", f, p)
		if f == 0 || p == 0 {
			fail("the proxy forwarded nothing")
		}
	}
}

func runExchange(s *session, nbytes, chunk int, xorMask byte, seed uint64, deadline time.Time) {
	payload := makePayload(nbytes, seed)
	want := make([]byte, nbytes)
	for i := range payload {
		want[i] = payload[i] ^ xorMask
	}

	var wg sync.WaitGroup
	var sendErr, recvErr error
	got := make([]byte, 0, nbytes)
	frames := 0
	recvFrames := 0

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.ws.SetWriteDeadline(deadline); err != nil {
			sendErr = err
			return
		}
		var seq uint64
		for off := 0; off < len(payload); off += chunk {
			end := off + chunk
			if end > len(payload) {
				end = len(payload)
			}
			f := &Frame{StreamID: 1, Seq: seq, Closing: closingNothing, Payload: payload[off:end]}
			if err := s.sendFrame(f); err != nil {
				sendErr = fmt.Errorf("send seq %d: %w", seq, err)
				return
			}
			seq++
			frames++
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, goReadBufSize)
		var expectSeq uint64
		if err := s.ws.SetReadDeadline(deadline); err != nil {
			recvErr = err
			return
		}
		for len(got) < nbytes {
			f, err := s.recvFrame(buf)
			if err != nil {
				recvErr = err
				return
			}
			if f.StreamID != 1 {
				recvErr = fmt.Errorf("frame on stream %d, want 1", f.StreamID)
				return
			}
			if f.Seq != expectSeq {
				recvErr = fmt.Errorf("frame seq %d, want %d", f.Seq, expectSeq)
				return
			}
			expectSeq++
			recvFrames++
			if f.Closing != closingNothing {
				recvErr = fmt.Errorf("stream closed after %d of %d bytes", len(got), nbytes)
				return
			}
			got = append(got, f.Payload...)
		}
	}()

	wg.Wait()
	if sendErr != nil {
		fail("%v", sendErr)
	}
	if recvErr != nil {
		fail("%v", recvErr)
	}
	if len(got) != nbytes {
		fail("got %d bytes, want %d", len(got), nbytes)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				fail("byte %d differs: got %02x want %02x", i, got[i], want[i])
			}
		}
		fail("payload differs")
	}
	if recvFrames < 2 {
		fail("the reply arrived in %d frame(s); this case is only meaningful across more than one", recvFrames)
	}
	fmt.Printf("EXCHANGE ok bytes=%d sent_frames=%d recv_frames=%d\n", nbytes, frames, recvFrames)
}

// Pong-on-ping. The pong handler is gorilla's own hook, and the read loop
// exists because gorilla processes control frames only while a read is in
// flight -- which is also why "within one turn" is measurable here: no
// data message is ever sent on this connection, so the only thing that can
// wake the reader is the pong.
func runPing(s *session, deadline time.Time) {
	payload := []byte("cloak-cdn-liveness-probe")
	pong := make(chan string, 4)
	s.ws.SetPongHandler(func(data string) error {
		pong <- data
		return nil
	})

	dataMsg := make(chan int, 4)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, goReadBufSize)
		for {
			n, err := s.ws.Read(buf)
			if err != nil {
				readErr <- err
				return
			}
			dataMsg <- n
		}
	}()

	start := time.Now()
	if err := s.ws.SetReadDeadline(deadline); err != nil {
		fail("%v", err)
	}
	if err := s.ws.WriteControl(websocket.PingMessage, payload, deadline); err != nil {
		fail("write ping: %v", err)
	}

	select {
	case got := <-pong:
		if got != string(payload) {
			fail("pong payload %q, want %q", got, payload)
		}
		fmt.Printf("PONG ok rtt_ms=%d bytes=%d\n", time.Since(start).Milliseconds(), len(got))
	case n := <-dataMsg:
		fail("a %d-byte data message arrived before the pong", n)
	case err := <-readErr:
		fail("read while waiting for pong: %v", err)
	case <-time.After(time.Until(deadline)):
		fail("no pong within the deadline")
	}
	os.Exit(0)
}

// Used by the C side's expectations and by nothing else; kept next to the
// payload generator so the two cannot drift.
var _ = binary.BigEndian
