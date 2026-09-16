// CODE COPIED FROM THE GO ORIGINAL, cbeuw/Cloak, AND WHY IT IS COPIED.
//
// The whole point of this oracle is that the peer on the other end of the
// socket was NOT written by this project. Reimplementing Cloak's wire
// format in Go from the C would defeat that entirely: a C bug faithfully
// re-derived in Go is exactly the self-consistent error this task exists
// to catch. So every byte-level decision below is the Go original's own
// code, copied verbatim from /Users/sam/Cloak, with the ONLY edits being
// the ones the Go toolchain forces (import paths -- `internal/` packages
// of another module are not importable, and this image's module cache
// holds gorilla/websocket and nothing else).
//
// WHAT IS COPIED, AND FROM WHERE (file : lines in cbeuw/Cloak @ the tree
// at /Users/sam/Cloak):
//
//   internal/multiplex/frame.go:3-13       closing consts, type Frame
//   internal/multiplex/obfs.go:15-31       frameHeaderLength, salsa20NonceSize,
//                                          maxExtraLen, padFirstNFrames,
//                                          the EncryptionMethod* consts
//   internal/multiplex/obfs.go:34-38       type Obfuscator
//   internal/multiplex/obfs.go:40-111      (*Obfuscator).obfuscate
//   internal/multiplex/obfs.go:113-155     (*Obfuscator).deobfuscate
//   internal/multiplex/obfs.go:157-201     MakeObfuscator
//   internal/common/crypto.go:15-50        AESGCMEncrypt, AESGCMDecrypt
//   internal/common/websocket.go:12-77     type WebSocketConn and its
//                                          Write/Read/Close/SetDeadline
//   internal/client/auth.go:11-56          UNORDERED_FLAG,
//                                          authenticationPayload,
//                                          makeAuthenticationPayload
//
// THE FOUR EDITS, each one forced and each one named:
//
//  E1. import "github.com/cbeuw/Cloak/internal/common" is dropped; the one
//      symbol obfuscate() uses from it, common.RandInt, is defined below
//      with the same behaviour (the original wraps crypto/rand in a
//      logrus-based retry loop; logrus is not in this image's module
//      cache and a retry ladder around crypto/rand changes nothing a wire
//      format can observe).
//  E2. import "golang.org/x/crypto/salsa20" becomes the copy of that same
//      package vendored under internal/salsa20 -- upstream's own source,
//      x/crypto v0.37.0, which is the exact version Cloak's go.mod pins.
//      Not reimplemented: the C side's Salsa20 has only round-trip tests
//      of its own, so a hand-written Go one would have been a second
//      unverified implementation rather than an oracle.
//  E3. import "golang.org/x/crypto/chacha20poly1305" is dropped along with
//      the EncryptionMethodChaha20Poly1305 arm of MakeObfuscator's switch,
//      which this oracle never selects (it speaks aes-gcm, the method the
//      C tests configure). The const keeps its value so the numbering that
//      goes into the authentication payload's byte 28 is unchanged.
//  E4. makeAuthenticationPayload takes its inputs as plain arguments
//      instead of an client.AuthInfo (that struct drags in the whole
//      client package, utls included) and uses crypto/ecdh's X25519 in
//      place of internal/ecdh, which is a thin wrapper over
//      golang.org/x/crypto/curve25519 -- also absent from the cache. Both
//      compute the same RFC 7748 X25519: internal/ecdh clamps the scalar
//      itself and then calls curve25519.X25519, and crypto/ecdh clamps
//      per RFC 7748 inside NewPrivateKey. The BODY of the function -- the
//      48-byte payload layout, the field offsets, the nonce choice, the
//      order of operations -- is untouched, and that is the part a wire
//      format depends on.
//
// Everything else in this directory (main.go, client.go, fragproxy.go,
// decode.go) is this task's own code and is not claimed to be Cloak's.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"oracle/internal/salsa20"
)

// ---------------------------------------------------------------------
// internal/multiplex/frame.go:3-13
// ---------------------------------------------------------------------

const (
	closingNothing = iota
	closingStream
	closingSession
)

type Frame struct {
	StreamID uint32
	Seq      uint64
	Closing  uint8
	Payload  []byte
}

// ---------------------------------------------------------------------
// internal/multiplex/obfs.go:15-201
// ---------------------------------------------------------------------

const frameHeaderLength = 14
const salsa20NonceSize = 8

// maxExtraLen equals the max length of padding + AEAD tag.
// It is 255 bytes because the extra len field in frame header is only one byte.
const maxExtraLen = 1<<8 - 1

// padFirstNFrames specifies the number of initial frames to pad,
// to avoid TLS-in-TLS detection
const padFirstNFrames = 5

const (
	EncryptionMethodPlain = iota
	EncryptionMethodAES256GCM
	EncryptionMethodChaha20Poly1305
	EncryptionMethodAES128GCM
)

// Obfuscator is responsible for serialisation, obfuscation, and optional encryption of data frames.
type Obfuscator struct {
	payloadCipher cipher.AEAD

	sessionKey [32]byte
}

// obfuscate adds multiplexing headers, encrypt and add TLS header
func (o *Obfuscator) obfuscate(f *Frame, buf []byte, payloadOffsetInBuf int) (int, error) {
	// The method here is to use the first payloadCipher.NonceSize() bytes of the serialised frame header
	// as iv/nonce for the AEAD cipher to encrypt the frame payload. Then we use
	// the authentication tag produced appended to the end of the ciphertext (of size payloadCipher.Overhead())
	// as nonce for Salsa20 to encrypt the frame header. Both with sessionKey as keys.
	payloadLen := len(f.Payload)
	if payloadLen == 0 {
		return 0, errors.New("payload cannot be empty")
	}
	tagLen := 0
	if o.payloadCipher != nil {
		tagLen = o.payloadCipher.Overhead()
	} else {
		tagLen = salsa20NonceSize
	}
	// Pad to avoid size side channel leak
	padLen := 0
	if f.Seq < padFirstNFrames {
		padLen = RandInt(maxExtraLen - tagLen + 1)
	}

	usefulLen := frameHeaderLength + payloadLen + padLen + tagLen
	if len(buf) < usefulLen {
		return 0, errors.New("obfs buffer too small")
	}
	// we do as much in-place as possible to save allocation
	payload := buf[frameHeaderLength : frameHeaderLength+payloadLen+padLen]
	if payloadOffsetInBuf != frameHeaderLength {
		// if payload is not at the correct location in buffer
		copy(payload, f.Payload)
	}

	header := buf[:frameHeaderLength]
	binary.BigEndian.PutUint32(header[0:4], f.StreamID)
	binary.BigEndian.PutUint64(header[4:12], f.Seq)
	header[12] = f.Closing
	header[13] = byte(padLen + tagLen)

	// Random bytes for padding and nonce
	_, err := rand.Read(buf[frameHeaderLength+payloadLen : usefulLen])
	if err != nil {
		return 0, fmt.Errorf("failed to pad random: %w", err)
	}

	if o.payloadCipher != nil {
		o.payloadCipher.Seal(payload[:0], header[:o.payloadCipher.NonceSize()], payload, nil)
	}

	nonce := buf[usefulLen-salsa20NonceSize : usefulLen]
	salsa20.XORKeyStream(header, header, nonce, &o.sessionKey)

	return usefulLen, nil
}

// deobfuscate removes TLS header, decrypt and unmarshall frames
func (o *Obfuscator) deobfuscate(f *Frame, in []byte) error {
	if len(in) < frameHeaderLength+salsa20NonceSize {
		return fmt.Errorf("input size %v, but it cannot be shorter than %v bytes", len(in), frameHeaderLength+salsa20NonceSize)
	}

	header := in[:frameHeaderLength]
	pldWithOverHead := in[frameHeaderLength:] // payload + potential overhead

	nonce := in[len(in)-salsa20NonceSize:]
	salsa20.XORKeyStream(header, header, nonce, &o.sessionKey)

	streamID := binary.BigEndian.Uint32(header[0:4])
	seq := binary.BigEndian.Uint64(header[4:12])
	closing := header[12]
	extraLen := header[13]

	usefulPayloadLen := len(pldWithOverHead) - int(extraLen)
	if usefulPayloadLen < 0 || usefulPayloadLen > len(pldWithOverHead) {
		return errors.New("extra length is negative or extra length is greater than total pldWithOverHead length")
	}

	var outputPayload []byte

	if o.payloadCipher == nil {
		if extraLen == 0 {
			outputPayload = pldWithOverHead
		} else {
			outputPayload = pldWithOverHead[:usefulPayloadLen]
		}
	} else {
		_, err := o.payloadCipher.Open(pldWithOverHead[:0], header[:o.payloadCipher.NonceSize()], pldWithOverHead, nil)
		if err != nil {
			return err
		}
		outputPayload = pldWithOverHead[:usefulPayloadLen]
	}

	f.StreamID = streamID
	f.Seq = seq
	f.Closing = closing
	f.Payload = outputPayload
	return nil
}

func MakeObfuscator(encryptionMethod byte, sessionKey [32]byte) (o Obfuscator, err error) {
	o = Obfuscator{
		sessionKey: sessionKey,
	}
	switch encryptionMethod {
	case EncryptionMethodPlain:
		o.payloadCipher = nil
	case EncryptionMethodAES256GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey[:])
		if err != nil {
			return
		}
		o.payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
	case EncryptionMethodAES128GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey[:16])
		if err != nil {
			return
		}
		o.payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
	default:
		return o, fmt.Errorf("unknown encryption method valued %v", encryptionMethod)
	}

	if o.payloadCipher != nil {
		if o.payloadCipher.NonceSize() > frameHeaderLength {
			return o, errors.New("payload AEAD's nonce size cannot be greater than size of frame header")
		}
	}

	return
}

// ---------------------------------------------------------------------
// internal/common/crypto.go:15-50
// ---------------------------------------------------------------------

func AESGCMEncrypt(nonce []byte, key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		// check here so it doesn't panic
		return nil, errors.New("incorrect nonce size")
	}

	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

func AESGCMDecrypt(nonce []byte, key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		// check here so it doesn't panic
		return nil, errors.New("incorrect nonce size")
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// RandInt is internal/common/crypto.go:86-97 with the logrus retry ladder
// (E1) removed: crypto/rand.Int does not fail on any platform this runs on,
// and a retry has no wire-visible effect.
func RandInt(n int) int {
	s, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(s.Int64())
}

// ---------------------------------------------------------------------
// internal/common/websocket.go:12-77
// ---------------------------------------------------------------------

// WebSocketConn implements io.ReadWriteCloser
// it makes websocket.Conn binary-oriented
type WebSocketConn struct {
	*websocket.Conn
	writeM sync.Mutex
}

func (ws *WebSocketConn) Write(data []byte) (int, error) {
	ws.writeM.Lock()
	err := ws.WriteMessage(websocket.BinaryMessage, data)
	ws.writeM.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func (ws *WebSocketConn) Read(buf []byte) (n int, err error) {
	t, r, err := ws.NextReader()
	if err != nil {
		return 0, err
	}
	if t != websocket.BinaryMessage {
		return 0, nil
	}

	// Read until io.EOL for one full message
	for {
		var read int
		read, err = r.Read(buf[n:])
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			} else {
				break
			}
		} else {
			// There may be data available to read but n == len(buf)-1, read==0 because buffer is full
			if read == 0 {
				err = errors.New("nothing more is read. message may be larger than buffer")
				break
			}
		}
		n += read
	}
	return
}

func (ws *WebSocketConn) Close() error {
	ws.writeM.Lock()
	defer ws.writeM.Unlock()
	return ws.Conn.Close()
}

func (ws *WebSocketConn) SetDeadline(t time.Time) error {
	err := ws.SetReadDeadline(t)
	if err != nil {
		return err
	}
	err = ws.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// internal/client/auth.go:11-56
// ---------------------------------------------------------------------

const (
	UNORDERED_FLAG = 0x01 // 0000 0001
)

type authenticationPayload struct {
	randPubKey        [32]byte
	ciphertextWithTag [64]byte
}

// makeAuthenticationPayload generates the ephemeral key pair, calculates the shared secret, and then compose and
// encrypt the authenticationPayload
//
// E4: the AuthInfo struct and internal/ecdh are replaced by plain
// arguments and crypto/ecdh; the body below is the original's.
func makeAuthenticationPayload(uid []byte, proxyMethod string, encryptionMethod byte,
	sessionId uint32, unordered bool, serverPubKey []byte, now time.Time) (ret authenticationPayload, sharedSecret [32]byte) {
	/*
		Authentication data:
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		|  _UID_   | _Proxy Method_ | _Encryption Method_ | _Timestamp_ | _Session Id_ | _Flag_ | _reserved_ |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		| 16 bytes | 12 bytes       | 1 byte              | 8 bytes     | 4 bytes      | 1 byte | 6 bytes    |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
	*/
	ephPv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("failed to generate ephemeral key pair: %v", err))
	}
	copy(ret.randPubKey[:], ephPv.PublicKey().Bytes())

	plaintext := make([]byte, 48)
	copy(plaintext, uid)
	copy(plaintext[16:28], proxyMethod)
	plaintext[28] = encryptionMethod
	binary.BigEndian.PutUint64(plaintext[29:37], uint64(now.UTC().Unix()))
	binary.BigEndian.PutUint32(plaintext[37:41], sessionId)

	if unordered {
		plaintext[41] |= UNORDERED_FLAG
	}

	serverPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	if err != nil {
		panic(fmt.Sprintf("bad server public key: %v", err))
	}
	secret, err := ephPv.ECDH(serverPub)
	if err != nil {
		panic(fmt.Sprintf("error in generating shared secret: %v", err))
	}
	copy(sharedSecret[:], secret)
	ciphertextWithTag, _ := AESGCMEncrypt(ret.randPubKey[:12], sharedSecret[:], plaintext)
	copy(ret.ciphertextWithTag[:], ciphertextWithTag[:])
	return
}

// Referenced so the copied closing constants do not trip Go's unused
// checks; the values themselves are what the wire format depends on.
var _ = []int{closingNothing, closingStream, closingSession}
