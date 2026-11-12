// Package hello reads a TLS ClientHello off the wire and names it by the
// fingerprints of the Hikkari client's release test (hk, ja4): a copy of
// hikkari-client engine/core/engine/singbox/diagnostics/wire.go from
// readClientHello on, hk version h1, so a hello here and a hello there with
// one hk are one hello. Keep it in step with that file.
package hello

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	wireMaxHello = 1 << 16
	hkVersion    = "h1"
)

// Read reads TLS handshake records until one whole ClientHello is in and
// returns the handshake message.
func Read(r io.Reader) ([]byte, error) {
	msg, _, err := readClientHello(r)
	return msg, err
}

// Names gives a ClientHello message's hk and ja4.
func Names(msg []byte) (hk, ja4 string, err error) {
	h, err := parseClientHello(msg)
	if err != nil {
		return "", "", err
	}
	return h.hk(), h.ja4(), nil
}

// readClientHello reads TLS handshake records until one whole ClientHello is in,
// however the client split it: a post-quantum share can make it span records.
func readClientHello(r io.Reader) ([]byte, int, error) {
	var buf []byte
	records := 0
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, records, errors.New("hello cut short")
		}
		if header[0] != 22 {
			return nil, records, fmt.Errorf("record type %d, not a handshake", header[0])
		}
		n := int(binary.BigEndian.Uint16(header[3:5]))
		if n == 0 || n > 1<<14+2048 {
			return nil, records, errors.New("bad record length")
		}
		frag := make([]byte, n)
		if _, err := io.ReadFull(r, frag); err != nil {
			return nil, records, errors.New("hello cut short")
		}
		records++
		buf = append(buf, frag...)
		if len(buf) < 4 {
			continue
		}
		if buf[0] != 1 {
			return nil, records, fmt.Errorf("handshake type %d, not a ClientHello", buf[0])
		}
		need := 4 + (int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3]))
		if need > wireMaxHello {
			return nil, records, errors.New("hello too long")
		}
		if len(buf) >= need {
			return buf[:need], records, nil
		}
	}
}

// Extension types the line and the hashes single out.
const (
	extSNI              = 0x0000
	extSupportedGroups  = 0x000a
	extSigAlgs          = 0x000d
	extALPN             = 0x0010
	extPadding          = 0x0015
	extSessionTicket    = 0x0023
	extPSK              = 0x0029
	extSupportedVersion = 0x002b
	extKeyShare         = 0x0033
	extECH              = 0xfe0d
)

type helloExt struct {
	Type uint16
	Data []byte
}

type keyShare struct {
	Group uint16
	Len   int
}

// clientHello is a parsed ClientHello: the fields fingerprints are made of.
type clientHello struct {
	Legacy      uint16
	Ciphers     []uint16
	Compression []byte
	Exts        []helloExt
	SNI         bool
	ALPN        []string
	Groups      []uint16
	Shares      []keyShare
	SigAlgs     []uint16
	Versions    []uint16
	Padding     int // bytes of the padding extension; -1 without one
	Len         int // the handshake message, header included
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// grease folds every GREASE value into one, since each connection picks its own.
func grease(v uint16) uint16 {
	if isGREASE(v) {
		return 0x0a0a
	}
	return v
}

// helloReader walks a byte slice; any read past the end marks it broken.
type helloReader struct {
	b   []byte
	bad bool
}

func (r *helloReader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *helloReader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (r *helloReader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func u16s(b []byte) ([]uint16, bool) {
	if len(b)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out, true
}

var errBadHello = errors.New("hello not readable")

// parseClientHello reads a handshake message that starts with its 4-byte header.
func parseClientHello(msg []byte) (*clientHello, error) {
	if len(msg) < 4 || msg[0] != 1 {
		return nil, errBadHello
	}
	h := &clientHello{Padding: -1, Len: len(msg)}
	r := &helloReader{b: msg[4:]}
	h.Legacy = uint16(r.u16())
	r.take(32)     // random
	r.take(r.u8()) // session id
	cs, ok := u16s(r.take(r.u16()))
	if !ok || r.bad {
		return nil, errBadHello
	}
	h.Ciphers = cs
	h.Compression = append([]byte(nil), r.take(r.u8())...)
	if r.bad {
		return nil, errBadHello
	}
	if len(r.b) == 0 {
		return h, nil // no extensions at all: TLS 1.2 and older may do that
	}
	exts := &helloReader{b: r.take(r.u16())}
	if r.bad {
		return nil, errBadHello
	}
	for len(exts.b) > 0 {
		typ := uint16(exts.u16())
		data := exts.take(exts.u16())
		if exts.bad {
			return nil, errBadHello
		}
		h.Exts = append(h.Exts, helloExt{Type: typ, Data: data})
		if err := h.readExt(typ, data); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *clientHello) readExt(typ uint16, data []byte) error {
	r := &helloReader{b: data}
	switch typ {
	case extSNI:
		h.SNI = true
	case extALPN:
		list := &helloReader{b: r.take(r.u16())}
		for len(list.b) > 0 && !list.bad {
			h.ALPN = append(h.ALPN, string(list.take(list.u8())))
		}
		r.bad = r.bad || list.bad
	case extSupportedGroups:
		v, ok := u16s(r.take(r.u16()))
		r.bad = r.bad || !ok
		h.Groups = v
	case extSigAlgs:
		v, ok := u16s(r.take(r.u16()))
		r.bad = r.bad || !ok
		h.SigAlgs = v
	case extSupportedVersion:
		v, ok := u16s(r.take(r.u8()))
		r.bad = r.bad || !ok
		h.Versions = v
	case extKeyShare:
		list := &helloReader{b: r.take(r.u16())}
		for len(list.b) > 0 && !list.bad {
			g := uint16(list.u16())
			n := list.u16()
			list.take(n)
			h.Shares = append(h.Shares, keyShare{Group: g, Len: n})
		}
		r.bad = r.bad || list.bad
	case extPadding:
		h.Padding = len(data)
	}
	if r.bad {
		return errBadHello
	}
	return nil
}

// tlsVersion is the highest version offered, as JA4 writes it.
func (h *clientHello) tlsVersion() string {
	v := h.Legacy
	for _, s := range h.Versions {
		if !isGREASE(s) && s > v {
			v = s
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	}
	return "00"
}

func hex4(v uint16) string { return fmt.Sprintf("%04x", v) }

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// ja4 is FoxIO's JA4 of the hello (github.com/FoxIO-LLC/ja4, JA4 over TCP),
// so a hello can be looked up in outside databases.
func (h *clientHello) ja4() string {
	var ciphers, exts []string
	for _, c := range h.Ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, hex4(c))
		}
	}
	extCount := 0
	for _, e := range h.Exts {
		if isGREASE(e.Type) {
			continue
		}
		extCount++
		if e.Type != extSNI && e.Type != extALPN {
			exts = append(exts, hex4(e.Type))
		}
	}
	sni := "i"
	if h.SNI {
		sni = "d"
	}
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		v := h.ALPN[0]
		first, last := v[0], v[len(v)-1]
		if isAlnum(first) && isAlnum(last) {
			alpn = string([]byte{first, last})
		} else {
			alpn = fmt.Sprintf("%02x", first)[:1] + fmt.Sprintf("%02x", last)[1:]
		}
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", h.tlsVersion(), sni, min(len(ciphers), 99), min(extCount, 99), alpn)
	sort.Strings(ciphers)
	sort.Strings(exts)
	c := strings.Join(exts, ",")
	// GREASE is dropped here as in the ciphers and extensions: Chrome 155 puts
	// one into signature_algorithms, and a fingerprint that changes with every
	// connection matches nothing.
	var algs []string
	for _, s := range h.SigAlgs {
		if !isGREASE(s) {
			algs = append(algs, hex4(s))
		}
	}
	if len(algs) > 0 {
		c += "_" + strings.Join(algs, ",")
	}
	if len(exts) == 0 {
		c = ""
	}
	return a + "_" + hash12(strings.Join(ciphers, ",")) + "_" + hash12(c)
}

// hk hashes the whole hello minus what changes from one connection to the next
// or with a knob the line reports on its own. JA4 leaves out supported_groups
// and the key shares, and Chrome 131 → 133 shows there first (X25519Kyber768 →
// X25519MLKEM768); hk keeps them. Left out: random, session id, key bytes (their
// lengths stay), GREASE values (folded into one), the bodies of SNI and ALPN
// (knobs, reported apart), padding (its length follows the SNI's), PSK, session
// ticket and ECH bodies (random). Extensions are sorted: Chrome shuffles them on
// every connection.
func (h *clientHello) hk() string {
	var b []byte
	put16 := func(v uint16) { b = binary.BigEndian.AppendUint16(b, v) }
	b = append(b, hkVersion...)
	put16(h.Legacy)
	put16(uint16(len(h.Ciphers)))
	for _, c := range h.Ciphers {
		put16(grease(c))
	}
	b = append(b, byte(len(h.Compression)))
	b = append(b, h.Compression...)
	type ext struct {
		typ  uint16
		body []byte
	}
	var exts []ext
	for _, e := range h.Exts {
		if e.Type == extPadding {
			continue
		}
		exts = append(exts, ext{grease(e.Type), hkBody(e)})
	}
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].typ != exts[j].typ {
			return exts[i].typ < exts[j].typ
		}
		return string(exts[i].body) < string(exts[j].body)
	})
	for _, e := range exts {
		put16(e.typ)
		put16(uint16(len(e.body)))
		b = append(b, e.body...)
	}
	sum := sha256.Sum256(b)
	return hkVersion + hex.EncodeToString(sum[:8])
}

func hkBody(e helloExt) []byte {
	switch e.Type {
	case extSNI, extALPN, extPSK, extSessionTicket, extECH:
		return nil
	case extSupportedGroups, extSupportedVersion, extSigAlgs:
		// A length prefix, then a list of 16-bit values.
		pre := 2
		if e.Type == extSupportedVersion {
			pre = 1
		}
		if len(e.Data) < pre {
			return e.Data
		}
		out := append([]byte(nil), e.Data...)
		for i := pre; i+1 < len(out); i += 2 {
			binary.BigEndian.PutUint16(out[i:], grease(binary.BigEndian.Uint16(out[i:])))
		}
		return out
	case extKeyShare:
		var out []byte
		r := &helloReader{b: e.Data}
		list := &helloReader{b: r.take(r.u16())}
		for len(list.b) > 0 && !list.bad {
			g := uint16(list.u16())
			n := list.u16()
			list.take(n)
			out = binary.BigEndian.AppendUint16(out, grease(g))
			out = binary.BigEndian.AppendUint16(out, uint16(n))
		}
		return out
	}
	return e.Data
}

// groupNames are the groups a modern hello offers; others print as hex.
var groupNames = map[uint16]string{
	0x001d: "x25519",
	0x001e: "x448",
	0x0017: "p256",
	0x0018: "p384",
	0x0019: "p521",
	0x0100: "ffdhe2048",
	0x0101: "ffdhe3072",
	0x11ec: "x25519mlkem768",
	0x11eb: "secp256r1mlkem768",
	0x6399: "x25519kyber768",
}

func groupName(g uint16) string {
	if isGREASE(g) {
		return "grease"
	}
	if n, ok := groupNames[g]; ok {
		return n
	}
	return "0x" + hex4(g)
}

func groupList(gs []uint16) string {
	if len(gs) == 0 {
		return "-"
	}
	parts := make([]string, len(gs))
	for i, g := range gs {
		parts[i] = groupName(g)
	}
	return strings.Join(parts, ",")
}

// wireALPN keeps the line one token per field: a protocol with anything but
// plain characters prints as hex.
func wireALPN(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	parts := make([]string, len(list))
	for i, p := range list {
		plain := p != ""
		for j := 0; j < len(p); j++ {
			plain = plain && (isAlnum(p[j]) || strings.IndexByte("./-_", p[j]) >= 0)
		}
		if plain {
			parts[i] = p
		} else {
			parts[i] = "0x" + hex.EncodeToString([]byte(p))
		}
	}
	return strings.Join(parts, ",")
}

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// fields is the hello's part of the line.
func (h *clientHello) fields() string {
	var shares []uint16
	for _, s := range h.Shares {
		shares = append(shares, s.Group)
	}
	ext, gr, ech, psk := 0, false, false, false
	for _, e := range h.Exts {
		if isGREASE(e.Type) {
			gr = true
			continue
		}
		ext++
		ech = ech || e.Type == extECH
		psk = psk || e.Type == extPSK
	}
	ciphers := 0
	for _, c := range h.Ciphers {
		if isGREASE(c) {
			gr = true
		} else {
			ciphers++
		}
	}
	return fmt.Sprintf("ja4=%s hk=%s tls=%s sni_sent=%s alpn_sent=%s groups=%s shares=%s ext=%d ciphers=%d grease=%s ech=%s psk=%s pad=%d len=%d",
		h.ja4(), h.hk(), h.tlsVersion(), flag(h.SNI), wireALPN(h.ALPN), groupList(h.Groups), groupList(shares),
		ext, ciphers, flag(gr), flag(ech), flag(psk), h.Padding, h.Len)
}
