package fts0001

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSource / memSink are the in-memory Source and Sink the tests use.
type memSource struct {
	files []*OutFile
	i     int
	done  []string
}

func newSource(files map[string][]byte, order ...string) *memSource {
	s := &memSource{}
	for _, n := range order {
		name := n
		s.files = append(s.files, &OutFile{Name: name, ModTime: time.Unix(1_600_000_000, 0), Data: files[name],
			Done: func(sent int64, err error) {
				if err == nil {
					s.done = append(s.done, name)
				}
			}})
	}
	return s
}

func (s *memSource) Next() *OutFile {
	if s.i >= len(s.files) {
		return nil
	}
	f := s.files[s.i]
	s.i++
	return f
}

type memSink struct {
	mu    sync.Mutex
	files map[string][]byte
	sizes map[string]int64
	order []string
	bufs  map[string]*bytes.Buffer
}

func newSink() *memSink {
	return &memSink{files: map[string][]byte{}, sizes: map[string]int64{}, bufs: map[string]*bytes.Buffer{}}
}

type bufCloser struct {
	*bytes.Buffer
	onClose func()
}

func (b bufCloser) Close() error { b.onClose(); return nil }

func (s *memSink) Open(name string, size int64, _ time.Time) (io.WriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := &bytes.Buffer{}
	s.bufs[name] = buf
	s.sizes[name] = size
	return bufCloser{buf, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.files[name] = append([]byte(nil), buf.Bytes()...)
	}}, nil
}

func (s *memSink) Done(name string, _ int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.order = append(s.order, name)
	}
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7+int(seed)) ^ byte(i>>3)
	}
	return b
}

// runSession wires Originate on one end and Answer on the other, with
// the caller's TSYNC/poll synchronisation played by hand (the caller's
// job in real use): the answerer side is told to start, the caller
// side's first poll byte comes straight from the answerer's recvBatch.
func runSession(t *testing.T, mode Mode, callerSrc Source, callerSink Sink, answererSrc Source, answererSink Sink) (cerr, aerr error) {
	t.Helper()
	c, a := net.Pipe()
	defer c.Close()
	defer a.Close()
	cfg := Config{Mode: mode, Program: "test", PickupWait: 2 * time.Second, Logger: tLogger(t, slog.LevelDebug)}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		aerr = Answer(ctx, a, cfg, answererSrc, answererSink)
	}()
	cerr = Originate(ctx, c, cfg, callerSrc, callerSink)
	wg.Wait()
	return
}

func TestFTS0001PacketAndFilesBothWays(t *testing.T) {
	out := map[string][]byte{
		"1a2b3c4d.pkt": pattern(300, 1),  // the mail packet: nameless, Telink header
		"file1.txt":    pattern(1000, 2), // attached: MODEM7 name + Telink
		"EXACT.BIN":    pattern(256, 3),  // an exact multiple of the block size
	}
	back := map[string][]byte{
		"deadbeef.pkt": pattern(60, 9),
		"reply.zip":    pattern(5000, 4),
	}
	csrc := newSource(out, "1a2b3c4d.pkt", "file1.txt", "EXACT.BIN")
	csink := newSink()
	asrc := newSource(back, "deadbeef.pkt", "reply.zip")
	asink := newSink()

	cerr, aerr := runSession(t, ModeFTS0001, csrc, csink, asrc, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)

	// The answerer got the packet under a generated name, the rest by name.
	require.Len(t, asink.order, 3)
	assert.Regexp(t, `^[0-9a-f]{8}\.pkt$`, asink.order[0])
	assert.Equal(t, out["1a2b3c4d.pkt"], asink.files[asink.order[0]])
	// The receiver polls 'C' (FTS-0007 BR0): no MODEM7 names, the SEAlink
	// header carries the DOS (upper-case) name and the size.
	assert.Equal(t, out["file1.txt"], asink.files["FILE1.TXT"])
	assert.Equal(t, out["EXACT.BIN"], asink.files["EXACT.BIN"])
	assert.Equal(t, int64(1000), asink.sizes["FILE1.TXT"], "the SEAlink header announced the size")
	assert.Equal(t, []string{"1a2b3c4d.pkt", "file1.txt", "EXACT.BIN"}, csrc.done)

	// Pickup: the caller received the answerer's batch.
	require.Len(t, csink.order, 2)
	assert.Equal(t, back["deadbeef.pkt"], csink.files[csink.order[0]])
	assert.Equal(t, back["reply.zip"], csink.files["REPLY.ZIP"])
	assert.Equal(t, []string{"deadbeef.pkt", "reply.zip"}, asrc.done)
}

func TestFTS0001NothingToPickUp(t *testing.T) {
	out := map[string][]byte{"p.pkt": pattern(129, 1)}
	csink, asink := newSink(), newSink()
	cerr, aerr := runSession(t, ModeFTS0001, newSource(out, "p.pkt"), csink, Nothing{}, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	require.Len(t, asink.order, 1)
	assert.Equal(t, out["p.pkt"], asink.files[asink.order[0]])
	assert.Empty(t, csink.order)
}

func TestFTS0001EmptyPoll(t *testing.T) {
	// A caller with nothing to send (a poll) and an answerer holding mail.
	back := map[string][]byte{"held.pkt": pattern(700, 5)}
	csink, asink := newSink(), newSink()
	asrc := newSource(back, "held.pkt")
	cerr, aerr := runSession(t, ModeFTS0001, Nothing{}, csink, asrc, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Empty(t, asink.order)
	require.Len(t, csink.order, 1)
	assert.Equal(t, back["held.pkt"], csink.files[csink.order[0]])
}

func TestDietIFNABothWays(t *testing.T) {
	out := map[string][]byte{
		"00010008.pkt": pattern(300, 1),
		"00010008.su0": pattern(2049, 2),
	}
	back := map[string][]byte{"0001000a.pkt": pattern(60, 9)}
	csrc := newSource(out, "00010008.pkt", "00010008.su0")
	csink, asink := newSink(), newSink()
	asrc := newSource(back, "0001000a.pkt")
	cerr, aerr := runSession(t, ModeDietIFNA, csrc, csink, asrc, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	// Names travel in the (SEAlink, since we poll with 'C') header, upper-cased on the wire.
	assert.Equal(t, []string{"00010008.PKT", "00010008.SU0"}, asink.order)
	assert.Equal(t, out["00010008.pkt"], asink.files["00010008.PKT"])
	assert.Equal(t, out["00010008.su0"], asink.files["00010008.SU0"])
	assert.Equal(t, int64(2049), asink.sizes["00010008.SU0"])
	assert.Equal(t, []string{"0001000A.PKT"}, csink.order)
	assert.Equal(t, back["0001000a.pkt"], csink.files["0001000A.PKT"])
}

func TestDietIFNANothingBack(t *testing.T) {
	out := map[string][]byte{"00010008.pkt": pattern(300, 1)}
	csink, asink := newSink(), newSink()
	start := time.Now()
	cerr, aerr := runSession(t, ModeDietIFNA, newSource(out, "00010008.pkt"), csink, Nothing{}, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"00010008.PKT"}, asink.order)
	assert.Empty(t, csink.order)
	assert.Less(t, time.Since(start), 10*time.Second, "an EOT, not a silence timeout, ends the empty batch")
}

func TestHeadersRoundTrip(t *testing.T) {
	mt := time.Date(2026, 10, 18, 21, 30, 44, 0, time.Local)
	h := &FileHeader{Name: "longname.pkt", Size: 123456, ModTime: mt, Program: "TestMailer", CRC: true, Resync: true}
	tl := ParseHeader(HeaderTelink, h.MarshalTelink())
	assert.Equal(t, "LONGNAME.PKT", tl.Name)
	assert.Equal(t, int64(123456), tl.Size)
	assert.Equal(t, "TestMailer", tl.Program)
	assert.True(t, tl.CRC)
	assert.Equal(t, mt, tl.ModTime, "DOS time has two-second resolution; 44 s survives")

	sl := ParseHeader(HeaderSEAlink, h.MarshalSEAlink())
	assert.Equal(t, "LONGNAME.PKT", sl.Name)
	assert.Equal(t, int64(123456), sl.Size)
	assert.True(t, sl.Resync)
	assert.False(t, sl.Overdrive)
	assert.Equal(t, mt.Unix(), sl.ModTime.Unix())

	// The ifcico signed-char trap: a size byte >= 0x80 reads correctly.
	big := &FileHeader{Name: "x", Size: 185}
	assert.Equal(t, int64(185), ParseHeader(HeaderSEAlink, big.MarshalSEAlink()).Size)
}

func TestModem7Name(t *testing.T) {
	wire, cs := modem7Name("file1.txt")
	assert.Equal(t, "FILE1   TXT", wire)
	var want byte = SUB
	for i := 0; i < len(wire); i++ {
		want += wire[i]
	}
	assert.Equal(t, want, cs)
	assert.Equal(t, "file1.txt", fromModem7([]byte(wire)))
	w2, _ := modem7Name("/path/to/VeryLongFileName.archive")
	assert.Equal(t, "VERYLONGARC", w2)
	assert.Equal(t, "verylong.arc", fromModem7([]byte(w2)))
	assert.Equal(t, "noext", fromModem7([]byte("NOEXT      ")))
}

// TestFTS0001PacketFirstAndEmptyPacketSlot: a bundle offered before the
// packet is reordered behind it; a batch with no packet puts EOT in the
// packet slot and the receiver still takes the attached files (XR1.3 →
// FR5), and the receiver's generated packet name is never used for them.
func TestFTS0001PacketFirstAndEmptyPacketSlot(t *testing.T) {
	out := map[string][]byte{"bundle.mo0": pattern(500, 3), "mail.pkt": pattern(200, 1)}
	csrc := newSource(out, "bundle.mo0", "mail.pkt")
	asink := newSink()
	cerr, aerr := runSession(t, ModeFTS0001, csrc, newSink(), Nothing{}, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	require.Len(t, asink.order, 2)
	assert.Regexp(t, `^[0-9a-f]{8}\.pkt$`, asink.order[0], "the packet went first, nameless")
	assert.Equal(t, out["mail.pkt"], asink.files[asink.order[0]])
	assert.Equal(t, "BUNDLE.MO0", asink.order[1])
	assert.Equal(t, out["bundle.mo0"], asink.files["BUNDLE.MO0"])

	// No packet at all: EOT in the slot, then the file by name.
	only := map[string][]byte{"only.zip": pattern(300, 7)}
	asink2 := newSink()
	cerr, aerr = runSession(t, ModeFTS0001, newSource(only, "only.zip"), newSink(), Nothing{}, asink2)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"ONLY.ZIP"}, asink2.order)
	assert.Equal(t, only["only.zip"], asink2.files["ONLY.ZIP"])
}

func TestSafeNames(t *testing.T) {
	assert.Equal(t, "_etc_passwd", safeName("/etc/passwd"))
	assert.Equal(t, "_._secret", safeName("../secret"))
	assert.Equal(t, "hidden", safeName(".hidden"))
	assert.Equal(t, "a_b.txt", safeName("a\\b.txt"))
	h := &FileHeader{Name: "x", Size: 1}
	b := h.MarshalSEAlink()
	copy(b[hdrName:], []byte("..\\..\\win.ini\x00"))
	assert.Equal(t, "_.__._win.ini", ParseHeader(HeaderSEAlink, b).Name, "no separator and no '..' survive")
}

// TestModem7NameTooLong: a sender that keeps streaming characters is
// restarted after the eleventh, never buffered.
func TestModem7NameTooLong(t *testing.T) {
	c, a := net.Pipe()
	defer c.Close()
	defer a.Close()
	go func() {
		buf := make([]byte, 1)
		_, _ = a.Read(buf) // our NAK
		_, _ = a.Write([]byte{ACK})
		for i := 0; i < 40; i++ {
			if _, err := a.Write([]byte{'A'}); err != nil {
				return
			}
			_ = a.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := a.Read(buf); err != nil || buf[0] != ACK {
				a.Close() // 'u': the restart we expect; hang up so the test ends at once
				return
			}
		}
	}()
	l := newLine(c, tLogger(t, slog.LevelDebug))
	// Prime the exchange the way recvFile does: our poll, the sender's ACK.
	require.NoError(t, l.putc(NAK))
	b, err := l.getc(2 * time.Second)
	require.NoError(t, err)
	require.Equal(t, ACK, b)
	_, err = l.recvName()
	require.Error(t, err)
}

// runSession2 is runSession with a Config per side.
func runSession2(t *testing.T, ccfg, acfg Config, callerSrc Source, callerSink Sink, answererSrc Source, answererSink Sink) (cerr, aerr error) {
	t.Helper()
	c, a := net.Pipe()
	defer c.Close()
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		aerr = Answer(ctx, a, acfg, answererSrc, answererSink)
	}()
	cerr = Originate(ctx, c, ccfg, callerSrc, callerSink)
	wg.Wait()
	return
}

func barkCfg(t *testing.T, serve BarkServer) Config {
	return Config{Mode: ModeFTS0001, Program: "test", PickupWait: 3 * time.Second, Serve: serve, Logger: tLogger(t, slog.LevelDebug)}
}

// catalogue serves two files by exact name, one of them passworded.
func catalogue(t *testing.T, seen *[]BarkRequest) BarkServer {
	files := map[string][]byte{"NODELIST.Z99": pattern(700, 11), "SECRET.ZIP": pattern(300, 12)}
	return func(reqs ...BarkRequest) ([]*OutFile, bool) {
		var out []*OutFile
		for _, req := range reqs {
			*seen = append(*seen, req)
			name := strings.ToUpper(req.Name)
			data, ok := files[name]
			if !ok || (name == "SECRET.ZIP" && req.Password != "open") {
				continue
			}
			out = append(out, &OutFile{Name: name, Data: data, Done: func(int64, error) {}})
		}
		return out, true
	}
}

// TestBarkCallerRequests: the caller's .req goes out as Bark packets
// when the called system invites them; the answers land in the caller's
// sink; a missing file and a wrong password get an empty answer.
func TestBarkCallerRequests(t *testing.T) {
	req := []byte("NODELIST.Z99\r\nsecret.zip !open\r\nNOSUCH.FIL\r\nsecret.zip !wrong\r\n")
	out := map[string][]byte{"mail.pkt": pattern(100, 1), "0001.req": req}
	csrc := newSource(out, "mail.pkt", "0001.req")
	csink := newSink()
	var seen []BarkRequest
	cerr, aerr := runSession2(t, barkCfg(t, nil), barkCfg(t, catalogue(t, &seen)), csrc, csink, Nothing{}, newSink())
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"mail.pkt", "0001.req"}, csrc.done, "the .req is done once its requests went out")
	require.Len(t, seen, 4)
	assert.Equal(t, "NODELIST.Z99", seen[0].Name)
	assert.Equal(t, "open", seen[1].Password)
	assert.Equal(t, []string{"NODELIST.Z99", "SECRET.ZIP"}, csink.order, "names from the SEAlink headers")
	assert.Equal(t, pattern(700, 11), csink.files["NODELIST.Z99"])
	assert.Equal(t, pattern(300, 12), csink.files["SECRET.ZIP"])
}

// TestBarkAnswererRequests: the called system asks leave (SYN), the
// caller invites (ENQ) and serves.
func TestBarkAnswererRequests(t *testing.T) {
	back := map[string][]byte{"held.pkt": pattern(60, 2), "0002.req": []byte("NODELIST.Z99\r\n")}
	asrc := newSource(back, "held.pkt", "0002.req")
	asink := newSink()
	csink := newSink()
	var seen []BarkRequest
	cerr, aerr := runSession2(t, barkCfg(t, catalogue(t, &seen)), barkCfg(t, nil), newSource(map[string][]byte{"c.pkt": pattern(70, 3)}, "c.pkt"), csink, asrc, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"held.pkt", "0002.req"}, asrc.done)
	require.Len(t, seen, 1)
	assert.Equal(t, "NODELIST.Z99", seen[0].Name)
	// The caller received the held packet (pickup) and served the request.
	require.Len(t, csink.order, 1)
	assert.Equal(t, back["held.pkt"], csink.files[csink.order[0]])
	require.Len(t, asink.order, 2, "the caller's packet, then the requested file")
	assert.Equal(t, "NODELIST.Z99", asink.order[1])
	assert.Equal(t, pattern(700, 11), asink.files["NODELIST.Z99"])
}

// TestBarkRefused: a caller with requests meets an answerer that serves
// none; the answerer still ends cleanly and the .req is reported failed
// (left queued), not lost.
func TestBarkRefused(t *testing.T) {
	out := map[string][]byte{"mail.pkt": pattern(100, 1), "0001.req": []byte("X.ZIP\r\n")}
	csrc := newSource(out, "mail.pkt", "0001.req")
	cerr, aerr := runSession2(t, barkCfg(t, nil), barkCfg(t, nil), csrc, newSink(), Nothing{}, newSink())
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"mail.pkt"}, csrc.done, "the .req stays queued")
}

// TestBarkCallerRefusingOursStillGetsR8: the called system's requests
// meet a caller that serves none (CAN at our SYN). FTS-0008 R7.1: on to
// R8 — the caller's own requests are still invited and served, and ours
// stay queued.
func TestBarkCallerRefusingOursStillGetsR8(t *testing.T) {
	csrc := newSource(map[string][]byte{"c.pkt": pattern(70, 3), "0001.req": []byte("NODELIST.Z99\r\n")}, "c.pkt", "0001.req")
	csink := newSink()
	asrc := newSource(map[string][]byte{"held.pkt": pattern(60, 2), "0002.req": []byte("WANTED.ZIP\r\n")}, "held.pkt", "0002.req")
	var seen []BarkRequest
	cerr, aerr := runSession2(t, barkCfg(t, nil), barkCfg(t, catalogue(t, &seen)), csrc, csink, asrc, newSink())
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, []string{"held.pkt"}, asrc.done, "our refused .req stays queued")
	require.Len(t, seen, 1, "the caller's request was still invited")
	assert.Equal(t, "NODELIST.Z99", seen[0].Name)
	assert.Equal(t, pattern(700, 11), csink.files["NODELIST.Z99"])
	assert.Equal(t, []string{"c.pkt", "0001.req"}, csrc.done)
}

func TestBarkPacket(t *testing.T) {
	r := BarkRequest{Name: "nodelist.z99", Password: "pw", Since: 1700000000}
	pkt := r.Marshal()
	assert.Equal(t, ACK, pkt[0])
	assert.Equal(t, ETX, pkt[len(pkt)-3])
	body := pkt[1 : len(pkt)-3]
	assert.Equal(t, "NODELIST.Z99 1700000000 pw", string(body))
	assert.Equal(t, CRC(body), uint16(pkt[len(pkt)-1])<<8|uint16(pkt[len(pkt)-2]), "CRC low byte first")
	back, ok := parseBarkBody(body)
	require.True(t, ok)
	assert.Equal(t, BarkRequest{Name: "NODELIST.Z99", Password: "pw", Since: 1700000000}, back)
	_, ok = parseBarkBody([]byte("a b c d"))
	assert.False(t, ok)
	reqs := ParseRequestFile([]byte("; comment\r\nFILE.ONE\r\nFILE.TWO !secret +1700000000\r\n\r\n"))
	assert.Equal(t, []BarkRequest{{Name: "FILE.ONE"}, {Name: "FILE.TWO", Password: "secret", Since: 1700000000}}, reqs)
}

// scriptedPeer is the receiving end of a net.Pipe, driven byte by byte.
type scriptedPeer struct {
	t *testing.T
	p net.Conn
}

func (sp scriptedPeer) read(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(sp.p, b)
	require.NoError(sp.t, err)
	return b
}

func (sp scriptedPeer) write(b ...byte) {
	_, err := sp.p.Write(b)
	require.NoError(sp.t, err)
}

// startSendFiles runs sendFiles for one named file (a Bark answer) after
// a poll that asked for crc, against a scripted receiver.
func startSendFiles(t *testing.T, name string, data []byte, crc bool) (scriptedPeer, chan error) {
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	l := newLine(c, tLogger(t, slog.LevelDebug))
	t.Cleanup(l.close)
	errc := make(chan error, 1)
	go func() {
		src := &sliceSource{files: []*OutFile{{Name: name, Data: data, Done: func(int64, error) {}}}}
		errc <- sendFiles(context.Background(), l, Config{Mode: ModeFTS0001, Program: "t"}, src, crc, true)
	}()
	_ = p.SetDeadline(time.Now().Add(20 * time.Second))
	return scriptedPeer{t: t, p: p}, errc
}

// TestNamedFileNumberedPollSkipsHeader scripts ifcico 3.03's receiver in
// checksum mode: it polled NAK, takes the MODEM7 name, then polls
// "NAK 01 FE" for block 1 — the name stood in for block 0, and a header
// sent now would be dropped as an old block. The sender must send block
// 1 at once, with no header.
func TestNamedFileNumberedPollSkipsHeader(t *testing.T) {
	data := pattern(200, 5)
	sp, errc := startSendFiles(t, "ALLFILES.TXT", data, false)
	// The name: ACK opens it, each character is ACKed, SUB ends it.
	require.Equal(t, []byte{ACK}, sp.read(1))
	cs := SUB
	for {
		b := sp.read(1)[0]
		if b == SUB {
			break
		}
		cs += b
		sp.write(ACK)
	}
	sp.write(cs)
	require.Equal(t, []byte{ACK}, sp.read(1))
	sp.write(NAK, 0x01, 0xFE)
	got := []byte{}
	for blk := 1; blk <= 2; blk++ {
		frame := sp.read(3 + BlockSize + 1)
		require.Equal(t, SOH, frame[0], "a data block, not a Telink header (SYN)")
		require.Equal(t, byte(blk), frame[1])
		payload := frame[3 : 3+BlockSize]
		require.Equal(t, Checksum(payload), frame[3+BlockSize], "checksum mode, as the poll before the name chose")
		got = append(got, payload...)
		sp.write(ACK, byte(blk), ^byte(blk))
	}
	require.Equal(t, []byte{EOT}, sp.read(1))
	sp.write(ACK, 0x03, 0xFC)
	sp.write(NAK) // BS3: the poll for the next file; EOT says there is none.
	require.Equal(t, []byte{EOT}, sp.read(1))
	require.NoError(t, <-errc)
	assert.Equal(t, data, got[:len(data)])
}

// TestCPollSkipsModem7Name: a receiver that polls 'C' at the name slot
// (a SEAlink receiver's BR0; ifcico 3.03 in CRC mode) gets no MODEM7
// name but a SEAlink header carrying the name and the true size
// (FTS-0007 BS1.2).
func TestCPollSkipsModem7Name(t *testing.T) {
	data := pattern(200, 6)
	sp, errc := startSendFiles(t, "ALLFILES.TXT", data, true)
	frame := sp.read(3 + BlockSize + 2)
	require.Equal(t, SOH, frame[0], "a SEAlink header, not a MODEM7 ACK")
	require.Equal(t, byte(0), frame[1])
	h := ParseHeader(HeaderSEAlink, frame[3:3+BlockSize])
	assert.Equal(t, "ALLFILES.TXT", h.Name)
	assert.EqualValues(t, 200, h.Size)
	sp.write(ACK, 0x00, 0xFF)
	for blk := 1; blk <= 2; blk++ {
		frame := sp.read(3 + BlockSize + 2)
		require.Equal(t, SOH, frame[0])
		crc := CRC(frame[3 : 3+BlockSize])
		require.Equal(t, []byte{byte(crc >> 8), byte(crc)}, frame[3+BlockSize:])
		sp.write(ACK, byte(blk), ^byte(blk))
	}
	require.Equal(t, []byte{EOT}, sp.read(1))
	sp.write(ACK, 0x03, 0xFC)
	sp.write(PollCRC)
	require.Equal(t, []byte{EOT}, sp.read(1))
	require.NoError(t, <-errc)
}

// TestBarkStrayACKThenETBEndsRequests replays BinkleyTerm as captured
// on the wire: after our batch-ending EOT it ACKs that EOT just as
// our ENQ for the next request arrives, then answers the ENQ with ETB.
// The ACK must not be read as a request packet.
func TestBarkStrayACKThenETBEndsRequests(t *testing.T) {
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	l := newLine(c, tLogger(t, slog.LevelDebug))
	t.Cleanup(l.close)
	data := pattern(62, 8)
	serve := func(...BarkRequest) ([]*OutFile, bool) {
		return []*OutFile{{Name: "ALLFILES.TXT", Data: data, Done: func(int64, error) {}}}, true
	}
	errc := make(chan error, 1)
	go func() {
		errc <- recvBarkRequests(context.Background(), l, Config{Mode: ModeFTS0001, Program: "t"}, serve)
	}()
	_ = p.SetDeadline(time.Now().Add(20 * time.Second))
	sp := scriptedPeer{t: t, p: p}

	require.Equal(t, []byte{ENQ}, sp.read(1))
	sp.write(BarkRequest{Name: "FILES"}.Marshal()...)
	require.Equal(t, []byte{ACK}, sp.read(1))
	sp.write(PollCRC)
	hdr := sp.read(3 + BlockSize + 2)
	require.Equal(t, []byte{SOH, 0x00, 0xFF}, hdr[:3])
	sp.write(ACK, 0x00, 0xFF)
	blk := sp.read(3 + BlockSize + 2)
	require.Equal(t, []byte{SOH, 0x01, 0xFE}, blk[:3])
	sp.write(ACK, 0x01, 0xFE)
	require.Equal(t, []byte{EOT}, sp.read(1))
	sp.write(ACK, 0x02, 0xFD)
	sp.write(PollCRC) // the batch receiver polls for another file
	require.Equal(t, []byte{EOT}, sp.read(1))
	require.Equal(t, []byte{ENQ}, sp.read(1))
	sp.write(ACK, ETB) // the EOT's ACK, then "no more requests"
	require.NoError(t, <-errc)
}

// TestBarkBareACKThenSilenceEndsRequests replays D'Bridge 4: after its
// file it ACKs our EOT, answers our ENQ with a second bare ACK and waits
// for the hang-up. The session is complete, not a timeout.
func TestBarkBareACKThenSilenceEndsRequests(t *testing.T) {
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	l := newLine(c, tLogger(t, slog.LevelDebug))
	t.Cleanup(l.close)
	data := pattern(62, 8)
	serve := func(...BarkRequest) ([]*OutFile, bool) {
		return []*OutFile{{Name: "ALLFILES.TXT", Data: data, Done: func(int64, error) {}}}, true
	}
	errc := make(chan error, 1)
	go func() {
		errc <- recvBarkRequests(context.Background(), l, Config{Mode: ModeFTS0001, Program: "t"}, serve)
	}()
	_ = p.SetDeadline(time.Now().Add(20 * time.Second))
	sp := scriptedPeer{t: t, p: p}

	require.Equal(t, []byte{ENQ}, sp.read(1))
	sp.write(BarkRequest{Name: "FILES"}.Marshal()...)
	require.Equal(t, []byte{ACK}, sp.read(1))
	sp.write(PollCRC)
	sp.read(3 + BlockSize + 2)
	sp.write(ACK, 0x00, 0xFF)
	sp.read(3 + BlockSize + 2)
	sp.write(ACK, 0x01, 0xFE)
	require.Equal(t, []byte{EOT}, sp.read(1))
	sp.write(ACK, 0x02, 0xFD)
	sp.write(PollCRC)
	require.Equal(t, []byte{EOT}, sp.read(1))
	require.Equal(t, []byte{ENQ}, sp.read(1))
	sp.write(ACK) // the EOT's ACK
	sp.write(ACK) // and the answer to the ENQ; then nothing
	require.NoError(t, <-errc)
}

// startPacketBatch runs the poll wait and sendBatch for one mail packet
// against a scripted receiver whose first poll is poll.
func startPacketBatch(t *testing.T, data []byte, poll ...byte) (scriptedPeer, chan error) {
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	l := newLine(c, tLogger(t, slog.LevelDebug))
	t.Cleanup(l.close)
	errc := make(chan error, 1)
	go func() {
		crc, err := waitPoll(l, 5*time.Second)
		if err != nil {
			errc <- err
			return
		}
		src := &sliceSource{files: []*OutFile{{Name: "0001000a.pkt", Data: data, Done: func(int64, error) {}}}}
		errc <- sendBatch(context.Background(), l, Config{Mode: ModeFTS0001, Program: "t"}, src, crc)
	}()
	_ = p.SetDeadline(time.Now().Add(20 * time.Second))
	sp := scriptedPeer{t: t, p: p}
	sp.write(poll...)
	return sp, errc
}

// TestPacketSlotNumberedPollGetsSEAlinkHeader: D'Bridge 4 answers TSYNC
// with "C 00 FF" and waits for a SEAlink block 0; a Telink one (SYN) is
// ignored, and so is every block after it.
func TestPacketSlotNumberedPollGetsSEAlinkHeader(t *testing.T) {
	sp, errc := startPacketBatch(t, pattern(100, 9), PollCRC, 0x00, 0xFF)
	frame := sp.read(3 + BlockSize + 2)
	require.Equal(t, SOH, frame[0], "a SEAlink header")
	require.Equal(t, []byte{0x00, 0xFF}, frame[1:3])
	sp.write(ACK, 0x00, 0xFF)
	frame = sp.read(3 + BlockSize + 2)
	require.Equal(t, []byte{SOH, 0x01, 0xFE}, frame[:3])
	sp.write(ACK, 0x01, 0xFE)
	require.Equal(t, []byte{EOT}, sp.read(1))
	sp.write(ACK, 0x02, 0xFD)
	sp.write(PollCRC)
	require.Equal(t, []byte{EOT}, sp.read(1))
	require.NoError(t, <-errc)
}

// TestPacketSlotBareCPollKeepsTelinkHeader: the shape every other FTS-0001
// peer in the zone was measured on stays as it was.
func TestPacketSlotBareCPollKeepsTelinkHeader(t *testing.T) {
	sp, errc := startPacketBatch(t, pattern(100, 9), PollCRC)
	require.Equal(t, []byte{SYN}, sp.read(1), "a Telink header")
	sp.p.Close()
	<-errc
}

// TestBarkRepeatedACKCannotHoldTheLine: a caller that answers our ENQ
// with a bare ACK every second restarts the request body but not RB1's
// clock (it used to hold the line indefinitely).
func TestBarkRepeatedACKCannotHoldTheLine(t *testing.T) {
	saved := barkRequestWait
	barkRequestWait = 3 * time.Second
	t.Cleanup(func() { barkRequestWait = saved })
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	l := newLine(c, tLogger(t, slog.LevelDebug))
	t.Cleanup(l.close)
	serve := func(...BarkRequest) ([]*OutFile, bool) { return nil, false }
	errc := make(chan error, 1)
	go func() {
		errc <- recvBarkRequests(context.Background(), l, Config{Mode: ModeFTS0001, Program: "t"}, serve)
	}()
	go func() {
		for i := 0; i < 30; i++ {
			if _, err := p.Write([]byte{ACK}); err != nil {
				return
			}
			time.Sleep(time.Second)
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, p) }()
	select {
	case err := <-errc:
		// Ended at RB1's limit: as "no more requests" (a bare ACK, then
		// nothing in time) or as a timeout — either way the line is free.
		if err != nil {
			assert.ErrorIs(t, err, ErrTimeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("repeated ACKs held the request phase open")
	}
}

// TestParseRequestFileKeepsEveryLine: a cap dropped the tail of our own
// .req while the file was still reported sent.
func TestParseRequestFileKeepsEveryLine(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 65; i++ {
		fmt.Fprintf(&b, "FILE%02d.ZIP\r\n", i)
	}
	reqs := ParseRequestFile([]byte(b.String()))
	require.Len(t, reqs, 65)
	assert.Equal(t, "FILE64.ZIP", reqs[64].Name)
}

// TestRequestFileInTheBatchIsAnsweredInPickup is Fido 12 / FrontDoor
// calling: the request is a WaZOO .REQ FILE in the attached-file batch,
// and the files are expected in the called system's pickup turn.
func TestRequestFileInTheBatchIsAnsweredInPickup(t *testing.T) {
	out := map[string][]byte{"mail.pkt": pattern(100, 1), "00010002.req": []byte("NODELIST.Z99\r\nsecret.zip !open\r\n")}
	csrc := newSource(out, "mail.pkt", "00010002.req")
	csink := newSink()
	asink := newSink()
	ccfg := barkCfg(t, nil)
	ccfg.RequestsAsFiles = true
	var seen []BarkRequest
	acfg := barkCfg(t, catalogue(t, &seen))
	reply := pattern(60, 4)
	acfg.PickupPacket = func() ([]byte, bool) { return reply, true }
	cerr, aerr := runSession2(t, ccfg, acfg, csrc, csink, Nothing{}, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	require.NotEmpty(t, csink.order)
	assert.Equal(t, reply, csink.files[csink.order[0]], "the pickup opens with a real packet, not an EOT")
	assert.Equal(t, []string{"mail.pkt", "00010002.req"}, csrc.done, "the .req went as a file")
	assert.Contains(t, asink.order, "00010002.REQ", "and reached the answerer's sink as one (MODEM7 names are upper case)")
	require.Len(t, seen, 2)
	assert.Equal(t, pattern(700, 11), csink.files["NODELIST.Z99"])
	assert.Equal(t, pattern(300, 12), csink.files["SECRET.ZIP"])
}

// TestRequestFileWithoutServerIsOnlyAFile: no server, no pickup turn —
// the .req is an ordinary received file, as before.
func TestRequestFileWithoutServerIsOnlyAFile(t *testing.T) {
	out := map[string][]byte{"mail.pkt": pattern(100, 1), "00010002.req": []byte("NODELIST.Z99\r\n")}
	ccfg := barkCfg(t, nil)
	ccfg.RequestsAsFiles = true
	csink := newSink()
	asink := newSink()
	cerr, aerr := runSession2(t, ccfg, barkCfg(t, nil), newSource(out, "mail.pkt", "00010002.req"), csink, Nothing{}, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Contains(t, asink.order, "00010002.REQ")
	assert.Empty(t, csink.order)
}

// TestFilesWithoutDoneCallbacks: Done is optional. A whole session —
// packet and attached file out, packet back — runs with no callback on
// any file.
func TestFilesWithoutDoneCallbacks(t *testing.T) {
	plain := func(name string, data []byte) *OutFile {
		return &OutFile{Name: name, ModTime: time.Unix(1_600_000_000, 0), Data: data}
	}
	csrc := &memSource{files: []*OutFile{plain("1a2b3c4d.pkt", pattern(300, 1)), plain("file1.txt", pattern(1000, 2))}}
	asrc := &memSource{files: []*OutFile{plain("deadbeef.pkt", pattern(60, 9))}}
	csink, asink := newSink(), newSink()
	cerr, aerr := runSession(t, ModeFTS0001, csrc, csink, asrc, asink)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Len(t, asink.files, 2)
	assert.Len(t, csink.files, 1)
}
