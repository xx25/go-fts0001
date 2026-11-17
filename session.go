package fts0001

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Mode selects the session shape.
type Mode int

const (
	// ModeFTS0001 is the original session: the caller sends ONE mail
	// packet by XMODEM/Telink without a name, then attached files each
	// behind a MODEM7 filename, then EOT; the called system receives the
	// same way, and the roles swap for pickup (FTS-0001 D, F.3).
	ModeFTS0001 Mode = iota
	// ModeDietIFNA is FTS-0006's variant after a YooHoo handshake: every
	// file (packets included, several allowed) carries its name in a
	// Telink or SEAlink header, there are no MODEM7 names and no Bark,
	// and a system with nothing to send stays quiet — the batch ends by
	// EOT or by silence.
	ModeDietIFNA
)

func (m Mode) String() string {
	if m == ModeDietIFNA {
		return "DietIFNA"
	}
	return "FTS-0001"
}

// OutFile is one file to send.
type OutFile struct {
	Name    string
	ModTime time.Time
	Data    []byte
	// Done reports the outcome: sent is the byte count acknowledged (the
	// whole file on success), err nil on success. Optional.
	Done func(sent int64, err error)
}

// done reports the file's outcome to its Done callback, if it has one.
func (f *OutFile) done(sent int64, err error) {
	if f.Done != nil {
		f.Done(sent, err)
	}
}

// Source yields the files to send, in order; nil ends the batch.
type Source interface {
	Next() *OutFile
}

// Sink receives files. Open is called once the file is known (size 0 =
// unknown, zero mtime = none); Done after its EOT (err nil) or failure.
type Sink interface {
	Open(name string, size int64, mtime time.Time) (io.WriteCloser, error)
	Done(name string, bytes int64, err error)
}

// Config parameterises a session.
type Config struct {
	Mode Mode
	// Program is our name in header blocks (up to 15 bytes).
	Program string
	// PreferCRC polls with 'C' when we receive (default true).
	PreferCRC *bool
	// PacketName names the FTS-0001 mail packet we receive (the sender
	// gives it none); "" generates "<hex-time>.pkt".
	PacketName string
	// PickupWait is how long the FTS-0001 caller waits for the called
	// system's TSYNC after its own batch (S8/R2); 0 = 30 s. A called
	// system with nothing hangs up instead (R7.2), so carrier loss
	// usually ends the wait early. FTS-0008 extends the same wait to
	// the request phases (45 s).
	PickupWait time.Duration
	// Serve answers the peer's Bark file requests (FTS-0008) in an
	// FTS-0001 session. nil refuses them with CAN. Requests of OUR own
	// are the .req files the Source yields; in FTS-0001 mode they go out
	// as Bark packets instead of as files.
	Serve BarkServer
	// RequestsAsFiles sends our .req files in the attached-file batch,
	// the WaZOO way Fido 12 and FrontDoor request over FTS-0001, instead
	// of as Bark packets: for a called system that never invites Bark.
	RequestsAsFiles bool
	// PickupPacket builds the mail packet for a pickup turn that answers
	// a caller's request file when we hold no packet for it (FrontDoor
	// refuses an EOT in the packet slot). nil: the EOT.
	PickupPacket func() ([]byte, bool)
	Logger       *slog.Logger
}

func (c *Config) pickupWait() time.Duration {
	if c.PickupWait > 0 {
		return c.PickupWait
	}
	return 30 * time.Second
}

func (c *Config) preferCRC() bool { return c.PreferCRC == nil || *c.PreferCRC }

// Originate runs the calling side after the TSYNC synchronisation: the
// connection must deliver the receiver's first poll (NAK or 'C') as its
// next byte — the handshake that read it replays it.
//
// FTS-0001: send the batch, then offer pickup: a TSYNC from the called
// system opens its batch to us; silence for 30 s, or CAN, ends the
// session. DietIFNA: send the batch, then receive the peer's.
func Originate(ctx context.Context, rw io.ReadWriter, cfg Config, src Source, sink Sink) error {
	l := newLine(rw, cfg.Logger)
	defer l.close()
	crc, err := waitPoll(l, 60*time.Second)
	if err != nil {
		return fmt.Errorf("waiting for the receiver's first poll: %w", err)
	}
	if cfg.Mode == ModeDietIFNA {
		if err := sendBatch(ctx, l, cfg, src, crc); err != nil {
			return err
		}
		return recvBatch(ctx, l, cfg, sink)
	}
	// FTS-0001: our requests travel as Bark packets, not as files.
	files, reqs, reqsDone := cfg.splitRequests(src)
	if err := sendBatch(ctx, l, cfg, files, crc); err != nil {
		reqsDone(err)
		return err
	}
	// FTS-0008 S5: the called system drives what follows — TSYNC for its
	// mail, SYN to ask leave for its requests, ENQ to invite ours.
	requested := len(reqs) == 0
	defer func() {
		if !requested {
			reqsDone(fmt.Errorf("%w (the called system)", ErrBarkNotInvited))
		}
	}()
	for {
		b, err := l.getc(cfg.pickupWait())
		if err != nil {
			if err == ErrTimeout {
				l.dbg("no pickup offered in %v; session complete", cfg.pickupWait())
				return nil
			}
			if errors.Is(err, ErrCarrierLost) {
				l.dbg("peer hung up after our batch (FTS-0001 R7.2); session complete")
				return nil
			}
			return err
		}
		switch b {
		case TSync:
			if err := recvBatch(ctx, l, cfg, sink); err != nil {
				return err
			}
		case SYN:
			// RB0: the called system wants to request files from us.
			if err := recvBarkRequests(ctx, l, cfg, cfg.Serve); err != nil {
				return err
			}
		case ENQ:
			// SB0: it invites our requests.
			if requested {
				if err := l.putc(ETB); err != nil {
					return err
				}
				continue
			}
			l.dbg("bark: sending %d request(s): %s", len(reqs), requestsSummary(reqs))
			err := sendBarkRequests(ctx, l, cfg, reqs, sink)
			requested = true
			reqsDone(err)
			if err != nil {
				return err
			}
		case NAK, PollCRC:
			// The peer still expects a file from us: there is none.
			if err := l.putc(EOT); err != nil {
				return err
			}
		case CAN:
			return nil
		case SUB:
		default:
			l.dbg("debris 0x%02x after our batch", b)
		}
	}
}

// Answer runs the called side after the caller's TSYNC (consumed by the
// handshake that recognised it) or after a YooHoo handshake that chose
// DietIFNA. We receive first, then send whatever src holds.
//
// FTS-0001: with files to send we take the sender role — TSYNC, the
// caller's poll, our batch (R7.1); with none we are done (R7.2).
// DietIFNA: we always wait for the caller's poll and answer it with our
// batch, or EOT alone when there is nothing (what ifcico sends; MacWoof
// logs "No Mail Packet" at once instead of waiting a timeout out).
func Answer(ctx context.Context, rw io.ReadWriter, cfg Config, src Source, sink Sink) error {
	l := newLine(rw, cfg.Logger)
	defer l.close()
	// A WaZOO .REQ in an FTS-0001 caller's batch (reqfile.go) is answered
	// in our pickup turn, after whatever we already hold for it.
	var tee *reqTee
	if cfg.Mode == ModeFTS0001 && cfg.Serve != nil {
		tee = &reqTee{Sink: sink}
		sink = tee
	}
	if err := recvBatch(ctx, l, cfg, sink); err != nil {
		return err
	}
	if tee != nil && len(tee.got) > 0 {
		if served := serveRequestFiles(l, tee.got, cfg.Serve); len(served) > 0 {
			l.dbg("req file: %d file(s) for the caller's request file, in the pickup batch", len(served))
			src = withPickupPacket(l, cfg, &thenSource{src: src, more: served})
		}
	}
	ps := &peekSource{src: src}
	if cfg.Mode == ModeDietIFNA {
		// FTS-0006 admits that most DietIFNA implementations are "the mere
		// exchange of packets, followed by straight FTS-0001/0007 code":
		// MacWoof, its batch sent, waits in FTS-0001's S8/R2 for OUR TSYNC
		// before it polls for mail (measured: it answered our poll with
		// EOT, then sat 30 s and hung up with no "No Mail Packet"). A
		// strictly DietIFNA caller (ifcico) reads a TSYNC at its poll as
		// "poll again" — harmless. So: TSYNC, then its poll, then our batch
		// (EOT alone when there is nothing).
		for try := 0; try < 4; try++ {
			if err := l.putc(TSync); err != nil {
				return err
			}
			crc, err := waitPoll(l, 15*time.Second)
			if err != nil {
				if err == ErrTimeout {
					continue
				}
				return err
			}
			return sendBatch(ctx, l, cfg, ps, crc)
		}
		l.dbg("caller never polled for our batch; done")
		return nil
	}
	// FTS-0001: our requests travel as Bark packets, not as files.
	files, reqs, reqsDone := cfg.splitRequests(ps)
	fs := &peekSource{src: files}
	if fs.has() {
		sent := false
		for try := 0; try < 6 && !sent; try++ {
			if err := l.putc(TSync); err != nil {
				reqsDone(err)
				return err
			}
			b, err := l.getc(15 * time.Second)
			if err != nil {
				if err == ErrTimeout {
					continue
				}
				reqsDone(err)
				return err
			}
			switch b {
			case NAK, PollCRC:
				if err := sendBatch(ctx, l, cfg, fs, b == PollCRC); err != nil {
					reqsDone(err)
					return err
				}
				sent = true
			case EOT:
				// The caller's own batch end still in flight: acknowledge, retry.
				_ = l.putc(ACK)
			case CAN:
				l.dbg("caller refused pickup")
				sent = true
			default:
				l.dbg("debris 0x%02x while offering pickup", b)
			}
		}
		if !sent {
			err := fmt.Errorf("%w: caller never polled for pickup", ErrTimeout)
			reqsDone(err)
			return err
		}
	}
	// FTS-0008 R6/R7: our requests — SYN, the caller's ENQ, the packets.
	if len(reqs) > 0 {
		err := askAndSendRequests(ctx, l, cfg, reqs, sink)
		reqsDone(err)
		// R7.1/R7.7: a caller that refuses or ignores our requests still
		// gets R8 — its own requests are not lost with ours.
		if err != nil && !errors.Is(err, ErrBarkNotInvited) {
			return err
		}
	}
	// R8: the caller's requests, or a CAN when we serve none.
	if cfg.Serve == nil && len(reqs) == 0 && !fs.has() {
		// Nothing offered and nothing to serve: the classic R7.2 hangup,
		// without a CAN a pre-Bark caller would not expect.
		l.dbg("nothing to send: session complete")
		return nil
	}
	return recvBarkRequests(ctx, l, cfg, cfg.Serve)
}

// askAndSendRequests runs FTS-0008 R6/R7 for the called system: SYN
// until the caller's ENQ (resent every 5 s, 45 s in all), then the
// requests. CAN or a poll from the caller means it has no Bark.
func askAndSendRequests(ctx context.Context, l *line, cfg Config, reqs []BarkRequest, sink Sink) error {
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if err := l.putc(SYN); err != nil {
			return err
		}
		b, err := l.getc(5 * time.Second)
		if err != nil {
			if err == ErrTimeout {
				continue
			}
			return err
		}
		switch b {
		case ENQ:
			l.dbg("bark: sending %d request(s): %s", len(reqs), requestsSummary(reqs))
			return sendBarkRequests(ctx, l, cfg, reqs, sink)
		case CAN:
			return fmt.Errorf("%w (the caller refused them)", ErrBarkNotInvited)
		case NAK, PollCRC:
			if err := l.putc(EOT); err != nil {
				return err
			}
		case SUB:
		default:
			l.dbg("bark: debris 0x%02x asking to request", b)
		}
	}
	return fmt.Errorf("%w (the caller, in 45 s)", ErrBarkNotInvited)
}

// waitPoll reads the receiver's poll for a first block: NAK (checksum)
// or 'C' (CRC). TSYNC, EOT and debris are ignored.
func waitPoll(l *line, timeout time.Duration) (crc bool, err error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, ErrTimeout
		}
		b, err := l.getc(remaining)
		if err != nil {
			return false, err
		}
		switch b {
		case NAK:
			return false, nil
		case PollCRC:
			return true, nil
		case CAN:
			if l.sawCAN() {
				return false, ErrCancelled
			}
		default:
			l.dbg("debris 0x%02x waiting for a poll", b)
		}
	}
}

// waitPollAfterName reads the receiver's poll after a MODEM7 name. A
// bare NAK or 'C' asks for block 0 (the header) and names the check mode.
// A NUMBERED poll for block 1 — "NAK 01 FE", ifcico 3.03 and its
// descendants — says the name stood in for block 0: the receiver has set
// its acknowledged block to 0 and drops a header sent now as an old
// block, and its NAK is SEAlink's negative acknowledgement, not a mode
// choice (it polls that way in CRC mode too). Then the file goes without
// a header, in the mode the poll BEFORE the name chose (crc). Measured
// 2026-10-19: answering it with a Telink header cost 3 × 15 s of
// "refusals" and then checksum blocks to a CRC receiver, which never
// lined up (ifcico answering a Bark request). The one-second look for the
// suffix is paid once per named file.
func waitPollAfterName(l *line, timeout time.Duration, crc bool) (bool, bool, error) {
	c, err := waitPoll(l, timeout)
	if err != nil {
		return crc, false, err
	}
	if n, ok := l.readNumberedAny(); ok {
		if n == 1 {
			l.dbg("modem7: numbered poll for block 1: no header, crc=%v", crc)
			return crc, true, nil
		}
		l.unread(n, ^n)
	}
	return c, false, nil
}

// sendBatch sends every file from src (BS0-BS3). crc is what the
// receiver's current poll asked for.
//
// FTS-0001's first slot is the MAIL PACKET, sent nameless (FR3 on the
// other side "Receiving Mail Packet"): the batch is reordered so a .pkt
// goes first, and when the batch holds none the slot is answered with
// EOT alone — an empty packet, which the receiver takes as "no file"
// (XR1.3) before it polls for the attached files (FR5). Fido 12 sends
// exactly that when it has nothing: "FS5: Packet sent (0 bytes)".
func sendBatch(ctx context.Context, l *line, cfg Config, src Source, crc bool) error {
	if cfg.Mode == ModeFTS0001 {
		src = packetFirst(src)
	}
	return sendFiles(ctx, l, cfg, src, crc, false)
}

// sendFiles is the batch proper. allNamed (a Bark answer) gives every
// file a MODEM7 name; otherwise the first FTS-0001 slot is the nameless
// mail packet (EOT when there is none).
func sendFiles(ctx context.Context, l *line, cfg Config, src Source, crc bool, allNamed bool) error {
	sent := 0
	for i := 0; ; i++ {
		f := src.Next()
		if f == nil {
			break
		}
		if i == 0 && allNamed {
			i++ // the requester already polled; the name goes first
		}
		if i == 0 && cfg.Mode == ModeFTS0001 && !isPacketName(f.Name) {
			// No packet in this batch: an empty one, then the files.
			l.dbg("no mail packet to send; EOT in the packet slot")
			if err := l.putc(EOT); err != nil {
				f.done(0, err)
				return err
			}
			i++
		}
		sent++
		noHeader, nameSkipped := false, false
		// The packet slot's header is Telink (what Fido 12, MacWoof,
		// ifcico, mbcico and BinkleyTerm were measured on) unless the
		// receiver's poll was NUMBERED — "C 00 FF", a SEAlink receiver
		// asking for block 0. D'Bridge 4 ignores a Telink block there
		// and every block after it (measured 2026-10-19).
		seaPacket := i == 0 && cfg.Mode == ModeFTS0001 && crc && l.numberedPoll(0)
		if i > 0 {
			// The receiver polls for the next item: a MODEM7 name in
			// FTS-0001 (BR0/MR0), a header block in DietIFNA (XR0). A Bark
			// answer's first name follows the poll the caller just read.
			if !(allNamed && sent == 1) {
				c, err := waitPoll(l, 60*time.Second)
				if err != nil {
					f.done(0, err)
					return fmt.Errorf("waiting for the poll before %q: %w", f.Name, err)
				}
				crc = c
			}
			if cfg.Mode == ModeFTS0001 {
				// FTS-0007 BS1: a NAK asks for the MODEM7 name (then a
				// Telink header, XS0T); a 'C' is a SEAlink receiver's BR0
				// poll — no name, a SEAlink header (XS0, which falls back
				// to Telink after three refusals). FTS-0001's MS0.3 is the
				// same rule seen from a strict sender. ifcico 3.03 polls
				// 'C' here: after a name it drops any header as an old
				// block 0 and stores the file padded and undated, and it
				// reads a blank-filled 16-byte Telink name unterminated
				// (measured 2026-10-19, Bark answers to ifcico: 128 bytes
				// for 62, then "ALLFILES.TXT    Dec 31 23:59:59").
				skipped := crc
				if skipped {
					nameSkipped = true
					l.dbg("modem7: 'C' poll, no name (FTS-0007 BS1.2); a SEAlink header carries %q", f.Name)
				} else {
					var err error
					skipped, err = l.sendName(f.Name)
					if err != nil {
						f.done(0, err)
						return fmt.Errorf("modem7 name %q: %w", f.Name, err)
					}
				}
				if !skipped {
					// The name is in; the receiver now polls for block 0 —
					// or, numbered, for block 1 (see waitPollAfterName).
					c, block1, err := waitPollAfterName(l, 60*time.Second, crc)
					if err != nil {
						f.done(0, err)
						return fmt.Errorf("waiting for the poll after the name %q: %w", f.Name, err)
					}
					crc, noHeader = c, block1
				}
			}
		}
		header := HeaderTelink
		if crc && (cfg.Mode == ModeDietIFNA || nameSkipped || seaPacket) {
			header = HeaderSEAlink
		}
		if noHeader {
			header = HeaderNone
		}
		err := l.sendFile(ctx, f.Name, f.ModTime, f.Data, sendOptions{Header: header, CRC: crc, Program: cfg.Program}, nil)
		if err != nil {
			f.done(0, err)
			return fmt.Errorf("sending %q: %w", f.Name, err)
		}
		f.done(int64(len(f.Data)), nil)
	}
	// BS3: the receiver polls for the next file; EOT says there is none
	// (after 10 s we send it anyway). An EMPTY batch answers the poll the
	// caller already read for us.
	if sent > 0 {
		if _, err := waitPoll(l, 10*time.Second); err != nil && err != ErrTimeout {
			return err
		}
	}
	return l.putc(EOT)
}

// recvBatch receives files until the sender's EOT (or, in DietIFNA,
// silence). In FTS-0001 the first file is the mail packet, nameless on
// the wire; the attached files that follow carry MODEM7 names.
func recvBatch(ctx context.Context, l *line, cfg Config, sink Sink) error {
	for i := 0; ; i++ {
		opts := recvOptions{PreferCRC: cfg.preferCRC(), Program: cfg.Program}
		switch cfg.Mode {
		case ModeFTS0001:
			if i == 0 {
				opts.Name = cfg.PacketName
				if opts.Name == "" {
					opts.Name = fmt.Sprintf("%08x.pkt", uint32(time.Now().Unix()))
				}
			} else {
				opts.Modem7 = true
			}
		case ModeDietIFNA:
			opts.SilenceEndsBatch = true
		}
		var cur string
		open := func(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
			cur = name
			return sink.Open(name, size, mtime)
		}
		res, err := l.recvFile(ctx, opts, open, nil)
		if err != nil {
			if errors.Is(err, ErrNoMoreFiles) {
				if cfg.Mode == ModeFTS0001 && i == 0 {
					// XR1.3: an EOT in the packet slot is an EMPTY mail packet
					// ("report no file"); the attached-file batch follows (FR5).
					l.dbg("empty mail packet (EOT); receiving attached files")
					continue
				}
				return nil
			}
			if cur != "" {
				sink.Done(cur, 0, err)
			}
			return fmt.Errorf("receiving file %d: %w", i+1, err)
		}
		sink.Done(res.Name, res.Bytes, nil)
	}
}

// isPacketName reports a FidoNet mail packet by its extension.
func isPacketName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, ".pkt")
}

// packetFirst reorders a Source so the first .pkt comes first. The
// files are already in memory (Data), so reading the source ahead costs
// nothing more.
func packetFirst(src Source) Source {
	var all []*OutFile
	for f := src.Next(); f != nil; f = src.Next() {
		all = append(all, f)
	}
	for i, f := range all {
		if isPacketName(f.Name) {
			if i > 0 {
				all = append([]*OutFile{f}, append(all[:i:i], all[i+1:]...)...)
			}
			break
		}
	}
	return &sliceSource{files: all}
}

type sliceSource struct {
	files []*OutFile
	i     int
}

func (s *sliceSource) Next() *OutFile {
	if s.i >= len(s.files) {
		return nil
	}
	f := s.files[s.i]
	s.i++
	return f
}

// peekSource lets Answer ask "anything to send?" without losing the
// first file.
type peekSource struct {
	src    Source
	peeked *OutFile
	done   bool
}

func (p *peekSource) has() bool {
	if p.peeked == nil && !p.done {
		p.peeked = p.src.Next()
		p.done = p.peeked == nil
	}
	return p.peeked != nil
}

func (p *peekSource) Next() *OutFile {
	if p.peeked != nil {
		f := p.peeked
		p.peeked = nil
		return f
	}
	if p.done {
		return nil
	}
	f := p.src.Next()
	p.done = f == nil
	return f
}

// Nothing is a Source with no files.
type Nothing struct{}

// Next returns nil.
func (Nothing) Next() *OutFile { return nil }

// Discard is a Sink that drops every file.
type Discard struct{}

// Open returns a writer to nowhere.
func (Discard) Open(string, int64, time.Time) (io.WriteCloser, error) {
	return nopCloser{io.Discard}, nil
}

// Done ignores the outcome.
func (Discard) Done(string, int64, error) {}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
