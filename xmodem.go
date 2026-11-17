package fts0001

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrNoMoreFiles marks a bare EOT where a header was expected: the
// sender's batch is over. The session functions consume it; it is
// exported for errors.Is on a wrapped session error.
var ErrNoMoreFiles = errors.New("fts0001: no more files")

// MaxRecvBytes bounds one received file: an anonymous FTS-0001 caller
// must not stream a headerless file for ever. 64 MiB is far above
// anything XMODEM ever carried in one call.
const MaxRecvBytes = 64 << 20

// noProgressLimit ends a receive or send that keeps the line busy with
// polls, TSYNCs or debris but never completes a block.
const noProgressLimit = 2 * time.Minute

var errNoMoreFiles = ErrNoMoreFiles

// sendOptions parameterise sendFile.
type sendOptions struct {
	// Header is the block-0 header to lead with. HeaderNone sends a bare
	// XMODEM stream (the receiver names the file itself).
	Header HeaderKind
	// CRC is what the receiver's poll asked for ('C'); the caller read
	// that poll before calling sendFile.
	CRC bool
	// Program is the sending program's name for the header.
	Program string
	// Window is the SEAlink window once numbered ACKs prove the receiver
	// speaks it; 0 = 6, the standard.
	Window int
	// Timeout is the per-response wait; 0 = 20 s.
	Timeout time.Duration
}

// progressFunc reports bytes acknowledged so far.
type progressFunc func(bytes int64)

// sendFile sends one file: the header block (if any), the 128-byte data
// blocks, EOT. data is the whole file: XMODEM resends by block number
// and SEAlink's RESYNC may move the cursor back arbitrarily, so the
// sender needs random access.
//
// Protocol notes (FTS-0001 XS0-XS4, FTS-0007 AC0-AC10):
//   - The receiver's first poll decided CRC vs checksum (opts.CRC). A
//     NAK or 'C' arriving before any data block is acknowledged may
//     still switch it (XS1).
//   - The header block is offered up to three times; a receiver that
//     will not take it gets the data without one.
//   - Numbered acknowledgements (ACK n ~n) switch the sender to SEAlink:
//     a window of opts.Window blocks in flight. A plain ACK keeps the
//     window at one.
//   - A RESYNC packet (SYN digits ETX crc) moves the cursor.
func (l *line) sendFile(ctx context.Context, name string, mtime time.Time, data []byte, opts sendOptions, progress progressFunc) error {
	if opts.Window <= 0 {
		opts.Window = 6
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	size := int64(len(data))
	blocks := int((size + BlockSize - 1) / BlockSize)
	crc := opts.CRC
	l.dbg("send %q %d bytes (%d blocks) header=%s crc=%v", name, size, blocks, opts.Header, crc)

	hdr := &FileHeader{Name: name, Size: size, ModTime: mtime, Program: opts.Program, CRC: true, Resync: true}
	blockData := func(n int) []byte {
		start := int64(n-1) * BlockSize
		end := start + BlockSize
		if end > size {
			end = size
		}
		b := make([]byte, BlockSize)
		for i := range b {
			b[i] = SUB
		}
		copy(b, data[start:end])
		return b
	}
	// sendBlock writes block n (0 = header of kind).
	sendBlock := func(n int, kind HeaderKind) error {
		var lead byte = SOH
		var payload []byte
		useCRC := crc
		switch {
		case n == 0 && kind == HeaderTelink:
			lead, payload, useCRC = SYN, hdr.MarshalTelink(), false // Telink is always checksum
		case n == 0 && kind == HeaderSEAlink:
			payload = hdr.MarshalSEAlink()
		default:
			payload = blockData(n)
		}
		frame := make([]byte, 0, 3+BlockSize+2)
		frame = append(frame, lead, byte(n), ^byte(n))
		frame = append(frame, payload...)
		if useCRC {
			c := CRC(payload)
			frame = append(frame, byte(c>>8), byte(c))
		} else {
			frame = append(frame, Checksum(payload))
		}
		return l.write(frame)
	}

	// Stage A: the header block.
	kind := opts.Header
	headerDone := kind == HeaderNone
	headerAcked := false // an ACKed header block already showed the receiver's style
	seaMode := false
	errorsN := 0
	resumeAt := 1 // first data block to send (a RESYNC to the header moves it)
	for tries := 0; !headerDone; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sendBlock(0, kind); err != nil {
			return err
		}
		tries++
		b, err := l.getc(opts.Timeout)
		if err != nil {
			if err == ErrTimeout {
				if tries >= 3 {
					l.dbg("header %s unanswered, sending data without it", kind)
					headerDone = true
				}
				continue
			}
			return err
		}
		switch b {
		case ACK:
			// The ACK for block 0 settles the receiver's style: numbered
			// (SEAlink) or bare.
			seaMode = l.readNumbered(0)
			headerDone, headerAcked = true, true
		case NAK, PollCRC:
			if b == PollCRC {
				crc = true
			} else if kind != HeaderTelink {
				crc = false
			}
			if tries >= 3 {
				if kind == HeaderSEAlink {
					l.dbg("SEAlink header refused, trying a Telink header")
					kind, tries = HeaderTelink, 0
				} else {
					l.dbg("header refused three times, sending data without it")
					headerDone = true
				}
			}
		case SYN:
			// A RESYNC answering the header (the receiver resumes a partial
			// file): honour it and skip to the data stage from that block.
			if target, ok := l.readResync(); ok && target >= 1 && target <= blocks+1 {
				seaMode, headerDone, headerAcked = true, true, true
				resumeAt = target
				l.dbg("RESYNC to block %d in answer to the header", target)
				if err := l.putc(ACK); err != nil {
					return err
				}
			} else {
				_ = l.putc(NAK)
			}
		case CAN:
			if l.sawCAN() {
				return ErrCancelled
			}
		default:
			l.dbg("debris 0x%02x while sending header", b)
		}
	}

	// Stage B: data blocks and EOT.
	ackd, sendBlk := resumeAt-1, resumeAt
	window := 1
	if seaMode {
		window = opts.Window
	}
	eotSent := false
	// probed: whether the receiver's acknowledgement style is known. The
	// first ACK is examined for a SEAlink "n ~n" suffix (one second); a
	// bare one settles the question — probing every ACK would cost a
	// second per block, which is most of an XMODEM transfer's time.
	probed := seaMode || headerAcked
	numberedNext := func() (byte, bool) {
		if seaMode {
			return l.readNumberedAny()
		}
		if probed {
			return 0, false
		}
		probed = true
		return l.readNumberedAny()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if errorsN > 10 {
			return fmt.Errorf("%w: sending %q", ErrTooMany, name)
		}
		// Fill the window.
		for sendBlk <= blocks && sendBlk-ackd <= window {
			if err := sendBlock(sendBlk, HeaderNone); err != nil {
				return err
			}
			sendBlk++
		}
		if ackd >= blocks && !eotSent {
			if err := l.putc(EOT); err != nil {
				return err
			}
			eotSent = true
		}
		// Wait for the receiver.
		b, err := l.getc(opts.Timeout)
		if err != nil {
			if err == ErrTimeout {
				errorsN++
				l.dbg("timeout waiting for ACK (ackd %d, sent through %d)", ackd, sendBlk-1)
				sendBlk = ackd + 1
				eotSent = false
				continue
			}
			return err
		}
		switch b {
		case ACK:
			if eotSent {
				if seaMode {
					// FTS-0007 XS3: the EOT's acknowledgement names the block
					// after the last one; a numbered ACK of an earlier block is
					// a late one for data, not for the EOT.
					n, numbered := l.readNumberedAny()
					if numbered && int(n) != (blocks+1)&0xFF && int(n) != blocks&0xFF {
						l.dbg("late numbered ACK %d after EOT, still waiting", n)
						continue
					}
				}
				if progress != nil {
					progress(size)
				}
				return nil
			}
			n, numbered := numberedNext()
			if numbered {
				if !seaMode {
					seaMode = true
					window = opts.Window
					l.dbg("numbered ACK: SEAlink window %d", window)
				}
				// FTS-0007 AC3 note 1, tightened: a block can only be acknowledged
				// once it has been SENT (sendBlk is the next unsent one).
				arblk := sendBlk - int((sendBlk-int(n))&0xFF)
				if arblk >= 0 && arblk < sendBlk && arblk > sendBlk-128 && arblk > ackd {
					ackd = arblk
				}
			} else {
				ackd++
			}
			errorsN = 0
			if progress != nil {
				p := int64(ackd) * BlockSize
				if p > size {
					p = size
				}
				progress(p)
			}
		case NAK, PollCRC:
			errorsN++
			if ackd == 0 && !headerAcked {
				// XS1: the receiver is (re)choosing the check mode. After an
				// ACKed header the mode is settled; a NAK here is a bad
				// block 1 (the receiver re-polls with 'C' in CRC mode, SN1).
				crc = b == PollCRC
			}
			if eotSent {
				eotSent = false // resend EOT
				continue
			}
			n, numbered := numberedNext()
			if numbered {
				arblk := sendBlk - int((sendBlk-int(n))&0xFF)
				if arblk > ackd && arblk <= sendBlk {
					ackd = arblk - 1
				}
			}
			sendBlk = ackd + 1
			l.dbg("NAK: resending from block %d", sendBlk)
		case SYN:
			// RESYNC: SYN digits ETX crc-lo crc-hi.
			target, ok := l.readResync()
			if !ok || target < 1 || target > blocks+1 {
				_ = l.putc(NAK)
				errorsN++
				continue
			}
			seaMode, window = true, opts.Window
			sendBlk, ackd = target, target-1
			eotSent = false
			l.dbg("RESYNC to block %d", target)
			if err := l.putc(ACK); err != nil {
				return err
			}
		case CAN:
			if l.sawCAN() {
				return ErrCancelled
			}
		default:
			l.dbg("debris 0x%02x while sending", b)
		}
	}
}

// readNumbered reads the "n ~n" that may follow an ACK/NAK and reports
// whether it was there and named block n (8-bit).
func (l *line) readNumbered(want int) bool {
	n, ok := l.readNumberedAny()
	return ok && int(n) == want&0xFF
}

// readNumberedAny reads a numbered-ACK suffix if one follows at once.
func (l *line) readNumberedAny() (byte, bool) {
	if !l.waitPending(time.Second) {
		return 0, false
	}
	n, err := l.getc(time.Second)
	if err != nil {
		return 0, false
	}
	if !l.waitPending(time.Second) {
		l.unread(n)
		return 0, false
	}
	m, err := l.getc(time.Second)
	if err != nil {
		l.unread(n)
		return 0, false
	}
	if n != ^m {
		l.unread(n, m)
		return 0, false
	}
	return n, true
}

// numberedPoll consumes a poll's "n ~n" suffix when it is already on
// the line (SEAlink receivers number even the first poll: D'Bridge 4
// answers TSYNC with 'C' 00 FF). Anything else is left unread.
func (l *line) numberedPoll(want byte) bool {
	if !l.waitPending(100 * time.Millisecond) {
		return false
	}
	n, err := l.getc(100 * time.Millisecond)
	if err != nil {
		return false
	}
	m, err := l.getc(100 * time.Millisecond)
	if err != nil {
		l.unread(n)
		return false
	}
	if n != want || m != ^want {
		l.unread(n, m)
		return false
	}
	return true
}

// waitPending waits up to d for input to be available.
func (l *line) waitPending(d time.Duration) bool {
	if l.pending() {
		return true
	}
	return l.fill(d) == nil
}

// unread pushes bytes back to the front of the buffer.
func (l *line) unread(bs ...byte) {
	l.buf = append(append([]byte(nil), bs...), l.buf...)
}

// sawCAN reports a second CAN within a second: the peer means it.
func (l *line) sawCAN() bool {
	b, err := l.getc(time.Second)
	return err == nil && b == CAN
}

// readResync reads a RESYNC packet body after its SYN.
func (l *line) readResync() (int, bool) {
	var digits []byte
	for {
		b, err := l.getc(5 * time.Second)
		if err != nil {
			return 0, false
		}
		if b == ETX {
			break
		}
		if b < '0' || b > '9' || len(digits) > 10 {
			return 0, false
		}
		digits = append(digits, b)
	}
	lo, err := l.getc(2 * time.Second)
	if err != nil {
		return 0, false
	}
	hi, err := l.getc(2 * time.Second)
	if err != nil {
		return 0, false
	}
	if CRC(digits) != uint16(hi)<<8|uint16(lo) {
		return 0, false
	}
	n, err := strconv.Atoi(string(digits))
	return n, err == nil
}

// recvOptions parameterise recvFile.
type recvOptions struct {
	// PreferCRC polls with 'C' first (then NAK after four unanswered polls).
	PreferCRC bool
	// Modem7 lets an ACK where a header is expected open a MODEM7
	// filename exchange (an FTS-0001 attached-file batch).
	Modem7 bool
	// Name is the name to store a file under when the sender gives none:
	// the FTS-0001 mail packet. Takes precedence over a header's name.
	Name string
	// SilenceEndsBatch treats three unanswered polls as "no more files"
	// (DietIFNA: "when there is nothing to send, a system should remain
	// quiet"). Off, the poll runs the FTS-0001 ten tries / one minute.
	SilenceEndsBatch bool
	// Program is our name, unused on receive but kept for symmetry.
	Program string
}

// recvResult describes one received file.
type recvResult struct {
	Name   string
	Header *FileHeader // nil for a bare XMODEM stream
	Bytes  int64
	// Named reports the name came from a MODEM7 exchange or a header,
	// not from recvOptions.Name or a generated fallback.
	Named bool
}

// openFunc is called once the file is known (name, size when the header
// gave one, else 0; modification time or zero) and returns its sink.
type openFunc func(name string, size int64, mtime time.Time) (io.WriteCloser, error)

// recvFile receives one file: the poll, the header or first block, the
// data, EOT. ErrNoMoreFiles reports a bare EOT at the poll — the end of
// the sender's batch. On success the writer has been closed.
func (l *line) recvFile(ctx context.Context, opts recvOptions, open openFunc, progress progressFunc) (*recvResult, error) {
	crc := opts.PreferCRC
	polls := 0
	name := opts.Name
	var hdr *FileHeader
	seaMode := false
	ackd := -1 // last block acknowledged; -1 = nothing yet
	expected := 1
	var w io.WriteCloser
	var written int64
	var pending []byte // the last block, held back so SUB padding can be trimmed at EOT
	res := &recvResult{}
	eotNAKed := false
	errorsN := 0
	namePending := false // a MODEM7 name was taken; the next poll is for its data

	closeW := func(err error) {
		if w != nil {
			_ = w.Close()
			w = nil
		}
		_ = err
	}
	lastProgress := time.Now()
	ack := func(n int) error {
		if seaMode {
			return l.write([]byte{ACK, byte(n), ^byte(n)})
		}
		return l.putc(ACK)
	}
	// nak follows FTS-0007 SN1: while no data block has been taken yet
	// and we want CRC, the negative acknowledgement is 'C', so the sender
	// does not read a bare NAK as a switch to checksum (XS1). Later blocks
	// are NAKed with NAK, which every XMODEM sender resends on.
	nak := func(n int) error {
		verb := NAK
		if crc && ackd <= 0 {
			verb = PollCRC
		}
		if seaMode {
			return l.write([]byte{verb, byte(n), ^byte(n)})
		}
		return l.putc(verb)
	}
	flushPending := func(final bool) error {
		if pending == nil {
			return nil
		}
		b := pending
		pending = nil
		if hdr != nil && hdr.Size > 0 {
			// Truncate to the announced size.
			remain := hdr.Size - written
			if remain < int64(len(b)) {
				if remain < 0 {
					remain = 0
				}
				b = b[:remain]
			}
		} else if final {
			b = bytes.TrimRight(b, string(rune(SUB)))
		}
		if len(b) == 0 {
			return nil
		}
		n, err := w.Write(b)
		written += int64(n)
		if progress != nil {
			progress(written)
		}
		return err
	}
	openFile := func() error {
		if w != nil {
			return nil
		}
		if name == "" {
			if hdr != nil && hdr.Name != "" {
				name, res.Named = hdr.Name, true
			} else {
				name = fmt.Sprintf("%08x.xm", uint32(time.Now().Unix()))
			}
		}
		var size int64
		var mtime time.Time
		if hdr != nil {
			size, mtime = hdr.Size, hdr.ModTime
		}
		ww, err := open(name, size, mtime)
		if err != nil {
			return err
		}
		w = ww
		res.Name = name
		l.dbg("receiving %q (%d bytes announced, header=%v)", name, size, hdr != nil)
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			closeW(err)
			return res, err
		}
		if errorsN > 10 {
			closeW(ErrTooMany)
			return res, fmt.Errorf("%w: receiving", ErrTooMany)
		}
		if time.Since(lastProgress) > noProgressLimit {
			closeW(ErrTimeout)
			return res, fmt.Errorf("%w: no block completed in %v", ErrTimeout, noProgressLimit)
		}
		// Poll when nothing has been acknowledged yet (or after a name).
		if ackd < 0 && !namePending {
			if polls >= 10 || (opts.SilenceEndsBatch && polls >= 3) {
				if opts.SilenceEndsBatch {
					return res, ErrNoMoreFiles
				}
				return res, fmt.Errorf("%w: no file offered", ErrTimeout)
			}
			if crc && polls >= 4 {
				l.dbg("no answer to 'C', polling with NAK")
				crc = false
			}
			poll := NAK
			if crc {
				poll = PollCRC
			}
			if err := l.putc(poll); err != nil {
				return res, err
			}
			polls++
		}
		namePending = false

		b, err := l.getc(firstByteTimeout(ackd))
		if err != nil {
			if err == ErrTimeout {
				if ackd >= 0 {
					errorsN++
					l.dbg("timeout waiting for block %d", expected)
					if nerr := nak(expected); nerr != nil {
						return res, nerr
					}
				}
				continue
			}
			closeW(err)
			return res, err
		}
		switch b {
		case EOT:
			if ackd < 0 {
				l.dbg("EOT at the poll: no more files")
				return res, ErrNoMoreFiles
			}
			if hdr != nil && hdr.Size > 0 && written+int64(len(pending)) < hdr.Size {
				if !eotNAKed {
					// FTS-0007 note 4: a premature EOT is NAKed once.
					eotNAKed = true
					if err := nak(expected); err != nil {
						return res, err
					}
					continue
				}
				// The sender insists: the file is short of its own header. A
				// truncated packet must not be published as whole.
				_ = ack(expected)
				closeW(ErrShortFile)
				return res, fmt.Errorf("%w: %q got %d of %d bytes", ErrShortFile, name, written+int64(len(pending)), hdr.Size)
			}
			if err := flushPending(true); err != nil {
				closeW(err)
				return res, err
			}
			if err := w.Close(); err != nil {
				w = nil
				return res, err
			}
			w = nil
			if err := ack(expected); err != nil {
				return res, err
			}
			res.Bytes = written
			res.Header = hdr
			l.dbg("received %q: %d bytes", name, written)
			return res, nil
		case CAN:
			if l.sawCAN() {
				closeW(ErrCancelled)
				return res, ErrCancelled
			}
		case ACK:
			l.dbg("ACK while receiving (ackd %d, modem7=%v)", ackd, opts.Modem7)
			if ackd < 0 && opts.Modem7 {
				n, nerr := l.recvName()
				if nerr != nil {
					if errors.Is(nerr, ErrNoMoreFiles) {
						return res, nerr
					}
					return res, nerr
				}
				name, res.Named = n, true
				l.dbg("modem7 name %q", n)
				// The sender now waits for our poll for block 0.
				polls = 0
				continue
			}
			l.dbg("stray ACK")
		case TSync:
			// The caller is still synchronising: poll again (it counts as a
			// poll, so a TSYNC per timeout cannot hold the session open).
			l.dbg("TSYNC while polling")
		case NAK, PollCRC:
			if ackd < 0 {
				// The peer also waits to receive: tell it we have nothing.
				l.dbg("peer polled us while we poll it; sending EOT")
				if err := l.putc(EOT); err != nil {
					return res, err
				}
			}
		case SOH, SYN:
			n1, err := l.getc(5 * time.Second)
			if err != nil {
				errorsN++
				continue
			}
			n2, err := l.getc(5 * time.Second)
			if err != nil {
				errorsN++
				continue
			}
			if n1 != ^n2 {
				l.dbg("block number %02x/%02x mismatch, resyncing", n1, n2)
				if !seaMode {
					errorsN++
				}
				continue
			}
			isHeader := n1 == 0 && ackd < 0
			useCRC := crc && b != SYN
			data := make([]byte, BlockSize)
			if err := l.read(data, 15*time.Second); err != nil {
				if err == ErrTimeout {
					errorsN++
					_ = nak(expected)
					continue
				}
				closeW(err)
				return res, err
			}
			var good bool
			if useCRC {
				var cb [2]byte
				if err := l.read(cb[:], 5*time.Second); err != nil {
					errorsN++
					_ = nak(expected)
					continue
				}
				good = CRC(data) == uint16(cb[0])<<8|uint16(cb[1])
			} else {
				var cb [1]byte
				if err := l.read(cb[:], 5*time.Second); err != nil {
					errorsN++
					_ = nak(expected)
					continue
				}
				good = Checksum(data) == cb[0]
			}
			if !good {
				errorsN++
				l.dbg("bad check on block %d", n1)
				if !seaMode {
					l.drain(300 * time.Millisecond)
				}
				if err := nak(expected); err != nil {
					return res, err
				}
				continue
			}
			if isHeader {
				kind := HeaderSEAlink
				if b == SYN {
					kind = HeaderTelink
				}
				hdr = ParseHeader(kind, data)
				lastProgress = time.Now()
				seaMode = kind == HeaderSEAlink
				if opts.Name != "" {
					l.dbg("header names %q, keeping %q", hdr.Name, opts.Name)
				}
				if err := openFile(); err != nil {
					closeW(err)
					return res, err
				}
				ackd = 0
				errorsN = 0
				if err := ack(0); err != nil {
					return res, err
				}
				if strings.HasPrefix(strings.ToLower(hdr.Program), "ifcico") {
					// ifcico 3.03 loses the first ACK of a file: it reads it
					// while probing our ACK style and then waits 20 s for an
					// acknowledgement it has already consumed. Only our 15 s
					// re-poll (a 'C', which makes it resend block 0) moved it
					// on, so every file it sent cost 15 s (measured
					// 2026-10-19 in the interop test zone). A second copy of
					// the same ACK is what it needs to see.
					if err := ack(0); err != nil {
						return res, err
					}
				}
				continue
			}
			// A data block. Which one?
			blk := int(n1)
			if ackd >= 0 {
				// Reconstruct the 32-bit number from the 8-bit one.
				base := expected &^ 0xFF
				blk = base | int(n1)
				if blk > expected+127 {
					blk -= 256
				}
			} else {
				// First block with no header: plain XMODEM block 1.
				if n1 != 1 {
					l.dbg("first block is #%d, not 1; ignoring", n1)
					errorsN++
					continue
				}
				if err := openFile(); err != nil {
					closeW(err)
					return res, err
				}
				ackd = 0
			}
			switch {
			case blk == expected:
				if written+int64(len(pending))+BlockSize > MaxRecvBytes {
					_ = l.write([]byte{CAN, CAN, CAN})
					closeW(ErrTooLarge)
					return res, fmt.Errorf("%w: %q", ErrTooLarge, name)
				}
				if err := flushPending(false); err != nil {
					closeW(err)
					return res, err
				}
				pending = data
				expected++
				ackd = blk
				errorsN = 0
				lastProgress = time.Now()
				if err := ack(blk); err != nil {
					return res, err
				}
			case blk == expected-1:
				// A duplicate of the last block: ACK again, keep what we have.
				if err := ack(blk); err != nil {
					return res, err
				}
			default:
				l.dbg("block %d out of sequence (expected %d)", blk, expected)
				errorsN++
				if err := nak(expected); err != nil {
					return res, err
				}
			}
		default:
			// Debris between blocks: XMODEM says wait for the line to settle.
			l.dbg("debris 0x%02x while receiving (ackd %d)", b, ackd)
		}
	}
}

// firstByteTimeout: a poll waits 5-10 s for a header (XR1.6, ifcico 5 s
// then re-poll); mid-file the next block has 15 s.
func firstByteTimeout(ackd int) time.Duration {
	if ackd < 0 {
		return 5 * time.Second
	}
	return 15 * time.Second
}
