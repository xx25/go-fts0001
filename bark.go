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

// Bark file requests (FTS-0008). A request is a short packet — ACK, the
// DOS file name, a space, a decimal Unix time (0 unless an update
// request), optionally a space and a password, ETX, CRC-16 low byte,
// high byte — and the answer is an ordinary attached-file batch
// (MODEM7 names + Telink/SEAlink), or EOT alone for "cannot send". The
// phase is controlled by the CALLED system (FTS-0008 C.1): it sends ENQ
// to invite the caller's requests and SYN to ask leave to make its own.
// FTS-0006 forbids Bark inside DietIFNA; it runs only in ModeFTS0001.

const (
	// ETB ends a run of requests ("no more files to request", SB0.2).
	ETB byte = 0x17
	// ENQ invites the peer to send its requests (RB0 / S5.3).
	ENQ byte = 0x05
	// maxBarkBody bounds a request packet's data (name + date + password).
	maxBarkBody = 64
)

// BarkRequest is one file request.
type BarkRequest struct {
	Name     string
	Password string
	Since    int64 // Unix time of the requester's copy; 0 = plain request
}

// Marshal renders the packet: ACK body ETX crc-lo crc-hi. The CRC covers
// the body only, bytes reversed relative to an XMODEM block's.
func (r BarkRequest) Marshal() []byte {
	body := wireName(r.Name, 12) + " " + strconv.FormatInt(r.Since, 10)
	if r.Password != "" {
		body += " " + cut(r.Password, 8)
	}
	c := CRC([]byte(body))
	out := []byte{ACK}
	out = append(out, body...)
	out = append(out, ETX, byte(c), byte(c>>8))
	return out
}

// parseBarkBody decodes "NAME DATE [PASSWORD]".
func parseBarkBody(body []byte) (BarkRequest, bool) {
	f := strings.Fields(string(body))
	if len(f) < 1 || len(f) > 3 {
		return BarkRequest{}, false
	}
	r := BarkRequest{Name: safeName(f[0])}
	if r.Name == "" {
		return BarkRequest{}, false
	}
	if len(f) >= 2 {
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || n < 0 {
			return BarkRequest{}, false
		}
		r.Since = n
	}
	if len(f) == 3 {
		r.Password = f[2]
	}
	return r, true
}

// ParseRequestFile turns the lines of a WaZOO-style .req file into Bark
// requests: "NAME [!password] [+time]" per line, ';' comments and blank
// lines skipped. A WaZOO "-time" (older-than) token is ignored: the
// request is answered as if it had none. Every line is kept: a cap
// here would drop the tail of a .req and still report the file sent.
// Names are returned as written — a BarkServer must treat them as
// untrusted input.
func ParseRequestFile(data []byte) []BarkRequest {
	var out []BarkRequest
	for _, line := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '\r' || r == '\n' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		r := BarkRequest{Name: f[0]}
		for _, tok := range f[1:] {
			switch {
			case strings.HasPrefix(tok, "!"):
				r.Password = strings.TrimPrefix(tok, "!")
			case strings.HasPrefix(tok, "+"):
				if n, err := strconv.ParseInt(tok[1:], 10, 64); err == nil {
					r.Since = n
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// barkRequestWait is RB1's limit: 20 s for the requester's next packet,
// ETB or ENQ (a var so tests can shorten it).
var barkRequestWait = 20 * time.Second

// maxBarkRequests bounds one session's requests (FTS-0008 gives none;
// the WaZOO responder's default line cap is 64).
const maxBarkRequests = 64

// BarkServer answers one request — or all the lines of a request file,
// together (reqfile.go) — with the files to send. ok == false refuses
// the whole request phase (RB0.2, a CAN); an empty list with ok == true
// is "cannot send that one" (RB4.2, an EOT).
type BarkServer func(reqs ...BarkRequest) (files []*OutFile, ok bool)

// isRequestFile reports a WaZOO request file by name.
func isRequestFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".req")
}

// splitRequests is splitRequests unless cfg.RequestsAsFiles keeps the
// .req files in the batch.
func (c Config) splitRequests(src Source) (Source, []BarkRequest, func(err error)) {
	if c.RequestsAsFiles {
		return src, nil, func(error) {}
	}
	return splitRequests(src)
}

// splitRequests takes the .req files out of a Source (FTS-0001 carries
// requests as Bark packets, not as files) and returns the rest plus the
// parsed requests. Each .req's Done fires once its requests went out.
func splitRequests(src Source) (Source, []BarkRequest, func(err error)) {
	var files, reqFiles []*OutFile
	for f := src.Next(); f != nil; f = src.Next() {
		if isRequestFile(f.Name) {
			reqFiles = append(reqFiles, f)
		} else {
			files = append(files, f)
		}
	}
	var reqs []BarkRequest
	for _, f := range reqFiles {
		reqs = append(reqs, ParseRequestFile(f.Data)...)
	}
	done := func(err error) {
		for _, f := range reqFiles {
			f.done(int64(len(f.Data)), err)
		}
	}
	return &sliceSource{files: files}, reqs, done
}

// sendBarkRequests runs the requester side (FTS-0008 SB0-SB3) after the
// peer's ENQ was read: each request packet until ACKed, the answering
// batch into sink, ENQ before the next, ETB at the end.
func sendBarkRequests(ctx context.Context, l *line, cfg Config, reqs []BarkRequest, sink Sink) error {
	for i, req := range reqs {
		if err := ctx.Err(); err != nil {
			return err
		}
		pkt := req.Marshal()
		acked := false
		for tries := 0; tries < 6 && !acked; tries++ {
			l.dbg("bark: request %q since %d (try %d)", req.Name, req.Since, tries+1)
			if err := l.write(pkt); err != nil {
				return err
			}
			b, err := l.getc(10 * time.Second)
			if err != nil {
				if err == ErrTimeout {
					continue
				}
				return err
			}
			switch b {
			case ACK:
				acked = true
			case CAN:
				if l.sawCAN() {
					return ErrCancelled
				}
			default:
				l.dbg("bark: 0x%02x instead of ACK, purging", b)
				l.drain(300 * time.Millisecond)
			}
		}
		if !acked {
			_ = l.putc(ETB)
			return fmt.Errorf("%w: bark request %q not acknowledged", ErrTooMany, req.Name)
		}
		// The answer: an attached-file batch (BR0), or EOT alone.
		for n := 0; ; n++ {
			opts := recvOptions{PreferCRC: cfg.preferCRC(), Modem7: true, Program: cfg.Program}
			var cur string
			open := func(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
				cur = name
				return sink.Open(name, size, mtime)
			}
			res, err := l.recvFile(ctx, opts, open, nil)
			if err != nil {
				if errors.Is(err, ErrNoMoreFiles) {
					l.dbg("bark: %d file(s) for %q", n, req.Name)
					break
				}
				if cur != "" {
					sink.Done(cur, 0, err)
				}
				return fmt.Errorf("bark: receiving the answer to %q: %w", req.Name, err)
			}
			sink.Done(res.Name, res.Bytes, nil)
		}
		if i == len(reqs)-1 {
			break
		}
		// SB3: the peer's ENQ for the next request.
		if err := waitFor(l, ENQ, 45*time.Second, 5*time.Second, SUB); err != nil {
			return fmt.Errorf("bark: no ENQ for the next request: %w", err)
		}
	}
	// SB0.2 — or the peer's trailing ENQ when there was nothing: ETB.
	if len(reqs) > 0 {
		if err := waitFor(l, ENQ, 45*time.Second, 5*time.Second, SUB); err != nil && err != ErrTimeout {
			return err
		}
	}
	l.dbg("bark: no more requests (ETB)")
	return l.putc(ETB)
}

// waitFor reads until want arrives, nudging with nudge every nudgeEvery
// of silence, for at most total. Debris is purged.
func waitFor(l *line, want byte, total, nudgeEvery time.Duration, nudge byte) error {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		b, err := l.getc(nudgeEvery)
		if err != nil {
			if err == ErrTimeout {
				if nudge != 0 {
					_ = l.putc(nudge)
				}
				continue
			}
			return err
		}
		if b == want {
			return nil
		}
		if b == CAN && l.sawCAN() {
			return ErrCancelled
		}
		l.dbg("bark: debris 0x%02x waiting for 0x%02x", b, want)
	}
	return ErrTimeout
}

// recvBarkRequests runs the serving side (FTS-0008 RB0-RB4): ENQ, the
// peer's request packet, ACK, its poll, the files (or EOT), until ETB.
// serve == nil refuses the phase with CAN (RB0.2).
func recvBarkRequests(ctx context.Context, l *line, cfg Config, serve BarkServer) error {
	if serve == nil {
		l.dbg("bark: refusing the peer's requests (CAN)")
		return l.putc(CAN)
	}
	for round := 0; round < maxBarkRequests+2; round++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		// RB0: purge, ENQ.
		l.drain(0)
		if err := l.putc(ENQ); err != nil {
			return err
		}
		// RB1: the request packet, ETB, or another ENQ.
		var req BarkRequest
		got := false
		start := time.Now()
		for time.Since(start) < barkRequestWait && !got {
			b, err := l.getc(2 * time.Second)
			if err != nil {
				if err == ErrTimeout {
					l.drain(0)
					if err := l.putc(ENQ); err != nil {
						return err
					}
					continue
				}
				return err
			}
			switch b {
			case ETB:
				l.dbg("bark: peer has no more requests")
				return nil
			case ENQ:
				// Both sides offered at once: yield (RB1.3).
				if err := l.putc(ETB); err != nil {
					return err
				}
				continue
			case ACK:
				body, err := l.readBarkBody(ctx, start.Add(barkRequestWait))
				if err != nil {
					if errors.Is(err, errBarkEnd) {
						l.dbg("bark: peer has no more requests (a stray ACK, then ETB or silence)")
						return nil
					}
					if errors.Is(err, errBarkResync) {
						l.drain(0)
						_ = l.putc(ENQ)
						continue
					}
					return err
				}
				var cb [2]byte
				if err := l.read(cb[:], 5*time.Second); err != nil {
					return err
				}
				r, ok := parseBarkBody(body)
				if !ok || CRC(body) != uint16(cb[1])<<8|uint16(cb[0]) {
					l.dbg("bark: bad request packet %q, NAK", body)
					if err := l.putc(NAK); err != nil {
						return err
					}
					continue
				}
				req, got = r, true
			default:
				l.dbg("bark: debris 0x%02x waiting for a request", b)
			}
		}
		if !got {
			return fmt.Errorf("%w: no bark request in %v", ErrTimeout, barkRequestWait)
		}
		// RB2: ACK the packet; RB3: the requester's poll for the first file.
		if err := l.putc(ACK); err != nil {
			return err
		}
		l.dbg("bark: request %q since %d password=%v", req.Name, req.Since, req.Password != "")
		crc := false
		polled := false
		pollStart := time.Now()
		for time.Since(pollStart) < 15*time.Second && !polled {
			b, err := l.getc(3 * time.Second)
			if err != nil {
				if err == ErrTimeout {
					_ = l.putc(ACK)
					continue
				}
				return err
			}
			switch b {
			case NAK:
				polled = true
			case PollCRC:
				crc, polled = true, true
			case CAN:
				if l.sawCAN() {
					return ErrCancelled
				}
			}
		}
		if !polled {
			return fmt.Errorf("%w: requester never polled for %q", ErrTimeout, req.Name)
		}
		// RB4: the files, every one behind a MODEM7 name; none → EOT.
		files, ok := serve(req)
		if !ok {
			l.dbg("bark: serving withdrawn; CAN")
			return l.putc(CAN)
		}
		if len(files) == 0 {
			l.dbg("bark: nothing to send for %q (EOT)", req.Name)
			if err := l.putc(EOT); err != nil {
				return err
			}
			continue
		}
		if err := sendFiles(ctx, l, cfg, &sliceSource{files: files}, crc, true); err != nil {
			return fmt.Errorf("bark: sending the answer to %q: %w", req.Name, err)
		}
	}
	return fmt.Errorf("%w: too many bark requests", ErrTooMany)
}

// ErrBarkNotInvited reports requests the peer never invited (no ENQ
// after our batch, or CAN / silence after our SYN). Not a session
// failure: the .req is deferred to a later call, like binkp's M_SKIP.
var ErrBarkNotInvited = errors.New("fts0001: the peer never invited our file requests")

var errBarkResync = errors.New("fts0001: bark request interrupted (SUB)")

// errBarkEnd: an ETB where a request body should be. A request body is
// printable text; an ETB there means the "ACK" that seemed to open a
// packet was a stray — BinkleyTerm's batch receiver ACKs our batch-ending
// EOT just after our ENQ arrives, then answers the ENQ with ETB
// (measured 2026-10-19: ... 04 | 05 → 06 17, hangup).
// D'Bridge 4 sends a second bare ACK instead of the ETB, then nothing:
// a bare ACK and silence ends the requests too.
var errBarkEnd = errors.New("fts0001: no more bark requests (ETB)")

// readBarkBody reads a request body up to ETX; SUB restarts (RB1 *1).
// The deadline is RB1's (barkRequestWait): a repeated ACK restarts the body but never
// the clock, so a caller sending ACK every few seconds cannot hold the
// line.
func (l *line) readBarkBody(ctx context.Context, deadline time.Time) ([]byte, error) {
	var body []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, fmt.Errorf("%w: no bark request in %v", ErrTimeout, barkRequestWait)
		}
		b, err := l.getc(min(5*time.Second, left))
		if err != nil {
			if err == ErrTimeout && len(body) == 0 {
				// A bare ACK, then silence: D'Bridge 4 answers the ENQ
				// after its last file with ACK ACK and waits for the
				// hang-up (measured 2026-10-19). A request's body follows
				// its ACK at once.
				return nil, errBarkEnd
			}
			return nil, err
		}
		switch b {
		case ETX:
			return body, nil
		case SUB:
			return nil, errBarkResync
		case ETB:
			if len(body) == 0 {
				return nil, errBarkEnd
			}
			return nil, errBarkResync
		case ACK:
			// A repeated header: the sender restarted; keep what follows.
			body = body[:0]
		default:
			if len(body) >= maxBarkBody {
				return nil, errBarkResync
			}
			body = append(body, b)
		}
	}
}

// requestsSummary is a log helper.
func requestsSummary(reqs []BarkRequest) string {
	var sb bytes.Buffer
	for i, r := range reqs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(r.Name)
	}
	return sb.String()
}
