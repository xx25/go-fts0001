package fts0001

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// Errors every step reports through.
var (
	ErrTimeout     = errors.New("fts0001: timeout")
	ErrCarrierLost = errors.New("fts0001: carrier lost")
	ErrCancelled   = errors.New("fts0001: peer cancelled (CAN)")
	ErrTooMany     = errors.New("fts0001: too many errors")
	ErrTooLarge    = errors.New("fts0001: file larger than the receive limit")
	ErrShortFile   = errors.New("fts0001: sender ended the file short of its announced size")
)

// writeTimeout bounds every write: a modem whose CTS stays low must not
// hold the line forever (the modem conn retries while CTS is low).
const writeTimeout = 60 * time.Second

// deadliner is what a net.Conn offers. With it, the reader goroutine
// polls a stop flag through one-second read deadlines and the session's
// close joins it, so no reader outlives its session on a pooled modem
// line; without it (a plain pipe in tests) the reader blocks until the
// connection closes.
type deadliner interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// line is the byte-level view of the connection: a reader goroutine
// feeds a channel so every step waits with its own timeout and the two
// directions never block each other (a SEAlink window has both sides
// writing at once); writes are bounded by a deadline when available.
type line struct {
	rw   io.ReadWriter
	dl   deadliner // nil → no deadlines (tests over plain pipes)
	buf  []byte
	err  error
	log  *slog.Logger
	ch   chan []byte
	errc chan error
	stop chan struct{}
	done chan struct{}
}

func newLine(rw io.ReadWriter, log *slog.Logger) *line {
	if log == nil {
		log = slog.Default()
	}
	l := &line{rw: rw, log: log, ch: make(chan []byte, 256), errc: make(chan error, 1),
		stop: make(chan struct{}), done: make(chan struct{})}
	l.dl, _ = rw.(deadliner)
	go l.pump()
	return l
}

// close ends the session's use of the line: the reader is stopped and
// joined (it notices within a second when deadlines exist), and the
// deadlines are cleared so the transport's own close is not disturbed.
func (l *line) close() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	if l.dl != nil {
		select {
		case <-l.done:
		case <-time.After(3 * time.Second):
		}
		_ = l.dl.SetReadDeadline(time.Time{})
		_ = l.dl.SetWriteDeadline(time.Time{})
	}
}

func (l *line) pump() {
	defer close(l.done)
	for {
		select {
		case <-l.stop:
			return
		default:
		}
		if l.dl != nil {
			_ = l.dl.SetReadDeadline(time.Now().Add(time.Second))
		}
		b := make([]byte, 2048)
		n, err := l.rw.Read(b)
		if n > 0 {
			select {
			case l.ch <- b[:n]:
			case <-l.stop:
				return
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue // the one-second poll; look at the stop flag again
			}
			l.errc <- err
			return
		}
	}
}

func (l *line) dbg(format string, args ...any) {
	l.log.Debug("fts0001: " + fmt.Sprintf(format, args...))
}

// fill blocks for more input until timeout. Data the reader produced
// before a connection error always wins over the error, so a peer that
// sends its last byte and hangs up at once is still read whole.
func (l *line) fill(timeout time.Duration) error {
	if l.err != nil {
		return l.err
	}
	select {
	case b := <-l.ch:
		l.buf = append(l.buf, b...)
		return nil
	default:
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case b := <-l.ch:
		l.buf = append(l.buf, b...)
		return nil
	case err := <-l.errc:
		for {
			select {
			case b := <-l.ch:
				l.buf = append(l.buf, b...)
				continue
			default:
			}
			break
		}
		l.err = fmt.Errorf("%w: %v", ErrCarrierLost, err)
		if len(l.buf) > 0 {
			return nil
		}
		return l.err
	case <-t.C:
		return ErrTimeout
	}
}

// getc returns one byte within timeout.
func (l *line) getc(timeout time.Duration) (byte, error) {
	deadline := time.Now().Add(timeout)
	for len(l.buf) == 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, ErrTimeout
		}
		if err := l.fill(remaining); err != nil {
			return 0, err
		}
	}
	b := l.buf[0]
	l.buf = l.buf[1:]
	return b, nil
}

// pending reports whether a byte is already available (no wait).
func (l *line) pending() bool {
	if len(l.buf) > 0 {
		return true
	}
	select {
	case b := <-l.ch:
		l.buf = append(l.buf, b...)
		return len(l.buf) > 0
	default:
		return false
	}
}

// read fills exactly len(p) within timeout.
func (l *line) read(p []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for len(l.buf) < len(p) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrTimeout
		}
		if err := l.fill(remaining); err != nil {
			return err
		}
	}
	copy(p, l.buf[:len(p)])
	l.buf = l.buf[len(p):]
	return nil
}

// drain discards input until the line has been quiet for d, for at most
// 3 s in all — a chattering peer must not hold the step open.
func (l *line) drain(d time.Duration) int {
	n := len(l.buf)
	l.buf = l.buf[:0]
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if err := l.fill(d); err != nil {
			return n
		}
		n += len(l.buf)
		l.buf = l.buf[:0]
	}
	return n
}

func (l *line) write(b []byte) error {
	if l.dl != nil {
		_ = l.dl.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	if _, err := l.rw.Write(b); err != nil {
		return fmt.Errorf("%w: write: %v", ErrCarrierLost, err)
	}
	return nil
}

func (l *line) putc(b byte) error { return l.write([]byte{b}) }
