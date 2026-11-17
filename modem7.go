package fts0001

import (
	"fmt"
	"strings"
	"time"
)

// modem7Name is the 11-character "FILENAMEEXT" form (8 + 3, blank
// filled, upper case) MODEM7 transfers; the checksum covers the eleven
// characters and the SUB that ends them.
func modem7Name(name string) (string, byte) {
	base := wireName(name, 64)
	stem, ext := base, ""
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		stem, ext = base[:i], base[i+1:]
	}
	stem = cut(strings.ReplaceAll(stem, ".", ""), 8)
	ext = cut(ext, 3)
	wire := stem + strings.Repeat(" ", 8-len(stem)) + ext + strings.Repeat(" ", 3-len(ext))
	cs := SUB
	for i := 0; i < len(wire); i++ {
		cs += wire[i]
	}
	return wire, cs
}

// sendName runs the MODEM7 filename sender (FTS-0001 MS0-MS2) for a
// receiver that has ALREADY polled with NAK — the batch sender reads
// that NAK between files. skipped reports FSC-0011's
// MS0.3: a receiver that answers 'C' instead of NAK does not want
// filenames (SEAdog; the name then comes from the header block).
func (l *line) sendName(name string) (skipped bool, err error) {
	wire, cs := modem7Name(name)
	l.dbg("modem7: send name %q checksum %02x", wire, cs)
	for try := 0; try < 7; try++ {
		if try > 0 {
			// Restart: 'u' was sent; wait for the receiver's fresh NAK.
			b, gerr := l.getc(15 * time.Second)
			if gerr != nil {
				if gerr == ErrTimeout {
					continue
				}
				return false, gerr
			}
			switch b {
			case NAK:
			case PollCRC:
				return true, nil
			default:
				_ = l.putc(M7Abort)
				continue
			}
		}
		if err := l.putc(ACK); err != nil {
			return false, err
		}
		ok := true
		for i := 0; i < len(wire); i++ {
			if err := l.putc(wire[i]); err != nil {
				return false, err
			}
			b, gerr := l.getc(15 * time.Second)
			if gerr != nil && gerr != ErrTimeout {
				return false, gerr
			}
			if gerr != nil || b != ACK {
				l.dbg("modem7: no ACK for name char %d (%v / 0x%02x), restarting", i, gerr, b)
				ok = false
				break
			}
		}
		if !ok {
			_ = l.putc(M7Abort)
			continue
		}
		if err := l.putc(SUB); err != nil {
			return false, err
		}
		b, gerr := l.getc(15 * time.Second)
		if gerr != nil && gerr != ErrTimeout {
			return false, gerr
		}
		if gerr != nil || b != cs {
			l.dbg("modem7: checksum %02x not confirmed (%v / 0x%02x), restarting", cs, gerr, b)
			_ = l.putc(M7Abort)
			continue
		}
		if err := l.putc(ACK); err != nil {
			return false, err
		}
		return false, nil
	}
	return false, fmt.Errorf("%w: modem7 filename not accepted", ErrTooMany)
}

// recvName runs the MODEM7 filename receiver (MR0-MR3) AFTER the ACK
// that answered our NAK poll has been read by the caller (the batch
// receiver sees the ACK where a block header would be). It returns the
// name in lower case, "name.ext".
func (l *line) recvName() (string, error) {
	deadline := time.Now().Add(60 * time.Second)
	for try := 0; try < 7 && time.Now().Before(deadline); try++ {
		if try > 0 {
			// Restart: NAK, then the sender's ACK that opens the name.
			if err := l.putc(NAK); err != nil {
				return "", err
			}
			b, gerr := l.getc(15 * time.Second)
			if gerr != nil {
				if gerr == ErrTimeout {
					continue
				}
				return "", gerr
			}
			if b == EOT {
				return "", errNoMoreFiles
			}
			if b != ACK {
				continue
			}
		}
		var raw []byte
		cs := SUB
		failed := false
		for {
			b, gerr := l.getc(15 * time.Second)
			if gerr != nil {
				if gerr == ErrTimeout {
					failed = true
					break
				}
				return "", gerr
			}
			if b == EOT {
				return "", errNoMoreFiles
			}
			if b == SUB {
				break
			}
			if b == M7Abort || len(raw) >= 11 {
				// 'u' restarts; a twelfth character is not a MODEM7 name
				// (8 + 3), so the exchange restarts rather than growing.
				failed = true
				break
			}
			cs += b
			raw = append(raw, b)
			if err := l.putc(ACK); err != nil {
				return "", err
			}
		}
		if failed {
			continue
		}
		if err := l.putc(cs); err != nil {
			return "", err
		}
		b, gerr := l.getc(15 * time.Second)
		if gerr != nil && gerr != ErrTimeout {
			return "", gerr
		}
		if gerr != nil || b != ACK {
			continue
		}
		return fromModem7(raw), nil
	}
	return "", fmt.Errorf("%w: modem7 filename not received", ErrTooMany)
}

// fromModem7 turns "FILENAMEEXT" (blank filled) into "filename.ext".
func fromModem7(raw []byte) string {
	s := string(raw)
	if len(s) > 11 {
		s = s[:11]
	}
	for len(s) < 11 {
		s += " "
	}
	stem := strings.TrimSpace(s[:8])
	ext := strings.TrimSpace(s[8:])
	name := strings.ToLower(stem)
	if ext != "" {
		name += "." + strings.ToLower(ext)
	}
	return safeName(name)
}
