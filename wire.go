// Package fts0001 implements the FTS-0001 mail session — the protocol
// FidoNet began with and the one every mailer of the 1980s answers —
// together with its data link, XMODEM with the Telink header block
// (FTS-0001) and SEAlink's sliding window, numbered acknowledgements
// and RESYNC (FTS-0007 / FSC-0019), and the MODEM7 filename exchange
// of the attached-file batch. It also runs DietIFNA (FTS-0006), the
// WaZOO variant in which the same transfers carry every file under the
// name in its header block, with no MODEM7 names and no Bark.
//
// Layering, bottom up:
//
//   - wire.go: byte constants, checksum, the Telink and SEAlink header
//     blocks (block 0) and their DOS / SEAlink timestamps.
//   - line.go: a byte-at-a-time reader with per-step timeouts over any
//     io.ReadWriter (a pump goroutine; the data link does not need the
//     connection to support deadlines).
//   - xmodem.go: sendFile / recvFile — one file, block 0 through EOT.
//   - modem7.go: sendName / recvName — the MODEM7 filename handshake.
//   - session.go: the batches, the pickup turnaround and the two modes
//     (FTS-0001 proper, DietIFNA), driven by a Source and a Sink the
//     caller supplies.
//   - bark.go, reqfile.go: file requests — Bark packets (FTS-0008) and
//     WaZOO request files inside the batch.
//
// The package depends on the standard library only. Specs:
// FTS-0001.016, FTS-0007.003, FTS-0008; behaviour is checked against
// real mailers in an interop test zone.
package fts0001

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
)

// Wire bytes.
const (
	SOH   byte = 0x01 // start of an XMODEM data block (and of a SEAlink header)
	ETX   byte = 0x03 // end of a RESYNC packet
	EOT   byte = 0x04 // end of a file; alone, "no more files" in a batch
	ACK   byte = 0x06
	NAK   byte = 0x15 // also the poll for block 1 in checksum mode
	SYN   byte = 0x16 // start of a Telink header block; start of a RESYNC packet
	CAN   byte = 0x18
	SUB   byte = 0x1A // XMODEM padding, the MODEM7 name terminator
	TSync byte = 0xAE // FTS-0001 session synchronisation
	// PollCRC is the receiver's poll for block 1 when it wants CRC-16.
	PollCRC byte = 'C'
	// M7Abort restarts the MODEM7 filename exchange.
	M7Abort byte = 'u'
	// BlockSize is XMODEM's fixed data block.
	BlockSize = 128
)

// Checksum is XMODEM's: the low eight bits of the sum of the data bytes.
func Checksum(data []byte) byte {
	var s byte
	for _, b := range data {
		s += b
	}
	return s
}

// CRC is the CCITT remainder XMODEM uses (FTS-0007 "Calculating CRC").
func CRC(data []byte) uint16 { return crc16(data) }

// HeaderKind names the block-0 header a sender puts in front of a
// file, or none (plain XMODEM, the first block is data block 1).
type HeaderKind int

const (
	HeaderNone    HeaderKind = iota
	HeaderTelink             // SYN 00 FF ... checksum (FTS-0001)
	HeaderSEAlink            // SOH 00 FF ... crc or checksum (FTS-0007)
)

func (k HeaderKind) String() string {
	switch k {
	case HeaderTelink:
		return "Telink"
	case HeaderSEAlink:
		return "SEAlink"
	}
	return "none"
}

// FileHeader is the decoded block 0 of either kind.
type FileHeader struct {
	Kind    HeaderKind
	Name    string // 16 (Telink) or 17 (SEAlink) bytes, trimmed
	Size    int64
	ModTime time.Time // zero when the sender gave none
	Program string    // the sending program's name
	// Telink: the sender's CRC flag (always 1 in practice; ignored).
	CRC bool
	// SEAlink options the sender requests or supports.
	Overdrive bool // SLO: the receiver may withhold ACKs (streaming)
	Resync    bool // the sender honours RESYNC packets
	MacFlow   bool // XON/XOFF
}

// Telink block layout (data offsets).
const (
	hdrSize    = 0  // 4 bytes LE
	hdrTime    = 4  // Telink: DOS time(2) + date(2); SEAlink: seconds(4)
	hdrName    = 8  // Telink 16 bytes blank-filled; SEAlink 17 NUL-filled
	tlVersion  = 24 // Telink: header version 0
	hdrProgram = 25 // Telink 16 NUL-filled; SEAlink 15
	tlCRCFlag  = 41 // Telink: 1 for CRC
	slOverdrv  = 40 // SEAlink
	slResync   = 41
	slMacFlow  = 42
)

// MarshalTelink encodes the 128 data bytes of a Telink header block.
func (h *FileHeader) MarshalTelink() []byte {
	d := make([]byte, BlockSize)
	binary.LittleEndian.PutUint32(d[hdrSize:], uint32(h.Size))
	dt, dd := DOSTime(h.ModTime)
	binary.LittleEndian.PutUint16(d[hdrTime:], dt)
	binary.LittleEndian.PutUint16(d[hdrTime+2:], dd)
	name := wireName(h.Name, 16)
	copy(d[hdrName:], []byte(name+strings.Repeat(" ", 16-len(name))))
	d[tlVersion] = 0
	copy(d[hdrProgram:hdrProgram+16], cut(h.Program, 16))
	if h.CRC {
		d[tlCRCFlag] = 1
	}
	return d
}

// MarshalSEAlink encodes the 128 data bytes of a SEAlink header block.
func (h *FileHeader) MarshalSEAlink() []byte {
	d := make([]byte, BlockSize)
	binary.LittleEndian.PutUint32(d[hdrSize:], uint32(h.Size))
	binary.LittleEndian.PutUint32(d[hdrTime:], uint32(SEAlinkTime(h.ModTime)))
	copy(d[hdrName:hdrName+17], cut(wireName(h.Name, 17), 17))
	copy(d[hdrProgram:hdrProgram+15], cut(h.Program, 15))
	if h.Overdrive {
		d[slOverdrv] = 1
	}
	if h.Resync {
		d[slResync] = 1
	}
	if h.MacFlow {
		d[slMacFlow] = 1
	}
	return d
}

// ParseHeader decodes the 128 data bytes of a block 0 of the given kind.
func ParseHeader(kind HeaderKind, d []byte) *FileHeader {
	if len(d) < BlockSize {
		return nil
	}
	h := &FileHeader{Kind: kind}
	// Sizes are "4 bytes LSB first", unsigned: read signed, a 185-byte
	// packet becomes "-71 bytes".
	h.Size = int64(binary.LittleEndian.Uint32(d[hdrSize:]))
	switch kind {
	case HeaderTelink:
		h.Name = safeName(strings.TrimRight(cString(d[hdrName:hdrName+16]), " "))
		h.Program = cString(d[hdrProgram : hdrProgram+16])
		h.ModTime = FromDOSTime(binary.LittleEndian.Uint16(d[hdrTime:]), binary.LittleEndian.Uint16(d[hdrTime+2:]))
		h.CRC = d[tlCRCFlag] != 0
	case HeaderSEAlink:
		h.Name = safeName(strings.TrimRight(cString(d[hdrName:hdrName+17]), " "))
		h.Program = cString(d[hdrProgram : hdrProgram+15])
		if secs := binary.LittleEndian.Uint32(d[hdrTime:]); secs != 0 {
			h.ModTime = FromSEAlinkTime(int64(secs))
		}
		h.Overdrive = d[slOverdrv] != 0
		h.Resync = d[slResync] != 0
		h.MacFlow = d[slMacFlow] != 0
	}
	return h
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// safeName keeps a received name to a bare file name: path separators,
// ':' and control bytes become '_', leading dots are dropped, and ".."
// cannot survive.
// A caller may file by this name; the wire is not trusted to be polite.
func safeName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r == '/' || r == '\\' || r == ':' || r < 0x20 || r == 0x7F:
			sb.WriteByte('_')
		default:
			sb.WriteRune(r)
		}
	}
	out := strings.TrimSpace(sb.String())
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", "_.")
	}
	out = strings.TrimLeft(out, ".")
	return out
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// wireName is the DOS form of a name: upper case, no path, at most n
// bytes (8.3 fits every receiver of this era; a longer name is cut).
func wireName(name string, n int) string {
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	return cut(strings.ToUpper(name), n)
}

// DOSTime packs t into the DOS time and date words (FTS-0001
// CreationTime / CreationDate), in local time as DOS keeps them. A
// zero t gives 0, 0.
func DOSTime(t time.Time) (dosTime, dosDate uint16) {
	if t.IsZero() {
		return 0, 0
	}
	t = t.Local()
	y := t.Year() - 1980
	if y < 0 {
		y = 0
	}
	if y > 127 {
		y = 127
	}
	dosDate = uint16(y)<<9 | uint16(t.Month())<<5 | uint16(t.Day())
	dosTime = uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2)
	return dosTime, dosDate
}

// FromDOSTime unpacks the DOS words; 0,0 is the zero time.
func FromDOSTime(dosTime, dosDate uint16) time.Time {
	if dosTime == 0 && dosDate == 0 {
		return time.Time{}
	}
	return time.Date(1980+int(dosDate>>9), time.Month((dosDate>>5)&0x0F), int(dosDate&0x1F),
		int(dosTime>>11), int((dosTime>>5)&0x3F), int(dosTime&0x1F)*2, 0, time.Local)
}

// SEAlinkTime is the header's "seconds" field: Unix seconds shifted to
// local time, as mailers in the field and the DOS originals write it.
func SEAlinkTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	_, off := t.Local().Zone()
	return t.Unix() + int64(off)
}

// FromSEAlinkTime is the inverse.
func FromSEAlinkTime(secs int64) time.Time {
	t := time.Unix(secs, 0)
	_, off := t.Local().Zone()
	return time.Unix(secs-int64(off), 0)
}
