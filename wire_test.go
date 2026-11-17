package fts0001

import (
	"testing"
	"time"
)

// The session tests run the same constants on both ends, so they cannot
// notice a wrong one. These pin the wire in literal octets.

func TestWireBytes(t *testing.T) {
	for name, pair := range map[string][2]byte{
		"SOH": {SOH, 0x01}, "ETX": {ETX, 0x03}, "EOT": {EOT, 0x04}, "ACK": {ACK, 0x06},
		"NAK": {NAK, 0x15}, "SYN": {SYN, 0x16}, "CAN": {CAN, 0x18}, "SUB": {SUB, 0x1a},
		"TSync": {TSync, 0xae}, "PollCRC": {PollCRC, 0x43}, "M7Abort": {M7Abort, 0x75},
	} {
		assert.Equal(t, pair[1], pair[0], name)
	}
	assert.Equal(t, 128, BlockSize)
}

func TestChecksumAndCRCKnownVectors(t *testing.T) {
	// CRC-16/XMODEM check value.
	assert.Equal(t, uint16(0x31c3), CRC([]byte("123456789")))
	assert.Equal(t, uint16(0), CRC(nil))
	// XMODEM's checksum is the low byte of the SUM, not an XOR.
	assert.Equal(t, byte(0x06), Checksum([]byte{0x01, 0x02, 0x03}))
	assert.Equal(t, byte(0xfe), Checksum([]byte{0xff, 0xff}))
}

func TestSafeNameKeepsABareFileName(t *testing.T) {
	for in, want := range map[string]string{
		"file.pkt":         "file.pkt",
		"../../etc/passwd": "_.__._etc_passwd",
		"c:\\dir\\x.zip":   "c__dir_x.zip",
		".hidden":          "hidden",
	} {
		assert.Equal(t, want, safeName(in), "%q", in)
	}
}

// A file with no Done callback is legal: the outcome is simply not
// reported. With one, it is called exactly once per report.
func TestOutFileDoneIsOptional(t *testing.T) {
	(&OutFile{Name: "a.pkt"}).done(6, nil)

	calls, got := 0, int64(0)
	f := &OutFile{Name: "b.pkt", ModTime: time.Unix(1700000000, 0), Done: func(sent int64, err error) { calls++; got = sent }}
	f.done(42, nil)
	assert.Equal(t, 1, calls)
	assert.Equal(t, int64(42), got)
}
