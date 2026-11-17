package fts0001

import (
	"bytes"
	"fmt"
	"io"
	"time"
)

// WaZOO request files in an FTS-0001 batch. Fido 12 and FrontDoor make
// their FTS-0001 requests this way rather than by Bark: a .REQ file in
// the attached-file batch, the files expected in the called system's
// pickup turn — a caller that sent a .REQ file turns the line around to
// receive them. As the called system we answer such a file
// in that turn, through the same BarkServer — the same identity,
// eligibility and caps as a Bark request.

// maxReqFileBytes bounds what is kept of one received request file.
const maxReqFileBytes = 16 << 10

// reqTee passes everything to its Sink and keeps the bytes of each
// request file that arrives whole.
type reqTee struct {
	Sink
	pending map[string]*bytes.Buffer
	got     [][]byte
}

func (t *reqTee) Open(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
	w, err := t.Sink.Open(name, size, mtime)
	if err != nil || !isRequestFile(name) {
		return w, err
	}
	if t.pending == nil {
		t.pending = map[string]*bytes.Buffer{}
	}
	buf := &bytes.Buffer{}
	t.pending[name] = buf
	return &teeWriter{WriteCloser: w, buf: buf}, nil
}

func (t *reqTee) Done(name string, n int64, err error) {
	if buf, ok := t.pending[name]; ok {
		delete(t.pending, name)
		if err == nil {
			t.got = append(t.got, buf.Bytes())
		}
	}
	t.Sink.Done(name, n, err)
}

type teeWriter struct {
	io.WriteCloser
	buf *bytes.Buffer
}

func (w *teeWriter) Write(p []byte) (int, error) {
	if room := maxReqFileBytes - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return w.WriteCloser.Write(p)
}

// serveRequestFiles hands every line of the request files a caller sent
// (at most maxBarkRequests) to the server in ONE call: resolved
// together, the output caps, de-duplication and 8.3 names hold across
// the lines — line by line, a 64-line .req of BIG.ZIP was 64 copies held
// in memory.
func serveRequestFiles(l *line, reqFiles [][]byte, serve BarkServer) []*OutFile {
	var reqs []BarkRequest
	for _, data := range reqFiles {
		reqs = append(reqs, ParseRequestFile(data)...)
	}
	if len(reqs) > maxBarkRequests {
		l.dbg("req file: %d requests; the first %d are served", len(reqs), maxBarkRequests)
		reqs = reqs[:maxBarkRequests]
	}
	if len(reqs) == 0 {
		return nil
	}
	files, ok := serve(reqs...)
	l.dbg("req file: %s -> %d file(s), ok=%v", requestsSummary(reqs), len(files), ok)
	if !ok {
		return nil
	}
	return files
}

// thenSource yields src, then more.
type thenSource struct {
	src  Source
	more []*OutFile
}

func (s *thenSource) Next() *OutFile {
	if s.src != nil {
		if f := s.src.Next(); f != nil {
			return f
		}
		s.src = nil
	}
	if len(s.more) == 0 {
		return nil
	}
	f := s.more[0]
	s.more = s.more[1:]
	return f
}

// withPickupPacket makes sure a pickup batch opens with a mail packet:
// FTS-0001 sends one unconditionally, and FrontDoor answered the EOT
// that stands for "no packet" with SUB once a second until it hung up
// (measured 2026-10-19).
func withPickupPacket(l *line, cfg Config, src Source) Source {
	var all []*OutFile
	for f := src.Next(); f != nil; f = src.Next() {
		if isPacketName(f.Name) {
			return &thenSource{src: &sliceSource{files: append(all, f)}, more: drain(src)}
		}
		all = append(all, f)
	}
	if cfg.PickupPacket != nil {
		if data, ok := cfg.PickupPacket(); ok {
			name := fmt.Sprintf("%08x.pkt", uint32(time.Now().Unix()))
			l.dbg("req file: an empty packet %s opens the pickup batch", name)
			all = append([]*OutFile{{Name: name, Data: data, Done: func(int64, error) {}}}, all...)
		}
	}
	return &sliceSource{files: all}
}

func drain(src Source) []*OutFile {
	var out []*OutFile
	for f := src.Next(); f != nil; f = src.Next() {
		out = append(out, f)
	}
	return out
}
