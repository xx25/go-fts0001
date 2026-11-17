# fts0001

Pure Go implementation of the FTS-0001 mail session — the protocol FidoNet began with — together with its data link: XMODEM with the Telink header block, SEAlink's sliding window, and the MODEM7 filename exchange.

This is a library package — there is no CLI. It runs the transfer phase of a session on any `io.ReadWriter` (a modem line, a TCP socket): the caller's mail packet and attached files one way, the pickup the other. The TSYNC synchronisation (or the YooHoo handshake) that precedes it is not part of this package.

Two session modes are covered:

- **FTS-0001** proper: one mail packet, then the attached files by MODEM7 name, then the pickup turn; with Bark file requests (FTS-0008).
- **DietIFNA** (FTS-0006): the variant a YooHoo handshake selects, in which the same transfers carry every file under the name in its header block, with no MODEM7 names and no Bark.

## Features

- Both sides of a session: `Originate` (calling) and `Answer` (called), in either mode
- XMODEM with checksum or CRC-16, chosen by the receiver's poll
- Telink and SEAlink header blocks (name, size, timestamp), SEAlink's numbered acknowledgements, sliding window and RESYNC (FTS-0007)
- The MODEM7 filename handshake for attached files
- Bark file requests in both directions (FTS-0008), and WaZOO `.REQ` request files inside the batch for systems that never invite Bark
- The pickup turn, including the packet a called system must send when it answers a request
- Receive bounds: 64 MiB per file, and a sender that ends a file short of its announced size is an error, not a success
- Per-step read timeouts on any `io.ReadWriter`, without the connection supporting deadlines (see the note under Security on what that leaves open)
- Standard library only; no dependencies
- Interoperable with ifcico, mbcico, BinkleyTerm and FrontDoor

## Install

```
go get github.com/xx25/go-fts0001
```

## Usage

A session moves files in memory: a `Source` yields what to send, a `Sink` receives what arrives.

```go
package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"time"

	"github.com/xx25/go-fts0001"
)

// outbox yields the files to send; the mail packet comes first.
type outbox struct {
	files []*fts0001.OutFile
}

func (o *outbox) Next() *fts0001.OutFile {
	if len(o.files) == 0 {
		return nil // ends the batch
	}
	f := o.files[0]
	o.files = o.files[1:]
	return f
}

// inbox keeps what arrives in memory.
type inbox struct {
	files map[string]*bytes.Buffer
}

type buffer struct{ *bytes.Buffer }

func (buffer) Close() error { return nil }

func (i *inbox) Open(name string, size int64, mtime time.Time) (io.WriteCloser, error) {
	// name comes from the peer: never use it as a path unchecked.
	b := &bytes.Buffer{}
	i.files[name] = b
	return buffer{b}, nil
}

func (i *inbox) Done(name string, n int64, err error) {
	log.Printf("received %s: %d bytes, err=%v", name, n, err)
}

func main() {
	conn, err := net.Dial("tcp", "node.example.org:60179")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// The TSYNC synchronisation happens before this point. Originate
	// expects the receiver's first poll (NAK or 'C') as the next byte.
	packet := &fts0001.OutFile{
		Name:    "00000001.pkt",
		ModTime: time.Now(),
		Data:    []byte{ /* an FTS-0001 packet */ },
		Done: func(sent int64, err error) { // optional
			log.Printf("packet: %d bytes acknowledged, err=%v", sent, err)
		},
	}
	err = fts0001.Originate(context.Background(), conn,
		fts0001.Config{Mode: fts0001.ModeFTS0001, Program: "example"},
		&outbox{files: []*fts0001.OutFile{packet}},
		&inbox{files: map[string]*bytes.Buffer{}})
	if err != nil {
		log.Fatal(err)
	}
}
```

The called side runs `fts0001.Answer` with the same arguments: it receives first, then sends whatever its `Source` holds. `fts0001.Nothing{}` is a `Source` with no files and `fts0001.Discard{}` a `Sink` that drops everything.

## Configuration

| Field | Meaning | Default |
|---|---|---|
| `Mode` | `ModeFTS0001` or `ModeDietIFNA` | `ModeFTS0001` |
| `Program` | Our name in header blocks, up to 15 bytes | — |
| `PreferCRC` | Poll with `'C'` when receiving | true |
| `PacketName` | Name given to the mail packet we receive (the sender gives it none) | `<hex-time>.pkt` |
| `PickupWait` | How long the caller waits for the called system's turn | 30 s |
| `Serve` | Answers the peer's file requests; nil refuses them | nil |
| `RequestsAsFiles` | Send our `.req` files in the batch instead of as Bark packets | false |
| `PickupPacket` | Builds the mail packet for a pickup turn that answers a request file | nil |
| `Logger` | Debug logging | `slog.Default()` |

## Sentinel errors

| Error | Meaning |
|---|---|
| `ErrTimeout` | A step ran out of time |
| `ErrCarrierLost` | The connection dropped |
| `ErrCancelled` | The peer cancelled (CAN) |
| `ErrTooMany` | Too many errors on one block |
| `ErrTooLarge` | An incoming file exceeds the receive limit |
| `ErrShortFile` | The sender ended a file short of its announced size |
| `ErrBarkNotInvited` | The peer never invited our file requests; they wait for a later call |

All are matched with `errors.Is`.

## Security

- **File names come from the peer.** The name passed to `Sink.Open` is reduced to a bare file name (no path separators, no leading dot), but it is still the peer's choice: check it before using it in a path. Requested names are a different matter. A name in a Bark packet is reduced the same way, but the lines of a WaZOO `.REQ` file reach the `BarkServer` verbatim — `../../etc/passwd` included. A `BarkServer` must resolve every name against what it is willing to serve.
- **Files are held in memory.** A file to send is an `OutFile.Data` slice, in FTS-0001 mode the whole `Source` is read before the first block goes out (the mail packet has to be found and sent first), and an incoming file is bounded at 64 MiB. Size your process accordingly, or bound what you accept in your `Sink`.
- **Give it a connection that can time out.** Reads are bounded on any `io.ReadWriter`, but a write to a peer that has stopped reading is bounded only when the connection supports write deadlines (`net.Conn` does). On a bare reader/writer, a read that is in flight when the session ends stays parked until the connection is closed. Cancelling the context does not interrupt a wait in progress; waits end on their own timers.
- **FTS-0001 names nobody.** The session carries no address and no password; who the peer is must come from the layer above (a dialled number, a handshake, a packet header).
- **There is no encryption here.**

## License

MIT — see [LICENSE](LICENSE).
