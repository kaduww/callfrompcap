package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	pcapMagicLE     = 0xa1b2c3d4 // little-endian microseconds
	pcapMagicLENano = 0xa1b23c4d // little-endian nanoseconds
	pcapNGMagic     = 0x0A0D0D0A // pcapng section header block type
	pcapReadBufSize = 1 * 1024 * 1024 // 1 MB
	pcapWriteBufSize = 64 * 1024       // 64 KB
	pcapSnaplen      = 65535
)

// PcapReader reads packets from a PCAP file one at a time.
type PcapReader struct {
	f         *os.File
	r         *bufio.Reader
	byteOrder binary.ByteOrder
	nanos     bool
	datalink  uint32
	bytesRead int64
	buf       []byte // reusable packet buffer; valid only until the next Next() call
}

// Open opens a PCAP file and parses the global header.
func Open(path string) (*PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	r := bufio.NewReaderSize(f, pcapReadBufSize)

	// Read raw magic bytes to detect byte order and format
	var magicBytes [4]byte
	if _, err := io.ReadFull(r, magicBytes[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading pcap magic: %w", err)
	}

	// Check for pcapng (byte order independent)
	magicNG := binary.LittleEndian.Uint32(magicBytes[:])
	if magicNG == pcapNGMagic {
		f.Close()
		return nil, fmt.Errorf("pcapng format is not supported; convert with: tshark -r input.pcapng -w output.pcap")
	}

	var byteOrder binary.ByteOrder
	var nanos bool

	magicLE := binary.LittleEndian.Uint32(magicBytes[:])
	magicBE := binary.BigEndian.Uint32(magicBytes[:])

	switch {
	case magicLE == pcapMagicLE:
		byteOrder = binary.LittleEndian
		nanos = false
	case magicLE == pcapMagicLENano:
		byteOrder = binary.LittleEndian
		nanos = true
	case magicBE == pcapMagicLE:
		byteOrder = binary.BigEndian
		nanos = false
	case magicBE == pcapMagicLENano:
		byteOrder = binary.BigEndian
		nanos = true
	default:
		f.Close()
		return nil, fmt.Errorf("unknown pcap magic: 0x%08x", magicLE)
	}

	// Read the rest of the global header (20 bytes after magic)
	var hdr struct {
		Major    uint16
		Minor    uint16
		Thiszone int32
		Sigfigs  uint32
		Snaplen  uint32
		Network  uint32
	}
	if err := binary.Read(r, byteOrder, &hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading pcap global header: %w", err)
	}

	return &PcapReader{
		f:         f,
		r:         r,
		byteOrder: byteOrder,
		nanos:     nanos,
		datalink:  hdr.Network,
		bytesRead: 24, // global header already consumed (4 magic + 20 fields)
	}, nil
}

// Next returns the next packet. Returns io.EOF when done.
// ts is the packet timestamp in seconds (fractional).
func (p *PcapReader) Next() (ts float64, data []byte, err error) {
	var hdr struct {
		TsSec   uint32
		TsUsec  uint32 // may be nanoseconds depending on magic
		InclLen uint32
		OrigLen uint32
	}
	if err := binary.Read(p.r, p.byteOrder, &hdr); err != nil {
		return 0, nil, err // returns io.EOF naturally
	}

	var frac float64
	if p.nanos {
		frac = float64(hdr.TsUsec) / 1e9
	} else {
		frac = float64(hdr.TsUsec) / 1e6
	}
	ts = float64(hdr.TsSec) + frac

	if uint32(cap(p.buf)) < hdr.InclLen {
		p.buf = make([]byte, hdr.InclLen)
	} else {
		p.buf = p.buf[:hdr.InclLen]
	}
	if _, err := io.ReadFull(p.r, p.buf); err != nil {
		return 0, nil, fmt.Errorf("reading packet data: %w", err)
	}
	p.bytesRead += 16 + int64(hdr.InclLen) // 16 = packet record header (4×uint32)
	return ts, p.buf, nil
}

// IsTruncated reports whether err from Next() means the file ended in the
// middle of a packet record (a truncated or corrupt capture) rather than at a
// clean record boundary. Callers should treat this as end-of-file, keeping the
// packets read so far, instead of aborting the whole run.
func IsTruncated(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF)
}

// BytesRead returns the number of bytes consumed from the file so far.
func (p *PcapReader) BytesRead() int64 {
	return p.bytesRead
}

// Datalink returns the datalink type from the PCAP global header.
func (p *PcapReader) Datalink() uint32 {
	return p.datalink
}

// Close closes the underlying file.
func (p *PcapReader) Close() error {
	return p.f.Close()
}

// PcapWriter writes packets to a PCAP file.
type PcapWriter struct {
	f  *os.File
	w  *bufio.Writer
}

// NewPcapWriter creates a new PCAP file with the given datalink type.
func NewPcapWriter(path string, datalink uint32) (*PcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(f, pcapWriteBufSize)

	// Write global header (LE, microseconds) - fields written individually for correct types
	if err := binary.Write(w, binary.LittleEndian, uint32(pcapMagicLE)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(2)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, uint16(4)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, int32(0)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(0)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(pcapSnaplen)); err != nil {
		f.Close()
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, datalink); err != nil {
		f.Close()
		return nil, err
	}

	return &PcapWriter{f: f, w: w}, nil
}

// Write writes a packet to the PCAP file.
func (pw *PcapWriter) Write(ts float64, data []byte) error {
	sec := uint32(math.Floor(ts))
	usec := uint32((ts - math.Floor(ts)) * 1e6)
	incl := uint32(len(data))

	if err := binary.Write(pw.w, binary.LittleEndian, sec); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, usec); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, incl); err != nil {
		return err
	}
	if err := binary.Write(pw.w, binary.LittleEndian, incl); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}

// Close flushes and closes the PCAP writer.
func (pw *PcapWriter) Close() error {
	if err := pw.w.Flush(); err != nil {
		pw.f.Close()
		return err
	}
	return pw.f.Close()
}
