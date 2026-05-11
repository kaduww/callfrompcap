package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// G.711 lookup tables (built at init time, 256 entries each)
var ulawTable [256]int16
var alawTable [256]int16

func init() {
	// Build ulaw decode table (matches CPython audioop ulaw2lin)
	for i := 0; i < 256; i++ {
		b := byte(^i) // complement bits
		sign := (b >> 7) & 1
		exp := (b >> 4) & 0x07
		mantissa := b & 0x0f
		sample := int16((int(mantissa)<<1 + 33) << (int(exp) + 2))
		if sign != 0 {
			sample = -sample
		}
		ulawTable[i] = sample
	}

	// Build alaw decode table (matches CPython audioop alaw2lin)
	for i := 0; i < 256; i++ {
		b := byte(i ^ 0x55)
		sign := (b >> 7) & 1
		exp := (b >> 4) & 0x07
		mantissa := b & 0x0f
		var sample int16
		if exp == 0 {
			sample = int16((int(mantissa)<<1 + 1) << 1)
		} else {
			sample = int16((int(mantissa)<<1 + 33) << int(exp))
		}
		if sign == 0 {
			sample = -sample
		}
		alawTable[i] = sample
	}
}

// rtpPayloadType extracts RTP payload type from header byte 1 (mask 0x7F).
func rtpPayloadType(payload []byte) int {
	if len(payload) < 2 {
		return -1
	}
	return int(payload[1] & 0x7F)
}

// rtpAudioPayload strips the RTP fixed header plus any CSRC list and extension header.
// Returns the raw codec payload, or nil if the packet is malformed.
func rtpAudioPayload(rtpBytes []byte) []byte {
	if len(rtpBytes) < 12 {
		return nil
	}
	cc := int(rtpBytes[0] & 0x0F)
	offset := 12 + cc*4
	if rtpBytes[0]&0x10 != 0 { // extension bit
		if len(rtpBytes) < offset+4 {
			return nil
		}
		extWords := int(binary.BigEndian.Uint16(rtpBytes[offset+2 : offset+4]))
		offset += 4 + extWords*4
	}
	if offset >= len(rtpBytes) {
		return nil
	}
	return rtpBytes[offset:]
}

// wavHeader holds metadata for a WAV file being written.
const wavHeaderSize = 44 // RIFF(4)+size(4)+WAVE(4) + fmt (4)+chunksize(4)+pcm(2)+mono(2)+rate(4)+byterate(4)+blockalign(2)+bits(2) + data(4)+datasize(4)

// WavWriter writes a 16-bit mono PCM WAV file incrementally.
// Uses WriteAt to patch the header sizes on Close.
type WavWriter struct {
	f          *os.File
	bw         *bufio.Writer // 64 KB write buffer; must be flushed before WriteAt in close()
	sampleRate int
	dataBytes  int64
	buf        []byte // reusable G.711 decode buffer; grown as needed
}

// newWavWriter creates a new WAV file at path.
func newWavWriter(path string, sampleRate int) (*WavWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	bw := bufio.NewWriterSize(f, 64*1024)
	w := &WavWriter{f: f, bw: bw, sampleRate: sampleRate}

	// Write placeholder header (zeros for sizes, will patch on close)
	header := make([]byte, wavHeaderSize)
	copy(header[0:], "RIFF")
	// bytes 4-7: file size - 8 (placeholder)
	copy(header[8:], "WAVE")
	copy(header[12:], "fmt ")
	binary.LittleEndian.PutUint32(header[16:], 16) // fmt chunk size
	binary.LittleEndian.PutUint16(header[20:], 1)  // PCM format
	binary.LittleEndian.PutUint16(header[22:], 1)  // mono
	binary.LittleEndian.PutUint32(header[24:], uint32(sampleRate))
	binary.LittleEndian.PutUint32(header[28:], uint32(sampleRate*2)) // byte rate = rate * channels * bits/8
	binary.LittleEndian.PutUint16(header[32:], 2)                    // block align
	binary.LittleEndian.PutUint16(header[34:], 16)                   // bits per sample
	copy(header[36:], "data")
	// bytes 40-43: data chunk size (placeholder)

	if _, err := bw.Write(header); err != nil {
		f.Close()
		return nil, err
	}

	return w, nil
}

// writePacket decodes G.711 samples from an RTP packet and writes them to the WAV file.
// rtpPayload is the raw full RTP packet (including RTP header).
// pt is the payload type; rtpMap is the dynamic codec map for the call.
func (w *WavWriter) writePacket(rtpPayload []byte, pt int, rtpMap map[int]CodecInfo) {
	audio := rtpAudioPayload(rtpPayload)
	if len(audio) == 0 {
		return
	}

	// Determine if PCMU or PCMA
	isUlaw := false
	switch pt {
	case 0: // PCMU static
		isUlaw = true
	case 8: // PCMA static
		isUlaw = false
	default:
		// Check dynamic map
		if codec, ok := rtpMap[pt]; ok {
			switch strings.ToUpper(codec.Name) {
			case "PCMU":
				isUlaw = true
			case "PCMA":
				isUlaw = false
			default:
				return // unsupported codec in WavWriter
			}
		} else {
			return
		}
	}

	// Decode each sample into the reusable buffer, growing it only when needed
	need := len(audio) * 2
	if cap(w.buf) < need {
		w.buf = make([]byte, need)
	} else {
		w.buf = w.buf[:need]
	}
	if isUlaw {
		for i, b := range audio {
			s := ulawTable[b]
			binary.LittleEndian.PutUint16(w.buf[i*2:], uint16(s))
		}
	} else {
		for i, b := range audio {
			s := alawTable[b]
			binary.LittleEndian.PutUint16(w.buf[i*2:], uint16(s))
		}
	}

	if _, err := w.bw.Write(w.buf); err == nil {
		w.dataBytes += int64(need)
	}
}

// close flushes the write buffer, patches the WAV header with correct sizes, and closes the file.
func (w *WavWriter) close() error {
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}

	// Patch "data" chunk size at offset 40
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(w.dataBytes))
	if _, err := w.f.WriteAt(hdr[:], 40); err != nil {
		w.f.Close()
		return err
	}

	// Patch "RIFF" chunk size at offset 4: 36 + dataBytes
	binary.LittleEndian.PutUint32(hdr[:], uint32(36+w.dataBytes))
	if _, err := w.f.WriteAt(hdr[:], 4); err != nil {
		w.f.Close()
		return err
	}

	return w.f.Close()
}

// FfmpegWriter pipes raw RTP payloads to ffmpeg for G.729/G.722 decode.
type FfmpegWriter struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	dead   bool
}

// newFfmpegWriter starts an ffmpeg process writing to path.
// format is the ffmpeg input format string (e.g. "g722", "g729").
func newFfmpegWriter(path, format string) (*FfmpegWriter, error) {
	args := []string{"-y", "-f", format, "-ac", "1", "-i", "pipe:0", path}
	cmd := exec.Command("ffmpeg", args...)
	cmd.Stderr = io.Discard

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ffmpeg stdin pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting ffmpeg: %w", err)
	}

	return &FfmpegWriter{cmd: cmd, stdin: stdin}, nil
}

// writePacket sends raw RTP audio payload bytes to ffmpeg stdin.
// payload is the full RTP packet; the RTP header is stripped first.
func (w *FfmpegWriter) writePacket(_ float64, payload []byte) {
	if w.dead {
		return
	}
	audio := rtpAudioPayload(payload)
	if len(audio) == 0 {
		return
	}
	if _, err := w.stdin.Write(audio); err != nil {
		w.dead = true
	}
}

// close closes ffmpeg stdin and waits for the process to finish.
func (w *FfmpegWriter) close() error {
	if !w.dead {
		w.stdin.Close()
	}
	return w.cmd.Wait()
}

// audioWriter is the common interface for WavWriter and FfmpegWriter.
type audioWriter interface {
	writePacket(ts float64, payload []byte)
	close() error
}

// wavWriterAdapter wraps WavWriter to satisfy audioWriter (adapts the extra args).
type wavWriterAdapter struct {
	w      *WavWriter
	pt     int
	rtpMap map[int]CodecInfo
}

func (a *wavWriterAdapter) writePacket(_ float64, payload []byte) {
	a.w.writePacket(payload, a.pt, a.rtpMap)
}

func (a *wavWriterAdapter) close() error {
	return a.w.close()
}

// ffmpegAvailable checks if ffmpeg is in PATH.
func ffmpegAvailable() bool {
	_, err := exec.LookPath("ffmpeg")
	return err == nil
}

// makeWriter returns the appropriate audio writer for a given payload type and rtpmap.
// Priority:
//  1. Static G.711 (PT 0=PCMU, PT 8=PCMA)
//  2. Dynamic PT via rtpmap matched to G.711/G.729/G.722
//  3. Static ffmpeg PTs (PT 9=G.722, PT 18=G.729)
//
// Returns nil if codec is unsupported or ffmpeg not found.
func makeWriter(path string, pt int, rtpMap map[int]CodecInfo) (audioWriter, error) {
	// 1. Static G.711 PTs
	switch pt {
	case 0: // PCMU
		ww, err := newWavWriter(path, 8000)
		if err != nil {
			return nil, err
		}
		return &wavWriterAdapter{w: ww, pt: pt, rtpMap: rtpMap}, nil
	case 8: // PCMA
		ww, err := newWavWriter(path, 8000)
		if err != nil {
			return nil, err
		}
		return &wavWriterAdapter{w: ww, pt: pt, rtpMap: rtpMap}, nil
	}

	// 2. Dynamic PT via rtpmap
	if codec, ok := rtpMap[pt]; ok {
		name := strings.ToUpper(codec.Name)
		switch name {
		case "PCMU":
			ww, err := newWavWriter(path, codec.ClockRate)
			if err != nil {
				return nil, err
			}
			return &wavWriterAdapter{w: ww, pt: pt, rtpMap: rtpMap}, nil
		case "PCMA":
			ww, err := newWavWriter(path, codec.ClockRate)
			if err != nil {
				return nil, err
			}
			return &wavWriterAdapter{w: ww, pt: pt, rtpMap: rtpMap}, nil
		case "G722":
			if ffmpegAvailable() {
				return newFfmpegWriter(path, "g722")
			}
			return nil, nil
		case "G729", "G729A", "G729B":
			if ffmpegAvailable() {
				return newFfmpegWriter(path, "g729")
			}
			return nil, nil
		}
	}

	// 3. Static ffmpeg PTs
	switch pt {
	case 9: // G.722
		if ffmpegAvailable() {
			return newFfmpegWriter(path, "g722")
		}
	case 18: // G.729
		if ffmpegAvailable() {
			return newFfmpegWriter(path, "g729")
		}
	}

	return nil, nil
}

// mixCallAudio mixes all rtp_*.wav files in dir into rtp_mixed.wav using ffmpeg amix.
// Returns (false, nil) when there are fewer than 2 WAV files (nothing to mix).
func mixCallAudio(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}

	var wavFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rtp_") && strings.HasSuffix(e.Name(), ".wav") {
			wavFiles = append(wavFiles, filepath.Join(dir, e.Name()))
		}
	}

	if len(wavFiles) < 2 {
		return false, nil
	}

	if !ffmpegAvailable() {
		return false, fmt.Errorf("ffmpeg not found — cannot mix audio")
	}

	outPath := filepath.Join(dir, "rtp_mixed.wav")
	args := []string{"-y"}
	for _, f := range wavFiles {
		args = append(args, "-i", f)
	}
	args = append(args,
		"-filter_complex", fmt.Sprintf("amix=inputs=%d:duration=longest:normalize=0", len(wavFiles)),
		outPath,
	)

	cmd := exec.Command("ffmpeg", args...)
	cmd.Stderr = io.Discard
	return true, cmd.Run()
}

// Ring-tone detection constants.
const (
	rdSilenceRMS = 500.0 // RMS below this = silence (int16 scale, ~−42 dBFS)
	rdMinOnSec   = 0.30  // min ring burst duration (s)
	rdMaxOnSec   = 3.00  // max ring burst duration (s)
	rdMinOffSec  = 0.80  // min silence between ring bursts (s)
	rdMaxOffSec  = 7.00  // max silence between ring bursts (s)
	rdMaxBufSec  = 30.0  // safety cap: flush buffer after this many seconds of early media
)

// rdFrame is one buffered RTP frame with its energy level for cadence analysis.
type rdFrame struct {
	ts      float64
	payload []byte
	energy  float64
}

// isG711Codec reports whether the payload type resolves to G.711 PCMU or PCMA
// (either via static PT 0/8 or via a dynamic rtpmap entry).
func isG711Codec(pt int, rtpMap map[int]CodecInfo) bool {
	if pt == 0 || pt == 8 {
		return true
	}
	if codec, ok := rtpMap[pt]; ok {
		name := strings.ToUpper(codec.Name)
		return name == "PCMU" || name == "PCMA"
	}
	return false
}

// calcEnergy returns the RMS energy of the audio in one G.711 RTP packet
// (int16 scale). Returns 0 for non-G.711 codecs — ring detection is only
// enabled for G.711 where decoded amplitude is comparable to the fixed
// silence threshold.
func calcEnergy(payload []byte, pt int, rtpMap map[int]CodecInfo) float64 {
	audio := rtpAudioPayload(payload)
	if len(audio) == 0 {
		return 0
	}
	isUlaw := pt == 0
	if pt != 0 && pt != 8 {
		codec, ok := rtpMap[pt]
		if !ok {
			return 0
		}
		switch strings.ToUpper(codec.Name) {
		case "PCMU":
			isUlaw = true
		case "PCMA":
			isUlaw = false
		default:
			return 0
		}
	}
	var sum int64
	if isUlaw {
		for _, b := range audio {
			s := int64(ulawTable[b])
			sum += s * s
		}
	} else {
		for _, b := range audio {
			s := int64(alawTable[b])
			sum += s * s
		}
	}
	return math.Sqrt(float64(sum) / float64(len(audio)))
}

// findRingEnd analyses buffered early-media frames and returns the index of the
// first frame that is NOT part of a leading ring-tone sequence.
// Returns 0 when no ring cadence is detected (caller should write all frames).
func findRingEnd(frames []rdFrame) int {
	if len(frames) < 5 {
		return 0
	}

	type segment struct {
		active   bool
		startIdx int
		endIdx   int
	}
	var segs []segment
	cur := segment{active: frames[0].energy > rdSilenceRMS, startIdx: 0}
	for i := 1; i < len(frames); i++ {
		isActive := frames[i].energy > rdSilenceRMS
		if isActive != cur.active {
			cur.endIdx = i - 1
			segs = append(segs, cur)
			cur = segment{active: isActive, startIdx: i}
		}
	}
	cur.endIdx = len(frames) - 1
	segs = append(segs, cur)

	// Estimate frame duration from the buffer span (handles G.711@20ms,
	// G.722@10ms, etc.). The +frameDur term accounts for the last frame
	// that the ts-difference alone would miss.
	frameDur := 0.02
	if len(frames) >= 2 {
		if d := (frames[len(frames)-1].ts - frames[0].ts) / float64(len(frames)-1); d > 0 && d <= 0.5 {
			frameDur = d
		}
	}
	segDur := func(s segment) float64 {
		return frames[s.endIdx].ts - frames[s.startIdx].ts + frameDur
	}

	// Allow an optional leading silence (stream captured during a ring-off period).
	start := 0
	if !segs[0].active && segDur(segs[0]) >= rdMinOffSec {
		start = 1
	}

	ringEndIdx := -1
	i := start
	for i+1 < len(segs) {
		on, off := segs[i], segs[i+1]
		onDur, offDur := segDur(on), segDur(off)
		if on.active &&
			onDur >= rdMinOnSec && onDur <= rdMaxOnSec &&
			!off.active &&
			offDur >= rdMinOffSec && offDur <= rdMaxOffSec {
			ringEndIdx = off.endIdx + 1
			i += 2
		} else {
			break
		}
	}

	// Consume a trailing active burst that matches ring duration (buffer may end mid-cycle).
	if ringEndIdx >= 0 && i < len(segs) && segs[i].active {
		if d := segDur(segs[i]); d >= rdMinOnSec && d <= rdMaxOnSec {
			ringEndIdx = segs[i].endIdx + 1
		}
	}

	if ringEndIdx <= 0 || ringEndIdx >= len(frames) {
		return 0
	}
	return ringEndIdx
}

// RingDetector wraps an audioWriter, buffers early-media frames (before the call
// is answered), detects ring-tone cadence, and suppresses those frames before
// forwarding the rest to the underlying writer.
type RingDetector struct {
	inner  audioWriter
	call   *Call
	pt     int
	rtpMap map[int]CodecInfo
	role   string
	ssrc   uint32
	buf    []rdFrame
	pass   bool // true = passthrough, no more buffering
}

func newRingDetector(inner audioWriter, call *Call, pt int, rtpMap map[int]CodecInfo, role string, ssrc uint32) *RingDetector {
	return &RingDetector{inner: inner, call: call, pt: pt, rtpMap: rtpMap, role: role, ssrc: ssrc}
}

func (r *RingDetector) writePacket(ts float64, payload []byte) {
	if r.pass {
		r.inner.writePacket(ts, payload)
		return
	}

	connectedAt := r.call.ConnectedAt
	if connectedAt > 0 && ts >= connectedAt {
		r.flushBuf()
		r.pass = true
		r.inner.writePacket(ts, payload)
		return
	}

	energy := calcEnergy(payload, r.pt, r.rtpMap)
	r.buf = append(r.buf, rdFrame{
		ts:      ts,
		payload: append([]byte(nil), payload...),
		energy:  energy,
	})

	// Safety cap: flush unconditionally if buffer grows beyond rdMaxBufSec.
	if len(r.buf) > 1 && r.buf[len(r.buf)-1].ts-r.buf[0].ts > rdMaxBufSec {
		r.flushBuf()
		r.pass = true
	}
}

func (r *RingDetector) flushBuf() {
	if len(r.buf) == 0 {
		return
	}
	start := findRingEnd(r.buf)
	if start > 0 {
		trimmedSec := r.buf[start-1].ts - r.buf[0].ts
		logEvent("[ring]  %s  %s ssrc=%08x  trimmed %d frames (~%.2fs)",
			r.call.CallID, r.role, r.ssrc, start, trimmedSec)
	}
	for _, f := range r.buf[start:] {
		r.inner.writePacket(f.ts, f.payload)
	}
	r.buf = nil
}

func (r *RingDetector) close() error {
	r.flushBuf()
	return r.inner.close()
}

// mixCallsAudio runs mixCallAudio for every call that has 2+ WAV streams.
func mixCallsAudio(calls map[string]*Call) {
	for _, call := range calls {
		mixed, err := mixCallAudio(call.Directory)
		if err != nil {
			logEvent("[warn]  mix %s: %v", call.CallID, err)
		} else if mixed {
			logEvent("[mix]   %s  →  rtp_mixed.wav", call.CallID)
		}
	}
}
