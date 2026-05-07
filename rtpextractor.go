package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// processRTPPkt processes one RTP packet: routes to call, writes pcap and wav.
func processRTPPkt(
	ts float64,
	srcIP, dstIP string,
	srcPort, dstPort uint16,
	rawPkt []byte,
	udpPayload []byte,
	datalink uint32,
	endpointMap map[Endpoint]*Call,
	pcapWriters map[rtpKey]*PcapWriter,
	wavWriters map[rtpKey]audioWriter,
	outputDir string,
) error {
	// Look up call via src or dst endpoint
	call := endpointMap[Endpoint{IP: srcIP, Port: srcPort}]
	if call == nil {
		call = endpointMap[Endpoint{IP: dstIP, Port: dstPort}]
	}
	if call == nil {
		return nil // silently skip unknown RTP
	}

	if len(udpPayload) < 12 {
		return nil
	}

	// Extract SSRC from RTP header bytes 8-11 (big-endian)
	ssrc := binary.BigEndian.Uint32(udpPayload[8:12])
	key := rtpKey{callID: call.CallID, ssrc: ssrc}

	if _, exists := pcapWriters[key]; !exists {
		// Determine caller/callee role by matching the packet's src/dst against
		// the endpoints collected from SDP in requests vs responses.
		srcEp := Endpoint{IP: srcIP, Port: srcPort}
		dstEp := Endpoint{IP: dstIP, Port: dstPort}
		role := "unknown"
		switch {
		case isIn(call.CallerEndpoints, srcEp):
			role = "caller"
		case isIn(call.CalleeEndpoints, srcEp):
			role = "callee"
		case isIn(call.CallerEndpoints, dstEp):
			// dst is caller's receive addr → src is callee sending to caller
			role = "callee"
		case isIn(call.CalleeEndpoints, dstEp):
			// dst is callee's receive addr → src is caller sending to callee
			role = "caller"
		}

		// Create PCAP writer for this SSRC stream
		pcapPath := fmt.Sprintf("%s/rtp_%s_%08x.pcap", call.Directory, role, ssrc)
		pw, err := NewPcapWriter(pcapPath, datalink)
		if err != nil {
			return fmt.Errorf("creating pcap writer %s: %w", pcapPath, err)
		}
		pcapWriters[key] = pw

		// Create audio writer for this SSRC stream
		pt := rtpPayloadType(udpPayload)
		wavPath := fmt.Sprintf("%s/rtp_%s_%08x.wav", call.Directory, role, ssrc)
		aw, err := makeWriter(wavPath, pt, call.RTPMap)
		if err != nil {
			logEvent("[warn]  rtp_%s_%08x: %v", role, ssrc, err)
		} else if aw != nil {
			wavWriters[key] = aw
		}

		logEvent("[rtp]   %s  %s  ssrc=%08x", call.CallID, role, ssrc)
	}

	// Write raw packet to PCAP
	if err := pcapWriters[key].Write(ts, rawPkt); err != nil {
		return fmt.Errorf("writing rtp pcap: %w", err)
	}

	// Write UDP payload to audio writer
	if aw, ok := wavWriters[key]; ok {
		aw.writePacket(udpPayload)
	}

	return nil
}

// extractRTP streams RTP packets from one or more PCAP files and writes per-SSRC files.
func extractRTP(pcapFiles []string, endpointMap map[Endpoint]*Call) error {
	var totalBytes int64
	for _, f := range pcapFiles {
		if fi, err := os.Stat(f); err == nil {
			totalBytes += fi.Size()
		}
	}

	pcapWriters := make(map[rtpKey]*PcapWriter)
	wavWriters := make(map[rtpKey]audioWriter)
	prog := newProgress(totalBytes)

	defer func() {
		for _, pw := range pcapWriters {
			pw.Close()
		}
		for _, aw := range wavWriters {
			aw.close()
		}
	}()

	var bytesOffset int64
	for i, pcapFile := range pcapFiles {
		if len(pcapFiles) > 1 {
			logEvent("[file]  %s (%d/%d)", filepath.Base(pcapFile), i+1, len(pcapFiles))
		}

		reader, err := Open(pcapFile)
		if err != nil {
			return fmt.Errorf("%s: %w", pcapFile, err)
		}
		datalink := reader.Datalink()

		for {
			ts, data, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				reader.Close()
				return fmt.Errorf("%s: reading packet: %w", pcapFile, err)
			}

			srcIP, dstIP, srcPort, dstPort, udpPayload := parseUDP(data, datalink)
			extra := fmt.Sprintf("%d streams", len(pcapWriters))
			if len(udpPayload) == 0 {
				prog.tick(bytesOffset+reader.BytesRead(), extra)
				continue
			}

			// Check for RTP v2: top 2 bits of first byte = 10
			if (udpPayload[0] & 0xC0) != 0x80 {
				prog.tick(bytesOffset+reader.BytesRead(), extra)
				continue
			}

			if err := processRTPPkt(
				ts, srcIP, dstIP, srcPort, dstPort,
				data, udpPayload, datalink,
				endpointMap, pcapWriters, wavWriters, "",
			); err != nil {
				logEvent("[warn]  %v", err)
			}

			prog.tick(bytesOffset+reader.BytesRead(), extra)
		}

		bytesOffset += reader.BytesRead()
		reader.Close()
	}

	prog.done(totalBytes, fmt.Sprintf("%d streams", len(pcapWriters)))
	return nil
}

