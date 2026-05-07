package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// analyze performs a single-pass analysis over one or more PCAP files,
// processing both SIP and RTP packets while maintaining a shared call context.
// methodFilter: set of uppercase SIP methods to accept (empty = accept all).
// Returns the map of calls (call_id -> *Call).
func analyze(pcapFiles []string, outputDir string, methodFilter map[string]struct{}) (map[string]*Call, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	var totalBytes int64
	for _, f := range pcapFiles {
		if fi, err := os.Stat(f); err == nil {
			totalBytes += fi.Size()
		}
	}

	calls := make(map[string]*Call)
	endpointMap := make(map[Endpoint]*Call)
	usedDirs := make(map[string]struct{})
	rejectedIDs := make(map[string]struct{})
	pcapWriters := make(map[rtpKey]*PcapWriter)
	wavWriters := make(map[rtpKey]audioWriter)
	cache := newSipFileCache()
	prog := newProgress(totalBytes)

	defer func() {
		cache.closeAll()
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
			return nil, fmt.Errorf("%s: %w", pcapFile, err)
		}
		datalink := reader.Datalink()

		for {
			ts, data, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				reader.Close()
				return nil, fmt.Errorf("%s: reading packet: %w", pcapFile, err)
			}

			srcIP, dstIP, srcPort, dstPort, udpPayload := parseUDP(data, datalink)
			extra := fmt.Sprintf("%d calls  %d streams", len(calls), len(pcapWriters))
			if len(udpPayload) == 0 {
				prog.tick(bytesOffset+reader.BytesRead(), extra)
				continue
			}

			if (udpPayload[0] & 0xC0) == 0x80 {
				// RTP v2 packet
				if err := processRTPPkt(
					ts, srcIP, dstIP, srcPort, dstPort,
					data, udpPayload, datalink,
					endpointMap, pcapWriters, wavWriters, outputDir,
				); err != nil {
					logEvent("[warn]  %v", err)
				}
			} else if udpPayload[0] >= 0x20 && udpPayload[0] <= 0x7e {
				// Printable ASCII start — likely SIP
				pkt := sipPkt{
					timestamp: ts,
					srcIP:     srcIP,
					dstIP:     dstIP,
					srcPort:   srcPort,
					dstPort:   dstPort,
					payload:   udpPayload,
				}
				if err := processSIPPkt(pkt, calls, endpointMap, usedDirs, outputDir, cache, methodFilter, rejectedIDs); err != nil {
					logEvent("[warn]  %v", err)
				}
			}

			prog.tick(bytesOffset+reader.BytesRead(), extra)
		}

		bytesOffset += reader.BytesRead()
		reader.Close()
	}

	prog.done(totalBytes, fmt.Sprintf("%d calls  %d streams", len(calls), len(pcapWriters)))
	return calls, nil
}
