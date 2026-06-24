package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// sipPkt holds parsed data for one SIP packet.
type sipPkt struct {
	timestamp        float64
	srcIP, dstIP     string
	srcPort, dstPort uint16
	payload          []byte
}

// _SipFileCache keeps up to 500 sip_trace.txt handles open (LRU eviction).
type _SipFileCache struct {
	handles map[string]*os.File
	order   []string // insertion order for LRU (pop front to evict oldest)
}

const sipFileCacheMax = 500

// newSipFileCache creates a new _SipFileCache.
func newSipFileCache() *_SipFileCache {
	return &_SipFileCache{
		handles: make(map[string]*os.File),
		order:   make([]string, 0, sipFileCacheMax+1),
	}
}

// write opens path if not cached (evicting oldest if at capacity), then writes entry.
func (c *_SipFileCache) write(path, entry string) error {
	f, ok := c.handles[path]
	if !ok {
		// Evict oldest if at capacity
		if len(c.handles) >= sipFileCacheMax {
			oldest := c.order[0]
			c.order = c.order[1:]
			c.handles[oldest].Close()
			delete(c.handles, oldest)
		}
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		c.handles[path] = f
		c.order = append(c.order, path)
	}
	_, err := f.WriteString(entry)
	return err
}

// closeAll closes all open handles.
func (c *_SipFileCache) closeAll() {
	for _, f := range c.handles {
		f.Close()
	}
	c.handles = make(map[string]*os.File)
	c.order = c.order[:0]
}

var nonSafeRe = regexp.MustCompile(`[^A-Za-z0-9_\-]`)

// safeDirname creates a filesystem-safe directory name from a Call-ID.
// Replaces non-[A-Za-z0-9_-] with '_', limits to 100 chars.
// Resolves collisions by appending _2, _3, etc.
func safeDirname(callID string, usedDirs map[string]struct{}) string {
	base := nonSafeRe.ReplaceAllString(callID, "_")
	if len(base) > 100 {
		base = base[:100]
	}
	name := base
	counter := 2
	for {
		if _, exists := usedDirs[name]; !exists {
			break
		}
		name = fmt.Sprintf("%s_%d", base, counter)
		counter++
	}
	usedDirs[name] = struct{}{}
	return name
}

// fmtTimestamp formats a UNIX epoch float as "2006-01-02 15:04:05.000000 UTC".
func fmtTimestamp(epoch float64) string {
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return t.Format("2006-01-02 15:04:05.000000 UTC")
}

// processSIPPkt updates call state and appends to sip_trace.txt via cache.
// methodFilter: set of uppercase SIP methods to accept (empty = accept all).
// rejectedIDs: Call-IDs that failed the method filter; populated by this function.
func processSIPPkt(
	pkt sipPkt,
	calls map[string]*Call,
	endpointMap map[Endpoint]*Call,
	usedDirs map[string]struct{},
	outputDir string,
	cache *_SipFileCache,
	methodFilter map[string]struct{},
	rejectedIDs map[string]struct{},
) error {
	info := parseSIP(pkt.payload)
	if info.CallID == "" {
		return nil
	}

	// Skip calls that previously failed the method filter
	if _, rejected := rejectedIDs[info.CallID]; rejected {
		return nil
	}

	call, exists := calls[info.CallID]
	if !exists {
		// Apply method filter: only when we have a concrete method (request packet)
		if len(methodFilter) > 0 && info.Method != "" {
			if _, allowed := methodFilter[info.Method]; !allowed {
				rejectedIDs[info.CallID] = struct{}{}
				return nil
			}
		}
		dirname := safeDirname(info.CallID, usedDirs)
		callDir := filepath.Join(outputDir, dirname)
		if err := os.MkdirAll(callDir, 0755); err != nil {
			return fmt.Errorf("creating call directory %s: %w", callDir, err)
		}
		call = newCall(info.CallID, info.RequestUser, info.FromUser, pkt.srcIP, pkt.dstIP, callDir)
		calls[info.CallID] = call
		logEvent("[call]  %s  →  %s", call.CallID, callDir)
	} else {
		if info.RequestUser != "" && call.RequestUser == "" {
			call.RequestUser = info.RequestUser
		}
		if info.FromUser != "" && call.FromUser == "" {
			call.FromUser = info.FromUser
		}
	}

	// Add new SDP endpoints to endpointMap and call.Endpoints.
	// Endpoints from requests (INVITE) belong to caller; from responses (200, 183) to callee.
	isRequest := info.Method != ""
	for _, ep := range info.SDPEndpoints {
		if _, ok := call.Endpoints[ep]; !ok {
			call.Endpoints[ep] = struct{}{}
			endpointMap[ep] = call
		}
		if isRequest {
			call.CallerEndpoints[ep] = struct{}{}
		} else {
			call.CalleeEndpoints[ep] = struct{}{}
		}
	}

	// Merge RTPMap
	for pt, codec := range info.RTPMap {
		call.RTPMap[pt] = codec
	}

	// Track last non-provisional response code (≥200) as the call's final status
	if info.StatusCode >= 200 {
		call.FinalCode = info.StatusCode
		call.FinalReason = info.StatusReason
	}

	// Track call duration anchors
	switch {
	case info.StatusCode == 200 && info.CSeqMethod == "INVITE" && call.ConnectedAt == 0:
		// First 200 OK to INVITE = call established
		call.ConnectedAt = pkt.timestamp
	case info.Method == "BYE":
		// BYE request: tentative disconnect time (overwritten if response arrives)
		call.DisconnectedAt = pkt.timestamp
	case info.StatusCode >= 200 && info.CSeqMethod == "BYE":
		// Final response to BYE: authoritative disconnect time
		call.DisconnectedAt = pkt.timestamp
	}

	// Format SIP trace entry
	separator := strings.Repeat("=", 72)
	ts := fmtTimestamp(pkt.timestamp)
	entry := fmt.Sprintf(
		"%s\n%s  %s:%d --> %s:%d\n%s\n%s\n\n",
		separator,
		ts,
		pkt.srcIP, pkt.srcPort,
		pkt.dstIP, pkt.dstPort,
		separator,
		strings.TrimRight(info.Text, "\r\n\t "),
	)

	sipPath := filepath.Join(call.Directory, "sip_trace.txt")
	return cache.write(sipPath, entry)
}

// extractCalls streams SIP packets from one or more PCAP files,
// maintaining a shared call context across all files.
// methodFilter: set of uppercase SIP methods to accept (empty = accept all).
// Returns (endpointMap, calls, error).
func extractCalls(pcapFiles []string, outputDir string, methodFilter map[string]struct{}) (map[Endpoint]*Call, map[string]*Call, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("creating output directory: %w", err)
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
	cache := newSipFileCache()
	prog := newProgress(totalBytes)

	defer cache.closeAll()

	var bytesOffset int64
	for i, pcapFile := range pcapFiles {
		if len(pcapFiles) > 1 {
			logEvent("[file]  %s (%d/%d)", filepath.Base(pcapFile), i+1, len(pcapFiles))
		}

		reader, err := Open(pcapFile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", pcapFile, err)
		}
		datalink := reader.Datalink()

		for {
			ts, data, err := reader.Next()
			if err == io.EOF {
				break
			}
			if IsTruncated(err) {
				warnTruncated(pcapFile, err)
				break
			}
			if err != nil {
				reader.Close()
				return nil, nil, fmt.Errorf("%s: reading packet: %w", pcapFile, err)
			}

			srcIP, dstIP, srcPort, dstPort, udpPayload := parseUDP(data, datalink)
			extra := fmt.Sprintf("%d calls", len(calls))
			if len(udpPayload) == 0 {
				prog.tick(bytesOffset+reader.BytesRead(), extra)
				continue
			}

			// Check if payload looks like SIP (first byte printable ASCII)
			if udpPayload[0] < 0x20 || udpPayload[0] > 0x7e {
				prog.tick(bytesOffset+reader.BytesRead(), extra)
				continue
			}

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
			prog.tick(bytesOffset+reader.BytesRead(), extra)
		}

		bytesOffset += reader.BytesRead()
		reader.Close()
	}

	prog.done(totalBytes, fmt.Sprintf("%d calls", len(calls)))
	return endpointMap, calls, nil
}
