package main

// Endpoint represents an IP:port pair used as an RTP media endpoint.
type Endpoint struct {
	IP   string
	Port uint16
}

// CodecInfo holds the codec name and clock rate from an SDP a=rtpmap line.
type CodecInfo struct {
	Name      string
	ClockRate int
}

// Call holds all state for one SIP dialog.
type Call struct {
	CallID          string
	RequestUser     string
	Directory       string
	Endpoints       map[Endpoint]struct{} // all endpoints (for fast lookup)
	CallerEndpoints map[Endpoint]struct{} // endpoints from SDP in requests (INVITE)
	CalleeEndpoints map[Endpoint]struct{} // endpoints from SDP in responses (200 OK, 183)
	RTPMap          map[int]CodecInfo
	FinalCode       int     // last non-provisional SIP response code (≥200); 0 if none seen
	FinalReason     string  // reason phrase of FinalCode (e.g. "OK", "Busy Here")
	ConnectedAt     float64 // timestamp of first 200 OK to INVITE; 0 if not seen
	DisconnectedAt  float64 // timestamp of final response to BYE, or BYE request if no response seen; 0 if not seen

	// RTP quality metrics — populated after all packets are processed
	MOSMin   float64 // minimum MOS across streams (worst perceived quality); 0 = no RTP seen
	JitterMs float64 // average jitter in ms across streams
	LossPct  float64 // average packet loss % across streams

	// Media flow direction — set as RTP streams are identified
	HadCallerRTP bool // at least one RTP stream sent by caller was seen
	HadCalleeRTP bool // at least one RTP stream sent by callee was seen

	// internal RTP accumulators
	rtpCount  int
	rtpJSum   float64
	rtpLSum   float64
	rtpMOSMin float64
}

// recordRTPStream incorporates one stream's metrics into the call-level aggregates.
func (c *Call) recordRTPStream(jitterMs, lossPct, mos float64) {
	c.rtpCount++
	c.rtpJSum += jitterMs
	c.rtpLSum += lossPct
	if c.rtpCount == 1 || mos < c.rtpMOSMin {
		c.rtpMOSMin = mos
	}
	c.JitterMs = c.rtpJSum / float64(c.rtpCount)
	c.LossPct = c.rtpLSum / float64(c.rtpCount)
	c.MOSMin = c.rtpMOSMin
}

// rtpKey is the map key for per-SSRC pcap/wav writers.
// Using a struct avoids a fmt.Sprintf allocation on every RTP packet.
type rtpKey struct {
	callID string
	ssrc   uint32
}

// isIn reports whether ep exists in the given endpoint set.
func isIn(set map[Endpoint]struct{}, ep Endpoint) bool {
	_, ok := set[ep]
	return ok
}

// newCall creates a new Call with initialized maps.
func newCall(callID, requestUser, directory string) *Call {
	return &Call{
		CallID:          callID,
		RequestUser:     requestUser,
		Directory:       directory,
		Endpoints:       make(map[Endpoint]struct{}),
		CallerEndpoints: make(map[Endpoint]struct{}),
		CalleeEndpoints: make(map[Endpoint]struct{}),
		RTPMap:          make(map[int]CodecInfo),
	}
}
