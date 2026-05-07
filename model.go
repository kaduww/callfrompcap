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
	FinalCode       int    // last non-provisional SIP response code (≥200); 0 if none seen
	FinalReason     string // reason phrase of FinalCode (e.g. "OK", "Busy Here")
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
