package main

import "math"

// rtpStreamState accumulates per-SSRC metrics during packet processing.
type rtpStreamState struct {
	call      *Call
	clockRate int

	// packet counting
	received int64
	firstSeq uint16
	lastSeq  uint16
	hasFirst bool

	// jitter (RFC 3550 section 6.4.1)
	lastArrival float64 // capture timestamp of previous packet
	lastRTPTS   uint32  // RTP timestamp of previous packet
	jitterAcc   float64 // running estimate in RTP timestamp units
}

func newRTPStreamState(call *Call, clockRate int) *rtpStreamState {
	if clockRate <= 0 {
		clockRate = 8000
	}
	return &rtpStreamState{call: call, clockRate: clockRate}
}

// update processes one RTP packet. seq and rtpTS come from the RTP header;
// arrival is the packet capture timestamp in seconds.
func (s *rtpStreamState) update(seq uint16, rtpTS uint32, arrival float64) {
	s.received++
	if !s.hasFirst {
		s.firstSeq = seq
		s.lastSeq = seq
		s.lastArrival = arrival
		s.lastRTPTS = rtpTS
		s.hasFirst = true
		return
	}

	// Track highest sequence number (uint16 subtraction handles wraparound)
	if int16(seq-s.lastSeq) > 0 {
		s.lastSeq = seq
	}

	// RFC 3550 jitter — only update for in-sequence packets to avoid
	// polluting the estimator with reordering artifacts
	if seq == s.lastSeq {
		arrivalDelta := (arrival - s.lastArrival) * float64(s.clockRate)
		rtpDelta := float64(int32(rtpTS - s.lastRTPTS))
		d := arrivalDelta - rtpDelta
		if d < 0 {
			d = -d
		}
		s.jitterAcc += (d - s.jitterAcc) / 16.0
		s.lastArrival = arrival
		s.lastRTPTS = rtpTS
	}
}

// finalize computes final metrics and records them on the associated Call.
func (s *rtpStreamState) finalize() {
	if !s.hasFirst || s.received < 2 {
		return
	}

	// Jitter in ms
	jitterMs := s.jitterAcc * 1000.0 / float64(s.clockRate)

	// Packet loss — uint16 wraparound handled by the subtraction
	expected := int64(s.lastSeq-s.firstSeq) + 1
	if expected < s.received {
		expected = s.received // protect: can't lose more than expected
	}
	lost := expected - s.received
	if lost < 0 {
		lost = 0
	}
	lossPct := 0.0
	if expected > 0 {
		lossPct = float64(lost) * 100.0 / float64(expected)
	}

	mos := calcMOS(jitterMs, lossPct)
	s.call.recordRTPStream(jitterMs, lossPct, mos)
}

// calcMOS estimates MOS using Wireshark's simplified E-model.
// Since one-way delay is unknown from a single capture point, effective
// latency is approximated as jitter*2 + 10 ms (Wireshark's heuristic).
func calcMOS(jitterMs, lossPct float64) float64 {
	effectiveLatency := jitterMs*2 + 10

	var R float64
	if effectiveLatency < 160 {
		R = 93.2 - effectiveLatency/40.0
	} else {
		R = 93.2 - (effectiveLatency-120.0)/10.0
	}
	R -= lossPct * 2.5

	if R < 0 {
		return 1.0
	}
	if R > 100 {
		return 4.5
	}

	mos := 1.0 + 0.035*R + 7e-6*R*(R-60)*(100-R)
	mos = math.Round(mos*100) / 100
	if mos < 1.0 {
		return 1.0
	}
	if mos > 4.5 {
		return 4.5
	}
	return mos
}
