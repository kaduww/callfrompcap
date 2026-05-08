package main

import (
	"strconv"
	"strings"
)

// SIPInfo holds parsed information from a SIP message.
type SIPInfo struct {
	CallID       string
	Method       string // request method (INVITE, REGISTER, …); empty for responses
	StatusCode   int    // response status code (100–699); 0 for requests
	StatusReason string // response reason phrase (e.g. "OK", "Busy Here"); empty for requests
	CSeqMethod   string // method from CSeq header (tells which request a response belongs to)
	RequestUser  string
	SDPEndpoints []Endpoint
	RTPMap       map[int]CodecInfo
	Text         string
}

// parseSIP parses raw SIP message bytes and returns a SIPInfo.
// Returns a SIPInfo with empty CallID if the message is not valid SIP.
func parseSIP(payload []byte) *SIPInfo {
	text := string(payload)
	info := &SIPInfo{
		Text:   text,
		RTPMap: make(map[int]CodecInfo),
	}

	// Split headers from body
	var headerBlock, body string
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		headerBlock = text[:idx]
		body = text[idx+4:]
	} else if idx := strings.Index(text, "\n\n"); idx >= 0 {
		headerBlock = text[:idx]
		body = text[idx+2:]
	} else {
		headerBlock = text
		body = ""
	}

	// Split header block into lines
	var headerLines []string
	if strings.Contains(headerBlock, "\r\n") {
		headerLines = strings.Split(headerBlock, "\r\n")
	} else {
		headerLines = strings.Split(headerBlock, "\n")
	}

	if len(headerLines) == 0 {
		return info
	}

	firstLine := strings.TrimSpace(headerLines[0])

	// Parse headers (skip first line)
	for _, line := range headerLines[1:] {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:colonIdx]))
		val := strings.TrimSpace(line[colonIdx+1:])

		if key == "call-id" || key == "i" {
			if info.CallID == "" {
				info.CallID = val
			}
		} else if key == "cseq" {
			// CSeq: <seq-number> <method>
			if f := strings.Fields(val); len(f) >= 2 {
				info.CSeqMethod = strings.ToUpper(f[1])
			}
		}
	}

	parts := strings.Fields(firstLine)
	if len(parts) >= 2 && parts[0] == "SIP/2.0" {
		// It's a response: "SIP/2.0 CODE Reason phrase..."
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				info.StatusCode = code
			}
		}
		if len(parts) >= 3 {
			info.StatusReason = strings.Join(parts[2:], " ")
		}
	} else if len(parts) >= 2 {
		// It's a request: parts[0]=method, parts[1]=Request-URI
		info.Method = strings.ToUpper(parts[0])
		uri := parts[1]
		// Match sip:USER@... or sip:USER;... or sip:USER?...
		if sipIdx := strings.Index(strings.ToLower(uri), "sip:"); sipIdx >= 0 {
			userPart := uri[sipIdx+4:]
			// Find end of user (at @, ;, ?, or whitespace)
			end := len(userPart)
			for i, ch := range userPart {
				if ch == '@' || ch == ';' || ch == '?' || ch == ' ' || ch == '\t' {
					end = i
					break
				}
			}
			info.RequestUser = userPart[:end]
		}
	}

	// Parse SDP body
	bodyLines := strings.Split(strings.ReplaceAll(body, "\r", ""), "\n")
	var sdpIP string
	inAudio := false

	for _, line := range bodyLines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "c=") {
			// c=IN IP4 <IP>
			f := strings.Fields(line)
			if len(f) >= 1 {
				addr := f[len(f)-1]
				if addr != "0.0.0.0" && addr != "::" {
					sdpIP = addr
				}
			}
		} else if strings.HasPrefix(line, "m=") {
			inAudio = strings.HasPrefix(line, "m=audio")
			if inAudio && sdpIP != "" {
				// m=audio <PORT> ...
				f := strings.Fields(line)
				if len(f) >= 2 {
					port, err := strconv.Atoi(f[1])
					if err == nil && port > 0 {
						ep := Endpoint{IP: sdpIP, Port: uint16(port)}
						info.SDPEndpoints = append(info.SDPEndpoints, ep)
					}
				}
			}
		} else if strings.HasPrefix(line, "a=rtpmap:") && inAudio {
			// a=rtpmap:<PT> <NAME>/<RATE>[/<channels>]
			rest := line[9:] // after "a=rtpmap:"
			spaceIdx := strings.IndexByte(rest, ' ')
			if spaceIdx < 0 {
				continue
			}
			ptStr := rest[:spaceIdx]
			codecStr := rest[spaceIdx+1:]

			pt, err := strconv.Atoi(ptStr)
			if err != nil {
				continue
			}

			codecParts := strings.Split(codecStr, "/")
			codecName := strings.ToUpper(codecParts[0])
			clockRate := 8000
			if len(codecParts) > 1 {
				if cr, err := strconv.Atoi(codecParts[1]); err == nil {
					clockRate = cr
				}
			}
			info.RTPMap[pt] = CodecInfo{Name: codecName, ClockRate: clockRate}
		}
	}

	return info
}
