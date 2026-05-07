package main

import (
	"encoding/binary"
	"fmt"
)

const (
	dltEthernet   = 1
	dltLinuxCook  = 113
	dltRawIPv4    = 228
	dltRawBSD     = 12
)

// parseUDP extracts src/dst IP:port and UDP payload from a raw frame.
// Returns nil payload if the frame is not IPv4/UDP.
// Handles datalink types: 1 (Ethernet, with VLAN), 113 (Linux cooked SLL), 228/12 (raw IPv4).
func parseUDP(data []byte, datalink uint32) (srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	var ipStart int

	switch datalink {
	case dltEthernet:
		// Ethernet: 6 dst MAC + 6 src MAC = 12 bytes, then ethertype at 12-13
		if len(data) < 14 {
			return
		}
		ethertype := binary.BigEndian.Uint16(data[12:14])
		if ethertype == 0x8100 {
			// VLAN tag: skip 4 bytes, re-read ethertype
			if len(data) < 18 {
				return
			}
			ethertype = binary.BigEndian.Uint16(data[16:18])
			ipStart = 18
		} else {
			ipStart = 14
		}
		if ethertype != 0x0800 {
			return
		}

	case dltLinuxCook:
		// SLL header is 16 bytes; ethertype at bytes 14-15
		if len(data) < 16 {
			return
		}
		ethertype := binary.BigEndian.Uint16(data[14:16])
		if ethertype != 0x0800 {
			return
		}
		ipStart = 16

	case dltRawIPv4, dltRawBSD:
		// Data IS the IP header
		ipStart = 0

	default:
		return
	}

	return parseIPv4UDP(data[ipStart:])
}

// parseIPv4UDP parses an IPv4 packet and extracts UDP src/dst and payload.
func parseIPv4UDP(ip []byte) (srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	if len(ip) < 20 {
		return
	}

	version := ip[0] >> 4
	if version != 4 {
		return
	}

	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || len(ip) < ihl {
		return
	}

	proto := ip[9]
	if proto != 17 { // UDP
		return
	}

	srcIP = fmt.Sprintf("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15])
	dstIP = fmt.Sprintf("%d.%d.%d.%d", ip[16], ip[17], ip[18], ip[19])

	udp := ip[ihl:]
	if len(udp) < 8 {
		return
	}

	srcPort = binary.BigEndian.Uint16(udp[0:2])
	dstPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	payloadLen := udpLen - 8
	if payloadLen < 0 || len(udp) < 8+payloadLen {
		// Use whatever is available
		if len(udp) <= 8 {
			return
		}
		payload = udp[8:]
		return
	}
	payload = udp[8 : 8+payloadLen]
	return
}
