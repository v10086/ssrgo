package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	AddrTypeIPv4    = 1
	AddrTypeHost    = 3
	AddrTypeIPv6    = 4
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

type HeaderData struct {
	AddrType  int
	DestAddr  string
	DestPort  int
	HeaderLen int
}

func ParseSocket5Header(buffer []byte) (*HeaderData, error) {
	if len(buffer) < 1 {
		return nil, fmt.Errorf("invalid length for header")
	}

	addrType := int(buffer[0])
	header := &HeaderData{
		AddrType: addrType,
	}

	switch addrType {
	case AddrTypeIPv4:
		header.HeaderLen = 7
		if len(buffer) < header.HeaderLen {
			return nil, fmt.Errorf("invalid length for ipv4 address")
		}
		ip := net.IPv4(buffer[1], buffer[2], buffer[3], buffer[4])
		header.DestAddr = ip.String()
		header.DestPort = int(binary.BigEndian.Uint16(buffer[5:7]))

	case AddrTypeHost:
		if len(buffer) < 2 {
			return nil, fmt.Errorf("invalid length host name length")
		}
		addrLen := int(buffer[1])
		header.HeaderLen = addrLen + 4
		if len(buffer) < header.HeaderLen {
			return nil, fmt.Errorf("invalid host name length")
		}
		header.DestAddr = string(buffer[2 : 2+addrLen])
		header.DestPort = int(binary.BigEndian.Uint16(buffer[2+addrLen : 2+addrLen+2]))

	case AddrTypeIPv6:
		header.HeaderLen = 19
		if len(buffer) < header.HeaderLen {
			return nil, fmt.Errorf("invalid length for ipv6 address")
		}
		ip := net.IP(buffer[1:17])
		header.DestAddr = ip.String()
		header.DestPort = int(binary.BigEndian.Uint16(buffer[17:19]))

	default:
		return nil, fmt.Errorf("unsupported addrtype %d", addrType)
	}

	return header, nil
}

func PackHeader(addr string, addrType, port int) ([]byte, error) {
	var header []byte

	switch addrType {
	case AddrTypeIPv4:
		header = append(header, AddrTypeIPv4)
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", addr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			ipv4 = ip
		}
		header = append(header, ipv4...)

	case AddrTypeIPv6:
		header = append(header, AddrTypeIPv6)
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", addr)
		}
		header = append(header, ip...)

	case AddrTypeHost:
		if len(addr) > 255 {
			addr = addr[:255]
		}
		header = append(header, AddrTypeHost)
		header = append(header, byte(len(addr)))
		header = append(header, []byte(addr)...)

	default:
		return nil, fmt.Errorf("unsupported addrtype: %d", addrType)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	header = append(header, portBuf...)

	return header, nil
}

func BuildSocks5AuthResponse() []byte {
	return []byte{0x05, 0x00}
}

func BuildSocks5ConnectResponse(localPort int) []byte {
	response := make([]byte, 10)
	response[0] = 0x05
	response[1] = 0x00
	response[2] = 0x00
	response[3] = 0x01
	binary.BigEndian.PutUint16(response[8:10], uint16(localPort))
	return response
}

func BuildSocks5UnsupportedCmd() []byte {
	return []byte{0x05, 0x07, 0x00, 0x01}
}

func BuildSocks5Error() []byte {
	return []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

type Stage int

const (
	StageInit       Stage = 0
	StageAddr       Stage = 1
	StageUdpAssoc   Stage = 2
	StageDns        Stage = 3
	StageConnecting Stage = 4
	StageStream     Stage = 5
	StageDestroyed  Stage = -1
)

func (s Stage) String() string {
	switch s {
	case StageInit:
		return "STAGE_INIT"
	case StageAddr:
		return "STAGE_ADDR"
	case StageUdpAssoc:
		return "STAGE_UDP_ASSOC"
	case StageDns:
		return "STAGE_DNS"
	case StageConnecting:
		return "STAGE_CONNECTING"
	case StageStream:
		return "STAGE_STREAM"
	case StageDestroyed:
		return "STAGE_DESTROYED"
	default:
		return "UNKNOWN"
	}
}
