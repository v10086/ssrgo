package main

import (
	"testing"
)

func TestParseSocket5HeaderIPv4(t *testing.T) {
	data := []byte{1, 127, 0, 0, 1, 0, 80}
	header, err := ParseSocket5Header(data)
	if err != nil {
		t.Fatalf("ParseSocket5Header failed: %v", err)
	}

	if header.AddrType != AddrTypeIPv4 {
		t.Errorf("Expected addr type %d, got %d", AddrTypeIPv4, header.AddrType)
	}
	if header.DestAddr != "127.0.0.1" {
		t.Errorf("Expected dest addr %s, got %s", "127.0.0.1", header.DestAddr)
	}
	if header.DestPort != 80 {
		t.Errorf("Expected dest port %d, got %d", 80, header.DestPort)
	}
	if header.HeaderLen != 7 {
		t.Errorf("Expected header length %d, got %d", 7, header.HeaderLen)
	}
}

func TestParseSocket5HeaderHost(t *testing.T) {
	host := "example.com"
	data := []byte{3, byte(len(host))}
	data = append(data, []byte(host)...)
	data = append(data, 0x01, 0xBB)

	header, err := ParseSocket5Header(data)
	if err != nil {
		t.Fatalf("ParseSocket5Header failed: %v", err)
	}

	if header.AddrType != AddrTypeHost {
		t.Errorf("Expected addr type %d, got %d", AddrTypeHost, header.AddrType)
	}
	if header.DestAddr != host {
		t.Errorf("Expected dest addr %s, got %s", host, header.DestAddr)
	}
	if header.DestPort != 443 {
		t.Errorf("Expected dest port %d, got %d", 443, header.DestPort)
	}
}

func TestParseSocket5HeaderIPv6(t *testing.T) {
	data := []byte{4}
	ipv6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	data = append(data, ipv6...)
	data = append(data, 0x1F, 0x90)

	header, err := ParseSocket5Header(data)
	if err != nil {
		t.Fatalf("ParseSocket5Header failed: %v", err)
	}

	if header.AddrType != AddrTypeIPv6 {
		t.Errorf("Expected addr type %d, got %d", AddrTypeIPv6, header.AddrType)
	}
	if header.DestPort != 8080 {
		t.Errorf("Expected dest port %d, got %d", 8080, header.DestPort)
	}
}

func TestParseSocket5HeaderInvalid(t *testing.T) {
	_, err := ParseSocket5Header([]byte{})
	if err == nil {
		t.Error("Expected error for empty buffer")
	}

	_, err = ParseSocket5Header([]byte{2})
	if err == nil {
		t.Error("Expected error for unsupported addr type")
	}
}

func TestPackHeaderIPv4(t *testing.T) {
	header, err := PackHeader("127.0.0.1", AddrTypeIPv4, 8080)
	if err != nil {
		t.Fatalf("PackHeader failed: %v", err)
	}

	if len(header) != 7 {
		t.Errorf("Expected header length 7, got %d", len(header))
	}
	if header[0] != AddrTypeIPv4 {
		t.Errorf("Expected addr type %d, got %d", AddrTypeIPv4, header[0])
	}
}

func TestPackHeaderHost(t *testing.T) {
	header, err := PackHeader("example.com", AddrTypeHost, 443)
	if err != nil {
		t.Fatalf("PackHeader failed: %v", err)
	}

	expectedLen := 1 + 1 + len("example.com") + 2
	if len(header) != expectedLen {
		t.Errorf("Expected header length %d, got %d", expectedLen, len(header))
	}
}

func TestBuildSocks5AuthResponse(t *testing.T) {
	resp := BuildSocks5AuthResponse()
	if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
		t.Error("Invalid auth response")
	}
}

func TestBuildSocks5ConnectResponse(t *testing.T) {
	resp := BuildSocks5ConnectResponse(1080)
	if len(resp) != 10 {
		t.Errorf("Expected response length 10, got %d", len(resp))
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Error("Invalid connect response header")
	}
}

func TestStageString(t *testing.T) {
	tests := []struct {
		stage    Stage
		expected string
	}{
		{StageInit, "STAGE_INIT"},
		{StageAddr, "STAGE_ADDR"},
		{StageStream, "STAGE_STREAM"},
		{StageDestroyed, "STAGE_DESTROYED"},
		{Stage(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.stage.String(); got != tt.expected {
			t.Errorf("Stage(%d).String() = %q, want %q", tt.stage, got, tt.expected)
		}
	}
}
