package main

import (
	"testing"
)

func TestOriginProtocol(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)

	proto, err := NewShadowsocksProtocol(key, iv, "origin", nil)
	if err != nil {
		t.Fatalf("NewShadowsocksProtocol failed: %v", err)
	}

	plaindata := []byte("test data")

	result, err := proto.ClientPreEncrypt(plaindata)
	if err != nil {
		t.Fatalf("ClientPreEncrypt failed: %v", err)
	}
	if string(result) != string(plaindata) {
		t.Errorf("Expected %q, got %q", plaindata, result)
	}

	result, err = proto.ClientPostDecrypt(plaindata)
	if err != nil {
		t.Fatalf("ClientPostDecrypt failed: %v", err)
	}
	if string(result) != string(plaindata) {
		t.Errorf("Expected %q, got %q", plaindata, result)
	}

	result, err = proto.ServerPreEncrypt(plaindata)
	if err != nil {
		t.Fatalf("ServerPreEncrypt failed: %v", err)
	}
	if string(result) != string(plaindata) {
		t.Errorf("Expected %q, got %q", plaindata, result)
	}

	result, err = proto.ServerPostDecrypt(plaindata)
	if err != nil {
		t.Fatalf("ServerPostDecrypt failed: %v", err)
	}
	if string(result) != string(plaindata) {
		t.Errorf("Expected %q, got %q", plaindata, result)
	}
}

func TestAuthAesProtocol(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	params := []string{"1:password1", "2:password2"}

	clientProto, err := NewShadowsocksProtocol(key, iv, "auth_aes128_md5", params)
	if err != nil {
		t.Fatalf("NewShadowsocksProtocol (client) failed: %v", err)
	}

	serverProto, err := NewShadowsocksProtocol(key, iv, "auth_aes128_md5", params)
	if err != nil {
		t.Fatalf("NewShadowsocksProtocol (server) failed: %v", err)
	}

	plaindata := []byte("test data for auth aes")

	encrypted, err := clientProto.ClientPreEncrypt(plaindata)
	if err != nil {
		t.Fatalf("ClientPreEncrypt failed: %v", err)
	}
	if encrypted == nil {
		t.Fatal("ClientPreEncrypt returned nil")
	}

	decrypted, err := serverProto.ServerPostDecrypt(encrypted)
	if err != nil {
		t.Fatalf("ServerPostDecrypt failed: %v", err)
	}
	if decrypted == nil {
		t.Fatal("ServerPostDecrypt returned nil")
	}
}

func TestUnsupportedProtocol(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)

	_, err := NewShadowsocksProtocol(key, iv, "unsupported_protocol", nil)
	if err == nil {
		t.Error("Expected error for unsupported protocol")
	}
}
