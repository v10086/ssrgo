package main

import (
	"testing"
)

func TestEVPBytesToKey(t *testing.T) {
	key, iv, err := EVPBytesToKey("test_password", 32, 16)
	if err != nil {
		t.Fatalf("EVPBytesToKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
	if len(iv) != 16 {
		t.Errorf("Expected IV length 16, got %d", len(iv))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	methods := []string{
		"aes-128-cfb",
		"aes-192-cfb",
		"aes-256-cfb",
		"aes-128-ctr",
		"aes-192-ctr",
		"aes-256-ctr",
		"rc4-md5",
		"chacha20-ietf",
	}

	password := "test_password_123"
	plaintext := []byte("Hello, Shadowsocks! This is a test message.")

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			enc, err := NewEncryptor(password, method, false)
			if err != nil {
				t.Fatalf("NewEncryptor failed for %s: %v", method, err)
			}

			encrypted, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed for %s: %v", method, err)
			}

			if len(encrypted) == 0 {
				t.Fatal("Encrypted data is empty")
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed for %s: %v", method, err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted data mismatch for %s: expected %q, got %q", method, plaintext, decrypted)
			}
		})
	}
}

func TestAEADMethods(t *testing.T) {
	methods := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"xchacha20-ietf-poly1305",
	}

	password := "test_password_123"
	plaintext := []byte("Hello, Shadowsocks AEAD!")

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			enc, err := NewEncryptor(password, method, false)
			if err != nil {
				t.Fatalf("NewEncryptor failed for %s: %v", method, err)
			}

			err = enc.InitForSend()
			if err != nil {
				t.Fatalf("InitForSend failed for %s: %v", method, err)
			}

			encrypted, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed for %s: %v", method, err)
			}

			if len(encrypted) == 0 {
				t.Fatal("Encrypted data is empty")
			}
		})
	}
}
