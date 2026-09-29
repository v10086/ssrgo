package main

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Mode != "server" {
		t.Errorf("Expected mode 'server', got '%s'", cfg.Mode)
	}
	if cfg.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Port)
	}
	if cfg.Method != "rc4" {
		t.Errorf("Expected method 'rc4', got '%s'", cfg.Method)
	}
	if cfg.Password != "abc@abc" {
		t.Errorf("Expected password 'abc@abc', got '%s'", cfg.Password)
	}
	if cfg.LocalPort != 1080 {
		t.Errorf("Expected local port 1080, got %d", cfg.LocalPort)
	}
}

func TestLoadConfig(t *testing.T) {
	configJSON := `{
		"mode": "server",
		"server": "0.0.0.0",
		"port": 8388,
		"method": "aes-256-cfb",
		"password": "my_password",
		"protocol": "auth_aes128_md5",
		"local_port": 1080
	}`

	tmpFile, err := os.CreateTemp("", "ssrgo_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configJSON); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Mode != "server" {
		t.Errorf("Expected mode 'server', got '%s'", cfg.Mode)
	}
	if cfg.Server != "0.0.0.0" {
		t.Errorf("Expected server '0.0.0.0', got '%s'", cfg.Server)
	}
	if cfg.Port != 8388 {
		t.Errorf("Expected port 8388, got %d", cfg.Port)
	}
	if cfg.Method != "aes-256-cfb" {
		t.Errorf("Expected method 'aes-256-cfb', got '%s'", cfg.Method)
	}
	if cfg.Password != "my_password" {
		t.Errorf("Expected password 'my_password', got '%s'", cfg.Password)
	}
	if cfg.ConfigFile != tmpFile.Name() {
		t.Errorf("Expected config file '%s', got '%s'", tmpFile.Name(), cfg.ConfigFile)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "Valid server config",
			cfg:     Config{Mode: "server", Port: 8080, Password: "test"},
			wantErr: false,
		},
		{
			name:    "Valid local config",
			cfg:     Config{Mode: "local", Port: 8080, LocalPort: 1080, Password: "test"},
			wantErr: false,
		},
		{
			name:    "Invalid mode",
			cfg:     Config{Mode: "invalid", Port: 8080, Password: "test"},
			wantErr: true,
		},
		{
			name:    "Invalid port",
			cfg:     Config{Mode: "server", Port: 0, Password: "test"},
			wantErr: true,
		},
		{
			name:    "Invalid local port",
			cfg:     Config{Mode: "local", Port: 8080, LocalPort: 0, Password: "test"},
			wantErr: true,
		},
		{
			name:    "Empty password",
			cfg:     Config{Mode: "server", Port: 8080, Password: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	cfg := &Config{
		Mode:      "server",
		Server:    "127.0.0.1",
		Port:      8080,
		LocalPort: 1080,
		Method:    "aes-256-cfb",
		Protocol:  "auth_aes128_md5",
	}

	str := cfg.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
}
