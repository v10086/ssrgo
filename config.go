package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Mode          string   `json:"mode"`
	UDPEnable     bool     `json:"udp_enable"`
	Server        string   `json:"server"`
	Port          int      `json:"port"`
	Method        string   `json:"method"`
	Password      string   `json:"password"`
	Protocol      string   `json:"protocol"`
	ProtocolParam []string `json:"protocol_param"`
	LocalPort     int      `json:"local_port"`
	ProcessCount  int      `json:"process_count"`
	ConfigFile    string   `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:          "server",
		UDPEnable:     false,
		Server:        "127.0.0.1",
		Port:          8080,
		Method:        "rc4",
		Password:      "1234@567",
		Protocol:      "auth_aes128_md5",
		ProtocolParam: []string{"1:password", "2:password", "3:password"},
		LocalPort:     1080,
		ProcessCount:  5,
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	cfg.ConfigFile = path
	return cfg, nil
}

func ParseFlags() (*Config, error) {
	cfg := DefaultConfig()
	var configFile string
	var protocolParams string

	flag.StringVar(&configFile, "c", "", "config file path (JSON format)")
	flag.StringVar(&configFile, "config", "", "config file path (JSON format)")
	flag.StringVar(&cfg.Mode, "mode", cfg.Mode, "mode: server or local")
	flag.StringVar(&cfg.Server, "server", cfg.Server, "server address")
	flag.IntVar(&cfg.Port, "port", cfg.Port, "server port")
	flag.StringVar(&cfg.Method, "method", cfg.Method, "encryption method")
	flag.StringVar(&cfg.Password, "password", cfg.Password, "password")
	flag.StringVar(&cfg.Protocol, "protocol", cfg.Protocol, "protocol: origin, auth_aes128_md5, auth_aes128_sha1")
	flag.StringVar(&protocolParams, "protocol-param", "", "protocol params (comma separated)")
	flag.IntVar(&cfg.LocalPort, "local-port", cfg.LocalPort, "local SOCKS5 proxy port")
	flag.IntVar(&cfg.ProcessCount, "process-count", cfg.ProcessCount, "number of worker goroutines")
	flag.BoolVar(&cfg.UDPEnable, "udp", cfg.UDPEnable, "enable UDP relay")

	flag.Parse()

	if configFile != "" {
		fileCfg, err := LoadConfig(configFile)
		if err != nil {
			return nil, err
		}

		if !isFlagPassed("mode") {
			cfg.Mode = fileCfg.Mode
		}
		if !isFlagPassed("server") {
			cfg.Server = fileCfg.Server
		}
		if !isFlagPassed("port") {
			cfg.Port = fileCfg.Port
		}
		if !isFlagPassed("method") {
			cfg.Method = fileCfg.Method
		}
		if !isFlagPassed("password") {
			cfg.Password = fileCfg.Password
		}
		if !isFlagPassed("protocol") {
			cfg.Protocol = fileCfg.Protocol
		}
		if !isFlagPassed("local-port") {
			cfg.LocalPort = fileCfg.LocalPort
		}
		if !isFlagPassed("process-count") {
			cfg.ProcessCount = fileCfg.ProcessCount
		}
		if !isFlagPassed("udp") {
			cfg.UDPEnable = fileCfg.UDPEnable
		}
		cfg.ProtocolParam = fileCfg.ProtocolParam
		cfg.ConfigFile = configFile
		return cfg, nil
	}

	if protocolParams != "" {
		cfg.ProtocolParam = strings.Split(protocolParams, ",")
	}

	return cfg, nil
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func (c *Config) Validate() error {
	if c.Mode != "server" && c.Mode != "local" {
		return fmt.Errorf("invalid mode: %s, must be 'server' or 'local'", c.Mode)
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if c.Mode == "local" && (c.LocalPort <= 0 || c.LocalPort > 65535) {
		return fmt.Errorf("invalid local port: %d", c.LocalPort)
	}
	if c.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

func (c *Config) String() string {
	return fmt.Sprintf("Config{Mode: %s, Server: %s, Port: %d, LocalPort: %d, Method: %s, Protocol: %s}",
		c.Mode, c.Server, c.Port, c.LocalPort, c.Method, c.Protocol)
}
