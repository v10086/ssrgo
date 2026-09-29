package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := ParseFlags()
	if err != nil {
		log.Fatalf("Failed to parse configuration: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	log.Printf("Configuration: %s", cfg.String())

	switch cfg.Mode {
	case "server":
		runServer(cfg)
	case "local":
		runLocal(cfg)
	default:
		log.Fatalf("Unknown mode: %s", cfg.Mode)
	}
}

func runServer(cfg *Config) {
	srv := NewServer(cfg)

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("Server is running. Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println("\nShutting down server...")
	srv.Stop()
	log.Println("Server stopped.")
}

func runLocal(cfg *Config) {
	loc := NewLocal(cfg)

	if err := loc.Start(); err != nil {
		log.Fatalf("Failed to start local proxy: %v", err)
	}

	log.Printf("Local proxy is running. Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println("\nShutting down local proxy...")
	loc.Stop()
	log.Println("Local proxy stopped.")
}
