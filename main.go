package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// Version is set at build time: -ldflags "-X main.Version=vX.Y.Z"
var Version = "dev"

func main() {
	log.SetOutput(os.Stdout)

	configPath := flag.String("config", "certforge-akvconnector.yaml", "path to config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		os.Exit(0)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("certforge-akvconnector %s starting", Version)
	log.Printf("certforge_url: %s", cfg.CertForgeURL)
	log.Printf("connector_id:  %s", cfg.ConnectorID)
	log.Printf("vault_url:     %s", cfg.VaultURL)
	log.Printf("poll_interval: %s", cfg.PollInterval)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	akvClient, err := newAKVClient(cfg.VaultURL)
	if err != nil {
		log.Fatalf("akv: %v", err)
	}

	cfClient := newCertForgeClient(cfg.CertForgeURL, cfg.APIKey, Version)

	worker := &Worker{
		cfg:     cfg,
		cf:      cfClient,
		akv:     akvClient,
		version: Version,
	}
	worker.Run(ctx)
	log.Println("connector stopped")
}
