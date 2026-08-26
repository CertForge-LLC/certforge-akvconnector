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

	// Sub-commands: enroll, (default: run)
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		runEnroll(os.Args[2:])
		return
	}

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

	// Build the CertForge client — mTLS if configured, Bearer token otherwise.
	var cfClient *certForgeClient
	if cfg.MTLSConfigured() {
		port := cfg.MTLSPort
		if port == 0 {
			port = 8443
		}
		mtlsBase := fmt.Sprintf("https://%s:%d", cfg.MTLSHost, port)
		cfClient, err = newCertForgeClientMTLS(mtlsBase, Version, cfg.MTLSCert, cfg.MTLSKey, cfg.MTLSCA)
		if err != nil {
			log.Fatalf("mTLS client: %v", err)
		}
		log.Printf("auth:          mTLS → %s", mtlsBase)
	} else {
		cfClient = newCertForgeClient(cfg.CertForgeURL, cfg.APIKey, Version)
		log.Printf("auth:          Bearer token")
	}

	worker := &Worker{
		cfg:     cfg,
		cf:      cfClient,
		akv:     akvClient,
		version: Version,
	}
	worker.Run(ctx)
	log.Println("connector stopped")
}
