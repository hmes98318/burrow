package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"malicious-detector/internal/panel"
	"malicious-detector/internal/shared"
)

func main() {
	var (
		port       = flag.Int("port", 0, "HTTP server port")
		dbPath     = flag.String("db", "", "SQLite database file path")
		configPath = flag.String("config", "panel.yaml", "Panel configuration file path")
	)
	flag.Parse()

	// Try to load configuration file
	var config *panel.Config
	var err error

	if _, err := os.Stat(*configPath); err == nil {
		config, err = panel.LoadConfig(*configPath)
		if err != nil {
			log.Printf("Failed to load config file %s: %v", *configPath, err)
			log.Println("Using command line arguments and defaults")
		} else if config != nil {
			log.Printf("Loaded configuration from %s", *configPath)
		}
	} else {
		log.Printf("Config file %s not found: %v", *configPath, err)
		log.Println("Using command line arguments and defaults")
	}

	// Use command line arguments if no config or config failed to load
	if config == nil {
		config = &panel.Config{
			Settings: shared.PanelSettings{
				Port:             8080,       // Default port
				DatabasePath:     "panel.db", // Default database path
				HeartbeatTimeout: 60,         // Default 60 seconds
			},
		}
	}

	// Override with command line arguments if provided (non-zero/non-empty values)
	if *port != 0 {
		config.Settings.Port = *port
	}
	if *dbPath != "" {
		config.Settings.DatabasePath = *dbPath
	}

	// Initialize database
	db, err := panel.NewDatabase(config.Settings.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize API server
	apiServer := panel.NewAPIServer(db, config.Settings.Port, config.Settings.HeartbeatTimeout, config.Settings.BlockCIDR24)

	// Start server in a goroutine
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("Failed to start API server: %v", err)
		}
	}()

	log.Printf("Malicious IP Threat Intelligence Panel started on port %d", config.Settings.Port)
	log.Printf("Database: %s", config.Settings.DatabasePath)
	log.Printf("Heartbeat timeout: %d seconds", config.Settings.HeartbeatTimeout)
	log.Printf("Block CIDR/24: %t", config.Settings.BlockCIDR24)
	log.Println("Press Ctrl+C to stop")

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down panel...")
}
