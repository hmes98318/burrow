package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"malicious-detector/internal/detector"
)

func main() {
	var (
		configPath   = flag.String("config", "detector.yaml", "Configuration file path")
		createSample = flag.Bool("create-sample", false, "Create sample configuration file")
		debugMode    = flag.Bool("debug", false, "Enable debug mode for verbose logging")
	)
	flag.Parse()

	// Create sample configuration if requested
	if *createSample {
		if err := detector.CreateSampleConfig(*configPath); err != nil {
			log.Fatalf("Failed to create sample config: %v", err)
		}
		log.Printf("Sample configuration created at: %s", *configPath)
		log.Println("Please edit the configuration file and restart the detector")
		return
	}

	// Load configuration
	config, err := detector.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting Malicious IP Detector: %s", config.Settings.Name)
	log.Printf("Panel URL: %s", config.Settings.PanelURL)
	log.Printf("Heartbeat interval: %d seconds", config.Settings.HeartbeatInterval)

	// Output registered log detection configurations
	config.LogRegisteredConfigs()

	if *debugMode {
		log.Println("Debug mode enabled - verbose logging active")
	}

	// Initialize reporter
	reporter := detector.NewReporter(config.Settings.PanelURL, config.Settings.Token)

	// Test connection to panel
	if err := reporter.TestConnection(); err != nil {
		log.Fatalf("Failed to connect to panel: %v", err)
	}
	log.Println("Successfully connected to panel")

	reporter.Start()
	defer reporter.Stop()

	// Initialize and start heartbeat service
	heartbeatService := detector.NewHeartbeatService(
		config.Settings.PanelURL,
		config.Settings.Token,
		config.Settings.HeartbeatInterval,
	)
	heartbeatService.Start()
	defer heartbeatService.Stop()

	// Initialize log monitors
	var monitors []*detector.LogMonitor
	for _, logConfig := range config.Settings.Logs {
		monitor := detector.NewLogMonitor(logConfig, &config.Settings, reporter, *debugMode)
		monitors = append(monitors, monitor)

		if err := monitor.Start(); err != nil {
			log.Fatalf("Failed to start log monitor for %s: %v", logConfig.Path, err)
		}

		if *debugMode {
			log.Printf("Started monitoring: %s (%s) with scan interval: %dms",
				logConfig.Path, logConfig.Description, logConfig.ScanInterval)
		} else {
			log.Printf("Started monitoring: %s (%s)", logConfig.Path, logConfig.Description)
		}
	}

	log.Println("Detector started successfully")
	log.Println("Press Ctrl+C to stop")

	// Start periodic statistics reporting
	go func() {
		ticker := time.NewTicker(1 * time.Minute) // Report stats every minute
		defer ticker.Stop()

		for range ticker.C {
			log.Println("=== Detector Statistics ===")
			for i, monitor := range monitors {
				stats := monitor.GetStats()
				log.Printf("Monitor %d (%s):", i+1, stats["description"])
				log.Printf("  Path: %s", stats["log_path"])
				log.Printf("  Scan interval: %v ms", stats["scan_interval_ms"])
				log.Printf("  Total scans: %v", stats["total_scans"])
				log.Printf("  Skipped scans: %v", stats["skipped_scans"])
				log.Printf("  Total lines scanned: %v", stats["total_lines_scanned"])
				log.Printf("  Average scan time: %.2f ms", stats["avg_scan_time_ms"])
				log.Printf("  Last scan duration: %.2f ms", stats["last_scan_duration_ms"])
				log.Printf("  Max scan duration: %.2f ms", stats["max_scan_duration_ms"])
				log.Printf("  Min scan duration: %.2f ms", stats["min_scan_duration_ms"])
				log.Printf("  Currently tracking IPs: %v", stats["tracking_count"])
				log.Printf("  Debug mode: %v", stats["debug_mode"])
			}
			log.Println("=== End Statistics ===")
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down detector...")

	// Stop all monitors
	for _, monitor := range monitors {
		monitor.Stop()
	}

	log.Println("Detector stopped")
}
