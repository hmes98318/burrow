package detector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"malicious-detector/internal/shared"
)

type LogMonitor struct {
	config            shared.LogConfig
	globalSettings    *shared.DetectorSettings // detector.yaml config
	ipTracker         *IPTracker
	reporter          *Reporter
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	scanStats         *ScanStats
	scanning          int32 // atomic flag to prevent concurrent scans
	debugMode         bool
	lastOffset        int64           // 記錄最後讀取的檔案位置
	lastLineContent   string          // 記錄最後一行的內容，用於檢測檔案是否被重寫
	currentLine       int64           // 記錄當前處理的行號
	isFirstScan       bool            // 標記是否為第一次掃描
	firstScanReported map[string]bool // 追蹤第一次掃描中已報告的 IP，避免重複報告
}

type ScanStats struct {
	mu                sync.RWMutex
	totalScans        int64
	totalLinesScanned int64
	totalScanTime     time.Duration
	lastScanDuration  time.Duration
	lastScanTime      time.Time
	skippedScans      int64         // count of skipped scans due to still running
	maxScanDuration   time.Duration // 最大掃描時間
	minScanDuration   time.Duration // 最小掃描時間
}

type IPTracker struct {
	mu      sync.RWMutex
	records map[string]*IPRecord
}

type IPRecord struct {
	IP        string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	LogPath   string
}

func NewLogMonitor(config shared.LogConfig, globalSettings *shared.DetectorSettings, reporter *Reporter, debugMode bool) *LogMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default scan interval if not specified (1000ms = 1 second)
	if config.ScanInterval <= 0 {
		config.ScanInterval = 1000
	}

	return &LogMonitor{
		config:         config,
		globalSettings: globalSettings,
		ipTracker: &IPTracker{
			records: make(map[string]*IPRecord),
		},
		reporter:          reporter,
		ctx:               ctx,
		cancel:            cancel,
		scanStats:         &ScanStats{},
		scanning:          0,
		debugMode:         debugMode,
		lastOffset:        0,
		lastLineContent:   "",
		isFirstScan:       true,                  // 初始為第一次掃描
		firstScanReported: make(map[string]bool), // 初始化第一次掃描報告追蹤
	}
}

func (lm *LogMonitor) Start() error {
	if lm.debugMode {
		log.Printf("Starting log monitor for: %s (debug mode enabled, scan interval: %dms)",
			lm.config.Path, lm.config.ScanInterval)
	} else {
		log.Printf("Starting log monitor for: %s (scan interval: %dms)",
			lm.config.Path, lm.config.ScanInterval)
	}

	// Start the monitoring goroutine
	lm.wg.Add(1)
	go lm.monitorLog()

	// Start the cleanup goroutine
	lm.wg.Add(1)
	go lm.cleanupOldRecords()

	return nil
}

func (lm *LogMonitor) Stop() {
	log.Printf("Stopping log monitor for: %s", lm.config.Path)
	lm.cancel()
	lm.wg.Wait()
}

func (lm *LogMonitor) monitorLog() {
	defer lm.wg.Done()

	// Convert scan interval from milliseconds to time.Duration
	scanInterval := time.Duration(lm.config.ScanInterval) * time.Millisecond
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	if lm.debugMode {
		log.Printf("Log monitor started for %s with %v interval", lm.config.Path, scanInterval)
	}

	for {
		select {
		case <-lm.ctx.Done():
			return
		case <-ticker.C:
			// Check if a scan is already running using atomic operation
			if !atomic.CompareAndSwapInt32(&lm.scanning, 0, 1) {
				// Skip this scan if another is still running
				lm.scanStats.mu.Lock()
				lm.scanStats.skippedScans++
				lm.scanStats.mu.Unlock()

				if lm.debugMode {
					log.Printf("Skipping scan for %s - previous scan still running (total skipped: %d)",
						lm.config.Path, lm.scanStats.skippedScans)
				}
				continue
			}

			// Perform the actual scan
			lm.performScan()

			// Release the scanning flag
			atomic.StoreInt32(&lm.scanning, 0)
		}
	}
}

func (lm *LogMonitor) performScan() {
	// Record start time for scan duration measurement
	scanStartTime := time.Now()
	linesProcessed := 0

	// Open the log file
	file, err := os.Open(lm.config.Path)
	if err != nil {
		log.Printf("Failed to open log file %s: %v", lm.config.Path, err)
		return
	}
	defer file.Close()

	// Get current file info
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Failed to get file info for %s: %v", lm.config.Path, err)
		return
	}

	currentFileSize := fileInfo.Size()

	if lm.debugMode {
		log.Printf("Scanning %s - Current size: %d, Last offset: %d",
			lm.config.Path, currentFileSize, lm.lastOffset)
	}

	// Check if file was truncated or recreated
	if currentFileSize < lm.lastOffset {
		if lm.debugMode {
			log.Printf("File %s was truncated or recreated, resetting offset", lm.config.Path)
		}
		lm.lastOffset = 0
		lm.lastLineContent = ""
		lm.currentLine = 0
	}

	// Calculate current line number if we're starting from a position > 0
	if lm.lastOffset == 0 {
		lm.currentLine = 0
	} else if lm.currentLine == 0 {
		// We need to count lines from the beginning to lastOffset
		tempFile, err := os.Open(lm.config.Path)
		if err == nil {
			defer tempFile.Close()
			tempScanner := bufio.NewScanner(tempFile)
			var lineCount int64 = 0
			var currentOffset int64 = 0

			for tempScanner.Scan() {
				line := tempScanner.Text()
				lineWithNewline := line + "\n"
				if currentOffset >= lm.lastOffset {
					break
				}
				lineCount++
				currentOffset += int64(len(lineWithNewline))
			}
			lm.currentLine = lineCount
		}
	}

	// Seek to the last known position
	if _, err := file.Seek(lm.lastOffset, io.SeekStart); err != nil {
		log.Printf("Failed to seek to position %d in %s: %v", lm.lastOffset, lm.config.Path, err)
		lm.lastOffset = 0
		file.Seek(0, io.SeekStart)
	}

	scanner := bufio.NewScanner(file)
	newLines := make([]string, 0)

	// Read all new lines from the current position
	for scanner.Scan() {
		line := scanner.Text()
		newLines = append(newLines, line)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading log file %s: %v", lm.config.Path, err)
		return
	}

	// If we have new lines, verify the continuity by checking the first line
	if len(newLines) > 0 {
		// If this is not the first scan and we have stored content
		if lm.lastOffset > 0 && lm.lastLineContent != "" {
			// Try to read the previous line to verify continuity
			if lm.lastOffset > 0 {
				tempFile, err := os.Open(lm.config.Path)
				if err == nil {
					defer tempFile.Close()

					// Read from the beginning to find the line at lastOffset
					tempFile.Seek(0, io.SeekStart)
					tempScanner := bufio.NewScanner(tempFile)
					var lastKnownLine string
					var currentOffset int64 = 0

					for tempScanner.Scan() {
						line := tempScanner.Text()
						lineWithNewline := line + "\n"
						if currentOffset == lm.lastOffset {
							break
						}
						if currentOffset < lm.lastOffset {
							lastKnownLine = line
						}
						currentOffset += int64(len(lineWithNewline))
					}

					// Check if the last known line still matches
					if lastKnownLine != "" {
						normalizedLastLine := lm.normalizeLineContent(lastKnownLine)
						if normalizedLastLine != lm.lastLineContent {
							if lm.debugMode {
								log.Printf("File %s appears to have been modified, starting from current position", lm.config.Path)
							}
						}
					}
				}
			}
		}

		// Process all new lines
		for _, line := range newLines {
			lm.currentLine++
			lm.processLogLine(line, lm.currentLine)
			linesProcessed++
		}

		// Update our position tracking
		newOffset, _ := file.Seek(0, io.SeekCurrent)
		lm.lastOffset = newOffset

		// Store content of the last line
		if len(newLines) > 0 {
			lm.lastLineContent = lm.normalizeLineContent(newLines[len(newLines)-1])
		}
	}

	// Calculate scan duration
	scanDuration := time.Since(scanStartTime)
	scanDurationMs := float64(scanDuration.Nanoseconds()) / 1000000.0

	// Update scan statistics
	lm.scanStats.mu.Lock()
	lm.scanStats.totalScans++
	lm.scanStats.totalLinesScanned += int64(linesProcessed)
	lm.scanStats.totalScanTime += scanDuration
	lm.scanStats.lastScanDuration = scanDuration
	lm.scanStats.lastScanTime = scanStartTime

	// 更新最大和最小掃描時間
	if lm.scanStats.totalScans == 1 {
		// 第一次掃描，初始化最大和最小值
		lm.scanStats.maxScanDuration = scanDuration
		lm.scanStats.minScanDuration = scanDuration
	} else {
		// 更新最大值
		if scanDuration > lm.scanStats.maxScanDuration {
			lm.scanStats.maxScanDuration = scanDuration
		}
		// 更新最小值
		if scanDuration < lm.scanStats.minScanDuration {
			lm.scanStats.minScanDuration = scanDuration
		}
	}

	lm.scanStats.mu.Unlock()

	// Log scan completion
	if lm.debugMode {
		log.Printf("Log scan completed - File: %s, Lines: %d, Duration: %.2f ms, New offset: %d",
			lm.config.Path, linesProcessed, scanDurationMs, lm.lastOffset)
	} else if linesProcessed > 0 {
		log.Printf("Log scan completed - File: %s, Lines processed: %d, Duration: %.2f ms",
			lm.config.Path, linesProcessed, scanDurationMs)
	} else {
		// Log periodic status for no-activity scans (every 30th scan)
		if lm.scanStats.totalScans%30 == 0 {
			log.Printf("Log scan cycle - File: %s, No new lines, Duration: %.2f ms (Total scans: %d, File size: %d bytes, Offset: %d)",
				lm.config.Path, scanDurationMs, lm.scanStats.totalScans, currentFileSize, lm.lastOffset)
		}
	}

	// 第一次掃描完成後，設置標記為 false
	if lm.isFirstScan {
		lm.isFirstScan = false
		// 清理第一次掃描的報告追蹤，釋放記憶體
		lm.firstScanReported = nil
		if lm.debugMode {
			log.Printf("First scan completed for %s, subsequent scans will use normal thresholds", lm.config.Path)
		}
	}
}

// 處理空行並返回標準化的字串內容
func (lm *LogMonitor) normalizeLineContent(s string) string {
	if s == "" {
		return "<EMPTY_LINE>"
	}
	return s
}

// 處理單行日誌，提取 IP 並更新追蹤記錄
func (lm *LogMonitor) processLogLine(line string, lineNumber int64) {
	if lm.debugMode {
		log.Printf("Processing line: %s", line)
	}

	// Extract IP from log line using regex
	ip, err := shared.ExtractIPFromLog(line, lm.config.Regex)
	if err != nil {
		log.Printf("⚠️  WARNING: Error extracting IP from log (file: %s) line %d: %v", lm.config.Path, lineNumber, err)
		return
	}

	if ip == "" {
		// log.Printf("⚠️  WARNING: No IP address found in log (file: %s) line %d: %s", lm.config.Path, lineNumber, line)
		// Silent skip - no IP found in this line (this is normal for non-matching lines)
		return
	}

	// Validate IP address
	if !shared.IsValidIP(ip) {
		log.Printf("⚠️  WARNING: Invalid IP address found in log (file: %s) line %d: %s", lm.config.Path, lineNumber, ip)
		return
	}

	// Skip private/local IP addresses (除非配置允許)
	if lm.isPrivateIP(ip) && !lm.globalSettings.IncludePrivateIPs {
		if lm.debugMode {
			log.Printf("Skipping private IP: %s", ip)
		}
		return
	}

	// Debug mode: print new IP found
	if lm.debugMode {
		log.Printf("🚨 Found suspicious IP: %s", ip)
	}

	now := time.Now()

	lm.ipTracker.mu.Lock()
	defer lm.ipTracker.mu.Unlock()

	record, exists := lm.ipTracker.records[ip]
	if !exists {
		record = &IPRecord{
			IP:        ip,
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
			LogPath:   lm.config.Path,
		}
		lm.ipTracker.records[ip] = record

		if lm.debugMode {
			log.Printf("📋 New IP tracked: %s from %s", ip, lm.config.Path)
		}
	} else {
		record.Count++
		record.LastSeen = now

		if lm.debugMode {
			log.Printf("📈 IP activity: %s (count: %d) from %s", ip, record.Count, lm.config.Path)
		}
	}

	// Check if this IP has exceeded the retry limit within the time window
	timeWindow := time.Duration(lm.config.TimeWindow) * time.Minute

	// 第一次掃描時，每個 IP 只報告一次就好（threshold = 1）
	// 之後的掃描使用配置的 MaxRetry 值
	threshold := lm.config.MaxRetry
	if lm.isFirstScan {
		threshold = 1
		// 檢查此 IP 是否已在第一次掃描中報告過
		if lm.firstScanReported[ip] {
			// 已經報告過，跳過此次報告
			if lm.debugMode {
				log.Printf("⏭️  IP %s already reported in first scan, skipping", ip)
			}
			return
		}
	}

	if now.Sub(record.FirstSeen) <= timeWindow && record.Count >= threshold {
		// Report malicious IP
		var reason string
		if lm.isFirstScan {
			reason = fmt.Sprintf("Initial scan detection on %s", lm.config.Description)
			// 標記此 IP 已在第一次掃描中報告
			lm.firstScanReported[ip] = true
		} else {
			reason = fmt.Sprintf("Exceeded %d retries in %d minutes on %s",
				lm.config.MaxRetry, lm.config.TimeWindow, lm.config.Description)
		}

		lm.reporter.ReportMaliciousIP(ip, reason, lm.config.Path, record.Count)

		// Reset the record to avoid duplicate reports
		delete(lm.ipTracker.records, ip)

		if lm.isFirstScan {
			log.Printf("🔥 Reported malicious IP (first scan): %s (reason: %s)", ip, reason)
		} else {
			log.Printf("🔥 Reported malicious IP: %s (reason: %s)", ip, reason)
		}

		if lm.debugMode {
			if lm.isFirstScan {
				log.Printf("🔥 MALICIOUS IP REPORTED (FIRST SCAN): %s (reason: %s)", ip, reason)
			} else {
				log.Printf("🔥 MALICIOUS IP REPORTED: %s (reason: %s)", ip, reason)
			}
		}
	}
}

// Periodically clean up old IP records that are outside the time window
func (lm *LogMonitor) cleanupOldRecords() {
	defer lm.wg.Done()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-lm.ctx.Done():
			return
		case <-ticker.C:
			lm.cleanupExpiredRecords()
		}
	}
}

// 清理超出時間窗口的過期 IP 記錄
func (lm *LogMonitor) cleanupExpiredRecords() {
	lm.ipTracker.mu.Lock()
	defer lm.ipTracker.mu.Unlock()

	now := time.Now()
	timeWindow := time.Duration(lm.config.TimeWindow) * time.Minute
	cleanedCount := 0

	for ip, record := range lm.ipTracker.records {
		if now.Sub(record.FirstSeen) > timeWindow {
			delete(lm.ipTracker.records, ip)
			cleanedCount++
		}
	}

	if lm.debugMode && cleanedCount > 0 {
		log.Printf("Cleaned up %d expired IP records for %s", cleanedCount, lm.config.Path)
	}
}

func (lm *LogMonitor) isPrivateIP(ip string) bool {
	// Check for common private IP ranges
	privateRanges := []string{
		"127.",     // Loopback
		"10.",      // Private Class A
		"192.168.", // Private Class C
		"169.254.", // Link-local
		"::1",      // IPv6 loopback
		"fc00::",   // IPv6 private
		"fe80::",   // IPv6 link-local
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	// Check for 172.16.0.0/12 (Private Class B)
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if second, err := strconv.Atoi(parts[1]); err == nil {
				if second >= 16 && second <= 31 {
					return true
				}
			}
		}
	}

	return false
}

func (lm *LogMonitor) GetStats() map[string]interface{} {
	lm.ipTracker.mu.RLock()
	trackingCount := len(lm.ipTracker.records)
	lm.ipTracker.mu.RUnlock()

	lm.scanStats.mu.RLock()
	totalScans := lm.scanStats.totalScans
	totalLinesScanned := lm.scanStats.totalLinesScanned
	totalScanTimeMs := float64(lm.scanStats.totalScanTime.Nanoseconds()) / 1000000.0
	lastScanDurationMs := float64(lm.scanStats.lastScanDuration.Nanoseconds()) / 1000000.0
	lastScanTime := lm.scanStats.lastScanTime
	skippedScans := lm.scanStats.skippedScans
	maxScanDurationMs := float64(lm.scanStats.maxScanDuration.Nanoseconds()) / 1000000.0
	minScanDurationMs := float64(lm.scanStats.minScanDuration.Nanoseconds()) / 1000000.0
	lm.scanStats.mu.RUnlock()

	var avgScanTimeMs float64
	if totalScans > 0 {
		avgScanTimeMs = totalScanTimeMs / float64(totalScans)
	}

	return map[string]interface{}{
		"log_path":              lm.config.Path,
		"description":           lm.config.Description,
		"max_retry":             lm.config.MaxRetry,
		"time_window":           lm.config.TimeWindow,
		"scan_interval_ms":      lm.config.ScanInterval,
		"tracking_count":        trackingCount,
		"total_scans":           totalScans,
		"total_lines_scanned":   totalLinesScanned,
		"total_scan_time_ms":    totalScanTimeMs,
		"avg_scan_time_ms":      avgScanTimeMs,
		"last_scan_duration_ms": lastScanDurationMs,
		"max_scan_duration_ms":  maxScanDurationMs,
		"min_scan_duration_ms":  minScanDurationMs,
		"last_scan_time":        lastScanTime,
		"skipped_scans":         skippedScans,
		"debug_mode":            lm.debugMode,
	}
}
