package panel

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"malicious-detector/internal/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type APIServer struct {
	db               *Database
	router           *gin.Engine
	port             int
	heartbeatTimeout int
	blockCIDR24      bool
}

func NewAPIServer(db *Database, port int, heartbeatTimeout int, blockCIDR24 bool) *APIServer {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Enable CORS
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	})

	server := &APIServer{
		db:               db,
		router:           router,
		port:             port,
		heartbeatTimeout: heartbeatTimeout,
		blockCIDR24:      blockCIDR24,
	}

	server.setupRoutes()
	return server
}

func (s *APIServer) setupRoutes() {
	api := s.router.Group("/api/v1")
	{
		// Detector management
		api.POST("/detectors", s.createDetector)
		api.GET("/detectors", s.getDetectors)
		api.GET("/detectors/:id", s.getDetector)
		api.DELETE("/detectors/:id", s.deleteDetector)

		// Malicious IP reporting (from detectors)
		api.POST("/report", s.reportMaliciousIP)

		// Heartbeat endpoint (from detectors)
		api.POST("/heartbeat", s.handleHeartbeat)

		// Malicious IP management
		api.GET("/malicious-ips", s.getMaliciousIPs)
		api.DELETE("/malicious-ips/:id", s.deleteMaliciousIP)

		// External feeds
		api.GET("/external-feeds", s.getExternalFeeds)
		api.POST("/external-feeds", s.createExternalFeed)
		api.DELETE("/external-feeds/:id", s.deleteExternalFeed)
		api.POST("/external-feeds/:id/update", s.updateExternalFeed)

		// Export endpoints for firewalls
		api.GET("/export/endpoints", s.getExportEndpoints)
		api.GET("/stats", s.getStats)
	}

	// Firewall export endpoints
	export := s.router.Group("/malicious-ips")
	{
		// FortiGate formats
		export.GET("/fortigate-13k-:page.txt", s.exportFortiGateOld)
		export.GET("/fortigate-30k-:page.txt", s.exportFortiGateNew)

		// Other firewall formats
		export.GET("/palo-alto-:page.txt", s.exportPaloAlto)
		export.GET("/pfsense-:page.txt", s.exportPfSense)
		export.GET("/opnsense-:page.txt", s.exportOPNsense)
		export.GET("/iptables-:page.txt", s.exportIPtables)

		// Nginx Geo module format
		export.GET("/nginx-geo-:page.txt", s.exportNginxGeo)
	}

	// Serve static files for web dashboard
	s.router.Static("/static", "./web/dist")
	s.router.NoRoute(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api") &&
			!strings.HasPrefix(c.Request.URL.Path, "/malicious-ips") {
			c.File("./web/dist/index.html")
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		}
	})
}

// Detector management handlers
func (s *APIServer) createDetector(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := shared.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	detector := &shared.DetectorConfig{
		ID:       uuid.New().String(),
		Name:     req.Name,
		Token:    token,
		Created:  time.Now(),
		LastSeen: time.Now(),
		Status:   "offline",
	}

	if err := s.db.CreateDetector(detector); err != nil {
		log.Printf("Failed to create detector: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create detector"})
		return
	}

	c.JSON(http.StatusCreated, detector)
}

func (s *APIServer) getDetectors(c *gin.Context) {
	detectors, err := s.db.GetAllDetectors()
	if err != nil {
		log.Printf("Failed to get detectors: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get detectors"})
		return
	}

	c.JSON(http.StatusOK, detectors)
}

func (s *APIServer) getDetector(c *gin.Context) {
	id := c.Param("id")

	detector, err := s.db.GetDetector(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Detector not found"})
		return
	}

	c.JSON(http.StatusOK, detector)
}

func (s *APIServer) deleteDetector(c *gin.Context) {
	id := c.Param("id")

	if err := s.db.DeleteDetector(id); err != nil {
		log.Printf("Failed to delete detector: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete detector"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Detector deleted successfully"})
}

// Malicious IP reporting handler
func (s *APIServer) reportMaliciousIP(c *gin.Context) {
	var req shared.ReportRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify detector token
	detector, err := s.db.GetDetectorByToken(req.DetectorID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid detector token"})
		return
	}

	// Update detector status and IP
	clientIP := c.ClientIP()
	if err := s.db.UpdateDetectorStatus(detector.ID, "online", clientIP); err != nil {
		log.Printf("Failed to update detector status: %v", err)
	}

	// Validate IP address
	if !shared.IsValidIP(req.IP) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	// Add malicious IP
	now := time.Now()
	maliciousIP := &shared.MaliciousIP{
		IP:         req.IP,
		Source:     detector.ID,
		SourceType: "detector",
		Weight:     10, // High weight for detector reports
		FirstSeen:  now,
		LastSeen:   now,
		Count:      req.Count,
		Reason:     req.Reason,
		Active:     true,
	}

	if err := s.db.AddMaliciousIP(maliciousIP); err != nil {
		log.Printf("Failed to add malicious IP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add malicious IP"})
		return
	}

	log.Printf("Malicious IP reported: %s from detector %s (%s)", req.IP, detector.Name, req.Reason)
	c.JSON(http.StatusOK, gin.H{"message": "Malicious IP reported successfully"})
}

// Heartbeat handler
func (s *APIServer) handleHeartbeat(c *gin.Context) {
	var req shared.HeartbeatRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify detector token
	detector, err := s.db.GetDetectorByToken(req.DetectorID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid detector token"})
		return
	}

	// Update detector status and last seen time
	clientIP := c.ClientIP()
	if err := s.db.UpdateDetectorStatus(detector.ID, "online", clientIP); err != nil {
		log.Printf("Failed to update detector status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update detector status"})
		return
	}

	log.Printf("Heartbeat received from detector %s (%s) at %s", detector.Name, detector.ID, clientIP)
	c.JSON(http.StatusOK, gin.H{"message": "Heartbeat received", "timestamp": time.Now().Unix()})
}

// Malicious IP management handlers
func (s *APIServer) getMaliciousIPs(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "1000")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 1000
	}

	ips, err := s.db.GetMaliciousIPs(limit)
	if err != nil {
		log.Printf("Failed to get malicious IPs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get malicious IPs"})
		return
	}

	c.JSON(http.StatusOK, ips)
}

func (s *APIServer) deleteMaliciousIP(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := s.db.DeactivateMaliciousIP(id); err != nil {
		log.Printf("Failed to deactivate malicious IP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deactivate malicious IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Malicious IP deactivated successfully"})
}

// External feed handlers
func (s *APIServer) getExternalFeeds(c *gin.Context) {
	feeds, err := s.db.GetExternalFeeds()
	if err != nil {
		log.Printf("Failed to get external feeds: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get external feeds"})
		return
	}

	c.JSON(http.StatusOK, feeds)
}

func (s *APIServer) createExternalFeed(c *gin.Context) {
	var feed shared.ExternalFeed

	if err := c.ShouldBindJSON(&feed); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	feed.LastUpdate = time.Now()
	if err := s.db.AddExternalFeed(&feed); err != nil {
		log.Printf("Failed to create external feed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create external feed"})
		return
	}

	c.JSON(http.StatusCreated, feed)
}

func (s *APIServer) deleteExternalFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	if err := s.db.DeleteExternalFeed(id); err != nil {
		log.Printf("Failed to delete external feed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete external feed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "External feed deleted successfully"})
}

func (s *APIServer) updateExternalFeed(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	// TODO: Implement external feed update logic
	if err := s.db.UpdateExternalFeedLastUpdate(id); err != nil {
		log.Printf("Failed to update external feed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update external feed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "External feed updated successfully"})
}

// Export endpoint information
func (s *APIServer) getExportEndpoints(c *gin.Context) {
	host := c.Request.Host
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}

	count, err := s.db.GetMaliciousIPCount()
	if err != nil {
		log.Printf("Failed to get malicious IP count: %v", err)
		count = 0
	}

	endpoints := make(map[string]interface{})

	for key, format := range shared.FirewallFormats {
		pages := (count + format.MaxCount - 1) / format.MaxCount // Ceiling division
		if pages == 0 {
			pages = 1
		}

		urls := make([]string, pages)
		for i := 0; i < pages; i++ {
			urls[i] = fmt.Sprintf("%s://%s/malicious-ips/%s-%d.txt",
				scheme, host, format.Endpoint, i+1)
		}

		endpoints[key] = gin.H{
			"name":      format.Name,
			"max_count": format.MaxCount,
			"pages":     pages,
			"urls":      urls,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_ips": count,
		"endpoints": endpoints,
	})
}

// Statistics handler
func (s *APIServer) getStats(c *gin.Context) {
	count, err := s.db.GetMaliciousIPCount()
	if err != nil {
		log.Printf("Failed to get malicious IP count: %v", err)
		count = 0
	}

	detectors, err := s.db.GetAllDetectors()
	if err != nil {
		log.Printf("Failed to get detectors: %v", err)
		detectors = []*shared.DetectorConfig{}
	}

	onlineDetectors := 0
	for _, detector := range detectors {
		if detector.Status == "online" {
			onlineDetectors++
		}
	}

	feeds, err := s.db.GetExternalFeeds()
	if err != nil {
		log.Printf("Failed to get external feeds: %v", err)
		feeds = []*shared.ExternalFeed{}
	}

	activeFeeds := 0
	for _, feed := range feeds {
		if feed.Active {
			activeFeeds++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"malicious_ips":    count,
		"total_detectors":  len(detectors),
		"online_detectors": onlineDetectors,
		"total_feeds":      len(feeds),
		"active_feeds":     activeFeeds,
	})
}

// Firewall export handlers
func (s *APIServer) exportIPs(c *gin.Context, maxCount int) {
	pageStr := c.Param("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	if s.blockCIDR24 {
		// Use CIDR /24 aggregation
		s.exportIPsWithCIDR24(c, maxCount)
	} else {
		// Use original IP list
		s.exportIPsOriginal(c, maxCount)
	}
}

// exportIPsOriginal exports original IPs without CIDR aggregation
func (s *APIServer) exportIPsOriginal(c *gin.Context, maxCount int) {
	pageStr := c.Param("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	offset := (page - 1) * maxCount
	ips, err := s.db.GetMaliciousIPs(maxCount)
	if err != nil {
		log.Printf("Failed to get malicious IPs for export: %v", err)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	// Apply offset
	startIdx := offset
	endIdx := startIdx + maxCount
	if startIdx >= len(ips) {
		c.String(http.StatusOK, "")
		return
	}
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	var result strings.Builder
	for i := startIdx; i < endIdx; i++ {
		result.WriteString(ips[i].IP)
		result.WriteString("\n")
	}

	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, result.String())
}

// exportIPsWithCIDR24 exports IPs aggregated into /24 CIDR blocks
func (s *APIServer) exportIPsWithCIDR24(c *gin.Context, maxCount int) {
	pageStr := c.Param("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	// Get all IPs first for CIDR aggregation
	allIPs, err := s.db.GetMaliciousIPs(0) // 0 means get all
	if err != nil {
		log.Printf("Failed to get malicious IPs for CIDR export: %v", err)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	// Group IPs by /24 networks for efficiency
	networks := make(map[string]bool)
	individualIPs := make([]string, 0)

	for _, maliciousIP := range allIPs {
		ip := maliciousIP.IP

		// Try to create /24 network
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			ipv4 := parsedIP.To4()
			if ipv4 != nil {
				// Create /24 network: x.x.x.0/24
				network := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
				networks[network] = true
			} else {
				// For IPv6 or other cases, add as individual IP
				individualIPs = append(individualIPs, ip)
			}
		} else {
			// Invalid IP, add as individual
			individualIPs = append(individualIPs, ip)
		}
	}

	// Convert networks map to slice and combine with individual IPs
	var allEntries []string
	for network := range networks {
		allEntries = append(allEntries, network)
	}
	allEntries = append(allEntries, individualIPs...)

	// Apply pagination
	offset := (page - 1) * maxCount
	startIdx := offset
	endIdx := startIdx + maxCount
	if startIdx >= len(allEntries) {
		c.String(http.StatusOK, "")
		return
	}
	if endIdx > len(allEntries) {
		endIdx = len(allEntries)
	}

	var result strings.Builder
	for i := startIdx; i < endIdx; i++ {
		result.WriteString(allEntries[i])
		result.WriteString("\n")
	}

	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, result.String())
}

// FortiGate 13k
func (s *APIServer) exportFortiGateOld(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["fortigate_old"].MaxCount)
}

// FortiGate 30k
func (s *APIServer) exportFortiGateNew(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["fortigate_new"].MaxCount)
}

func (s *APIServer) exportPaloAlto(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["palo_alto"].MaxCount)
}

func (s *APIServer) exportPfSense(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["pfsense"].MaxCount)
}

func (s *APIServer) exportOPNsense(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["opnsense"].MaxCount)
}

func (s *APIServer) exportIPtables(c *gin.Context) {
	s.exportIPs(c, shared.FirewallFormats["iptables"].MaxCount)
}

func (s *APIServer) exportNginxGeo(c *gin.Context) {
	if s.blockCIDR24 {
		s.exportNginxGeoWithCIDR24(c, shared.FirewallFormats["nginx_geo"].MaxCount) // Export with /24 CIDR aggregation
	} else {
		s.exportNginxGeoOriginal(c, shared.FirewallFormats["nginx_geo"].MaxCount) // Export original IPs
	}
}

// exportNginxGeoOriginal exports IPs in nginx Geo module format (original IPs)
func (s *APIServer) exportNginxGeoOriginal(c *gin.Context, maxCount int) {
	pageStr := c.Param("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	offset := (page - 1) * maxCount
	ips, err := s.db.GetMaliciousIPs(maxCount)
	if err != nil {
		log.Printf("Failed to get malicious IPs for nginx geo export: %v", err)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	// Apply offset
	startIdx := offset
	endIdx := startIdx + maxCount
	if startIdx >= len(ips) {
		c.String(http.StatusOK, "")
		return
	}
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	var result strings.Builder

	// Add individual IPs without CIDR aggregation
	for i := startIdx; i < endIdx; i++ {
		ip := ips[i].IP
		result.WriteString(fmt.Sprintf("%s 1;\n", ip))
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", "attachment; filename=nginx-geo-blacklist.txt")
	c.String(http.StatusOK, result.String())
}

// exportNginxGeoWithCIDR24 exports IPs in nginx Geo module format with /24 CIDR aggregation
func (s *APIServer) exportNginxGeoWithCIDR24(c *gin.Context, maxCount int) {
	pageStr := c.Param("page")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	// Get all IPs first for CIDR aggregation
	allIPs, err := s.db.GetMaliciousIPs(0) // 0 means get all
	if err != nil {
		log.Printf("Failed to get malicious IPs for nginx geo CIDR export: %v", err)
		c.String(http.StatusInternalServerError, "Internal server error")
		return
	}

	// Group IPs by /24 networks for efficiency
	networks := make(map[string]bool)
	var individualIPs []string

	for _, maliciousIP := range allIPs {
		ip := maliciousIP.IP

		// Try to create /24 network
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			ipv4 := parsedIP.To4()
			if ipv4 != nil {
				// Create /24 network: x.x.x.0/24
				network := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
				networks[network] = true
			} else {
				// For IPv6 or invalid IPs, add as individual IP
				individualIPs = append(individualIPs, ip)
			}
		} else {
			// Invalid IP, add as individual
			individualIPs = append(individualIPs, ip)
		}
	}

	// Convert networks map to slice and combine with individual IPs
	var allEntries []string
	for network := range networks {
		allEntries = append(allEntries, network)
	}
	allEntries = append(allEntries, individualIPs...)

	// Apply pagination
	offset := (page - 1) * maxCount
	startIdx := offset
	endIdx := startIdx + maxCount
	if startIdx >= len(allEntries) {
		c.String(http.StatusOK, "")
		return
	}
	if endIdx > len(allEntries) {
		endIdx = len(allEntries)
	}

	var result strings.Builder

	// Add entries in nginx geo format
	for i := startIdx; i < endIdx; i++ {
		result.WriteString(fmt.Sprintf("%-30s 1;\n", allEntries[i]))
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", "attachment; filename=nginx-geo-blacklist.txt")
	c.String(http.StatusOK, result.String())
}

func (s *APIServer) Start() error {
	log.Printf("Starting API server on port %d", s.port)

	// Start heartbeat monitor
	go s.startHeartbeatMonitor()

	return s.router.Run(fmt.Sprintf(":%d", s.port))
}

// startHeartbeatMonitor checks detector heartbeats and updates status
func (s *APIServer) startHeartbeatMonitor() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for range ticker.C {
		detectors, err := s.db.GetAllDetectors()
		if err != nil {
			log.Printf("Failed to get detectors for heartbeat check: %v", err)
			continue
		}

		threshold := time.Now().Add(-time.Duration(s.heartbeatTimeout) * time.Second)

		for _, detector := range detectors {
			if detector.Status == "online" && detector.LastSeen.Before(threshold) {
				// Detector is considered offline
				if err := s.db.UpdateDetectorStatus(detector.ID, "offline", detector.IP); err != nil {
					log.Printf("Failed to update detector %s status to offline: %v", detector.Name, err)
				} else {
					log.Printf("Detector %s (%s) marked as offline due to heartbeat timeout", detector.Name, detector.ID)
				}
			}
		}
	}
}

func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := c.GetHeader("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}

	return ip
}
