package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"malicious-detector/internal/shared"
)

type HeartbeatService struct {
	panelURL string
	token    string
	interval time.Duration
	client   *http.Client
	stopChan chan struct{}
}

func NewHeartbeatService(panelURL, token string, intervalSeconds int) *HeartbeatService {
	if intervalSeconds <= 0 {
		intervalSeconds = 10 // Default 10 seconds
	}

	return &HeartbeatService{
		panelURL: panelURL,
		token:    token,
		interval: time.Duration(intervalSeconds) * time.Second,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopChan: make(chan struct{}),
	}
}

func (h *HeartbeatService) Start() {
	log.Printf("Starting heartbeat service - sending heartbeat every %v", h.interval)

	// Send initial heartbeat
	h.sendHeartbeat()

	// Start periodic heartbeat
	ticker := time.NewTicker(h.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.sendHeartbeat()
			case <-h.stopChan:
				log.Println("Heartbeat service stopped")
				return
			}
		}
	}()
}

func (h *HeartbeatService) Stop() {
	close(h.stopChan)
}

func (h *HeartbeatService) sendHeartbeat() {
	heartbeat := shared.HeartbeatRequest{
		Token:     h.token,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		log.Printf("Failed to marshal heartbeat request: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/heartbeat", h.panelURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to create heartbeat request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("Failed to send heartbeat: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Heartbeat request failed with status: %d", resp.StatusCode)
		return
	}

	log.Printf("Heartbeat sent successfully")
}
