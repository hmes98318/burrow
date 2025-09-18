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

type Reporter struct {
	panelURL    string
	token       string
	client      *http.Client
	reportQueue chan *shared.ReportRequest
	quit        chan bool
}

func NewReporter(panelURL, token string) *Reporter {
	return &Reporter{
		panelURL: panelURL,
		token:    token,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		reportQueue: make(chan *shared.ReportRequest, 100),
		quit:        make(chan bool),
	}
}

func (r *Reporter) Start() {
	log.Println("Starting reporter service")
	go r.processReports()
}

func (r *Reporter) Stop() {
	log.Println("Stopping reporter service")
	close(r.quit)
}

func (r *Reporter) ReportMaliciousIP(ip, reason, logPath string, count, banTime int) {
	report := &shared.ReportRequest{
		Token:   r.token,
		IP:      ip,
		Reason:  reason,
		LogPath: logPath,
		Count:   count,
		BanTime: banTime,
	}

	select {
	case r.reportQueue <- report:
		// Report queued successfully
	default:
		log.Printf("Report queue is full, dropping report for IP: %s", ip)
	}
}

func (r *Reporter) processReports() {
	for {
		select {
		case report := <-r.reportQueue:
			r.sendReport(report)
		case <-r.quit:
			return
		}
	}
}

func (r *Reporter) sendReport(report *shared.ReportRequest) {
	jsonData, err := json.Marshal(report)
	if err != nil {
		log.Printf("Failed to marshal report: %v", err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/report", r.panelURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		log.Printf("Failed to send report to panel: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Panel returned error status: %d for IP %s", resp.StatusCode, report.IP)
		return
	}

	log.Printf("Successfully reported malicious IP: %s", report.IP)
}

func (r *Reporter) TestConnection() error {
	url := fmt.Sprintf("%s/api/v1/detectors", r.panelURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %v", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to panel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Println("Successfully connected to panel")
		return nil
	}

	return fmt.Errorf("panel returned status: %d", resp.StatusCode)
}
