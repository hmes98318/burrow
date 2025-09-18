package shared

import (
	"time"
)

// DetectorConfig represents detector configuration
type DetectorConfig struct {
	ID       int       `json:"id" db:"id"`
	Name     string    `json:"name" db:"name"`
	Token    string    `json:"token" db:"token"`
	Created  time.Time `json:"created" db:"created"`
	LastSeen time.Time `json:"last_seen" db:"last_seen"`
	Status   string    `json:"status" db:"status"` // online, offline, error
	IP       string    `json:"ip" db:"ip"`
}

// MaliciousIP represents a malicious IP entry
type MaliciousIP struct {
	ID         int       `json:"id" db:"id"`
	IP         string    `json:"ip" db:"ip"`
	Source     string    `json:"source" db:"source"`           // detector_id, external_feed, manual
	SourceType string    `json:"source_type" db:"source_type"` // detector, external, manual
	Weight     int       `json:"weight" db:"weight"`           // priority weight for sorting
	FirstSeen  time.Time `json:"first_seen" db:"first_seen"`
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	Count      int       `json:"count" db:"count"`       // how many times reported
	Reason     string    `json:"reason" db:"reason"`     // description of why it's malicious
	BanTime    int       `json:"ban_time" db:"ban_time"` // minutes, 0 = permanent ban, >0 = temporary ban
	Active     bool      `json:"active" db:"active"`
}

// ExternalFeed represents external threat intelligence feeds
type ExternalFeed struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	URL         string    `json:"url" db:"url"`
	UpdateFreq  int       `json:"update_freq" db:"update_freq"` // minutes
	LastUpdate  time.Time `json:"last_update" db:"last_update"`
	Active      bool      `json:"active" db:"active"`
	Format      string    `json:"format" db:"format"` // plain, csv, json
	Description string    `json:"description" db:"description"`
}

// LogConfig represents log monitoring configuration for detector
type LogConfig struct {
	Path         string `yaml:"path" json:"path"`
	Regex        string `yaml:"regex" json:"regex"`
	MaxRetry     int    `yaml:"max_retry" json:"max_retry"`
	TimeWindow   int    `yaml:"time_window" json:"time_window"`     // minutes
	ScanInterval int    `yaml:"scan_interval" json:"scan_interval"` // milliseconds, default 1000ms
	BanTime      int    `yaml:"ban_time" json:"ban_time"`           // minutes, 0 = permanent ban, >0 = temporary ban
	Description  string `yaml:"description" json:"description"`
}

// DetectorSettings represents detector configuration file
type DetectorSettings struct {
	PanelURL          string            `yaml:"panel_url" json:"panel_url"`
	Token             string            `yaml:"token" json:"token"`
	Name              string            `yaml:"name" json:"name"`
	IncludePrivateIPs bool              `yaml:"include_private_ips" json:"include_private_ips"` // 是否包含 private IP 的掃描，預設 false
	HeartbeatInterval int               `yaml:"heartbeat_interval" json:"heartbeat_interval"`   // 心跳發送間隔（秒），預設 10s
	Placeholders      map[string]string `yaml:"placeholders" json:"placeholders"`               // 佔位符定義
	Logs              []LogConfig       `yaml:"logs" json:"logs"`
}

// PanelSettings represents panel configuration file
type PanelSettings struct {
	Port             int    `yaml:"port" json:"port"`                           // HTTP server port, default 8080
	HeartbeatTimeout int    `yaml:"heartbeat_timeout" json:"heartbeat_timeout"` // 心跳超時時間（秒），預設 60s
	DatabasePath     string `yaml:"database_path" json:"database_path"`         // SQLite database file path
	BlockCIDR24      bool   `yaml:"block_cidr24" json:"block_cidr24"`           // 是否將 IP 轉換為 /24 網段進行封鎖，預設 false
}

// ReportRequest represents a request from detector to panel
type ReportRequest struct {
	Token   string `json:"token"` // Detector authentication token
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	LogPath string `json:"log_path"`
	Count   int    `json:"count"`
	BanTime int    `json:"ban_time"` // minutes, 0 = permanent ban, >0 = temporary ban
}

// HeartbeatRequest represents a heartbeat request from detector to panel
type HeartbeatRequest struct {
	Token     string `json:"token"` // Detector authentication token
	Timestamp int64  `json:"timestamp"`
}

// FirewallFormat represents different firewall export formats
type FirewallFormat struct {
	Name     string `json:"name"`
	MaxCount int    `json:"max_count"`
	Endpoint string `json:"endpoint"`
}

// Common firewall formats
var FirewallFormats = map[string]FirewallFormat{
	"fortigate_old": {
		Name:     "FortiGate (≤7.4.4)",
		MaxCount: 131072,
		Endpoint: "fortigate-13k",
	},
	"fortigate_new": {
		Name:     "FortiGate (>7.4.4)",
		MaxCount: 300000,
		Endpoint: "fortigate-30k",
	},
	"palo_alto": {
		Name:     "Palo Alto",
		MaxCount: 100000,
		Endpoint: "palo-alto",
	},
	"pfsense": {
		Name:     "pfSense",
		MaxCount: 50000,
		Endpoint: "pfsense",
	},
	"opnsense": {
		Name:     "OPNsense",
		MaxCount: 50000,
		Endpoint: "opnsense",
	},
	"iptables": {
		Name:     "IPtables",
		MaxCount: 65536,
		Endpoint: "iptables",
	},
	"nginx_geo": {
		Name:     "Nginx Geo Module",
		MaxCount: 50000,
		Endpoint: "nginx-geo",
	},
}
