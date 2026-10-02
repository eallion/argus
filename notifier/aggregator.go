package notifier

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AggregatedAlertItem struct {
	Host      string    `json:"host"`
	Messages  []string  `json:"messages"`
	Severity  string    `json:"severity"` // "critical", "warning", "notice", "info"
	Timestamp time.Time `json:"timestamp"`
}

type AlertAggregator struct {
	mu      sync.Mutex
	pending map[string]AggregatedAlertItem
}

func NewAlertAggregator() *AlertAggregator {
	return &AlertAggregator{
		pending: make(map[string]AggregatedAlertItem),
	}
}

// Add appends or updates an alert item for a given host in the aggregation buffer
func (a *AlertAggregator) Add(host string, messages []string, severity string) {
	if len(messages) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	normHost := strings.TrimSpace(host)
	now := time.Now().UTC()

	// Prioritize worse severity if already present
	prev, exists := a.pending[normHost]
	if exists {
		if severityWeight(severity) < severityWeight(prev.Severity) {
			severity = prev.Severity
		}
	}

	a.pending[normHost] = AggregatedAlertItem{
		Host:      normHost,
		Messages:  messages,
		Severity:  severity,
		Timestamp: now,
	}
}

func severityWeight(s string) int {
	switch s {
	case "critical", "expired", "error":
		return 3
	case "warning":
		return 2
	case "notice":
		return 1
	default:
		return 0
	}
}

// Count returns the number of pending aggregated items
func (a *AlertAggregator) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// Flush extracts all pending items and clears the queue
func (a *AlertAggregator) Flush() []AggregatedAlertItem {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pending) == 0 {
		return nil
	}

	items := make([]AggregatedAlertItem, 0, len(a.pending))
	for _, item := range a.pending {
		items = append(items, item)
	}
	a.pending = make(map[string]AggregatedAlertItem)
	return items
}

// ParseBatchTime parses time string like "09:00", "9:00", "23:59" into hour (0-23) and minute (0-59).
func ParseBatchTime(raw string) (int, int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 9, 0, false
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 9, 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 9, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 9, 0, false
	}
	return h, m, true
}

// GetServerLocation returns the location configured by TZ environment variable, falling back to time.Local.
func GetServerLocation() *time.Location {
	tz := strings.TrimSpace(os.Getenv("TZ"))
	if tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.Local
}

// GetTimezoneInfo returns the timezone identifier (e.g. "Asia/Shanghai") and offset string (e.g. "UTC+08:00").
func GetTimezoneInfo() (string, string) {
	loc := GetServerLocation()
	now := time.Now().In(loc)
	zoneName, offsetSec := now.Zone()

	sign := "+"
	if offsetSec < 0 {
		sign = "-"
		offsetSec = -offsetSec
	}
	hours := offsetSec / 3600
	mins := (offsetSec % 3600) / 60
	offsetStr := fmt.Sprintf("UTC%s%02d:%02d", sign, hours, mins)

	tzName := strings.TrimSpace(os.Getenv("TZ"))
	if tzName == "" {
		tzName = loc.String()
	}
	if tzName == "Local" || tzName == "" {
		tzName = zoneName
	}
	return tzName, offsetStr
}

// FormatSummary generates a unified notification title and body for the aggregated batch
func FormatSummary(items []AggregatedAlertItem, batchTimeStr string, loc *time.Location) (string, string, string) {
	if len(items) == 0 {
		return "", "", "info"
	}

	if loc == nil {
		loc = GetServerLocation()
	}
	now := time.Now().In(loc)

	title := fmt.Sprintf("[Argus 告警汇总] 发现 %d 项域名/证书异常 (合并通知)", len(items))
	worstSeverity := "warning"

	var blocks []string
	for i, item := range items {
		if severityWeight(item.Severity) >= 3 {
			worstSeverity = "critical"
		}
		block := fmt.Sprintf("[%d] 目标: %s\n%s", i+1, item.Host, strings.Join(item.Messages, "\n"))
		blocks = append(blocks, block)
	}

	tzName, tzOffset := GetTimezoneInfo()

	timeDesc := strings.TrimSpace(batchTimeStr)
	if timeDesc == "" {
		timeDesc = "每日汇总"
	} else if strings.Contains(timeDesc, ":") {
		timeDesc = fmt.Sprintf("每日 %s", timeDesc)
	}

	body := fmt.Sprintf("汇总时间: %s (%s, %s)\n发送时间: %s\n异常目标总计: %d 项\n\n%s",
		now.Format("2006-01-02 15:04:05"),
		tzName,
		tzOffset,
		timeDesc,
		len(items),
		strings.Join(blocks, "\n\n"),
	)

	return title, body, worstSeverity
}
