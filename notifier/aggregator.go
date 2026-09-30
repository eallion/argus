package notifier

import (
	"fmt"
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

// FormatSummary generates a unified notification title and body for the aggregated batch
func FormatSummary(items []AggregatedAlertItem, intervalStr string) (string, string, string) {
	if len(items) == 0 {
		return "", "", "info"
	}

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

	body := fmt.Sprintf("汇总时间: %s (周期: %s)\n异常目标总计: %d 项\n\n%s",
		time.Now().Format("2006-01-02 15:04:05"),
		intervalStr,
		len(items),
		strings.Join(blocks, "\n\n"),
	)

	return title, body, worstSeverity
}
