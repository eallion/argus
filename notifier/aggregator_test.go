package notifier

import (
	"strings"
	"testing"
)

func TestAlertAggregator(t *testing.T) {
	agg := NewAlertAggregator()

	if count := agg.Count(); count != 0 {
		t.Fatalf("expected 0 items initially, got %d", count)
	}

	// 1. 添加单个目标告警
	agg.Add("example.com", []string{"- SSL 证书临期: 剩余 7 天"}, "warning")
	if agg.Count() != 1 {
		t.Fatalf("expected count 1, got %d", agg.Count())
	}

	// 2. 重复添加相同目标更严重告警，等级应升级为 critical
	agg.Add("example.com", []string{"- SSL 证书过期: 证书已失效！"}, "critical")
	if agg.Count() != 1 {
		t.Fatalf("expected count still 1 after update, got %d", agg.Count())
	}

	// 3. 添加第二个目标告警
	agg.Add("api.example.com", []string{"- 域名注册 15天临期提醒"}, "notice")
	if agg.Count() != 2 {
		t.Fatalf("expected count 2, got %d", agg.Count())
	}

	// 4. Flush 队列
	items := agg.Flush()
	if len(items) != 2 {
		t.Fatalf("expected 2 flushed items, got %d", len(items))
	}
	if agg.Count() != 0 {
		t.Fatalf("expected count 0 after flush, got %d", agg.Count())
	}

	// 5. 格式化汇总测试
	title, body, severity := FormatSummary(items, "1h")
	if !strings.Contains(title, "2 项域名/证书异常") {
		t.Errorf("unexpected summary title: %s", title)
	}
	if severity != "critical" {
		t.Errorf("expected worst severity 'critical', got %s", severity)
	}
	if !strings.Contains(body, "example.com") || !strings.Contains(body, "api.example.com") {
		t.Errorf("summary body missing expected hosts: %s", body)
	}
}
