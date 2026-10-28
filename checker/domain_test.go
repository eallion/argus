package checker

import (
	"testing"
	"time"
)

func TestParseWhoisExpirationCNNIC(t *testing.T) {
	rawCNNIC := `Domain Name: alibaba.cn
ROID: 20030312s10001s00055047-cn
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Registrant: 阿里巴巴（中国）有限公司
Registrant Contact Email: dnsadmin@alibaba-inc.com
Sponsoring Registrar: 阿里云计算有限公司（万网）
Name Server: ns1.alidns.com
Name Server: ns2.alidns.com
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2028-03-17 12:48:36
DNSSEC: unsigned
`
	expire, err := parseWhoisExpiration(rawCNNIC)
	if err != nil {
		t.Fatalf("failed to parse CNNIC expiration: %v", err)
	}

	expectedYear := 2028
	expectedMonth := time.Month(3)
	expectedDay := 17
	if expire.Year() != expectedYear || expire.Month() != expectedMonth || expire.Day() != expectedDay {
		t.Errorf("expected %d-%d-%d, got %v", expectedYear, expectedMonth, expectedDay, expire)
	}
}

func TestParseWhoisExpirationGeneric(t *testing.T) {
	rawGeneric := `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2024-08-14T07:01:44Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
`
	expire, err := parseWhoisExpiration(rawGeneric)
	if err != nil {
		t.Fatalf("failed to parse generic expiration: %v", err)
	}

	if expire.Year() != 2027 || expire.Month() != time.August || expire.Day() != 13 {
		t.Errorf("unexpected date: %v", expire)
	}
}

func TestGetApexDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"api.sub.example.com", "example.com"},
		{"https://app.dev.test.example.com/path", "example.com"},
		{"test.co.uk", "test.co.uk"},
		{"sub.test.co.uk", "test.co.uk"},
		{"api.sub.example.com.cn", "example.com.cn"},
		{"192.168.1.1", "192.168.1.1"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		got := GetApexDomain(tt.input)
		if got != tt.expected {
			t.Errorf("GetApexDomain(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestEvaluateDomainStatus(t *testing.T) {
	now := time.Now()
	maxTier := 30

	// 1. 超过最大阶梯天数：正常
	daysLeft, status := EvaluateDomainStatus(now.Add(100*24*time.Hour), maxTier)
	if status != "healthy" || daysLeft < 99 {
		t.Errorf("expected healthy, got status=%s, daysLeft=%d", status, daysLeft)
	}

	// 2. 关注临期 (<= 30 天)
	_, status = EvaluateDomainStatus(now.Add(25*24*time.Hour), maxTier)
	if status != "info" {
		t.Errorf("expected info, got status=%s", status)
	}

	// 3. 注意 (<= 15 天)
	_, status = EvaluateDomainStatus(now.Add(12*24*time.Hour), maxTier)
	if status != "notice" {
		t.Errorf("expected notice, got status=%s", status)
	}

	// 4. 橙色警告 (<= 7 天)
	_, status = EvaluateDomainStatus(now.Add(5*24*time.Hour), maxTier)
	if status != "warning" {
		t.Errorf("expected warning, got status=%s", status)
	}

	// 5. 极危红色警告 (<= 3 天)
	_, status = EvaluateDomainStatus(now.Add(2*24*time.Hour), maxTier)
	if status != "critical" {
		t.Errorf("expected critical, got status=%s", status)
	}

	// 6. 已过期
	_, status = EvaluateDomainStatus(now.Add(-2*24*time.Hour), maxTier)
	if status != "expired" {
		t.Errorf("expected expired, got status=%s", status)
	}
}

