package checker

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type DomainResult struct {
	Domain    string
	ExpiresAt time.Time
	DaysLeft  int
	IsExpired bool
	Error     error
}

type rdapResponse struct {
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
}

var expirationPrefixes = []string{
	"expiration time:",
	"registry expiry date:",
	"registry expiration date:",
	"registrar registration expiration date:",
	"expiration date:",
	"expiry date:",
	"paid-till:",
	"expire date:",
	"expires on:",
	"expires:",
}

// CheckDomain performs domain expiration checks via RDAP (RFC 7483/9083) with authoritative WHOIS fallback (RFC 3912).
func CheckDomain(domain string, timeout time.Duration) DomainResult {
	// Remove port if present
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}
	domain = strings.TrimSpace(strings.ToLower(domain))

	// 1. .cn 系列域名 (CNNIC 未向 IANA 注册 RDAP 服务且无公开 RDAP 端点，直接通过权威 WHOIS 查询)
	if isCNDomain(domain) {
		return checkCNDomainWhois(domain, timeout)
	}

	// 2. 尝试标准 RDAP 协议
	rdapRes := checkRDAP(domain, timeout)
	if rdapRes.Error == nil {
		return rdapRes
	}

	// 3. 若 RDAP 返回 404 (该 TLD 尚未支持 RDAP)，回退到传统 WHOIS 协议兜底
	if strings.Contains(rdapRes.Error.Error(), "status 404") {
		whoisRes := checkGenericWhois(domain, timeout)
		if whoisRes.Error == nil {
			return whoisRes
		}
	}

	return rdapRes
}

func isCNDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.HasSuffix(d, ".cn") || strings.HasSuffix(d, ".中国") || strings.HasSuffix(d, ".公司") || strings.HasSuffix(d, ".网络")
}

func checkCNDomainWhois(domain string, timeout time.Duration) DomainResult {
	res := DomainResult{Domain: domain}
	// whois.cnnic.cn 是 CNNIC 官方权威注册局 WHOIS 服务器
	servers := []string{"whois.cnnic.cn:43", "whois.gtld.knet.cn:43"}
	var lastErr error

	whoisTimeout := timeout
	if whoisTimeout < 5*time.Second {
		whoisTimeout = 5 * time.Second
	}

	for _, srv := range servers {
		raw, err := queryWhois(srv, domain, whoisTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		t, err := parseWhoisExpiration(raw)
		if err != nil {
			lastErr = err
			continue
		}
		res.ExpiresAt = t
		res.DaysLeft = int(time.Until(t).Hours() / 24)
		if res.DaysLeft < 0 {
			res.IsExpired = true
		}
		res.Error = nil
		return res
	}

	if lastErr != nil {
		res.Error = fmt.Errorf("cnnic whois 查询失败: %w", lastErr)
	} else {
		res.Error = fmt.Errorf("未在 CNNIC whois 响应中解析到到期时间")
	}
	return res
}

func checkGenericWhois(domain string, timeout time.Duration) DomainResult {
	res := DomainResult{Domain: domain}
	whoisTimeout := timeout
	if whoisTimeout < 5*time.Second {
		whoisTimeout = 5 * time.Second
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		res.Error = fmt.Errorf("invalid domain format")
		return res
	}
	tld := parts[len(parts)-1]

	// 1. 查询 IANA 获取该 TLD 的权威 WHOIS 服务器
	ianaRaw, err := queryWhois("whois.iana.org:43", tld, whoisTimeout)
	if err != nil {
		res.Error = err
		return res
	}

	var targetWhoisServer string
	lines := strings.Split(ianaRaw, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(strings.ToLower(l), "whois:") {
			targetWhoisServer = strings.TrimSpace(l[6:])
			break
		}
	}

	if targetWhoisServer == "" {
		res.Error = fmt.Errorf("whois.iana.org 未包含该 TLD 的 whois 服务器")
		return res
	}

	// 2. 向该顶级域权威 WHOIS 服务器查询具体域名
	raw, err := queryWhois(targetWhoisServer, domain, whoisTimeout)
	if err != nil {
		res.Error = err
		return res
	}

	t, err := parseWhoisExpiration(raw)
	if err != nil {
		res.Error = err
		return res
	}

	res.ExpiresAt = t
	res.DaysLeft = int(time.Until(t).Hours() / 24)
	if res.DaysLeft < 0 {
		res.IsExpired = true
	}
	return res
}

func queryWhois(server, domain string, timeout time.Duration) (string, error) {
	if !strings.Contains(server, ":") {
		server += ":43"
	}
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", err
	}

	out, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parseWhoisExpiration(raw string) (time.Time, error) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		lineTrimmed := strings.TrimSpace(line)
		lineLower := strings.ToLower(lineTrimmed)
		for _, prefix := range expirationPrefixes {
			if strings.HasPrefix(lineLower, prefix) {
				dateStr := strings.TrimSpace(lineTrimmed[len(prefix):])
				if idx := strings.Index(dateStr, " ("); idx != -1 {
					dateStr = strings.TrimSpace(dateStr[:idx])
				}
				if t, err := parseTime(dateStr); err == nil {
					return t, nil
				}
			}
		}
	}
	return time.Time{}, fmt.Errorf("未在 whois 响应中找到有效到期时间")
}

func checkRDAP(domain string, timeout time.Duration) DomainResult {
	res := DomainResult{Domain: domain}
	client := &http.Client{Timeout: timeout}
	reqURL := fmt.Sprintf("https://rdap.org/domain/%s", domain)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		res.Error = err
		return res
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "Argus/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Errorf("rdap server responded with status %d", resp.StatusCode)
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err
		return res
	}

	var rdap rdapResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		res.Error = fmt.Errorf("failed to parse rdap response: %w", err)
		return res
	}

	for _, event := range rdap.Events {
		if event.EventAction == "expiration" {
			t, err := parseTime(event.EventDate)
			if err != nil {
				res.Error = fmt.Errorf("failed to parse expiration date %q: %w", event.EventDate, err)
				return res
			}
			res.ExpiresAt = t
			res.DaysLeft = int(time.Until(t).Hours() / 24)
			if res.DaysLeft < 0 {
				res.IsExpired = true
			}
			return res
		}
	}

	res.Error = fmt.Errorf("expiration event not found in rdap response")
	return res
}

func parseTime(val string) (time.Time, error) {
	val = strings.TrimSpace(val)
	cst := time.FixedZone("CST", 8*3600)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02-Jan-2006 15:04:05",
		"2006.01.02 15:04:05",
		"2006/01/02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, val); err == nil {
			return t, nil
		}
		if t, err := time.ParseInLocation(f, val, cst); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format")
}

// IsApexDomain determines if a hostname is an apex/root domain (excluding subdomains and www).
func IsApexDomain(input string) bool {
	host := strings.TrimSpace(strings.ToLower(input))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "" || host == "localhost" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	// www 视为子域名，默认不作为根域名查询到期时间
	if strings.HasPrefix(host, "www.") {
		return false
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}

	compoundTLDs := map[string]bool{
		"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
		"co.uk": true, "org.uk": true, "me.uk": true, "ac.uk": true,
		"com.hk": true, "org.hk": true, "edu.hk": true,
		"com.tw": true, "org.tw": true, "idv.tw": true,
		"co.jp": true, "ne.jp": true, "or.jp": true,
		"com.au": true, "net.au": true, "org.au": true,
	}

	if len(parts) >= 2 {
		lastTwo := strings.Join(parts[len(parts)-2:], ".")
		if compoundTLDs[lastTwo] {
			return len(parts) == 3
		}
	}

	return len(parts) == 2
}

// IsRootOrWWW determines if a hostname is an apex domain or starts with www. (used for default pinning)
func IsRootOrWWW(input string) bool {
	host := strings.TrimSpace(strings.ToLower(input))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if strings.HasPrefix(host, "www.") {
		return IsApexDomain(strings.TrimPrefix(host, "www."))
	}
	return IsApexDomain(host)
}

// GetApexDomain extracts the root/apex domain from a hostname or URL (e.g. sub.example.com -> example.com)
func GetApexDomain(input string) string {
	host := strings.TrimSpace(strings.ToLower(input))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return host
	}
	if strings.HasPrefix(host, "www.") {
		host = strings.TrimPrefix(host, "www.")
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}

	compoundTLDs := map[string]bool{
		"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
		"co.uk": true, "org.uk": true, "me.uk": true, "ac.uk": true,
		"com.hk": true, "org.hk": true, "edu.hk": true,
		"com.tw": true, "org.tw": true, "idv.tw": true,
		"co.jp": true, "ne.jp": true, "or.jp": true,
		"com.au": true, "net.au": true, "org.au": true,
	}

	lastTwo := strings.Join(parts[len(parts)-2:], ".")
	if compoundTLDs[lastTwo] {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
