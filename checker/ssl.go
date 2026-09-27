package checker

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type SSLResult struct {
	Target    string
	Host      string
	Port      string
	Issuer    string
	Subject   string
	ExpiresAt time.Time
	DaysLeft  int
	IsExpired bool
	Error     error
}

// NodeResult stores inspection detail for each specific node in multi-host mode
type NodeResult struct {
	Type      string     `json:"type,omitempty"` // A, AAAA, CNAME
	Node      string     `json:"node"`
	Alias     string     `json:"alias"`
	DaysLeft  int        `json:"days_left"`
	ExpiresAt *time.Time `json:"expires_at"`
	Issuer    string     `json:"issuer"`
	Status    string     `json:"status"` // "healthy", "info", "notice", "warning", "critical", "expired", "error"
	Error     string     `json:"error"`
}

type HostNodeConfig struct {
	Type    string `json:"type,omitempty"`
	Address string `json:"value,omitempty"`
	Node    string `json:"address,omitempty"` // fallback if address key is used
	Alias   string `json:"alias,omitempty"`
}

// ParseHostsList parses multi-line text input or JSON array into node configs, extracting comments and record types
func ParseHostsList(raw string) []HostNodeConfig {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// 1. Try JSON unmarshal
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		var jsonNodes []HostNodeConfig
		if err := json.Unmarshal([]byte(raw), &jsonNodes); err == nil && len(jsonNodes) > 0 {
			var validNodes []HostNodeConfig
			for _, n := range jsonNodes {
				addr := strings.TrimSpace(n.Address)
				if addr == "" {
					addr = strings.TrimSpace(n.Node)
				}
				if addr != "" {
					nodeType := strings.ToUpper(strings.TrimSpace(n.Type))
					if nodeType == "" {
						nodeType = "A"
					}
					validNodes = append(validNodes, HostNodeConfig{
						Type:    nodeType,
						Address: addr,
						Alias:   strings.TrimSpace(n.Alias),
					})
				}
			}
			if len(validNodes) > 0 {
				return validNodes
			}
		}
	}

	// 2. Line-by-line fallback parsing
	var nodes []HostNodeConfig
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		alias := ""
		if idx := strings.Index(line, "#"); idx != -1 {
			alias = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		} else if idx := strings.Index(line, "//"); idx != -1 {
			alias = strings.TrimSpace(line[idx+2:])
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		nodeType := "A"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			firstUpper := strings.ToUpper(parts[0])
			if firstUpper == "A" || firstUpper == "AAAA" || firstUpper == "CNAME" {
				nodeType = firstUpper
				line = parts[1]
			}
		}

		nodes = append(nodes, HostNodeConfig{
			Type:    nodeType,
			Address: line,
			Alias:   alias,
		})
	}
	return nodes
}

// CheckSSL dials the default host DNS resolution
func CheckSSL(target string, timeout time.Duration) SSLResult {
	host := target
	port := "443"
	if strings.Contains(target, ":") {
		h, p, err := net.SplitHostPort(target)
		if err == nil {
			host = h
			port = p
		}
	}
	return CheckSSLWithSNI(host, host, port, timeout)
}

// CheckSSLWithSNI dials connectAddr directly while presenting sniHost during TLS handshake
func CheckSSLWithSNI(sniHost, connectAddr, defaultPort string, timeout time.Duration) SSLResult {
	res := SSLResult{
		Target: connectAddr,
		Host:   sniHost,
		Port:   defaultPort,
	}

	hostToConnect := connectAddr
	portToConnect := defaultPort
	if strings.Contains(connectAddr, ":") {
		h, p, err := net.SplitHostPort(connectAddr)
		if err == nil {
			hostToConnect = h
			portToConnect = p
		}
	}
	res.Port = portToConnect

	dialer := &net.Dialer{Timeout: timeout}
	// InsecureSkipVerify allows completing handshake to retrieve peer certificates even if expired
	tlsConfig := &tls.Config{
		ServerName:         sniHost,
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(hostToConnect, portToConnect), tlsConfig)
	if err != nil {
		res.Error = err
		return res
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		res.Error = fmt.Errorf("no peer certificates presented")
		return res
	}

	leaf := certs[0]
	res.Issuer = leaf.Issuer.CommonName
	if res.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		res.Issuer = leaf.Issuer.Organization[0]
	}
	res.Subject = leaf.Subject.CommonName
	res.ExpiresAt = leaf.NotAfter
	res.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	if res.DaysLeft < 0 || time.Now().After(leaf.NotAfter) {
		res.IsExpired = true
	}

	// 1. 优先严格校验主机名与 SNI 匹配性 (RFC 6125)
	// 无论证书是否过期，若证书不包含该域名，必须优先作为域名不匹配错误拦截
	if hostErr := leaf.VerifyHostname(sniHost); hostErr != nil {
		res.Error = fmt.Errorf("证书域名不匹配 (SNI 不符): %w", hostErr)
		return res
	}

	// 2. 校验 CA 证书链有效性与信任度
	opts := x509.VerifyOptions{
		DNSName:       sniHost,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(opts); err != nil {
		// If expired, let isExpired flag handle it; otherwise record verification error (e.g. untrusted CA)
		if !res.IsExpired {
			res.Error = err
		}
	}

	return res
}
