package dns_provider

import (
	"context"
	"strings"
	"time"
)

// Record represents a single DNS record extracted from DNS API
type Record struct {
	Name     string `json:"name"`      // Full domain name e.g. "www.example.com"
	Type     string `json:"type"`      // A, AAAA, CNAME
	Value    string `json:"value"`     // IP or target host
	TTL      int    `json:"ttl"`
	ZoneID   string `json:"zone_id,omitempty"`
}

// ProviderConfig holds credentials and options for calling DNS API
type ProviderConfig struct {
	ProviderType string            `json:"provider_type"`
	AuthKey      string            `json:"auth_key"`    // API Token, AccessKeyId, etc.
	AuthSecret   string            `json:"auth_secret"` // SecretKey, Global API Key, etc.
	ZoneID       string            `json:"zone_id"`     // Specific Zone ID / Site ID (optional)
	Extra        map[string]string `json:"extra,omitempty"` // Region, ClientIP, etc.
}

// ProviderMeta describes a supported DNS provider
type ProviderMeta struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	AuthFields  []string `json:"auth_fields"` // e.g. ["auth_key"] or ["auth_key", "auth_secret"]
	KeyLabel    string   `json:"key_label"`
	SecretLabel string   `json:"secret_label"`
	ZoneLabel   string   `json:"zone_label"`
	DocURL              string   `json:"doc_url"`
	RequiredPermissions string   `json:"required_permissions"` // 对应平台官方所需的最小 API 权限
}

// Provider is the common interface implemented by all DNS API integrations
type Provider interface {
	Type() string
	Name() string
	FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error)
}

// BlacklistFilter filters out domains matching blacklist rules
// Blacklist rules support:
// 1. Exact full match: "mail.example.com"
// 2. Prefix / subdomain label match: "mail" (matches "mail.example.com")
// 3. Wildcard match: "*.internal" or "test-*"
func FilterBlacklist(domains []string, rootDomain string, blacklist []string) (allowed []string, blocked []string) {
	normRules := make([]string, 0, len(blacklist))
	for _, rule := range blacklist {
		r := strings.TrimSpace(strings.ToLower(rule))
		if r != "" && !strings.HasPrefix(r, "#") {
			normRules = append(normRules, r)
		}
	}

	normRoot := strings.TrimRight(strings.ToLower(strings.TrimSpace(rootDomain)), ".")

	seenAllowed := make(map[string]bool)
	seenBlocked := make(map[string]bool)

	for _, d := range domains {
		dom := strings.TrimRight(strings.ToLower(strings.TrimSpace(d)), ".")
		if dom == "" {
			continue
		}

		if isDomainBlocked(dom, normRoot, normRules) {
			if !seenBlocked[dom] {
				seenBlocked[dom] = true
				blocked = append(blocked, dom)
			}
		} else {
			if !seenAllowed[dom] {
				seenAllowed[dom] = true
				allowed = append(allowed, dom)
			}
		}
	}

	return allowed, blocked
}

// isDomainBlocked checks if a domain matches any blacklist rule
func isDomainBlocked(dom, rootDomain string, rules []string) bool {
	if len(rules) == 0 {
		return false
	}

	// Extract sub label (e.g. for "mail.example.com" with root "example.com", sub is "mail")
	subLabel := ""
	if rootDomain != "" && strings.HasSuffix(dom, "."+rootDomain) {
		subLabel = strings.TrimSuffix(dom, "."+rootDomain)
	} else if rootDomain != "" && dom == rootDomain {
		subLabel = "@"
	}

	for _, rule := range rules {
		// Exact full domain match
		if dom == rule {
			return true
		}

		// Exact sub-label match (e.g. rule is "mail", dom is "mail.example.com")
		if subLabel != "" && (subLabel == rule || rule == "@" && dom == rootDomain) {
			return true
		}

		// Wildcard match e.g. "*.dev" or "dev-*" or "*test*"
		if strings.Contains(rule, "*") {
			if matchWildcard(rule, dom) {
				return true
			}
			if subLabel != "" && matchWildcard(rule, subLabel) {
				return true
			}
		}
	}

	return false
}

// Simple wildcard matcher supporting '*'
func matchWildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}

	// Check prefix
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx == -1 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// Check suffix
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// IsWebRecordType returns true if record type is relevant for HTTP/HTTPS website checking
func IsWebRecordType(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "A", "AAAA", "CNAME":
		return true
	default:
		return false
	}
}

// NormalizeDomainName cleans and normalizes domain record
func NormalizeDomainName(name, rootDomain string) string {
	n := strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
	if n == "@" || n == "" {
		return rootDomain
	}
	// If it's a relative record without rootDomain
	if rootDomain != "" && !strings.HasSuffix(n, "."+rootDomain) && n != rootDomain {
		return n + "." + rootDomain
	}
	return n
}

// DefaultTimeout for API queries
const DefaultTimeout = 20 * time.Second
