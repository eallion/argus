package dns_provider

import (
	"fmt"
	"sync"
)

var (
	registryMu sync.RWMutex
	providers  = make(map[string]Provider)
	metas      = make(map[string]ProviderMeta)
)

// RegisterProvider registers a DNS Provider
func RegisterProvider(p Provider, meta ProviderMeta) {
	registryMu.Lock()
	defer registryMu.Unlock()
	providers[p.Type()] = p
	metas[p.Type()] = meta
}

// GetProvider retrieves a provider by its type key
func GetProvider(providerType string) (Provider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	p, ok := providers[providerType]
	if !ok {
		return nil, fmt.Errorf("不支持的 DNS 厂商类型: %s", providerType)
	}
	return p, nil
}

// ListProviders returns all registered providers with metadata for UI
func ListProviders() []ProviderMeta {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// Keep an orderly preferred list
	order := []string{
		"cloudflare",
		"aliyun",
		"aliyun_esa",
		"tencent",
		"dnspod_token",
		"edgeone",
		"volcengine",
		"huawei",
		"aws_route53",
		"godaddy",
		"digitalocean",
		"vultr",
	}

	result := make([]ProviderMeta, 0, len(metas))
	seen := make(map[string]bool)

	for _, k := range order {
		if m, ok := metas[k]; ok {
			result = append(result, m)
			seen[k] = true
		}
	}

	for k, m := range metas {
		if !seen[k] {
			result = append(result, m)
		}
	}

	return result
}
