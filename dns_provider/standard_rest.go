package dns_provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// -------------------------------------------------------------
// GoDaddy DNS Provider
// -------------------------------------------------------------
type GoDaddyProvider struct{}

func init() {
	RegisterProvider(&GoDaddyProvider{}, ProviderMeta{
		Type:        "godaddy",
		Name:        "GoDaddy DNS",
		Description: "GoDaddy 域名与 DNS 解析 API (Key & Secret)",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "API Key",
		SecretLabel: "API Secret",
		ZoneLabel:           "域名（无需额外 ZoneID）",
		DocURL:              "https://developer.godaddy.com/doc/endpoint/domains#/v1/recordGet",
		RequiredPermissions: "需申请 Production 生产环境 API Key & Secret，具备 Domains 读取权限",
	})
}

func (p *GoDaddyProvider) Type() string { return "godaddy" }
func (p *GoDaddyProvider) Name() string { return "GoDaddy DNS" }

type godaddyRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func (p *GoDaddyProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	key := strings.TrimSpace(cfg.AuthKey)
	secret := strings.TrimSpace(cfg.AuthSecret)
	if key == "" || secret == "" {
		return nil, fmt.Errorf("GoDaddy API Key 和 Secret 不能为空")
	}

	u := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records", url.PathEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", key, secret))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 GoDaddy API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errRes struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errRes)
		return nil, fmt.Errorf("GoDaddy API 返回错误 [%d]: %s", resp.StatusCode, errRes.Message)
	}

	var rawRecords []godaddyRecord
	if err := json.NewDecoder(resp.Body).Decode(&rawRecords); err != nil {
		return nil, fmt.Errorf("解析 GoDaddy 记录失败: %w", err)
	}

	var records []Record
	for _, r := range rawRecords {
		if IsWebRecordType(r.Type) {
			fullHost := domain
			if r.Name != "@" && r.Name != "" {
				fullHost = r.Name + "." + domain
			}
			records = append(records, Record{
				Name:  NormalizeDomainName(fullHost, domain),
				Type:  r.Type,
				Value: r.Data,
				TTL:   r.TTL,
			})
		}
	}

	return records, nil
}

// -------------------------------------------------------------
// DigitalOcean DNS Provider
// -------------------------------------------------------------
type DigitalOceanProvider struct{}

func init() {
	RegisterProvider(&DigitalOceanProvider{}, ProviderMeta{
		Type:        "digitalocean",
		Name:        "DigitalOcean DNS",
		Description: "DigitalOcean Networking Domains API",
		AuthFields:  []string{"auth_key"},
		KeyLabel:    "Personal Access Token",
		SecretLabel: "留空即可",
		ZoneLabel:           "域名（无需额外 ZoneID）",
		DocURL:              "https://docs.digitalocean.com/reference/api/api-reference/#tag/Domain-Records",
		RequiredPermissions: "Personal Access Token 需勾选 Read (只读) 权限",
	})
}

func (p *DigitalOceanProvider) Type() string { return "digitalocean" }
func (p *DigitalOceanProvider) Name() string { return "DigitalOcean DNS" }

type doRecordsResponse struct {
	DomainRecords []struct {
		ID   int    `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	} `json:"domain_records"`
	Links struct {
		Pages struct {
			Next string `json:"next"`
		} `json:"pages"`
	} `json:"links"`
	Message string `json:"message"`
}

func (p *DigitalOceanProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	token := strings.TrimSpace(cfg.AuthKey)
	if token == "" {
		return nil, fmt.Errorf("DigitalOcean Personal Access Token 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	page := 1
	var records []Record

	for {
		u := fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records?page=%d&per_page=200", url.PathEscape(domain), page)
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求 DigitalOcean 失败: %w", err)
		}

		var apiRes doRecordsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 DigitalOcean 记录失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DigitalOcean API 错误 [%d]: %s", resp.StatusCode, apiRes.Message)
		}

		for _, r := range apiRes.DomainRecords {
			if IsWebRecordType(r.Type) {
				fullHost := domain
				if r.Name != "@" && r.Name != "" {
					fullHost = r.Name + "." + domain
				}
				records = append(records, Record{
					Name:  NormalizeDomainName(fullHost, domain),
					Type:  r.Type,
					Value: r.Data,
					TTL:   r.TTL,
				})
			}
		}

		if apiRes.Links.Pages.Next == "" || len(apiRes.DomainRecords) == 0 {
			break
		}
		page++
	}

	return records, nil
}

// -------------------------------------------------------------
// Vultr DNS Provider
// -------------------------------------------------------------
type VultrProvider struct{}

func init() {
	RegisterProvider(&VultrProvider{}, ProviderMeta{
		Type:        "vultr",
		Name:        "Vultr DNS",
		Description: "Vultr 云平台 DNS API",
		AuthFields:  []string{"auth_key"},
		KeyLabel:    "API Key",
		SecretLabel: "留空即可",
		ZoneLabel:           "域名（无需额外 ZoneID）",
		DocURL:              "https://www.vultr.com/api/#tag/dns",
		RequiredPermissions: "需在 Vultr 账户后台生成 API Key，并将服务器外网 IP 加入访问白名单",
	})
}

func (p *VultrProvider) Type() string { return "vultr" }
func (p *VultrProvider) Name() string { return "Vultr DNS" }

type vultrRecordsResponse struct {
	Records []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	} `json:"records"`
	Meta struct {
		Total int `json:"total"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"meta"`
	Error string `json:"error"`
}

func (p *VultrProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	key := strings.TrimSpace(cfg.AuthKey)
	if key == "" {
		return nil, fmt.Errorf("Vultr API Key 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	cursor := ""
	var records []Record

	for {
		u := fmt.Sprintf("https://api.vultr.com/v2/domains/%s/records?per_page=500", url.PathEscape(domain))
		if cursor != "" {
			u += "&cursor=" + url.QueryEscape(cursor)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求 Vultr 失败: %w", err)
		}

		var apiRes vultrRecordsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 Vultr 记录失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Vultr API 错误 [%d]: %s", resp.StatusCode, apiRes.Error)
		}

		for _, r := range apiRes.Records {
			if IsWebRecordType(r.Type) {
				fullHost := domain
				if r.Name != "@" && r.Name != "" {
					fullHost = r.Name + "." + domain
				}
				records = append(records, Record{
					Name:  NormalizeDomainName(fullHost, domain),
					Type:  r.Type,
					Value: r.Data,
					TTL:   r.TTL,
				})
			}
		}

		if apiRes.Meta.Links.Next == "" || len(apiRes.Records) == 0 {
			break
		}
		cursor = apiRes.Meta.Links.Next
	}

	return records, nil
}
