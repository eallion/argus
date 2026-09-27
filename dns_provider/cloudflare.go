package dns_provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type CloudflareProvider struct{}

var cfGlobalKeyRegex = regexp.MustCompile(`^[0-9a-fA-F]{37}$`)

func isCloudflareGlobalKey(key string) bool {
	return cfGlobalKeyRegex.MatchString(strings.TrimSpace(key))
}

func init() {
	RegisterProvider(&CloudflareProvider{}, ProviderMeta{
		Type:                "cloudflare",
		Name:                "Cloudflare",
		Description:         "全球知名 CDN 与权威 DNS 平台 (支持 API Token 或 Global Key)",
		AuthFields:          []string{"auth_key", "auth_secret"},
		KeyLabel:            "API Token (推荐) 或 Global API Key",
		SecretLabel:         "账号邮箱 (若使用 Global API Key 时必填，Token 则留空)",
		ZoneLabel:           "Zone ID (可选，留空则通过域名自动解析获取)",
		DocURL:              "https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/",
		RequiredPermissions: "推荐使用 API Token，需具备权限：Zone.DNS:Read (只读) 与 Zone.Zone:Read (区域读取，用于匹配 ZoneID)。若未配置 Zone 读取权限，可手动在规则中填写 Zone ID。若使用 Global API Key (37 位)，必须同时填写绑定的 Cloudflare 账号邮箱。",
	})
}

func (p *CloudflareProvider) Type() string { return "cloudflare" }
func (p *CloudflareProvider) Name() string { return "Cloudflare" }

type cfZoneResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
}

type cfRecordsResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Result []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	} `json:"result"`
}

func (p *CloudflareProvider) setAuth(req *http.Request, cfg ProviderConfig) {
	key := strings.TrimSpace(cfg.AuthKey)
	email := strings.TrimSpace(cfg.AuthSecret)
	if email != "" && !strings.Contains(key, " ") {
		// Global API Key mode
		req.Header.Set("X-Auth-Email", email)
		req.Header.Set("X-Auth-Key", key)
	} else {
		// API Token mode (Bearer)
		token := strings.TrimPrefix(key, "Bearer ")
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
}

func (p *CloudflareProvider) getZoneID(ctx context.Context, client *http.Client, cfg ProviderConfig, domain string) (string, error) {
	if cfg.ZoneID != "" {
		return strings.TrimSpace(cfg.ZoneID), nil
	}

	currDomain := strings.Trim(strings.ToLower(domain), ".")
	for {
		u := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s&status=active", url.QueryEscape(currDomain))
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return "", err
		}
		p.setAuth(req, cfg)

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("请求 Cloudflare Zones 失败: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("读取 Cloudflare Zones 响应失败: %w", err)
		}

		var zRes cfZoneResponse
		if err := json.Unmarshal(body, &zRes); err != nil {
			if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("Cloudflare API 异常 (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			return "", fmt.Errorf("解析 Cloudflare 返回数据失败: %w", err)
		}

		if !zRes.Success {
			var errDetails []string
			for _, e := range zRes.Errors {
				if e.Message != "" {
					errDetails = append(errDetails, e.Message)
				}
			}
			errMsg := "认证或权限校验失败"
			if len(errDetails) > 0 {
				errMsg = strings.Join(errDetails, "; ")
			}
			return "", fmt.Errorf("Cloudflare 验证失败: %s", errMsg)
		}

		if len(zRes.Result) > 0 {
			return zRes.Result[0].ID, nil
		}

		// Try parent domain if currDomain has subdomains
		idx := strings.Index(currDomain, ".")
		if idx == -1 || !strings.Contains(currDomain[idx+1:], ".") {
			break
		}
		currDomain = currDomain[idx+1:]
	}

	return "", fmt.Errorf("未在 Cloudflare 账号中找到与域名 %s 匹配的有效 Zone (请确认域名已托管在该 Cloudflare 账号中，或手动在配置中填写 Zone ID)", domain)
}

func (p *CloudflareProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	key := strings.TrimSpace(cfg.AuthKey)
	email := strings.TrimSpace(cfg.AuthSecret)

	if key == "" {
		return nil, fmt.Errorf("Cloudflare 凭据不能为空，请输入 API Token 或 Global API Key")
	}

	if isCloudflareGlobalKey(key) && email == "" {
		return nil, fmt.Errorf("检测到您填写的是 37 位 Global API Key，该模式必须同时填写 Cloudflare 账号邮箱 (可在凭据编辑中补充 Secret/邮箱)。若使用 API Token 则无需邮箱")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	zoneID, err := p.getZoneID(ctx, client, cfg, domain)
	if err != nil {
		return nil, err
	}

	page := 1
	perPage := 500
	var allRecords []Record

	for {
		u := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?page=%d&per_page=%d", zoneID, page, perPage)
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		p.setAuth(req, cfg)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("获取 Cloudflare 解析记录失败: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("读取 Cloudflare 记录响应失败: %w", err)
		}

		var recRes cfRecordsResponse
		if err := json.Unmarshal(body, &recRes); err != nil {
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("Cloudflare API 异常 (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			return nil, fmt.Errorf("解析 Cloudflare 记录失败: %w", err)
		}

		if !recRes.Success {
			var errDetails []string
			for _, e := range recRes.Errors {
				if e.Message != "" {
					errDetails = append(errDetails, e.Message)
				}
			}
			errMsg := "查询记录返回失败"
			if len(errDetails) > 0 {
				errMsg = strings.Join(errDetails, "; ")
			}
			return nil, fmt.Errorf("Cloudflare API 错误: %s", errMsg)
		}

		for _, item := range recRes.Result {
			if IsWebRecordType(item.Type) {
				allRecords = append(allRecords, Record{
					Name:   NormalizeDomainName(item.Name, domain),
					Type:   item.Type,
					Value:  item.Content,
					TTL:    item.TTL,
					ZoneID: zoneID,
				})
			}
		}

		if len(recRes.Result) == 0 || recRes.ResultInfo.TotalPages == 0 || page >= recRes.ResultInfo.TotalPages {
			break
		}
		page++
	}

	return allRecords, nil
}
