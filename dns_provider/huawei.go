package dns_provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type HuaweiProvider struct{}

func init() {
	RegisterProvider(&HuaweiProvider{}, ProviderMeta{
		Type:        "huawei",
		Name:        "华为云 DNS",
		Description: "华为云云解析服务 (支持 IAM Token 或 API Token)",
		AuthFields:  []string{"auth_key"},
		KeyLabel:    "IAM Token (X-Auth-Token)",
		SecretLabel: "地域 Region (如 cn-north-4，默认通用)",
		ZoneLabel:           "Zone ID (可选，留空则根据域名自动查询)",
		DocURL:              "https://support.huaweicloud.com/api-dns/dns_api_64003.html",
		RequiredPermissions: "IAM 用户权限需包含 DNS ReadOnlyAccess (云解析服务只读权限)",
	})
}

func (p *HuaweiProvider) Type() string { return "huawei" }
func (p *HuaweiProvider) Name() string { return "华为云 DNS" }

type huaweiZonesResponse struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type huaweiRecordSetsResponse struct {
	Recordsets []struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		TTL     int      `json:"ttl"`
		Records []string `json:"records"`
		Status  string   `json:"status"`
	} `json:"recordsets"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (p *HuaweiProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	token := strings.TrimSpace(cfg.AuthKey)
	if token == "" {
		return nil, fmt.Errorf("华为云 IAM Token 不能为空")
	}

	region := strings.TrimSpace(cfg.AuthSecret)
	if region == "" {
		region = "cn-north-4"
	}

	baseURL := fmt.Sprintf("https://dns.%s.myhuaweicloud.com", region)
	client := &http.Client{Timeout: DefaultTimeout}

	// 1. Get ZoneID if not provided
	zoneID := strings.TrimSpace(cfg.ZoneID)
	if zoneID == "" {
		normDom := strings.TrimRight(domain, ".") + "."
		u := fmt.Sprintf("%s/v2/zones?name=%s", baseURL, url.QueryEscape(normDom))
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("查询华为云 Zone 失败: %w", err)
		}

		var zRes huaweiZonesResponse
		err = json.NewDecoder(resp.Body).Decode(&zRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析华为云 Zone 返回失败: %w", err)
		}

		if zRes.Code != "" {
			return nil, fmt.Errorf("华为云 API 错误 [%s]: %s", zRes.Code, zRes.Message)
		}

		for _, z := range zRes.Zones {
			if strings.EqualFold(strings.TrimRight(z.Name, "."), strings.TrimRight(domain, ".")) {
				zoneID = z.ID
				break
			}
		}

		if zoneID == "" && len(zRes.Zones) > 0 {
			zoneID = zRes.Zones[0].ID
		}

		if zoneID == "" {
			return nil, fmt.Errorf("未在华为云中找到与域名 %s 匹配的 Zone", domain)
		}
	}

	// 2. Fetch Recordsets
	offset := 0
	limit := 500
	var records []Record

	for {
		u := fmt.Sprintf("%s/v2/zones/%s/recordsets?limit=%d&offset=%d", baseURL, zoneID, limit, offset)
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求华为云解析记录失败: %w", err)
		}

		var apiRes huaweiRecordSetsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析华为云解析记录失败: %w", err)
		}

		if apiRes.Code != "" {
			return nil, fmt.Errorf("华为云 API 错误 [%s]: %s", apiRes.Code, apiRes.Message)
		}

		for _, rs := range apiRes.Recordsets {
			if IsWebRecordType(rs.Type) {
				cleanName := strings.TrimRight(rs.Name, ".")
				val := ""
				if len(rs.Records) > 0 {
					val = rs.Records[0]
				}
				records = append(records, Record{
					Name:   NormalizeDomainName(cleanName, domain),
					Type:   rs.Type,
					Value:  val,
					TTL:    rs.TTL,
					ZoneID: zoneID,
				})
			}
		}

		if apiRes.Links.Next == "" || len(apiRes.Recordsets) == 0 {
			break
		}
		offset += limit
	}

	return records, nil
}
