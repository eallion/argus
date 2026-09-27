package dns_provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type AliyunESAProvider struct{}

func init() {
	RegisterProvider(&AliyunESAProvider{}, ProviderMeta{
		Type:        "aliyun_esa",
		Name:        "阿里云 ESA (边缘安全加速)",
		Description: "阿里云边缘安全加速 ESA 站点与 DNS 记录解析 API",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "AccessKey ID",
		SecretLabel: "AccessKey Secret",
		ZoneLabel:           "Site ID (可选，留空则根据域名自动查询站点)",
		DocURL:              "https://help.aliyun.com/document_detail/2843468.html",
		RequiredPermissions: "RAM 访问控制策略需包含 AliyunESAReadOnlyAccess (只读访问边缘安全加速 ESA 权限，包含 ListSites、ListRecords 等)",
	})
}

func (p *AliyunESAProvider) Type() string { return "aliyun_esa" }
func (p *AliyunESAProvider) Name() string { return "阿里云 ESA" }

type esaSitesResponse struct {
	TotalCount int `json:"TotalCount"`
	Sites      []struct {
		SiteId   int64  `json:"SiteId"`
		SiteName string `json:"SiteName"`
	} `json:"Sites"`
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

type esaRecordsResponse struct {
	TotalCount int `json:"TotalCount"`
	Records    []struct {
		RecordId   int64  `json:"RecordId"`
		RecordName string `json:"RecordName"`
		RecordType string `json:"RecordType"`
		RecordData struct {
			Value string `json:"Value"`
		} `json:"RecordData"`
		TTL int `json:"Ttl"`
	} `json:"Records"`
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (p *AliyunESAProvider) getSiteID(ctx context.Context, client *http.Client, key, secret, domain string, manualSiteID string) (int64, error) {
	if manualSiteID != "" {
		if id, err := strconv.ParseInt(strings.TrimSpace(manualSiteID), 10, 64); err == nil && id > 0 {
			return id, nil
		}
	}

	params := map[string]string{
		"Action":           "ListSites",
		"Version":          "2024-09-10",
		"Format":           "JSON",
		"AccessKeyId":      key,
		"SignatureMethod":  "HMAC-SHA1",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": "1.0",
		"SignatureNonce":   generateNonce(),
		"SiteSearchType":   "exact",
		"SiteName":         domain,
		"PageNumber":       "1",
		"PageSize":         "50",
	}

	sig := aliyunSignPOP("GET", params, secret)
	params["Signature"] = sig

	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}

	u := "https://esa.aliyuncs.com/?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("查询阿里云 ESA 站点失败: %w", err)
	}
	defer resp.Body.Close()

	var res esaSitesResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return 0, fmt.Errorf("解析 ESA 站点返回失败: %w", err)
	}

	if res.Code != "" {
		return 0, fmt.Errorf("阿里云 ESA 错误 [%s]: %s", res.Code, res.Message)
	}

	for _, s := range res.Sites {
		if strings.EqualFold(s.SiteName, domain) {
			return s.SiteId, nil
		}
	}

	if len(res.Sites) > 0 {
		return res.Sites[0].SiteId, nil
	}

	return 0, fmt.Errorf("未在 ESA 中找到与 %s 匹配的站点", domain)
}

func (p *AliyunESAProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	key := strings.TrimSpace(cfg.AuthKey)
	secret := strings.TrimSpace(cfg.AuthSecret)
	if key == "" || secret == "" {
		return nil, fmt.Errorf("阿里云 ESA AccessKey ID 和 AccessKey Secret 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	siteID, err := p.getSiteID(ctx, client, key, secret, domain, cfg.ZoneID)
	if err != nil {
		return nil, err
	}

	page := 1
	pageSize := 500
	var allRecords []Record

	for {
		params := map[string]string{
			"Action":           "ListRecords",
			"Version":          "2024-09-10",
			"Format":           "JSON",
			"AccessKeyId":      key,
			"SignatureMethod":  "HMAC-SHA1",
			"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"SignatureVersion": "1.0",
			"SignatureNonce":   generateNonce(),
			"SiteId":           strconv.FormatInt(siteID, 10),
			"PageNumber":       strconv.Itoa(page),
			"PageSize":         strconv.Itoa(pageSize),
		}

		sig := aliyunSignPOP("GET", params, secret)
		params["Signature"] = sig

		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}

		u := "https://esa.aliyuncs.com/?" + values.Encode()
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求阿里云 ESA 解析记录失败: %w", err)
		}

		var apiRes esaRecordsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析阿里云 ESA 记录失败: %w", err)
		}

		if apiRes.Code != "" {
			return nil, fmt.Errorf("阿里云 ESA 错误 [%s]: %s", apiRes.Code, apiRes.Message)
		}

		for _, rec := range apiRes.Records {
			if IsWebRecordType(rec.RecordType) {
				allRecords = append(allRecords, Record{
					Name:   NormalizeDomainName(rec.RecordName, domain),
					Type:   rec.RecordType,
					Value:  rec.RecordData.Value,
					TTL:    rec.TTL,
					ZoneID: strconv.FormatInt(siteID, 10),
				})
			}
		}

		if apiRes.TotalCount <= page*pageSize || len(apiRes.Records) == 0 {
			break
		}
		page++
	}

	return allRecords, nil
}
