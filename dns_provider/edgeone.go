package dns_provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type EdgeOneProvider struct{}

func init() {
	RegisterProvider(&EdgeOneProvider{}, ProviderMeta{
		Type:        "edgeone",
		Name:        "腾讯云 EdgeOne",
		Description: "腾讯云边缘安全加速平台 EdgeOne (EO) 站点与解析记录",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "SecretId",
		SecretLabel: "SecretKey",
		ZoneLabel:           "Zone ID (可选，留空则根据域名自动查询站点)",
		DocURL:              "https://cloud.tencent.com/document/product/1552/80742",
		RequiredPermissions: "CAM 访问策略需包含系统策略 QcloudTEOReadOnlyAccess (EdgeOne 边缘安全加速平台只读权限)",
	})
}

func (p *EdgeOneProvider) Type() string { return "edgeone" }
func (p *EdgeOneProvider) Name() string { return "腾讯云 EdgeOne" }

type teoZonesResponse struct {
	Response struct {
		TotalCount int `json:"TotalCount"`
		Zones      []struct {
			ZoneId   string `json:"ZoneId"`
			ZoneName string `json:"ZoneName"`
		} `json:"Zones"`
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

type teoRecordsResponse struct {
	Response struct {
		TotalCount int `json:"TotalCount"`
		DnsRecords []struct {
			RecordId string `json:"RecordId"`
			Name     string `json:"Name"`
			Type     string `json:"Type"`
			Content  string `json:"Content"`
			TTL      int    `json:"TTL"`
			Status   string `json:"Status"`
		} `json:"DnsRecords"`
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

func (p *EdgeOneProvider) getZoneID(ctx context.Context, client *http.Client, secretId, secretKey, domain string, manualZoneID string) (string, error) {
	if manualZoneID != "" {
		return strings.TrimSpace(manualZoneID), nil
	}

	host := "teo.tencentcloudapi.com"
	service := "teo"
	action := "DescribeZones"
	version := "2022-09-01"

	reqMap := map[string]interface{}{
		"Filters": []map[string]interface{}{
			{
				"Name":   "zone-name",
				"Values": []string{domain},
				"Fuzzy":  false,
			},
		},
		"Offset": 0,
		"Limit":  20,
	}
	payload, _ := json.Marshal(reqMap)

	now := time.Now().UTC()
	timestamp := now.Unix()
	date := now.Format("2006-01-02")

	authHeader, err := tencentSignV3(secretId, secretKey, service, host, action, version, date, timestamp, payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("查询 EdgeOne 站点失败: %w", err)
	}

	var apiRes teoZonesResponse
	err = json.NewDecoder(resp.Body).Decode(&apiRes)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("解析 EdgeOne 站点返回失败: %w", err)
	}

	if apiRes.Response.Error != nil {
		return "", fmt.Errorf("EdgeOne 错误 [%s]: %s", apiRes.Response.Error.Code, apiRes.Response.Error.Message)
	}

	for _, z := range apiRes.Response.Zones {
		if strings.EqualFold(z.ZoneName, domain) {
			return z.ZoneId, nil
		}
	}

	if len(apiRes.Response.Zones) > 0 {
		return apiRes.Response.Zones[0].ZoneId, nil
	}

	return "", fmt.Errorf("未在 EdgeOne 中找到与域名 %s 匹配的站点", domain)
}

func (p *EdgeOneProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	secretId := strings.TrimSpace(cfg.AuthKey)
	secretKey := strings.TrimSpace(cfg.AuthSecret)
	if secretId == "" || secretKey == "" {
		return nil, fmt.Errorf("腾讯云 EdgeOne SecretId 和 SecretKey 不能为空")
	}

	host := "teo.tencentcloudapi.com"
	service := "teo"
	action := "DescribeDnsRecords"
	version := "2022-09-01"

	client := &http.Client{Timeout: DefaultTimeout}
	zoneId, err := p.getZoneID(ctx, client, secretId, secretKey, domain, cfg.ZoneID)
	if err != nil {
		return nil, err
	}

	offset := 0
	limit := 100
	var allRecords []Record

	for {
		reqMap := map[string]interface{}{
			"ZoneId": zoneId,
			"Offset": offset,
			"Limit":  limit,
		}
		payload, _ := json.Marshal(reqMap)

		now := time.Now().UTC()
		timestamp := now.Unix()
		date := now.Format("2006-01-02")

		authHeader, err := tencentSignV3(secretId, secretKey, service, host, action, version, date, timestamp, payload)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Host", host)
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("X-TC-Action", action)
		req.Header.Set("X-TC-Version", version)
		req.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求 EdgeOne 记录失败: %w", err)
		}

		var apiRes teoRecordsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 EdgeOne 记录返回失败: %w", err)
		}

		if apiRes.Response.Error != nil {
			return nil, fmt.Errorf("EdgeOne API 错误 [%s]: %s", apiRes.Response.Error.Code, apiRes.Response.Error.Message)
		}

		for _, rec := range apiRes.Response.DnsRecords {
			if IsWebRecordType(rec.Type) {
				allRecords = append(allRecords, Record{
					Name:   NormalizeDomainName(rec.Name, domain),
					Type:   rec.Type,
					Value:  rec.Content,
					TTL:    rec.TTL,
					ZoneID: zoneId,
				})
			}
		}

		if apiRes.Response.TotalCount <= offset+limit || len(apiRes.Response.DnsRecords) == 0 {
			break
		}
		offset += limit
	}

	return allRecords, nil
}
