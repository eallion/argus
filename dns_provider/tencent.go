package dns_provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TencentProvider struct{}
type DNSPodTokenProvider struct{}

func init() {
	RegisterProvider(&TencentProvider{}, ProviderMeta{
		Type:        "tencent",
		Name:        "腾讯云 DNSPod (API 3.0)",
		Description: "腾讯云官方云解析 DNSPod API 3.0 (SecretId / SecretKey)",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "SecretId",
		SecretLabel: "SecretKey",
		ZoneLabel:           "域名（自动匹配，无需额外 ZoneID）",
		DocURL:              "https://cloud.tencent.com/document/api/1427/56166",
		RequiredPermissions: "CAM 访问策略需包含系统策略 QcloudDNSPodReadOnlyAccess (或包含 dnspod:DescribeRecordList、dnspod:DescribeDomainList 等只读权限)",
	})

	RegisterProvider(&DNSPodTokenProvider{}, ProviderMeta{
		Type:                "dnspod_token",
		Name:                "DNSPod 经典 API Token",
		Description:         "经典 DNSPod API Token (格式: ID,Token)",
		AuthFields:          []string{"auth_key"},
		KeyLabel:            "DNSPod Token (ID,Token)",
		SecretLabel:         "留空即可",
		ZoneLabel:           "域名（无需额外 ZoneID）",
		DocURL:              "https://docs.dnspod.cn/api/5fe1a8a2e584f22e8964e527/",
		RequiredPermissions: "需在 DNSPod 控制台创建并开启对应域名的读取权限 Token",
	})
}

func (p *TencentProvider) Type() string { return "tencent" }
func (p *TencentProvider) Name() string { return "腾讯云 DNSPod" }

func (p *DNSPodTokenProvider) Type() string { return "dnspod_token" }
func (p *DNSPodTokenProvider) Name() string { return "DNSPod 经典 Token" }

// tencentSignV3 implements TC3-HMAC-SHA256 signature algorithm
func tencentSignV3(secretId, secretKey, service, host, action, version, date string, timestamp int64, payload []byte) (string, error) {
	// 1. Canonical request
	httpRequestMethod := "POST"
	canonicalURI := "/"
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("content-type:application/json; charset=utf-8\nhost:%s\nx-tc-action:%s\n", host, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"

	h := sha256.New()
	h.Write(payload)
	hashedRequestPayload := hex.EncodeToString(h.Sum(nil))

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload,
	)

	// 2. String to sign
	algorithm := "TC3-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	h2 := sha256.New()
	h2.Write([]byte(canonicalRequest))
	hashedCanonicalRequest := hex.EncodeToString(h2.Sum(nil))

	stringToSign := fmt.Sprintf("%s\n%d\n%s\n%s",
		algorithm,
		timestamp,
		credentialScope,
		hashedCanonicalRequest,
	)

	// 3. Signature
	secretDate := hmacSHA256([]byte("TC3"+secretKey), []byte(date))
	secretService := hmacSHA256(secretDate, []byte(service))
	secretSigning := hmacSHA256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(secretSigning, []byte(stringToSign)))

	// 4. Authorization header
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		secretId,
		credentialScope,
		signedHeaders,
		signature,
	)

	return authorization, nil
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

type tencentDNSPodResponse struct {
	Response struct {
		TotalCount int `json:"TotalCount"`
		RecordList []struct {
			RecordId uint64 `json:"RecordId"`
			Name     string `json:"Name"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
			TTL      int    `json:"TTL"`
			Status   string `json:"Status"`
		} `json:"RecordList"`
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

func (p *TencentProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	secretId := strings.TrimSpace(cfg.AuthKey)
	secretKey := strings.TrimSpace(cfg.AuthSecret)
	if secretId == "" || secretKey == "" {
		return nil, fmt.Errorf("腾讯云 SecretId 和 SecretKey 不能为空")
	}

	host := "dnspod.tencentcloudapi.com"
	service := "dnspod"
	action := "DescribeRecordList"
	version := "2021-03-23"

	client := &http.Client{Timeout: DefaultTimeout}
	offset := 0
	limit := 100
	var allRecords []Record

	for {
		reqMap := map[string]interface{}{
			"Domain": domain,
			"Offset": offset,
			"Limit":  limit,
		}
		payload, _ := json.Marshal(reqMap)

		now := time.Now().UTC()
		timestamp := now.Unix()
		date := now.Format("2006-01-02")

		authHeader, err := tencentSignV3(secretId, secretKey, service, host, action, version, date, timestamp, payload)
		if err != nil {
			return nil, fmt.Errorf("生成腾讯云签名失败: %w", err)
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
			return nil, fmt.Errorf("请求腾讯云 DNSPod 失败: %w", err)
		}

		var apiRes tencentDNSPodResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析腾讯云 DNSPod 返回失败: %w", err)
		}

		if apiRes.Response.Error != nil {
			return nil, fmt.Errorf("腾讯云 API 错误 [%s]: %s", apiRes.Response.Error.Code, apiRes.Response.Error.Message)
		}

		for _, rec := range apiRes.Response.RecordList {
			if IsWebRecordType(rec.Type) {
				fullHost := domain
				if rec.Name != "@" && rec.Name != "" {
					fullHost = rec.Name + "." + domain
				}
				allRecords = append(allRecords, Record{
					Name:  NormalizeDomainName(fullHost, domain),
					Type:  rec.Type,
					Value: rec.Value,
					TTL:   rec.TTL,
				})
			}
		}

		if apiRes.Response.TotalCount <= offset+limit || len(apiRes.Response.RecordList) == 0 {
			break
		}
		offset += limit
	}

	return allRecords, nil
}

// DNSPod Classic Token API Implementation
type classicDNSPodResponse struct {
	Status struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
	Records []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
		TTL   string `json:"ttl"`
	} `json:"records"`
}

func (p *DNSPodTokenProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	token := strings.TrimSpace(cfg.AuthKey)
	if token == "" {
		return nil, fmt.Errorf("DNSPod Token (ID,Token) 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	offset := 0
	length := 500
	var allRecords []Record

	for {
		data := url.Values{}
		data.Set("login_token", token)
		data.Set("format", "json")
		data.Set("domain", domain)
		data.Set("offset", strconv.Itoa(offset))
		data.Set("length", strconv.Itoa(length))

		req, err := http.NewRequestWithContext(ctx, "POST", "https://dnsapi.cn/Record.List", strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Argus-SSL-Monitor/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求 DNSPod API 失败: %w", err)
		}

		var apiRes classicDNSPodResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 DNSPod 记录失败: %w", err)
		}

		if apiRes.Status.Code != "1" && apiRes.Status.Code != "10" { // 10: 暂无记录
			return nil, fmt.Errorf("DNSPod 错误 [%s]: %s", apiRes.Status.Code, apiRes.Status.Message)
		}

		for _, rec := range apiRes.Records {
			if IsWebRecordType(rec.Type) {
				fullHost := domain
				if rec.Name != "@" && rec.Name != "" {
					fullHost = rec.Name + "." + domain
				}
				ttl, _ := strconv.Atoi(rec.TTL)
				allRecords = append(allRecords, Record{
					Name:  NormalizeDomainName(fullHost, domain),
					Type:  rec.Type,
					Value: rec.Value,
					TTL:   ttl,
				})
			}
		}

		if len(apiRes.Records) < length {
			break
		}
		offset += length
	}

	return allRecords, nil
}
