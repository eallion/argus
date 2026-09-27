package dns_provider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AliyunProvider struct{}

func init() {
	RegisterProvider(&AliyunProvider{}, ProviderMeta{
		Type:        "aliyun",
		Name:        "阿里云 DNS (Alidns)",
		Description: "阿里云云解析 DNS 权威解析 API",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "AccessKey ID",
		SecretLabel: "AccessKey Secret",
		ZoneLabel:           "域名（自动匹配，无需额外 ZoneID）",
		DocURL:              "https://help.aliyun.com/document_detail/29776.html",
		RequiredPermissions: "RAM 访问控制策略需包含系统策略 AliyunDNSReadOnlyAccess (只读访问云解析 DNS 权限，包含 DescribeDomainRecords 等)",
	})
}

func (p *AliyunProvider) Type() string { return "aliyun" }
func (p *AliyunProvider) Name() string { return "阿里云 DNS" }

type aliyunRecordItem struct {
	RecordId string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Status   string `json:"Status"`
}

type aliyunRecordsResponse struct {
	TotalCount    int `json:"TotalCount"`
	PageNumber    int `json:"PageNumber"`
	PageSize      int `json:"PageSize"`
	DomainRecords struct {
		Record []aliyunRecordItem `json:"Record"`
	} `json:"DomainRecords"`
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// aliyunSignPOP generates HMAC-SHA1 signature according to Alibaba Cloud POP RPC specification
func aliyunSignPOP(method string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalizedParts []string
	for _, k := range keys {
		part := specialURLEncode(k) + "=" + specialURLEncode(params[k])
		canonicalizedParts = append(canonicalizedParts, part)
	}
	canonicalizedQuery := strings.Join(canonicalizedParts, "&")

	stringToSign := method + "&" + specialURLEncode("/") + "&" + specialURLEncode(canonicalizedQuery)

	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func specialURLEncode(s string) string {
	res := url.QueryEscape(s)
	res = strings.ReplaceAll(res, "+", "%20")
	res = strings.ReplaceAll(res, "*", "%2A")
	res = strings.ReplaceAll(res, "%7E", "~")
	return res
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *AliyunProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	key := strings.TrimSpace(cfg.AuthKey)
	secret := strings.TrimSpace(cfg.AuthSecret)
	if key == "" || secret == "" {
		return nil, fmt.Errorf("阿里云 AccessKey ID 和 AccessKey Secret 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	page := 1
	pageSize := 500
	var allRecords []Record

	for {
		params := map[string]string{
			"Action":           "DescribeDomainRecords",
			"Version":          "2015-01-09",
			"Format":           "JSON",
			"AccessKeyId":      key,
			"SignatureMethod":  "HMAC-SHA1",
			"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"SignatureVersion": "1.0",
			"SignatureNonce":   generateNonce(),
			"DomainName":       domain,
			"PageNumber":       strconv.Itoa(page),
			"PageSize":         strconv.Itoa(pageSize),
		}

		sig := aliyunSignPOP("GET", params, secret)
		params["Signature"] = sig

		values := url.Values{}
		for k, v := range params {
			values.Set(k, v)
		}

		u := "https://alidns.aliyuncs.com/?" + values.Encode()
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求阿里云 DNS 失败: %w", err)
		}

		var apiRes aliyunRecordsResponse
		err = json.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析阿里云 DNS 返回失败: %w", err)
		}

		if apiRes.Code != "" {
			return nil, fmt.Errorf("阿里云 API 错误 [%s]: %s", apiRes.Code, apiRes.Message)
		}

		for _, rec := range apiRes.DomainRecords.Record {
			if IsWebRecordType(rec.Type) {
				fullHost := domain
				if rec.RR != "@" && rec.RR != "" {
					fullHost = rec.RR + "." + domain
				}
				allRecords = append(allRecords, Record{
					Name:  NormalizeDomainName(fullHost, domain),
					Type:  rec.Type,
					Value: rec.Value,
					TTL:   rec.TTL,
				})
			}
		}

		if apiRes.TotalCount <= page*pageSize || len(apiRes.DomainRecords.Record) == 0 {
			break
		}
		page++
	}

	return allRecords, nil
}
