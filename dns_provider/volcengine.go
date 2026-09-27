package dns_provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type VolcengineProvider struct{}

func init() {
	RegisterProvider(&VolcengineProvider{}, ProviderMeta{
		Type:        "volcengine",
		Name:        "火山引擎 DNS",
		Description: "火山引擎 (Volcano Engine) 云解析 DNS 权威解析 API",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "AccessKey ID (AK)",
		SecretLabel: "Secret Access Key (SK)",
		ZoneLabel:           "ZID / 域名 ID (数字，可选/自动查找)",
		DocURL:              "https://www.volcengine.com/docs/6758/107054",
		RequiredPermissions: "IAM 访问策略需包含系统策略 DNSReadOnlyAccess (包含 dns:ListZones 与 dns:ListRecords 只读权限)",
	})
}

func (p *VolcengineProvider) Type() string { return "volcengine" }
func (p *VolcengineProvider) Name() string { return "火山引擎 DNS" }

type volcengineResponseMetadata struct {
	RequestId string `json:"RequestId"`
	Action    string `json:"Action"`
	Version   string `json:"Version"`
	Service   string `json:"Service"`
	Region    string `json:"Region"`
	Error     *struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	} `json:"Error,omitempty"`
}

type volcengineListZonesResponse struct {
	ResponseMetadata volcengineResponseMetadata `json:"ResponseMetadata"`
	Result           struct {
		TotalCount int `json:"TotalCount"`
		Zones      []struct {
			ZID      int64  `json:"ZID"`
			ZoneName string `json:"ZoneName"`
		} `json:"Zones"`
	} `json:"Result"`
}

type volcengineListRecordsResponse struct {
	ResponseMetadata volcengineResponseMetadata `json:"ResponseMetadata"`
	Result           struct {
		TotalCount int `json:"TotalCount"`
		Records    []struct {
			RecordID string `json:"RecordID"`
			Host     string `json:"Host"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
			TTL      int    `json:"TTL"`
			Status   string `json:"Status"`
		} `json:"Records"`
	} `json:"Result"`
}

func (p *VolcengineProvider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	ak := strings.TrimSpace(cfg.AuthKey)
	sk := strings.TrimSpace(cfg.AuthSecret)
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("火山引擎鉴权失败: 必须提供 AccessKey ID 与 Secret Access Key")
	}

	normDomain := strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normDomain == "" {
		return nil, fmt.Errorf("目标主域名不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}

	// 1. 获取 ZID (Zone ID)
	zid := strings.TrimSpace(cfg.ZoneID)
	if zid == "" {
		foundZid, err := p.resolveZID(ctx, client, ak, sk, normDomain)
		if err != nil {
			return nil, fmt.Errorf("获取火山引擎域名 ZID 失败: %w", err)
		}
		zid = foundZid
	}

	// 2. 调用 ListRecords 获取解析记录
	pageNumber := 1
	pageSize := 500
	var allRecords []Record
	seen := make(map[string]bool)

	for {
		records, totalCount, err := p.fetchRecordsPage(ctx, client, ak, sk, zid, pageNumber, pageSize)
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			if !IsWebRecordType(r.Type) {
				continue
			}
			fqdn := NormalizeDomainName(r.Host, normDomain)
			key := fmt.Sprintf("%s:%s:%s", fqdn, r.Type, r.Value)
			if seen[key] {
				continue
			}
			seen[key] = true

			allRecords = append(allRecords, Record{
				Name:   fqdn,
				Type:   r.Type,
				Value:  r.Value,
				TTL:    r.TTL,
				ZoneID: zid,
			})
		}

		if len(allRecords) >= totalCount || len(records) < pageSize {
			break
		}
		pageNumber++
		if pageNumber > 10 { // 最多安全提取 5000 条记录
			break
		}
	}

	return allRecords, nil
}

func (p *VolcengineProvider) resolveZID(ctx context.Context, client *http.Client, ak, sk, normDomain string) (string, error) {
	endpoint := "https://open.volcengineapi.com"
	params := url.Values{}
	params.Set("Action", "ListZones")
	params.Set("Version", "2018-08-01")
	params.Set("Key", normDomain)
	params.Set("PageNumber", "1")
	params.Set("PageSize", "50")

	reqURL := fmt.Sprintf("%s/?%s", endpoint, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	volcengineSignV4(req, ak, sk, "cn-north-1", "dns", time.Now().UTC(), nil)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求火山引擎 API 失败: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var res volcengineListZonesResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return "", fmt.Errorf("解析火山引擎响应失败: %w (原始: %s)", err, string(bodyBytes))
	}

	if res.ResponseMetadata.Error != nil {
		return "", fmt.Errorf("火山引擎错误 [%s]: %s", res.ResponseMetadata.Error.Code, res.ResponseMetadata.Error.Message)
	}

	for _, z := range res.Result.Zones {
		zName := strings.TrimRight(strings.ToLower(strings.TrimSpace(z.ZoneName)), ".")
		if zName == normDomain {
			return strconv.FormatInt(z.ZID, 10), nil
		}
	}

	if len(res.Result.Zones) > 0 {
		return strconv.FormatInt(res.Result.Zones[0].ZID, 10), nil
	}

	return "", fmt.Errorf("未在火山引擎账号下找到域名 %s 对应的解析 Zone，请检查主域名或手动输入 ZID", normDomain)
}

func (p *VolcengineProvider) fetchRecordsPage(ctx context.Context, client *http.Client, ak, sk, zid string, pageNumber, pageSize int) ([]struct {
	RecordID string `json:"RecordID"`
	Host     string `json:"Host"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Status   string `json:"Status"`
}, int, error) {
	endpoint := "https://open.volcengineapi.com"
	params := url.Values{}
	params.Set("Action", "ListRecords")
	params.Set("Version", "2018-08-01")
	params.Set("ZID", zid)
	params.Set("PageNumber", strconv.Itoa(pageNumber))
	params.Set("PageSize", strconv.Itoa(pageSize))

	reqURL := fmt.Sprintf("%s/?%s", endpoint, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}

	volcengineSignV4(req, ak, sk, "cn-north-1", "dns", time.Now().UTC(), nil)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求火山引擎 ListRecords 失败: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	var res volcengineListRecordsResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, 0, fmt.Errorf("解析火山引擎 ListRecords 响应失败: %w", err)
	}

	if res.ResponseMetadata.Error != nil {
		return nil, 0, fmt.Errorf("火山引擎错误 [%s]: %s", res.ResponseMetadata.Error.Code, res.ResponseMetadata.Error.Message)
	}

	return res.Result.Records, res.Result.TotalCount, nil
}

// volcengineSignV4 implements Volcano Engine Signature Version 4
func volcengineSignV4(req *http.Request, accessKey, secretKey, region, service string, t time.Time, payload []byte) {
	date := t.UTC().Format("20060102")
	xDate := t.UTC().Format("20060102T150405Z")

	// 1. Hashed payload
	hPayload := sha256.Sum256(payload)
	xContentSha256 := hex.EncodeToString(hPayload[:])

	req.Header.Set("X-Date", xDate)
	req.Header.Set("X-Content-Sha256", xContentSha256)
	req.Header.Set("Host", req.URL.Host)

	// 2. Canonical Request
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQuery := buildVolcengineCanonicalQuery(req.URL.Query())
	canonicalHeaders := fmt.Sprintf("host:%s\nx-content-sha256:%s\nx-date:%s\n",
		req.URL.Host, xContentSha256, xDate)
	signedHeaders := "host;x-content-sha256;x-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		xContentSha256,
	)

	// 3. String to Sign
	credentialScope := fmt.Sprintf("%s/%s/%s/request", date, region, service)
	hCanon := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequest := hex.EncodeToString(hCanon[:])

	stringToSign := fmt.Sprintf("HMAC-SHA256\n%s\n%s\n%s",
		xDate,
		credentialScope,
		hashedCanonicalRequest,
	)

	// 4. Signing Key
	kDate := hmacSHA256Volc([]byte(secretKey), date)
	kRegion := hmacSHA256Volc(kDate, region)
	kService := hmacSHA256Volc(kRegion, service)
	kSigning := hmacSHA256Volc(kService, "request")

	// 5. Signature
	signature := hex.EncodeToString(hmacSHA256Volc(kSigning, stringToSign))

	// 6. Authorization
	authHeader := fmt.Sprintf("HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

func hmacSHA256Volc(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func buildVolcengineCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pairs []string
	for _, k := range keys {
		escapedKey := url.QueryEscape(k)
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			pairs = append(pairs, fmt.Sprintf("%s=%s", escapedKey, url.QueryEscape(v)))
		}
	}
	return strings.Join(pairs, "&")
}
