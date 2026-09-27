package dns_provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AWSRoute53Provider struct{}

func init() {
	RegisterProvider(&AWSRoute53Provider{}, ProviderMeta{
		Type:        "aws_route53",
		Name:        "AWS Route 53",
		Description: "Amazon Web Services Route 53 权威解析 API",
		AuthFields:  []string{"auth_key", "auth_secret"},
		KeyLabel:    "AWS Access Key ID",
		SecretLabel: "AWS Secret Access Key",
		ZoneLabel:           "Hosted Zone ID (如 Z123456789，可选/自动查找)",
		DocURL:              "https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html",
		RequiredPermissions: "IAM Policy 需包含 route53:ListHostedZones, route53:ListHostedZonesByName 与 route53:ListResourceRecordSets 只读权限",
	})
}

func (p *AWSRoute53Provider) Type() string { return "aws_route53" }
func (p *AWSRoute53Provider) Name() string { return "AWS Route 53" }

type awsListHostedZonesResult struct {
	XMLName     xml.Name `xml:"ListHostedZonesByNameResponse"`
	HostedZones []struct {
		ID   string `xml:"Id"`
		Name string `xml:"Name"`
	} `xml:"HostedZones>HostedZone"`
}

type awsResourceRecordSetsResult struct {
	XMLName            xml.Name `xml:"ListResourceRecordSetsResponse"`
	ResourceRecordSets []struct {
		Name            string   `xml:"Name"`
		Type            string   `xml:"Type"`
		TTL             int      `xml:"TTL"`
		ResourceRecords []string `xml:"ResourceRecords>ResourceRecord>Value"`
	} `xml:"ResourceRecordSets>ResourceRecordSet"`
	IsTruncated          bool   `xml:"IsTruncated"`
	NextRecordName       string `xml:"NextRecordName"`
	NextRecordType       string `xml:"NextRecordType"`
	NextRecordIdentifier string `xml:"NextRecordIdentifier"`
}

// awsSignV4 implements standard AWS Signature Version 4 for Route53
func awsSignV4(req *http.Request, accessKey, secretKey, region, service string, t time.Time, payloadHash string) {
	date := t.UTC().Format("20060102")
	amzDate := t.UTC().Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("host", req.URL.Host)

	// 1. Canonical Request
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := req.URL.RawQuery

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-date:%s\n", req.URL.Host, amzDate)
	signedHeaders := "host;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	// 2. String to Sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)
	h := sha256.New()
	h.Write([]byte(canonicalRequest))
	hashedCanonicalRequest := hex.EncodeToString(h.Sum(nil))

	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hashedCanonicalRequest,
	)

	// 3. Signing Key
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// 4. Signature
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authHeader)
}

func (p *AWSRoute53Provider) getHostedZoneID(ctx context.Context, client *http.Client, accessKey, secretKey, domain string, manualZoneID string) (string, error) {
	if manualZoneID != "" {
		zid := strings.TrimSpace(manualZoneID)
		zid = strings.TrimPrefix(zid, "/hostedzone/")
		return zid, nil
	}

	normDom := strings.TrimRight(domain, ".") + "."
	u, _ := url.Parse("https://route53.amazonaws.com/2013-04-01/hostedzonesbyname?dnsname=" + url.QueryEscape(normDom))

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	emptyPayloadHash := hex.EncodeToString(h.Sum(nil))
	awsSignV4(req, accessKey, secretKey, "us-east-1", "route53", time.Now().UTC(), emptyPayloadHash)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("查询 AWS Hosted Zone 失败: %w", err)
	}
	defer resp.Body.Close()

	var zRes awsListHostedZonesResult
	if err := xml.NewDecoder(resp.Body).Decode(&zRes); err != nil {
		return "", fmt.Errorf("解析 AWS Hosted Zone 返回失败: %w", err)
	}

	for _, z := range zRes.HostedZones {
		if strings.EqualFold(strings.TrimRight(z.Name, "."), strings.TrimRight(domain, ".")) {
			return strings.TrimPrefix(z.ID, "/hostedzone/"), nil
		}
	}

	if len(zRes.HostedZones) > 0 {
		return strings.TrimPrefix(zRes.HostedZones[0].ID, "/hostedzone/"), nil
	}

	return "", fmt.Errorf("未在 Route 53 中找到与域名 %s 匹配的 Hosted Zone", domain)
}

func (p *AWSRoute53Provider) FetchRecords(ctx context.Context, cfg ProviderConfig, domain string) ([]Record, error) {
	accessKey := strings.TrimSpace(cfg.AuthKey)
	secretKey := strings.TrimSpace(cfg.AuthSecret)
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("AWS Access Key ID 和 Secret Access Key 不能为空")
	}

	client := &http.Client{Timeout: DefaultTimeout}
	zoneID, err := p.getHostedZoneID(ctx, client, accessKey, secretKey, domain, cfg.ZoneID)
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	emptyPayloadHash := hex.EncodeToString(h.Sum(nil))

	nextRecordName := ""
	nextRecordType := ""
	var records []Record

	for {
		reqURL := fmt.Sprintf("https://route53.amazonaws.com/2013-04-01/hostedzone/%s/rrset?maxitems=500", zoneID)
		if nextRecordName != "" {
			reqURL += "&name=" + url.QueryEscape(nextRecordName) + "&type=" + url.QueryEscape(nextRecordType)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}

		awsSignV4(req, accessKey, secretKey, "us-east-1", "route53", time.Now().UTC(), emptyPayloadHash)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("请求 AWS Route 53 记录失败: %w", err)
		}

		var apiRes awsResourceRecordSetsResult
		err = xml.NewDecoder(resp.Body).Decode(&apiRes)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 AWS Route 53 记录失败: %w", err)
		}

		for _, r := range apiRes.ResourceRecordSets {
			if IsWebRecordType(r.Type) {
				cleanName := strings.TrimRight(r.Name, ".")
				val := ""
				if len(r.ResourceRecords) > 0 {
					val = r.ResourceRecords[0]
				}
				records = append(records, Record{
					Name:   NormalizeDomainName(cleanName, domain),
					Type:   r.Type,
					Value:  val,
					TTL:    r.TTL,
					ZoneID: zoneID,
				})
			}
		}

		if !apiRes.IsTruncated || apiRes.NextRecordName == "" {
			break
		}
		nextRecordName = apiRes.NextRecordName
		nextRecordType = apiRes.NextRecordType
	}

	return records, nil
}
