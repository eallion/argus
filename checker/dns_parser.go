package checker

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ParseDNSResult represents the output of DNS export file parsing
type ParseDNSResult struct {
	Format          string   `json:"format"`
	Domains         []string `json:"domains"`
	DomainCount     int      `json:"domain_count"`
	FilteredRecords int      `json:"filtered_records"`
	Message         string   `json:"message"`
}

// Domain name validation regex (RFC 1123 compliant)
var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Fallback domain extraction regex for plaintext and complex logs
var domainExtractRegex = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,})\b`)

// Cloudflare / BIND Domain header regex
var cloudflareDomainHeaderRegex = regexp.MustCompile(`(?i);;\s*Domain:\s*([a-zA-Z0-9.-]+)`)
var bindOriginRegex = regexp.MustCompile(`(?i)\$ORIGIN\s+([a-zA-Z0-9.-]+)`)

// ParseDNSExportFile automatically detects format and extracts valid web domains (A, AAAA, CNAME)
func ParseDNSExportFile(filename string, data []byte) (*ParseDNSResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("文件内容为空")
	}

	ext := strings.ToLower(filepath.Ext(filename))
	baseName := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	fallbackOrigin := extractOriginFromFilename(baseName)

	// 1. Excel (.xlsx) Detection via ZIP signature (PK\x03\x04) or extension
	if ext == ".xlsx" || (len(data) > 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04) {
		res, err := parseXLSX(data, fallbackOrigin)
		if err == nil && len(res.Domains) > 0 {
			return res, nil
		}
	}

	// 2. JSON Detection
	trimmed := bytes.TrimSpace(data)
	if ext == ".json" || (len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		res, err := parseJSON(trimmed)
		if err == nil && len(res.Domains) > 0 {
			return res, nil
		}
	}

	// 3. Cloudflare & RFC 1035 Standard BIND Zone (.zone, .txt, .dns, .db)
	// Cloudflare exports are named <domain>.txt (or @<domain>.txt) and formatted as standard BIND zone with tab/space separation.
	// We prioritize parsing as Zone if it contains zone-like records or header comments.
	contentStr := string(data)
	if isLikelyZoneOrCloudflare(contentStr) {
		res, err := parseZone(contentStr, fallbackOrigin)
		if err == nil && len(res.Domains) > 0 {
			return res, nil
		}
	}

	// 4. CSV / TSV Table Detection
	if ext == ".csv" || ext == ".tsv" || bytes.Contains(data, []byte(",")) {
		res, err := parseDelimitedTable(data, fallbackOrigin)
		if err == nil && len(res.Domains) > 0 {
			return res, nil
		}
	}

	// 5. If Zone parsing was not triggered before, try Zone parser unconditionally before plain text
	if res, err := parseZone(contentStr, fallbackOrigin); err == nil && len(res.Domains) > 0 {
		return res, nil
	}

	// 6. Final Fallback: Line-by-line / Word-level Plaintext extractor
	return parsePlainLines(contentStr)
}

// -------------------------------------------------------------
// Helper: Check if content has characteristics of a Zone or Cloudflare export
// -------------------------------------------------------------
func isLikelyZoneOrCloudflare(content string) bool {
	upper := strings.ToUpper(content)
	if strings.Contains(upper, ";; DOMAIN:") || strings.Contains(upper, "$ORIGIN") || strings.Contains(upper, ";; CLOUDFLARE") {
		return true
	}
	// Check for record types in lines
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if i > 50 {
			break
		}
		fields := strings.Fields(l)
		for _, f := range fields {
			fu := strings.ToUpper(f)
			if fu == "A" || fu == "AAAA" || fu == "CNAME" || fu == "SOA" {
				return true
			}
		}
	}
	return false
}

// -------------------------------------------------------------
// Helper: Extract origin from filename (e.g. "@example.com.txt" -> "example.com")
// -------------------------------------------------------------
func extractOriginFromFilename(baseName string) string {
	cleaned := strings.TrimPrefix(baseName, "@")
	cleaned = strings.TrimSpace(strings.ToLower(cleaned))
	if domainRegex.MatchString(cleaned) {
		return cleaned
	}
	return ""
}

// -------------------------------------------------------------
// 1. Standard RFC 1035 BIND Zone & Cloudflare DNS Parser
// Covers: Cloudflare Export (.txt), HE.net, PowerDNS, BIND 9, Porkbun, Google Cloud DNS Zone
// -------------------------------------------------------------
func parseZone(content string, defaultOrigin string) (*ParseDNSResult, error) {
	lines := strings.Split(content, "\n")
	origin := defaultOrigin
	var lastHost string
	seen := make(map[string]bool)
	var domains []string
	filteredCount := 0
	isCloudflare := false

	// First pass: look for Cloudflare Domain header or $ORIGIN
	for i, rawLine := range lines {
		if i > 30 {
			break
		}
		trimmed := strings.TrimSpace(rawLine)
		if m := cloudflareDomainHeaderRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			origin = strings.TrimSuffix(strings.TrimSpace(m[1]), ".")
			isCloudflare = true
		} else if m := bindOriginRegex.FindStringSubmatch(trimmed); len(m) > 1 {
			origin = strings.TrimSuffix(strings.TrimSpace(m[1]), ".")
		}
		if strings.Contains(strings.ToLower(trimmed), "cloudflare") {
			isCloudflare = true
		}
	}

	for _, rawLine := range lines {
		// Strip comments starting with semicolon
		line := rawLine
		if idx := strings.Index(line, ";"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle $ORIGIN directive
		if strings.HasPrefix(strings.ToUpper(line), "$ORIGIN") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				origin = strings.TrimSuffix(parts[1], ".")
			}
			continue
		}
		if strings.HasPrefix(strings.ToUpper(line), "$TTL") {
			continue
		}

		// Fields split handles both spaces and tabs (\t) seamlessly
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Locate Record Type in the fields (A, AAAA, CNAME vs TXT, MX, NS, SOA, CAA, SRV, etc.)
		typeIdx := -1
		var recType string
		for i, f := range fields {
			upper := strings.ToUpper(f)
			switch upper {
			case "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SOA", "CAA", "SRV", "PTR", "SPF":
				typeIdx = i
				recType = upper
				break
			}
			if typeIdx != -1 {
				break
			}
		}

		if typeIdx == -1 {
			continue
		}

		// Non-web record types (TXT, MX, NS, SOA, CAA, etc.)
		if recType != "A" && recType != "AAAA" && recType != "CNAME" {
			filteredCount++
			if typeIdx > 0 {
				lastHost = fields[0]
			}
			continue
		}

		// Extract host name
		var host string
		if typeIdx == 0 {
			host = lastHost
		} else {
			host = fields[0]
			lastHost = host
		}

		// If origin is not set yet, attempt to infer from absolute FQDN
		if origin == "" && strings.HasSuffix(host, ".") {
			parts := strings.Split(strings.TrimSuffix(host, "."), ".")
			if len(parts) >= 2 {
				origin = parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
		}

		fqdn := resolveFQDN(host, origin)
		if fqdn == "" || strings.HasPrefix(fqdn, "*") {
			continue
		}
		if !seen[fqdn] {
			seen[fqdn] = true
			domains = append(domains, fqdn)
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("未能从 Zone 文件中识别出有效的 Web 解析记录")
	}

	formatTitle := "BIND Zone (RFC 1035 标准)"
	if isCloudflare {
		formatTitle = "Cloudflare DNS 导出格式 (Zone)"
	}

	return &ParseDNSResult{
		Format:          formatTitle,
		Domains:         domains,
		DomainCount:     len(domains),
		FilteredRecords: filteredCount,
		Message:         fmt.Sprintf("识别为 %s，提取到 %d 个有效域名，已自动过滤 %d 条非 Web 记录", formatTitle, len(domains), filteredCount),
	}, nil
}

// -------------------------------------------------------------
// 2. CSV / TSV Delimited Parser
// Covers: DNSPod CSV, Alibaba Cloud CSV, GoDaddy CSV, Namecheap CSV, Porkbun CSV
// -------------------------------------------------------------
func parseDelimitedTable(data []byte, defaultOrigin string) (*ParseDNSResult, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("文件内容为空")
	}

	// Detect delimiter
	delim := rune(',')
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		tabCount := strings.Count(l, "\t")
		commaCount := strings.Count(l, ",")
		semiCount := strings.Count(l, ";")
		if tabCount > commaCount && tabCount > semiCount {
			delim = '\t'
		} else if semiCount > commaCount && semiCount > tabCount {
			delim = ';'
		}
		break
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = delim
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	return extractFromGrid(rows, "CSV / TSV 表格格式", defaultOrigin)
}

// -------------------------------------------------------------
// 3. Native OpenXML Excel (.xlsx) Parser (Pure Go Standard Library)
// Covers: Tencent DNSPod Excel, Alibaba Cloud DNS Excel, Huawei Cloud DNS Excel
// -------------------------------------------------------------
type xmlSharedStrings struct {
	XMLName xml.Name  `xml:"sst"`
	Items   []xmlItem `xml:"si"`
}

type xmlItem struct {
	Text string `xml:"t"`
	Runs []struct {
		Text string `xml:"t"`
	} `xml:"r"`
}

type xmlWorksheet struct {
	XMLName   xml.Name `xml:"worksheet"`
	SheetData struct {
		Rows []xmlRow `xml:"row"`
	} `xml:"sheetData"`
}

type xmlRow struct {
	R int       `xml:"r,attr"`
	C []xmlCell `xml:"c"`
}

type xmlCell struct {
	R         string `xml:"r,attr"`
	T         string `xml:"t,attr"`
	V         string `xml:"v"`
	InlineStr struct {
		Text string `xml:"t"`
	} `xml:"is"`
}

func parseXLSX(data []byte, defaultOrigin string) (*ParseDNSResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	// 1. Read shared strings
	var sharedStrings []string
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "sharedStrings.xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			var ss xmlSharedStrings
			_ = xml.NewDecoder(rc).Decode(&ss)
			rc.Close()

			for _, item := range ss.Items {
				txt := item.Text
				if txt == "" && len(item.Runs) > 0 {
					var sb strings.Builder
					for _, r := range item.Runs {
						sb.WriteString(r.Text)
					}
					txt = sb.String()
				}
				sharedStrings = append(sharedStrings, txt)
			}
			break
		}
	}

	// 2. Read first worksheet
	var targetSheet *zip.File
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml") {
			targetSheet = f
			break
		}
	}

	if targetSheet == nil {
		return nil, fmt.Errorf("xlsx 文件中未找到有效的工作表")
	}

	rc, err := targetSheet.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var ws xmlWorksheet
	if err := xml.NewDecoder(rc).Decode(&ws); err != nil {
		return nil, err
	}

	var rows [][]string
	for _, row := range ws.SheetData.Rows {
		var rowData []string
		for _, cell := range row.C {
			val := cell.V
			if cell.T == "s" {
				var idx int
				if _, err := fmt.Sscanf(val, "%d", &idx); err == nil && idx >= 0 && idx < len(sharedStrings) {
					val = sharedStrings[idx]
				}
			} else if cell.T == "inlineStr" {
				val = cell.InlineStr.Text
			}
			rowData = append(rowData, strings.TrimSpace(val))
		}
		rows = append(rows, rowData)
	}

	return extractFromGrid(rows, "Excel (.xlsx) 表格格式 (DNSPod / 阿里云 / 华为云)", defaultOrigin)
}

// -------------------------------------------------------------
// Helper: Extract valid domains from a 2D string grid (CSV / Excel)
// -------------------------------------------------------------
func extractFromGrid(rows [][]string, formatName string, defaultOrigin string) (*ParseDNSResult, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("表格数据为空")
	}

	headerIdx := -1
	nameCol := -1
	typeCol := -1
	domainCol := -1

	// Search header row in first 10 rows
	for rIdx, row := range rows {
		if rIdx > 10 {
			break
		}
		for cIdx, cell := range row {
			val := strings.ToLower(strings.TrimSpace(cell))
			val = strings.ReplaceAll(val, " ", "")
			val = strings.ReplaceAll(val, "_", "")

			if nameCol == -1 && (strings.Contains(val, "主机记录") || strings.Contains(val, "主机名") ||
				strings.Contains(val, "子域名") || strings.Contains(val, "记录名") ||
				val == "name" || val == "host" || val == "subdomain" || val == "rr") {
				nameCol = cIdx
			}
			if typeCol == -1 && (strings.Contains(val, "记录类型") || strings.Contains(val, "类型") ||
				val == "type" || val == "recordtype") {
				typeCol = cIdx
			}
			if domainCol == -1 && (val == "域名" || val == "所属域名" || val == "domain" || val == "zone") {
				domainCol = cIdx
			}
		}

		if nameCol != -1 && typeCol != -1 {
			headerIdx = rIdx
			break
		}
	}

	if headerIdx == -1 || nameCol == -1 {
		return nil, fmt.Errorf("未能定位到包含“主机记录/Name”和“记录类型/Type”的表头")
	}

	seen := make(map[string]bool)
	var domains []string
	filteredCount := 0

	for i := headerIdx + 1; i < len(rows); i++ {
		row := rows[i]
		if nameCol >= len(row) {
			continue
		}

		recType := ""
		if typeCol != -1 && typeCol < len(row) {
			recType = strings.ToUpper(strings.TrimSpace(row[typeCol]))
		}

		// Filter non-web records
		if recType != "" && recType != "A" && recType != "AAAA" && recType != "CNAME" {
			filteredCount++
			continue
		}

		host := strings.TrimSpace(row[nameCol])
		if host == "" || strings.HasPrefix(host, "*") {
			continue
		}

		parentDomain := defaultOrigin
		if domainCol != -1 && domainCol < len(row) && strings.TrimSpace(row[domainCol]) != "" {
			parentDomain = strings.TrimSuffix(strings.TrimSpace(row[domainCol]), ".")
		}

		fqdn := resolveFQDN(host, parentDomain)
		if fqdn == "" {
			continue
		}

		if !seen[fqdn] {
			seen[fqdn] = true
			domains = append(domains, fqdn)
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("未能从表格中识别出有效的 Web 解析记录")
	}

	return &ParseDNSResult{
		Format:          formatName,
		Domains:         domains,
		DomainCount:     len(domains),
		FilteredRecords: filteredCount,
		Message:         fmt.Sprintf("识别为 %s，提取到 %d 个有效域名，已过滤 %d 条非 Web 记录", formatName, len(domains), filteredCount),
	}, nil
}

// -------------------------------------------------------------
// 4. JSON Parser
// Covers: AWS Route 53, Cloudflare API, Google Cloud DNS API, Custom JSON
// -------------------------------------------------------------
func parseJSON(data []byte) (*ParseDNSResult, error) {
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var domains []string
	filteredCount := 0

	var walk func(v interface{})
	walk = func(v interface{}) {
		switch node := v.(type) {
		case map[string]interface{}:
			nameVal, hasName := node["Name"]
			if !hasName {
				nameVal, hasName = node["name"]
			}
			typeVal, hasType := node["Type"]
			if !hasType {
				typeVal, hasType = node["type"]
			}

			if hasName && hasType {
				nStr, ok1 := nameVal.(string)
				tStr, ok2 := typeVal.(string)
				if ok1 && ok2 {
					tUpper := strings.ToUpper(strings.TrimSpace(tStr))
					nClean := strings.TrimSuffix(strings.TrimSpace(nStr), ".")
					if tUpper == "A" || tUpper == "AAAA" || tUpper == "CNAME" {
						if nClean != "" && !strings.HasPrefix(nClean, "*") && domainRegex.MatchString(nClean) {
							if !seen[nClean] {
								seen[nClean] = true
								domains = append(domains, nClean)
							}
						}
					} else {
						filteredCount++
					}
				}
			}

			for _, val := range node {
				walk(val)
			}
		case []interface{}:
			for _, item := range node {
				walk(item)
			}
		}
	}

	walk(root)

	if len(domains) == 0 {
		return nil, fmt.Errorf("JSON 文件中未找到符合条件的 A/AAAA/CNAME 域名记录")
	}

	return &ParseDNSResult{
		Format:          "JSON 格式 (AWS Route 53 / Cloudflare API / 通用 DNS JSON)",
		Domains:         domains,
		DomainCount:     len(domains),
		FilteredRecords: filteredCount,
		Message:         fmt.Sprintf("识别为 JSON 格式，提取到 %d 个有效域名，已过滤 %d 条非 Web 记录", len(domains), filteredCount),
	}, nil
}

// -------------------------------------------------------------
// 5. Intelligent Plaintext & Fallback Extractor
// -------------------------------------------------------------
func parsePlainLines(content string) (*ParseDNSResult, error) {
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool)
	var domains []string

	for _, l := range lines {
		// Strip comments (; # //)
		if idx := strings.Index(l, ";"); idx != -1 {
			l = l[:idx]
		}
		if idx := strings.Index(l, "#"); idx != -1 {
			l = l[:idx]
		}
		if idx := strings.Index(l, "//"); idx != -1 {
			l = l[:idx]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}

		// Find all domain candidates in the line
		matches := domainExtractRegex.FindAllString(l, -1)
		for _, m := range matches {
			mClean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(m)), ".")
			if domainRegex.MatchString(mClean) && !seen[mClean] && !strings.HasPrefix(mClean, "*") {
				seen[mClean] = true
				domains = append(domains, mClean)
			}
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("未能从文本中提取到合法的域名")
	}

	return &ParseDNSResult{
		Format:          "纯文本列表",
		Domains:         domains,
		DomainCount:     len(domains),
		FilteredRecords: 0,
		Message:         fmt.Sprintf("提取到 %d 个有效域名", len(domains)),
	}, nil
}

// -------------------------------------------------------------
// Helper: Resolve host + parent domain into FQDN
// -------------------------------------------------------------
func resolveFQDN(host, parentDomain string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	parentDomain = strings.TrimSpace(strings.ToLower(parentDomain))

	if host == "" || host == "@" {
		return parentDomain
	}

	// Absolute domain ending with dot (e.g. "example.com." or "www.example.com.")
	if strings.HasSuffix(host, ".") {
		return strings.TrimSuffix(host, ".")
	}

	// If parentDomain is present
	if parentDomain != "" {
		if host == parentDomain || strings.HasSuffix(host, "."+parentDomain) {
			return host
		}
		return host + "." + parentDomain
	}

	// Check if host itself is a full domain
	if domainRegex.MatchString(host) {
		return host
	}

	return ""
}
