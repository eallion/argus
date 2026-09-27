package checker

import (
	"testing"
	"time"
)

func TestParseWhoisExpirationCNNIC(t *testing.T) {
	rawCNNIC := `Domain Name: alibaba.cn
ROID: 20030312s10001s00055047-cn
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Registrant: 阿里巴巴（中国）有限公司
Registrant Contact Email: dnsadmin@alibaba-inc.com
Sponsoring Registrar: 阿里云计算有限公司（万网）
Name Server: ns1.alidns.com
Name Server: ns2.alidns.com
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2028-03-17 12:48:36
DNSSEC: unsigned
`
	expire, err := parseWhoisExpiration(rawCNNIC)
	if err != nil {
		t.Fatalf("failed to parse CNNIC expiration: %v", err)
	}

	expectedYear := 2028
	expectedMonth := time.Month(3)
	expectedDay := 17
	if expire.Year() != expectedYear || expire.Month() != expectedMonth || expire.Day() != expectedDay {
		t.Errorf("expected %d-%d-%d, got %v", expectedYear, expectedMonth, expectedDay, expire)
	}
}

func TestParseWhoisExpirationGeneric(t *testing.T) {
	rawGeneric := `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2024-08-14T07:01:44Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
`
	expire, err := parseWhoisExpiration(rawGeneric)
	if err != nil {
		t.Fatalf("failed to parse generic expiration: %v", err)
	}

	if expire.Year() != 2027 || expire.Month() != time.August || expire.Day() != 13 {
		t.Errorf("unexpected date: %v", expire)
	}
}
