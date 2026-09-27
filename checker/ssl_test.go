package checker

import (
	"testing"
)

func TestParseHostsList(t *testing.T) {
	// 1. JSON Array format (New typed structured rows)
	jsonRaw := `[
		{"type":"A","value":"1.1.1.1","alias":"Cloudflare Edge"},
		{"type":"AAAA","value":"2606:4700::1111","alias":"IPv6 Node"},
		{"type":"CNAME","value":"cdn.example.com","alias":"CDN Endpoint"}
	]`

	nodes := ParseHostsList(jsonRaw)
	if len(nodes) != 3 {
		t.Fatalf("Expected 3 nodes from JSON, got %d", len(nodes))
	}
	if nodes[0].Type != "A" || nodes[0].Address != "1.1.1.1" || nodes[0].Alias != "Cloudflare Edge" {
		t.Errorf("Node 0 mismatch: %+v", nodes[0])
	}
	if nodes[1].Type != "AAAA" || nodes[1].Address != "2606:4700::1111" || nodes[1].Alias != "IPv6 Node" {
		t.Errorf("Node 1 mismatch: %+v", nodes[1])
	}
	if nodes[2].Type != "CNAME" || nodes[2].Address != "cdn.example.com" || nodes[2].Alias != "CDN Endpoint" {
		t.Errorf("Node 2 mismatch: %+v", nodes[2])
	}

	// 2. Legacy multi-line text format
	textRaw := `
1.2.3.4 # 境内腾讯云
CNAME edge.example.com # 境外别名
2.3.4.5:8443 // 自定义端口
`
	textNodes := ParseHostsList(textRaw)
	if len(textNodes) != 3 {
		t.Fatalf("Expected 3 nodes from text, got %d", len(textNodes))
	}
	if textNodes[0].Type != "A" || textNodes[0].Address != "1.2.3.4" || textNodes[0].Alias != "境内腾讯云" {
		t.Errorf("Text node 0 mismatch: %+v", textNodes[0])
	}
	if textNodes[1].Type != "CNAME" || textNodes[1].Address != "edge.example.com" || textNodes[1].Alias != "境外别名" {
		t.Errorf("Text node 1 mismatch: %+v", textNodes[1])
	}
	if textNodes[2].Type != "A" || textNodes[2].Address != "2.3.4.5:8443" || textNodes[2].Alias != "自定义端口" {
		t.Errorf("Text node 2 mismatch: %+v", textNodes[2])
	}
}
