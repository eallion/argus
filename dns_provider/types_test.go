package dns_provider

import (
	"reflect"
	"testing"
)

func TestFilterBlacklist(t *testing.T) {
	domains := []string{
		"example.com",
		"www.example.com",
		"mail.example.com",
		"smtp.example.com",
		"dev-api.example.com",
		"internal.corp.example.com",
		"test.example.com",
	}

	blacklist := []string{
		"mail",              // prefix match
		"smtp.example.com",  // exact match
		"dev-*",             // prefix wildcard
		"*.corp.example.com", // wildcard sub
	}

	allowed, blocked := FilterBlacklist(domains, "example.com", blacklist)

	expectedAllowed := []string{
		"example.com",
		"www.example.com",
		"test.example.com",
	}

	expectedBlocked := []string{
		"mail.example.com",
		"smtp.example.com",
		"dev-api.example.com",
		"internal.corp.example.com",
	}

	if !reflect.DeepEqual(allowed, expectedAllowed) {
		t.Errorf("allowed mismatch, got %v, want %v", allowed, expectedAllowed)
	}

	if !reflect.DeepEqual(blocked, expectedBlocked) {
		t.Errorf("blocked mismatch, got %v, want %v", blocked, expectedBlocked)
	}
}
