package schedule

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		ok       bool
	}{
		{"12h", 12 * time.Hour, true},
		{"1d", 24 * time.Hour, true},
		{"2d", 48 * time.Hour, true},
		{"7D", 7 * 24 * time.Hour, true},
		{"30m", 30 * time.Minute, true},
		{"1w", 7 * 24 * time.Hour, true},
		{"invalid", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		d, ok := ParseDuration(tt.input)
		if ok != tt.ok {
			t.Errorf("ParseDuration(%q) ok = %v, expected %v", tt.input, ok, tt.ok)
		}
		if ok && d != tt.expected {
			t.Errorf("ParseDuration(%q) = %v, expected %v", tt.input, d, tt.expected)
		}
	}
}

func TestCronNext(t *testing.T) {
	// 2026-10-01 10:15:00 UTC
	ref := time.Date(2026, 10, 1, 10, 15, 0, 0, time.UTC)

	// Every hour at minute 0
	c, err := ParseCron("0 * * * *")
	if err != nil {
		t.Fatalf("ParseCron failed: %v", err)
	}

	next := c.Next(ref)
	expected := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("Expected %v, got %v", expected, next)
	}

	// Every day at 02:00
	c2, err := ParseCron("0 2 * * *")
	if err != nil {
		t.Fatalf("ParseCron failed: %v", err)
	}
	next2 := c2.Next(ref)
	expected2 := time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC)
	if !next2.Equal(expected2) {
		t.Errorf("Expected %v, got %v", expected2, next2)
	}
}

func TestValidateSpec(t *testing.T) {
	valid := []string{"12h", "1d", "30m", "0 */6 * * *", "0 0 * * *", "*/15 * * * *", ""}
	for _, s := range valid {
		if err := ValidateSpec(s); err != nil {
			t.Errorf("ValidateSpec(%q) should be valid, got: %v", s, err)
		}
	}

	invalid := []string{"abc", "100", "0 0 0", "99 99 * * *", "0s"}
	for _, s := range invalid {
		if err := ValidateSpec(s); err == nil {
			t.Errorf("ValidateSpec(%q) should be invalid, got nil", s)
		}
	}
}
