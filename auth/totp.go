package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// GenerateTOTPSecret generates a new 20-byte (160-bit) random secret, encoded in Base32
func GenerateTOTPSecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// GenerateTOTPCode generates a 6-digit code for a given timestamp
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		// try with padding if failed
		key, err = base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
		if err != nil {
			return "", fmt.Errorf("invalid base32 secret: %w", err)
		}
	}

	counter := uint64(t.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	code := binaryCode % 1000000

	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP checks if the given code matches current or adjacent 30s windows (±1 window for clock drift)
func ValidateTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}

	now := time.Now().UTC()
	// Check t-30s, t, t+30s
	steps := []time.Time{
		now.Add(-30 * time.Second),
		now,
		now.Add(30 * time.Second),
	}

	for _, step := range steps {
		expected, err := GenerateTOTPCode(secret, step)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// GetTOTPUri builds the standard otpauth URI compatible with Bitwarden, Google Authenticator, etc.
func GetTOTPUri(username, secret string) string {
	issuer := "Argus"
	label := fmt.Sprintf("%s:%s", issuer, username)
	return fmt.Sprintf(
		"otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(label),
		secret,
		url.QueryEscape(issuer),
	)
}
