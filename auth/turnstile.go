package auth

import (
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

type turnstileVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// VerifyTurnstile checks token validity against Cloudflare's API
func VerifyTurnstile(secretKey, responseToken, remoteIP string) (bool, error) {
	if secretKey == "" || responseToken == "" {
		return false, fmt.Errorf("missing turnstile credentials or token")
	}

	client := &http.Client{Timeout: 6 * time.Second}
	data := url.Values{
		"secret":   {secretKey},
		"response": {responseToken},
	}
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	resp, err := client.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", data)
	if err != nil {
		return false, fmt.Errorf("failed to contact cloudflare turnstile API: %w", err)
	}
	defer resp.Body.Close()

	var result turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to parse turnstile response: %w", err)
	}

	return result.Success, nil
}

// CreateClearanceToken creates a signed token indicating the client has passed captcha recently
func CreateClearanceToken(secretKey string, duration time.Duration) string {
	expiresAt := time.Now().Add(duration).Unix()
	payload := fmt.Sprintf("%d", expiresAt)

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payload, sig)
}

// ValidateClearanceToken verifies that the client has a valid, unexpired clearance token
func ValidateClearanceToken(secretKey, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	payload := parts[0]
	sig := parts[1]

	expiresAt, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() > expiresAt {
		return false // Expired
	}

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}
