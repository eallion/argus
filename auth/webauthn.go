package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyUser implements the webauthn.User interface
type PasskeyUser struct {
	ID          []byte
	Username    string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte {
	return u.ID
}

func (u *PasskeyUser) WebAuthnName() string {
	return u.Username
}

func (u *PasskeyUser) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

func (u *PasskeyUser) WebAuthnIcon() string {
	return ""
}

func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// SessionStore keeps registration and login session data in memory with TTL
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
}

type sessionEntry struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

func NewSessionStore() *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*sessionEntry),
	}
	// Clean expired entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			store.mu.Lock()
			now := time.Now()
			for k, v := range store.sessions {
				if now.After(v.expiresAt) {
					delete(store.sessions, k)
				}
			}
			store.mu.Unlock()
		}
	}()
	return store
}

func (s *SessionStore) Save(key string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
}

func (s *SessionStore) Get(key string) *webauthn.SessionData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.data
}

func (s *SessionStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
}

// PasskeyManager wraps WebAuthn instantiation dynamically based on the incoming request Host
type PasskeyManager struct {
	sessions *SessionStore
}

func NewPasskeyManager() *PasskeyManager {
	return &PasskeyManager{
		sessions: NewSessionStore(),
	}
}

func (m *PasskeyManager) Sessions() *SessionStore {
	return m.sessions
}

// GetWebAuthnForRequest dynamically creates or configures a WebAuthn instance matching the request Host
func (m *PasskeyManager) GetWebAuthnForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = strings.TrimSpace(strings.Split(xfh, ",")[0])
	}
	rawHost := host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	origin := fmt.Sprintf("%s://%s", scheme, rawHost)

	config := &webauthn.Config{
		RPDisplayName: "Argus",
		RPID:          host,
		RPOrigins:     []string{origin},
	}

	return webauthn.New(config)
}

// GenerateRandomKey creates a random session key
func GenerateRandomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to serialize credential to JSON for database storage
func SerializeCredential(cred *webauthn.Credential) (string, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Helper to deserialize credential from JSON
func DeserializeCredential(jsonStr string) (*webauthn.Credential, error) {
	var cred webauthn.Credential
	if err := json.Unmarshal([]byte(jsonStr), &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}
