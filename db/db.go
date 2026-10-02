package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type User struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	TOTPEnabled bool      `json:"totp_enabled"`
	TOTPSecret  string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

type PasskeyRecord struct {
	ID             int64     `json:"id"`
	UserID         int64     `json:"user_id"`
	Name           string    `json:"name"`
	CredentialID   string    `json:"credential_id"`
	CredentialData string    `json:"credential_data"`
	CreatedAt      time.Time `json:"created_at"`
}

type Domain struct {
	ID              int64      `json:"id"`
	Host            string     `json:"host"`
	Port            string     `json:"port"`
	CheckSSL        bool       `json:"check_ssl"`
	CheckDomain     bool       `json:"check_domain"`
	MultiHost       bool       `json:"multi_host"`
	HostsList       string     `json:"hosts_list"`
	SSLDetails      string     `json:"ssl_details"`
	SSLDaysLeft     int        `json:"ssl_days_left"`
	SSLExpiresAt    *time.Time `json:"ssl_expires_at"`
	SSLIssuer       string     `json:"ssl_issuer"`
	SSLStatus       string     `json:"ssl_status"` // "healthy", "warning", "critical", "expired", "error", "pending"
	SSLError        string     `json:"ssl_error"`
	DomainDaysLeft  int        `json:"domain_days_left"`
	DomainExpiresAt     *time.Time `json:"domain_expires_at"`
	DomainStatus        string     `json:"domain_status"` // "healthy", "warning", "critical", "expired", "error", "skipped", "pending"
	DomainError         string     `json:"domain_error"`
	LastAlertSSLTier    int        `json:"last_alert_ssl_tier"`
	LastAlertDomainTier int        `json:"last_alert_domain_tier"`
	LastAlertSSLAt      *time.Time `json:"last_alert_ssl_at"`
	LastAlertDomainAt   *time.Time `json:"last_alert_domain_at"`
	LastCheckedAt       *time.Time `json:"last_checked_at"`
	IsPinned            bool       `json:"is_pinned"`
	NotifyDisabled      bool       `json:"notify_disabled"`
	CronSpec            string     `json:"cron_spec"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// DNSProviderAccount stores DNS API credentials
type DNSProviderAccount struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`          // Friendly label e.g. "我的 Cloudflare"
	ProviderType string    `json:"provider_type"` // "cloudflare", "aliyun", etc.
	AuthKey      string    `json:"auth_key"`
	AuthSecret   string    `json:"auth_secret,omitempty"`
	Extra        string    `json:"extra,omitempty"` // JSON string
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DNSSyncConfig stores dynamic sync configuration & blacklist for a root domain
type DNSSyncConfig struct {
	ID             int64      `json:"id"`
	ProviderID     int64      `json:"provider_id"`
	ProviderType   string     `json:"provider_type,omitempty"`
	ProviderName   string     `json:"provider_name,omitempty"`
	Domain         string     `json:"domain"`          // e.g. "example.com"
	ZoneID         string     `json:"zone_id"`         // Optional Zone ID
	Blacklist      []string   `json:"blacklist"`       // Subdomain blacklist rules
	AutoSync       bool       `json:"auto_sync"`       // Whether to auto sync in background
	CheckDomain    bool       `json:"check_domain"`    // Whether imported domains check RDAP
	DefaultPort    string     `json:"default_port"`    // Default 443
	IsDisabled     bool       `json:"is_disabled"`     // Whether API mode is disabled
	CronSpec       string     `json:"cron_spec"`       // Scheduled check cron or duration
	LastSyncAt     *time.Time `json:"last_sync_at"`
	LastSyncStatus string     `json:"last_sync_status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Settings struct {
	Interval           string   `json:"interval"`           // e.g. "12h"
	ThresholdDays      int      `json:"threshold_days"`     // e.g. 15 (fallback)
	AlertThresholds    string   `json:"alert_thresholds"`   // e.g. "30,15,10,7,5,3,1"
	AlertRuleMode      string   `json:"alert_rule_mode"`    // "tier_once" or "daily"
	Timeout            string   `json:"timeout"`            // e.g. "10s"
	ShoutrrrURLs       []string `json:"shoutrrr_urls"`      // URLs list
	AppriseEnabled     bool     `json:"apprise_enabled"`
	AppriseAPIURL      string   `json:"apprise_api_url"`
	AppriseURLs        []string `json:"apprise_urls"`
	TurnstileEnabled   bool     `json:"turnstile_enabled"`
	TurnstileSiteKey   string   `json:"turnstile_site_key"`
	TurnstileSecretKey string   `json:"turnstile_secret_key,omitempty"`
}

type DB struct {
	db *sql.DB
}

func InitDB(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT NOT NULL DEFAULT '',
		totp_enabled INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS passkeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		credential_id TEXT UNIQUE NOT NULL,
		credential_data TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT UNIQUE NOT NULL,
		port TEXT NOT NULL DEFAULT '443',
		check_ssl INTEGER NOT NULL DEFAULT 1,
		check_domain INTEGER NOT NULL DEFAULT 0,
		multi_host INTEGER NOT NULL DEFAULT 0,
		hosts_list TEXT NOT NULL DEFAULT '',
		ssl_details TEXT NOT NULL DEFAULT '',
		ssl_days_left INTEGER NOT NULL DEFAULT 0,
		ssl_expires_at DATETIME,
		ssl_issuer TEXT NOT NULL DEFAULT '',
		ssl_status TEXT NOT NULL DEFAULT 'pending',
		ssl_error TEXT NOT NULL DEFAULT '',
		domain_days_left INTEGER NOT NULL DEFAULT 0,
		domain_expires_at DATETIME,
		domain_status TEXT NOT NULL DEFAULT 'pending',
		domain_error TEXT NOT NULL DEFAULT '',
		last_alert_ssl_tier INTEGER NOT NULL DEFAULT 0,
		last_alert_domain_tier INTEGER NOT NULL DEFAULT 0,
		last_alert_ssl_at DATETIME,
		last_alert_domain_at DATETIME,
		last_checked_at DATETIME,
		is_pinned INTEGER NOT NULL DEFAULT 0,
		notify_disabled INTEGER NOT NULL DEFAULT 0,
		cron_spec TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS dns_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		provider_type TEXT NOT NULL,
		auth_key TEXT NOT NULL DEFAULT '',
		auth_secret TEXT NOT NULL DEFAULT '',
		extra TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS dns_sync_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		provider_id INTEGER NOT NULL DEFAULT 0,
		domain TEXT NOT NULL,
		zone_id TEXT NOT NULL DEFAULT '',
		blacklist TEXT NOT NULL DEFAULT '[]',
		auto_sync INTEGER NOT NULL DEFAULT 0,
		check_domain INTEGER NOT NULL DEFAULT 0,
		default_port TEXT NOT NULL DEFAULT '443',
		is_disabled INTEGER NOT NULL DEFAULT 0,
		cron_spec TEXT NOT NULL DEFAULT '',
		last_sync_at DATETIME,
		last_sync_status TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		FOREIGN KEY (provider_id) REFERENCES dns_providers(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT NOT NULL,
		level TEXT NOT NULL DEFAULT 'warning',
		target_host TEXT NOT NULL DEFAULT '',
		is_read INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL
	);
	`
	if _, err := d.db.Exec(schema); err != nil {
		return err
	}

	// Safe alter column migrations for existing databases
	_, _ = d.db.Exec("ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''")
	_, _ = d.db.Exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN check_ssl INTEGER NOT NULL DEFAULT 1")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN multi_host INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN hosts_list TEXT NOT NULL DEFAULT ''")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN ssl_details TEXT NOT NULL DEFAULT ''")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN is_pinned INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN notify_disabled INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN last_alert_ssl_tier INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN last_alert_domain_tier INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN last_alert_ssl_at DATETIME")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN last_alert_domain_at DATETIME")
	_, _ = d.db.Exec("ALTER TABLE domains ADD COLUMN cron_spec TEXT NOT NULL DEFAULT ''")
	_, _ = d.db.Exec("ALTER TABLE dns_sync_configs ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0")
	_, _ = d.db.Exec("ALTER TABLE dns_sync_configs ADD COLUMN cron_spec TEXT NOT NULL DEFAULT ''")
	_, _ = d.db.Exec("CREATE INDEX IF NOT EXISTS idx_dns_sync_configs_domain ON dns_sync_configs(domain)")
	_, _ = d.db.Exec("CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC)")
	_, _ = d.db.Exec("CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read)")

	return nil
}

// User & Auth operations

func (d *DB) HasAdmin() (bool, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0, err
}

func (d *DB) GetAdminUser() (*User, error) {
	var user User
	var totpEnabledInt int
	err := d.db.QueryRow("SELECT id, username, totp_secret, totp_enabled, created_at FROM users LIMIT 1").
		Scan(&user.ID, &user.Username, &user.TOTPSecret, &totpEnabledInt, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	user.TOTPEnabled = (totpEnabledInt == 1)
	return &user, nil
}

func (d *DB) CreateAdmin(username, password string) error {
	has, err := d.HasAdmin()
	if err != nil {
		return err
	}
	if has {
		return fmt.Errorf("admin user already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = d.db.Exec("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, string(hash), time.Now().UTC())
	return err
}

func (d *DB) VerifyUser(username, password string) (*User, error) {
	var user User
	var hash string
	var totpEnabledInt int
	err := d.db.QueryRow("SELECT id, username, password_hash, totp_secret, totp_enabled, created_at FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &hash, &user.TOTPSecret, &totpEnabledInt, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid username or password")
	}

	user.TOTPEnabled = (totpEnabledInt == 1)
	return &user, nil
}

func (d *DB) UpdatePassword(userID int64, oldPassword, newPassword string) error {
	var hash string
	err := d.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("incorrect current password")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	_, err = d.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), userID)
	return err
}

func (d *DB) SetTOTP(userID int64, secret string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := d.db.Exec("UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?", secret, enabledInt, userID)
	return err
}

func (d *DB) CreateSession(userID int64, duration time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	now := time.Now().UTC()
	expiresAt := now.Add(duration)

	_, err := d.db.Exec("INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		token, userID, expiresAt, now)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (d *DB) ValidateSession(token string) (*User, error) {
	var user User
	var totpEnabledInt int
	var expiresAt time.Time
	err := d.db.QueryRow(`
		SELECT u.id, u.username, u.totp_secret, u.totp_enabled, u.created_at, s.expires_at 
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token = ?
	`, token).Scan(&user.ID, &user.Username, &user.TOTPSecret, &totpEnabledInt, &user.CreatedAt, &expiresAt)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	user.TOTPEnabled = (totpEnabledInt == 1)

	if time.Now().UTC().After(expiresAt) {
		d.DeleteSession(token)
		return nil, fmt.Errorf("session expired")
	}

	return &user, nil
}

func (d *DB) DeleteSession(token string) error {
	_, err := d.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (d *DB) CleanExpiredSessions() {
	_, _ = d.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now().UTC())
}

// Passkey operations

func (d *DB) AddPasskey(userID int64, name, credID, credData string) (*PasskeyRecord, error) {
	now := time.Now().UTC()
	res, err := d.db.Exec(`
		INSERT INTO passkeys (user_id, name, credential_id, credential_data, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, userID, name, credID, credData, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &PasskeyRecord{
		ID:             id,
		UserID:         userID,
		Name:           name,
		CredentialID:   credID,
		CredentialData: credData,
		CreatedAt:      now,
	}, nil
}

func (d *DB) GetPasskeys(userID int64) ([]PasskeyRecord, error) {
	rows, err := d.db.Query("SELECT id, user_id, name, credential_id, credential_data, created_at FROM passkeys WHERE user_id = ? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []PasskeyRecord
	for rows.Next() {
		var r PasskeyRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.CredentialID, &r.CredentialData, &r.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) GetAllPasskeys() ([]PasskeyRecord, error) {
	rows, err := d.db.Query("SELECT id, user_id, name, credential_id, credential_data, created_at FROM passkeys ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []PasskeyRecord
	for rows.Next() {
		var r PasskeyRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.Name, &r.CredentialID, &r.CredentialData, &r.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) DeletePasskey(id, userID int64) error {
	_, err := d.db.Exec("DELETE FROM passkeys WHERE id = ? AND user_id = ?", id, userID)
	return err
}

// Domain operations

func (d *DB) GetAllDomains() ([]Domain, error) {
	rows, err := d.db.Query(`
		SELECT id, host, port, check_ssl, check_domain, multi_host, hosts_list, ssl_details,
		       ssl_days_left, ssl_expires_at, ssl_issuer, ssl_status, ssl_error,
		       domain_days_left, domain_expires_at, domain_status, domain_error,
		       last_alert_ssl_tier, last_alert_domain_tier, last_alert_ssl_at, last_alert_domain_at,
		       last_checked_at, is_pinned, notify_disabled, cron_spec, created_at, updated_at
		FROM domains
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		var dom Domain
		var checkSSLInt, checkDomInt, multiHostInt, isPinnedInt, notifyDisabledInt int
		if err := rows.Scan(
			&dom.ID, &dom.Host, &dom.Port, &checkSSLInt, &checkDomInt, &multiHostInt, &dom.HostsList, &dom.SSLDetails,
			&dom.SSLDaysLeft, &dom.SSLExpiresAt, &dom.SSLIssuer, &dom.SSLStatus, &dom.SSLError,
			&dom.DomainDaysLeft, &dom.DomainExpiresAt, &dom.DomainStatus, &dom.DomainError,
			&dom.LastAlertSSLTier, &dom.LastAlertDomainTier, &dom.LastAlertSSLAt, &dom.LastAlertDomainAt,
			&dom.LastCheckedAt, &isPinnedInt, &notifyDisabledInt, &dom.CronSpec, &dom.CreatedAt, &dom.UpdatedAt,
		); err != nil {
			return nil, err
		}
		dom.CheckSSL = (checkSSLInt == 1)
		dom.CheckDomain = (checkDomInt == 1)
		dom.MultiHost = (multiHostInt == 1)
		dom.IsPinned = (isPinnedInt == 1)
		dom.NotifyDisabled = (notifyDisabledInt == 1)
		domains = append(domains, dom)
	}
	return domains, rows.Err()
}

func (d *DB) GetDomainByID(id int64) (*Domain, error) {
	var dom Domain
	var checkSSLInt, checkDomInt, multiHostInt, isPinnedInt, notifyDisabledInt int
	err := d.db.QueryRow(`
		SELECT id, host, port, check_ssl, check_domain, multi_host, hosts_list, ssl_details,
		       ssl_days_left, ssl_expires_at, ssl_issuer, ssl_status, ssl_error,
		       domain_days_left, domain_expires_at, domain_status, domain_error,
		       last_alert_ssl_tier, last_alert_domain_tier, last_alert_ssl_at, last_alert_domain_at,
		       last_checked_at, is_pinned, notify_disabled, cron_spec, created_at, updated_at
		FROM domains
		WHERE id = ?
	`, id).Scan(
		&dom.ID, &dom.Host, &dom.Port, &checkSSLInt, &checkDomInt, &multiHostInt, &dom.HostsList, &dom.SSLDetails,
		&dom.SSLDaysLeft, &dom.SSLExpiresAt, &dom.SSLIssuer, &dom.SSLStatus, &dom.SSLError,
		&dom.DomainDaysLeft, &dom.DomainExpiresAt, &dom.DomainStatus, &dom.DomainError,
		&dom.LastAlertSSLTier, &dom.LastAlertDomainTier, &dom.LastAlertSSLAt, &dom.LastAlertDomainAt,
		&dom.LastCheckedAt, &isPinnedInt, &notifyDisabledInt, &dom.CronSpec, &dom.CreatedAt, &dom.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	dom.CheckSSL = (checkSSLInt == 1)
	dom.CheckDomain = (checkDomInt == 1)
	dom.MultiHost = (multiHostInt == 1)
	dom.IsPinned = (isPinnedInt == 1)
	dom.NotifyDisabled = (notifyDisabledInt == 1)
	return &dom, nil
}

func (d *DB) AddDomain(host, port string, checkSSL, checkDomain, multiHost bool, hostsList string, isPinned, notifyDisabled bool, cronSpec string) (*Domain, error) {
	now := time.Now().UTC()
	checkSSLInt := 0
	if checkSSL {
		checkSSLInt = 1
	}
	checkDomInt := 0
	if checkDomain {
		checkDomInt = 1
	}
	multiHostInt := 0
	if multiHost {
		multiHostInt = 1
	}
	isPinnedInt := 0
	if isPinned {
		isPinnedInt = 1
	}
	notifyDisabledInt := 0
	if notifyDisabled {
		notifyDisabledInt = 1
	}
	if port == "" {
		port = "443"
	}

	res, err := d.db.Exec(`
		INSERT INTO domains (host, port, check_ssl, check_domain, multi_host, hosts_list, is_pinned, notify_disabled, cron_spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, host, port, checkSSLInt, checkDomInt, multiHostInt, hostsList, isPinnedInt, notifyDisabledInt, strings.TrimSpace(cronSpec), now, now)
	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return d.GetDomainByID(id)
}

func (d *DB) UpdateDomain(id int64, host, port string, checkSSL, checkDomain, multiHost bool, hostsList string, isPinned, notifyDisabled bool, cronSpec string) error {
	now := time.Now().UTC()
	checkSSLInt := 0
	if checkSSL {
		checkSSLInt = 1
	}
	checkDomInt := 0
	if checkDomain {
		checkDomInt = 1
	}
	multiHostInt := 0
	if multiHost {
		multiHostInt = 1
	}
	isPinnedInt := 0
	if isPinned {
		isPinnedInt = 1
	}
	notifyDisabledInt := 0
	if notifyDisabled {
		notifyDisabledInt = 1
	}
	if port == "" {
		port = "443"
	}

	_, err := d.db.Exec(`
		UPDATE domains
		SET host = ?, port = ?, check_ssl = ?, check_domain = ?, multi_host = ?, hosts_list = ?, is_pinned = ?, notify_disabled = ?, cron_spec = ?, updated_at = ?
		WHERE id = ?
	`, host, port, checkSSLInt, checkDomInt, multiHostInt, hostsList, isPinnedInt, notifyDisabledInt, strings.TrimSpace(cronSpec), now, id)
	return err
}

func (d *DB) UpdateDomainPin(id int64, pinned bool) error {
	val := 0
	if pinned {
		val = 1
	}
	_, err := d.db.Exec("UPDATE domains SET is_pinned = ?, updated_at = ? WHERE id = ?", val, time.Now().UTC(), id)
	return err
}

func (d *DB) ToggleDomainPin(id int64) (bool, error) {
	var current int
	err := d.db.QueryRow("SELECT is_pinned FROM domains WHERE id = ?", id).Scan(&current)
	if err != nil {
		return false, err
	}
	newVal := 1
	if current == 1 {
		newVal = 0
	}
	_, err = d.db.Exec("UPDATE domains SET is_pinned = ?, updated_at = ? WHERE id = ?", newVal, time.Now().UTC(), id)
	if err != nil {
		return false, err
	}
	return newVal == 1, nil
}

func (d *DB) DeleteDomain(id int64) error {
	_, err := d.db.Exec("DELETE FROM domains WHERE id = ?", id)
	return err
}

func (d *DB) UpdateDomainCheckResult(
	id int64,
	sslDaysLeft int, sslExpiresAt *time.Time, sslIssuer, sslStatus, sslError, sslDetails string,
	domainDaysLeft int, domainExpiresAt *time.Time, domainStatus, domainError string,
) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		UPDATE domains
		SET ssl_days_left = ?, ssl_expires_at = ?, ssl_issuer = ?, ssl_status = ?, ssl_error = ?, ssl_details = ?,
		    domain_days_left = ?, domain_expires_at = ?, domain_status = ?, domain_error = ?,
		    last_checked_at = ?, updated_at = ?
		WHERE id = ?
	`, sslDaysLeft, sslExpiresAt, sslIssuer, sslStatus, sslError, sslDetails,
		domainDaysLeft, domainExpiresAt, domainStatus, domainError,
		now, now, id)
	return err
}

func (d *DB) UpdateDomainAlertState(id int64, lastAlertSSLTier, lastAlertDomainTier int, lastAlertSSLAt, lastAlertDomainAt *time.Time) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		UPDATE domains
		SET last_alert_ssl_tier = ?, last_alert_domain_tier = ?,
		    last_alert_ssl_at = ?, last_alert_domain_at = ?,
		    updated_at = ?
		WHERE id = ?
	`, lastAlertSSLTier, lastAlertDomainTier, lastAlertSSLAt, lastAlertDomainAt, now, id)
	return err
}

func (d *DB) ResetDomainAlertSSLTier(id int64) error {
	_, err := d.db.Exec(`UPDATE domains SET last_alert_ssl_tier = 0 WHERE id = ?`, id)
	return err
}

func (d *DB) ResetDomainAlertDomainTier(id int64) error {
	_, err := d.db.Exec(`UPDATE domains SET last_alert_domain_tier = 0 WHERE id = ?`, id)
	return err
}

// Settings operations

func (d *DB) GetSetting(key, defaultVal string) string {
	var val string
	err := d.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err != nil {
		return defaultVal
	}
	return val
}

func (d *DB) SetSetting(key, val string) error {
	_, err := d.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, val)
	return err
}

func (d *DB) EnsureDefaultSettings() {
	defaults := map[string]string{
		"interval":                    "12h",
		"threshold_days":              "15",
		"alert_thresholds":            "30,15,10,7,5,3,1",
		"alert_rule_mode":             "tier_once",
		"timeout":                     "10s",
		"shoutrrr_urls":               "[]",
		"apprise_enabled":             "false",
		"apprise_api_url":             "http://apprise:8000/notify",
		"apprise_urls":                "[]",
		"turnstile_enabled":           "false",
		"turnstile_site_key":          "",
		"turnstile_secret_key":         "",
		"notification_mode":           "realtime",
		"notification_batch_time":     "09:00",
		"notification_batch_interval": "09:00",
	}
	for k, v := range defaults {
		var exists int
		_ = d.db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = ?", k).Scan(&exists)
		if exists == 0 {
			_ = d.SetSetting(k, v)
		}
	}
}

func (d *DB) GetAllSettings() (map[string]string, error) {
	rows, err := d.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		res[k] = v
	}
	return res, rows.Err()
}

type DomainImportItem struct {
	Host           string `json:"host"`
	Port           string `json:"port"`
	CheckSSL       *bool  `json:"check_ssl,omitempty"`
	CheckDomain    bool   `json:"check_domain"`
	MultiHost      bool   `json:"multi_host,omitempty"`
	HostsList      string `json:"hosts_list,omitempty"`
	IsPinned       bool   `json:"is_pinned,omitempty"`
	NotifyDisabled bool   `json:"notify_disabled,omitempty"`
	CronSpec       string `json:"cron_spec,omitempty"`
}

type BatchImportResult struct {
	Total   int     `json:"total"`
	Added   int     `json:"added"`
	Skipped int     `json:"skipped"`
	NewIDs  []int64 `json:"new_ids,omitempty"`
}

func (d *DB) BatchAddDomains(items []DomainImportItem) (*BatchImportResult, error) {
	now := time.Now().UTC()
	res := &BatchImportResult{Total: len(items)}

	tx, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	checkStmt, err := tx.Prepare("SELECT id FROM domains WHERE host = ?")
	if err != nil {
		return nil, err
	}
	defer checkStmt.Close()

	insertStmt, err := tx.Prepare(`
		INSERT INTO domains (host, port, check_ssl, check_domain, multi_host, hosts_list, is_pinned, notify_disabled, cron_spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}
	defer insertStmt.Close()

	for _, item := range items {
		host := strings.TrimSpace(item.Host)
		if host == "" {
			continue
		}
		port := strings.TrimSpace(item.Port)
		if port == "" {
			port = "443"
		}
		checkSSLInt := 1
		if item.CheckSSL != nil && !*item.CheckSSL {
			checkSSLInt = 0
		}
		checkDomInt := 0
		if item.CheckDomain {
			checkDomInt = 1
		}
		multiHostInt := 0
		if item.MultiHost {
			multiHostInt = 1
		}
		isPinnedInt := 0
		if item.IsPinned {
			isPinnedInt = 1
		}
		notifyDisabledInt := 0
		if item.NotifyDisabled {
			notifyDisabledInt = 1
		}

		var existingID int64
		err := checkStmt.QueryRow(host).Scan(&existingID)
		if err == nil {
			res.Skipped++
			continue
		}

		execRes, err := insertStmt.Exec(host, port, checkSSLInt, checkDomInt, multiHostInt, item.HostsList, isPinnedInt, notifyDisabledInt, strings.TrimSpace(item.CronSpec), now, now)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				res.Skipped++
				continue
			}
			return nil, err
		}

		newID, _ := execRes.LastInsertId()
		res.Added++
		res.NewIDs = append(res.NewIDs, newID)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return res, nil
}

// -------------------------------------------------------------
// DNS Providers & Dynamic Sync Configurations
// -------------------------------------------------------------

func (d *DB) ListDNSProviders() ([]DNSProviderAccount, error) {
	rows, err := d.db.Query(`SELECT id, name, provider_type, auth_key, auth_secret, extra, created_at, updated_at FROM dns_providers ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []DNSProviderAccount
	for rows.Next() {
		var p DNSProviderAccount
		if err := rows.Scan(&p.ID, &p.Name, &p.ProviderType, &p.AuthKey, &p.AuthSecret, &p.Extra, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, nil
}

func (d *DB) GetDNSProviderByID(id int64) (*DNSProviderAccount, error) {
	var p DNSProviderAccount
	err := d.db.QueryRow(`SELECT id, name, provider_type, auth_key, auth_secret, extra, created_at, updated_at FROM dns_providers WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.ProviderType, &p.AuthKey, &p.AuthSecret, &p.Extra, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (d *DB) SaveDNSProvider(p *DNSProviderAccount) error {
	now := time.Now().UTC()
	if p.ID == 0 {
		res, err := d.db.Exec(`INSERT INTO dns_providers (name, provider_type, auth_key, auth_secret, extra, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.Name, p.ProviderType, p.AuthKey, p.AuthSecret, p.Extra, now, now)
		if err != nil {
			return err
		}
		p.ID, _ = res.LastInsertId()
		p.CreatedAt = now
		p.UpdatedAt = now
		return nil
	}

	_, err := d.db.Exec(`UPDATE dns_providers SET name = ?, provider_type = ?, auth_key = ?, auth_secret = ?, extra = ?, updated_at = ? WHERE id = ?`,
		p.Name, p.ProviderType, p.AuthKey, p.AuthSecret, p.Extra, now, p.ID)
	p.UpdatedAt = now
	return err
}

func (d *DB) DeleteDNSProvider(id int64) error {
	_, err := d.db.Exec(`DELETE FROM dns_providers WHERE id = ?`, id)
	return err
}

func (d *DB) ListDNSSyncConfigs() ([]DNSSyncConfig, error) {
	query := `
		SELECT c.id, c.provider_id, p.provider_type, p.name, c.domain, c.zone_id, c.blacklist, c.auto_sync, c.check_domain, c.default_port, c.is_disabled, c.cron_spec, c.last_sync_at, c.last_sync_status, c.created_at, c.updated_at
		FROM dns_sync_configs c
		LEFT JOIN dns_providers p ON c.provider_id = p.id
		ORDER BY c.domain ASC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []DNSSyncConfig
	for rows.Next() {
		var item DNSSyncConfig
		var pType, pName sql.NullString
		var blacklistJSON string
		var autoSyncInt, checkDomInt, isDisabledInt int
		var lastSyncAt sql.NullTime

		if err := rows.Scan(&item.ID, &item.ProviderID, &pType, &pName, &item.Domain, &item.ZoneID, &blacklistJSON, &autoSyncInt, &checkDomInt, &item.DefaultPort, &isDisabledInt, &item.CronSpec, &lastSyncAt, &item.LastSyncStatus, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}

		item.ProviderType = pType.String
		item.ProviderName = pName.String
		item.AutoSync = autoSyncInt == 1
		item.CheckDomain = checkDomInt == 1
		item.IsDisabled = isDisabledInt == 1
		if lastSyncAt.Valid {
			item.LastSyncAt = &lastSyncAt.Time
		}

		_ = json.Unmarshal([]byte(blacklistJSON), &item.Blacklist)
		if item.Blacklist == nil {
			item.Blacklist = []string{}
		}

		list = append(list, item)
	}
	return list, nil
}

func (d *DB) GetDNSSyncConfigByID(id int64) (*DNSSyncConfig, error) {
	query := `
		SELECT c.id, c.provider_id, p.provider_type, p.name, c.domain, c.zone_id, c.blacklist, c.auto_sync, c.check_domain, c.default_port, c.is_disabled, c.cron_spec, c.last_sync_at, c.last_sync_status, c.created_at, c.updated_at
		FROM dns_sync_configs c
		LEFT JOIN dns_providers p ON c.provider_id = p.id
		WHERE c.id = ?`

	var item DNSSyncConfig
	var pType, pName sql.NullString
	var blacklistJSON string
	var autoSyncInt, checkDomInt, isDisabledInt int
	var lastSyncAt sql.NullTime

	err := d.db.QueryRow(query, id).Scan(
		&item.ID, &item.ProviderID, &pType, &pName, &item.Domain, &item.ZoneID, &blacklistJSON, &autoSyncInt, &checkDomInt, &item.DefaultPort, &isDisabledInt, &item.CronSpec, &lastSyncAt, &item.LastSyncStatus, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	item.ProviderType = pType.String
	item.ProviderName = pName.String
	item.AutoSync = autoSyncInt == 1
	item.CheckDomain = checkDomInt == 1
	item.IsDisabled = isDisabledInt == 1
	if lastSyncAt.Valid {
		item.LastSyncAt = &lastSyncAt.Time
	}

	_ = json.Unmarshal([]byte(blacklistJSON), &item.Blacklist)
	if item.Blacklist == nil {
		item.Blacklist = []string{}
	}

	return &item, nil
}

func (d *DB) GetDNSSyncConfigByDomain(domain string) (*DNSSyncConfig, error) {
	query := `
		SELECT c.id, c.provider_id, p.provider_type, p.name, c.domain, c.zone_id, c.blacklist, c.auto_sync, c.check_domain, c.default_port, c.is_disabled, c.cron_spec, c.last_sync_at, c.last_sync_status, c.created_at, c.updated_at
		FROM dns_sync_configs c
		LEFT JOIN dns_providers p ON c.provider_id = p.id
		WHERE LOWER(c.domain) = LOWER(?) LIMIT 1`

	var item DNSSyncConfig
	var pType, pName sql.NullString
	var blacklistJSON string
	var autoSyncInt, checkDomInt, isDisabledInt int
	var lastSyncAt sql.NullTime

	err := d.db.QueryRow(query, strings.TrimSpace(domain)).Scan(
		&item.ID, &item.ProviderID, &pType, &pName, &item.Domain, &item.ZoneID, &blacklistJSON, &autoSyncInt, &checkDomInt, &item.DefaultPort, &isDisabledInt, &item.CronSpec, &lastSyncAt, &item.LastSyncStatus, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	item.ProviderType = pType.String
	item.ProviderName = pName.String
	item.AutoSync = autoSyncInt == 1
	item.CheckDomain = checkDomInt == 1
	item.IsDisabled = isDisabledInt == 1
	if lastSyncAt.Valid {
		item.LastSyncAt = &lastSyncAt.Time
	}

	_ = json.Unmarshal([]byte(blacklistJSON), &item.Blacklist)
	if item.Blacklist == nil {
		item.Blacklist = []string{}
	}

	return &item, nil
}

func (d *DB) SaveDNSSyncConfig(c *DNSSyncConfig) error {
	now := time.Now().UTC()
	bBytes, _ := json.Marshal(c.Blacklist)
	if bBytes == nil {
		bBytes = []byte("[]")
	}
	autoSyncInt := 0
	if c.AutoSync {
		autoSyncInt = 1
	}
	checkDomInt := 0
	if c.CheckDomain {
		checkDomInt = 1
	}
	isDisabledInt := 0
	if c.IsDisabled {
		isDisabledInt = 1
	}
	if c.DefaultPort == "" {
		c.DefaultPort = "443"
	}

	normDom := strings.TrimRight(strings.ToLower(strings.TrimSpace(c.Domain)), ".")

	if c.ID == 0 {
		// Check existing domain
		var existingID int64
		err := d.db.QueryRow(`SELECT id FROM dns_sync_configs WHERE LOWER(domain) = LOWER(?)`, normDom).Scan(&existingID)
		if err == nil {
			c.ID = existingID
		}
	}

	if c.ID == 0 {
		res, err := d.db.Exec(`
			INSERT INTO dns_sync_configs (provider_id, domain, zone_id, blacklist, auto_sync, check_domain, default_port, is_disabled, cron_spec, last_sync_status, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ProviderID, normDom, c.ZoneID, string(bBytes), autoSyncInt, checkDomInt, c.DefaultPort, isDisabledInt, strings.TrimSpace(c.CronSpec), c.LastSyncStatus, now, now)
		if err != nil {
			return err
		}
		c.ID, _ = res.LastInsertId()
		c.CreatedAt = now
		c.UpdatedAt = now
		return nil
	}

	_, err := d.db.Exec(`
		UPDATE dns_sync_configs
		SET provider_id = ?, domain = ?, zone_id = ?, blacklist = ?, auto_sync = ?, check_domain = ?, default_port = ?, is_disabled = ?, cron_spec = ?, updated_at = ?
		WHERE id = ?`,
		c.ProviderID, normDom, c.ZoneID, string(bBytes), autoSyncInt, checkDomInt, c.DefaultPort, isDisabledInt, strings.TrimSpace(c.CronSpec), now, c.ID)
	c.UpdatedAt = now
	return err
}

func (d *DB) SetApexCronSpec(domain, cronSpec string) error {
	normDom := strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	if normDom == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	cronSpec = strings.TrimSpace(cronSpec)
	now := time.Now().UTC()

	var existingID int64
	err := d.db.QueryRow(`SELECT id FROM dns_sync_configs WHERE LOWER(domain) = LOWER(?)`, normDom).Scan(&existingID)
	if err == sql.ErrNoRows {
		_, err = d.db.Exec(`
			INSERT INTO dns_sync_configs (provider_id, domain, zone_id, blacklist, auto_sync, check_domain, default_port, is_disabled, cron_spec, last_sync_status, created_at, updated_at)
			VALUES (0, ?, '', '[]', 0, 1, '443', 0, ?, '', ?, ?)`,
			normDom, cronSpec, now, now)
		return err
	}
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`UPDATE dns_sync_configs SET cron_spec = ?, updated_at = ? WHERE id = ?`, cronSpec, now, existingID)
	return err
}

func (d *DB) DeleteDNSSyncConfig(id int64) error {
	_, err := d.db.Exec(`DELETE FROM dns_sync_configs WHERE id = ?`, id)
	return err
}

func (d *DB) UpdateDNSSyncResult(id int64, status string, syncTime time.Time) error {
	_, err := d.db.Exec(`UPDATE dns_sync_configs SET last_sync_status = ?, last_sync_at = ?, updated_at = ? WHERE id = ?`,
		status, syncTime, time.Now().UTC(), id)
	return err
}

// In-app Notifications operations

type NotificationRecord struct {
	ID         int64     `json:"id"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	Level      string    `json:"level"` // "critical", "warning", "notice", "info", "success"
	TargetHost string    `json:"target_host"`
	IsRead     bool      `json:"is_read"`
	CreatedAt  time.Time `json:"created_at"`
}

func (d *DB) AddNotification(title, content, level, targetHost string) (*NotificationRecord, error) {
	now := time.Now().UTC()
	if level == "" {
		level = "warning"
	}
	res, err := d.db.Exec(`
		INSERT INTO notifications (title, content, level, target_host, is_read, created_at)
		VALUES (?, ?, ?, ?, 0, ?)
	`, title, content, level, targetHost, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &NotificationRecord{
		ID:         id,
		Title:      title,
		Content:    content,
		Level:      level,
		TargetHost: targetHost,
		IsRead:     false,
		CreatedAt:  now,
	}, nil
}

func (d *DB) GetNotifications(limit, offset int, unreadOnly bool) ([]NotificationRecord, int, int, error) {
	var totalCount int
	var unreadCount int
	_ = d.db.QueryRow("SELECT COUNT(*) FROM notifications").Scan(&totalCount)
	_ = d.db.QueryRow("SELECT COUNT(*) FROM notifications WHERE is_read = 0").Scan(&unreadCount)

	query := "SELECT id, title, content, level, target_host, is_read, created_at FROM notifications"
	var args []interface{}
	if unreadOnly {
		query += " WHERE is_read = 0"
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	var list []NotificationRecord
	for rows.Next() {
		var n NotificationRecord
		var isReadInt int
		if err := rows.Scan(&n.ID, &n.Title, &n.Content, &n.Level, &n.TargetHost, &isReadInt, &n.CreatedAt); err != nil {
			return nil, 0, 0, err
		}
		n.IsRead = (isReadInt == 1)
		list = append(list, n)
	}
	return list, totalCount, unreadCount, rows.Err()
}

func (d *DB) MarkNotificationRead(id int64) error {
	_, err := d.db.Exec("UPDATE notifications SET is_read = 1 WHERE id = ?", id)
	return err
}

func (d *DB) MarkAllNotificationsRead() error {
	_, err := d.db.Exec("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
	return err
}

func (d *DB) DeleteNotification(id int64) error {
	_, err := d.db.Exec("DELETE FROM notifications WHERE id = ?", id)
	return err
}

func (d *DB) ClearNotifications(readOnly bool) error {
	if readOnly {
		_, err := d.db.Exec("DELETE FROM notifications WHERE is_read = 1")
		return err
	}
	_, err := d.db.Exec("DELETE FROM notifications")
	return err
}

func (d *DB) GetUnreadNotificationCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM notifications WHERE is_read = 0").Scan(&count)
	return count, err
}


