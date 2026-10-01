package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"argus/auth"
	"argus/checker"
	"argus/db"
	"argus/dns_provider"
	"argus/notifier"
	"argus/schedule"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	db                 *db.DB
	version            string
	notifierFunc       func() *notifier.Notifier
	triggerCheck       func()
	checkSingle        func(dom *db.Domain) (*db.Domain, error)
	passkeyMgr         *auth.PasskeyManager
	assets             fs.FS
	mux                *http.ServeMux
	flushAggregated    func() (int, error)
	getAggregatedCount func() int
}

func NewServer(
	database *db.DB,
	appVersion string,
	notifierGetter func() *notifier.Notifier,
	triggerCheckAll func(),
	checkSingleDomain func(dom *db.Domain) (*db.Domain, error),
	assetsFS fs.FS,
	flushAggregated func() (int, error),
	getAggregatedCount func() int,
) *Server {
	if appVersion == "" {
		appVersion = "dev"
	}
	s := &Server{
		db:                 database,
		version:            appVersion,
		notifierFunc:       notifierGetter,
		triggerCheck:       triggerCheckAll,
		checkSingle:        checkSingleDomain,
		passkeyMgr:         auth.NewPasskeyManager(),
		assets:             assetsFS,
		mux:                http.NewServeMux(),
		flushAggregated:    flushAggregated,
		getAggregatedCount: getAggregatedCount,
	}

	// 存量域名首版迁移：将已有根域名与 www 域名默认标记为置顶（仅执行一次，之后用户可自由取消置顶）
	if database.GetSetting("default_pin_initialized", "") == "" {
		if allDoms, err := database.GetAllDomains(); err == nil {
			for _, d := range allDoms {
				if checker.IsRootOrWWW(d.Host) {
					_ = database.UpdateDomainPin(d.ID, true)
				}
			}
		}
		_ = database.SetSetting("default_pin_initialized", "1")
	}

	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	// Public auth routes
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/auth/2fa/verify", s.handle2FAVerify)

	// Passkey public login ceremony
	s.mux.HandleFunc("POST /api/auth/passkey/login/start", s.handlePasskeyLoginStart)
	s.mux.HandleFunc("POST /api/auth/passkey/login/finish", s.handlePasskeyLoginFinish)

	// Protected routes
	s.mux.HandleFunc("PUT /api/auth/password", s.authMiddleware(s.handleUpdatePassword))
	s.mux.HandleFunc("POST /api/auth/2fa/setup", s.authMiddleware(s.handle2FASetup))
	s.mux.HandleFunc("POST /api/auth/2fa/enable", s.authMiddleware(s.handle2FAEnable))
	s.mux.HandleFunc("POST /api/auth/2fa/disable", s.authMiddleware(s.handle2FADisable))

	// Passkey protected registration ceremony
	s.mux.HandleFunc("POST /api/auth/passkey/register/start", s.authMiddleware(s.handlePasskeyRegisterStart))
	s.mux.HandleFunc("POST /api/auth/passkey/register/finish", s.authMiddleware(s.handlePasskeyRegisterFinish))
	s.mux.HandleFunc("GET /api/auth/passkey/list", s.authMiddleware(s.handlePasskeyList))
	s.mux.HandleFunc("DELETE /api/auth/passkey/{id}", s.authMiddleware(s.handlePasskeyDelete))

	// Domains
	s.mux.HandleFunc("GET /api/domains", s.authMiddleware(s.handleGetDomains))
	s.mux.HandleFunc("POST /api/domains", s.authMiddleware(s.handleAddDomain))
	s.mux.HandleFunc("POST /api/domains/batch-import", s.authMiddleware(s.handleBatchImportDomains))
	s.mux.HandleFunc("POST /api/domains/parse-file", s.authMiddleware(s.handleParseDNSFile))
	s.mux.HandleFunc("PUT /api/domains/{id}", s.authMiddleware(s.handleUpdateDomain))
	s.mux.HandleFunc("DELETE /api/domains/{id}", s.authMiddleware(s.handleDeleteDomain))
	s.mux.HandleFunc("POST /api/domains/{id}/pin", s.authMiddleware(s.handleTogglePinDomain))
	s.mux.HandleFunc("POST /api/domains/{id}/check", s.authMiddleware(s.handleCheckDomain))
	s.mux.HandleFunc("POST /api/check-all", s.authMiddleware(s.handleCheckAll))

	// Settings, Testing & Backup
	s.mux.HandleFunc("GET /api/settings", s.authMiddleware(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/settings", s.authMiddleware(s.handleUpdateSettings))
	s.mux.HandleFunc("POST /api/test-notification", s.authMiddleware(s.handleTestNotification))
	s.mux.HandleFunc("GET /api/backup/export", s.authMiddleware(s.handleExportBackup))
	s.mux.HandleFunc("POST /api/backup/import", s.authMiddleware(s.handleImportBackup))

	// DNS Providers & Dynamic API Sync
	s.mux.HandleFunc("GET /api/dns/providers/meta", s.authMiddleware(s.handleGetDNSProvidersMeta))
	s.mux.HandleFunc("GET /api/dns/providers", s.authMiddleware(s.handleListDNSProviders))
	s.mux.HandleFunc("POST /api/dns/providers", s.authMiddleware(s.handleSaveDNSProvider))
	s.mux.HandleFunc("DELETE /api/dns/providers/{id}", s.authMiddleware(s.handleDeleteDNSProvider))
	s.mux.HandleFunc("GET /api/dns/sync-configs", s.authMiddleware(s.handleListDNSSyncConfigs))
	s.mux.HandleFunc("POST /api/dns/sync-configs", s.authMiddleware(s.handleSaveDNSSyncConfig))
	s.mux.HandleFunc("DELETE /api/dns/sync-configs/{id}", s.authMiddleware(s.handleDeleteDNSSyncConfig))
	s.mux.HandleFunc("POST /api/dns/fetch-records", s.authMiddleware(s.handleFetchDNSRecords))
	s.mux.HandleFunc("POST /api/dns/sync-now", s.authMiddleware(s.handleSyncDNSNow))
	s.mux.HandleFunc("POST /api/apex/schedule", s.authMiddleware(s.handleSetApexSchedule))
	s.mux.HandleFunc("POST /api/apex/{apex}/check", s.authMiddleware(s.handleCheckApex))

	// Internal Notifications & History
	s.mux.HandleFunc("GET /api/notifications", s.authMiddleware(s.handleGetNotifications))
	s.mux.HandleFunc("GET /api/notifications/unread-count", s.authMiddleware(s.handleGetUnreadNotificationCount))
	s.mux.HandleFunc("POST /api/notifications/read", s.authMiddleware(s.handleMarkNotificationsRead))
	s.mux.HandleFunc("DELETE /api/notifications/{id}", s.authMiddleware(s.handleDeleteNotification))
	s.mux.HandleFunc("DELETE /api/notifications", s.authMiddleware(s.handleClearNotifications))
	s.mux.HandleFunc("POST /api/notifications/flush-batch", s.authMiddleware(s.handleFlushBatchNotifications))

	// Embedded Static Assets & SPA fallback
	fileServer := http.FileServer(http.FS(s.assets))
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || path == "index.html" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			path = "index.html"
		}

		if path == "favicon.ico" {
			if _, err := s.assets.Open("favicon.ico"); err != nil {
				if f, err := s.assets.Open("favicon.svg"); err == nil {
					f.Close()
					r.URL.Path = "/favicon.svg"
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}

		if f, err := s.assets.Open(path); err == nil {
			f.Close()
			if strings.HasSuffix(path, ".html") {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
			fileServer.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

// Helpers
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func isAppriseReachable() bool {
	conn, err := net.DialTimeout("tcp", "apprise:8000", 600*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Auth Middleware
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("argus_session")
		if err != nil || cookie.Value == "" {
			jsonError(w, http.StatusUnauthorized, "未登录或登录会话已过期")
			return
		}

		user, err := s.db.ValidateSession(cookie.Value)
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:     "argus_session",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			})
			jsonError(w, http.StatusUnauthorized, "会话已过期，请重新登录")
			return
		}

		_ = user
		next(w, r)
	}
}

// Handlers
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := s.db.HasAdmin()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	isAuthenticated := false
	username := ""
	totpEnabled := false
	var user *db.User

	if cookie, err := r.Cookie("argus_session"); err == nil && cookie.Value != "" {
		if u, err := s.db.ValidateSession(cookie.Value); err == nil {
			isAuthenticated = true
			username = u.Username
			totpEnabled = u.TOTPEnabled
			user = u
		}
	}

	// Check if passkeys exist
	hasPasskeys := false
	allPasskeys, _ := s.db.GetAllPasskeys()
	if len(allPasskeys) > 0 {
		hasPasskeys = true
	}

	// Check if turnstile clearance cookie exists
	turnstilePassed := false
	turnstileSecret := s.db.GetSetting("turnstile_secret_key", "")
	if c, err := r.Cookie("argus_cf_clearance"); err == nil && c.Value != "" {
		if auth.ValidateClearanceToken(turnstileSecret, c.Value) {
			turnstilePassed = true
		}
	}

	turnstileEnabled := s.db.GetSetting("turnstile_enabled", "false") == "true"
	turnstileSiteKey := s.db.GetSetting("turnstile_site_key", "")
	icp := s.db.GetSetting("icp", "")
	mps := s.db.GetSetting("mps", "")
	defaultTheme := s.db.GetSetting("default_theme", "auto")

	_ = user

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"has_admin":         hasAdmin,
		"is_authenticated":  isAuthenticated,
		"username":          username,
		"totp_enabled":      totpEnabled,
		"has_passkeys":      hasPasskeys,
		"turnstile_enabled": turnstileEnabled,
		"turnstile_site_key": turnstileSiteKey,
		"turnstile_passed":  turnstilePassed,
		"icp":               icp,
		"mps":               mps,
		"default_theme":     defaultTheme,
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	hasAdmin, err := s.db.HasAdmin()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hasAdmin {
		jsonError(w, http.StatusBadRequest, "系统已完成初始化，管理员已存在")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Password) < 6 {
		jsonError(w, http.StatusBadRequest, "用户名不能为空，且密码长度至少为 6 位")
		return
	}

	if err := s.db.CreateAdmin(req.Username, req.Password); err != nil {
		jsonError(w, http.StatusInternalServerError, "创建管理员失败: "+err.Error())
		return
	}

	user, err := s.db.VerifyUser(req.Username, req.Password)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "验证新用户失败")
		return
	}

	token, err := s.db.CreateSession(user.ID, 30*24*time.Hour)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(30 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": user.Username,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	// 1. Cloudflare Turnstile Verification
	turnstileEnabled := s.db.GetSetting("turnstile_enabled", "false") == "true"
	turnstileSecret := s.db.GetSetting("turnstile_secret_key", "")
	turnstileCleared := false

	if turnstileEnabled && turnstileSecret != "" {
		// Check clearance cookie first
		if c, err := r.Cookie("argus_cf_clearance"); err == nil && c.Value != "" {
			if auth.ValidateClearanceToken(turnstileSecret, c.Value) {
				turnstileCleared = true
			}
		}

		if !turnstileCleared {
			if req.TurnstileToken == "" {
				jsonError(w, http.StatusBadRequest, "请先完成人机安全验证")
				return
			}
			ok, err := auth.VerifyTurnstile(turnstileSecret, req.TurnstileToken, getClientIP(r))
			if err != nil || !ok {
				jsonError(w, http.StatusBadRequest, "人机安全验证未通过，请重试")
				return
			}
			// Mark as cleared
			turnstileCleared = true
			clearanceToken := auth.CreateClearanceToken(turnstileSecret, 10*time.Minute)
			http.SetCookie(w, &http.Cookie{
				Name:     "argus_cf_clearance",
				Value:    clearanceToken,
				Path:     "/",
				MaxAge:   600, // 10 minutes
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}

	// 2. Verify Username and Password
	user, err := s.db.VerifyUser(strings.TrimSpace(req.Username), req.Password)
	if err != nil {
		// Return 401 with turnstile_passed: true so client doesn't re-run Turnstile
		jsonResponse(w, http.StatusUnauthorized, map[string]interface{}{
			"error":            "用户名或密码错误",
			"turnstile_passed": turnstileCleared,
		})
		return
	}

	// 3. Check if 2FA (TOTP) is enabled
	if user.TOTPEnabled && user.TOTPSecret != "" {
		// Issue temporary 2FA challenge token (valid for 5 minutes)
		tempToken := fmt.Sprintf("%d:%s", user.ID, auth.GenerateRandomKey())
		s.passkeyMgr.Sessions().Save("2fa:"+tempToken, &webauthn.SessionData{
			UserID: []byte(strconv.FormatInt(user.ID, 10)),
		})

		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"need_2fa":         true,
			"temp_token":       tempToken,
			"turnstile_passed": true,
		})
		return
	}

	// 4. Log in successfully
	token, err := s.db.CreateSession(user.ID, 30*24*time.Hour)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(30 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear turnstile clearance cookie after successful login
	http.SetCookie(w, &http.Cookie{
		Name:     "argus_cf_clearance",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": user.Username,
	})
}

func (s *Server) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TempToken string `json:"temp_token"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	entry := s.passkeyMgr.Sessions().Get("2fa:" + req.TempToken)
	if entry == nil {
		jsonError(w, http.StatusBadRequest, "验证会话已过期，请重新登录")
		return
	}

	userIDStr := string(entry.UserID)
	userID, _ := strconv.ParseInt(userIDStr, 10, 64)

	admin, err := s.db.GetAdminUser()
	if err != nil || admin.ID != userID || !admin.TOTPEnabled {
		jsonError(w, http.StatusBadRequest, "用户状态异常")
		return
	}

	if !auth.ValidateTOTP(admin.TOTPSecret, req.Code) {
		jsonError(w, http.StatusBadRequest, "动态验证码错误，请重新输入")
		return
	}

	s.passkeyMgr.Sessions().Delete("2fa:" + req.TempToken)

	token, err := s.db.CreateSession(admin.ID, 30*24*time.Hour)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "创建会话失败")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(30 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": admin.Username,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("argus_session"); err == nil {
		_ = s.db.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, err := s.db.ValidateSession(cookie.Value)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "未授权")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	if len(req.NewPassword) < 6 {
		jsonError(w, http.StatusBadRequest, "新密码长度至少为 6 位")
		return
	}

	if err := s.db.UpdatePassword(user.ID, req.OldPassword, req.NewPassword); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// 2FA Admin Management
func (s *Server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "生成密钥失败")
		return
	}

	otpUri := auth.GetTOTPUri(user.Username, secret)
	jsonResponse(w, http.StatusOK, map[string]string{
		"secret":     secret,
		"otpauth_uri": otpUri,
	})
}

func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if !auth.ValidateTOTP(req.Secret, req.Code) {
		jsonError(w, http.StatusBadRequest, "输入的验证码错误，请核对后重试")
		return
	}

	if err := s.db.SetTOTP(user.ID, req.Secret, true); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存 2FA 配置失败")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// Verify current password
	if _, err := s.db.VerifyUser(user.Username, req.Password); err != nil {
		jsonError(w, http.StatusBadRequest, "管理员密码错误，无法关闭 2FA")
		return
	}

	if err := s.db.SetTOTP(user.ID, "", false); err != nil {
		jsonError(w, http.StatusInternalServerError, "更新失败")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// Passkey WebAuthn Ceremony
func (s *Server) handlePasskeyRegisterStart(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	wa, err := s.passkeyMgr.GetWebAuthnForRequest(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Load existing credentials
	records, _ := s.db.GetPasskeys(user.ID)
	var creds []webauthn.Credential
	for _, rec := range records {
		if c, err := auth.DeserializeCredential(rec.CredentialData); err == nil {
			creds = append(creds, *c)
		}
	}

	passUser := &auth.PasskeyUser{
		ID:          []byte(strconv.FormatInt(user.ID, 10)),
		Username:    user.Username,
		DisplayName: "Argus Admin",
		Credentials: creds,
	}

	options, sessionData, err := wa.BeginRegistration(passUser)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "启动 Passkey 注册失败: "+err.Error())
		return
	}

	sessKey := auth.GenerateRandomKey()
	s.passkeyMgr.Sessions().Save("pk_reg:"+sessKey, sessionData)

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_pk_reg",
		Value:    sessKey,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
	})

	jsonResponse(w, http.StatusOK, options)
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	regCookie, err := r.Cookie("argus_pk_reg")
	if err != nil || regCookie.Value == "" {
		jsonError(w, http.StatusBadRequest, "注册会话已失效")
		return
	}

	sessionData := s.passkeyMgr.Sessions().Get("pk_reg:" + regCookie.Value)
	if sessionData == nil {
		jsonError(w, http.StatusBadRequest, "注册凭证会话已超时，请重试")
		return
	}
	defer s.passkeyMgr.Sessions().Delete("pk_reg:" + regCookie.Value)

	wa, err := s.passkeyMgr.GetWebAuthnForRequest(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	passUser := &auth.PasskeyUser{
		ID:          []byte(strconv.FormatInt(user.ID, 10)),
		Username:    user.Username,
		DisplayName: "Argus Admin",
	}

	credential, err := wa.FinishRegistration(passUser, *sessionData, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Passkey 凭据校验失败: "+err.Error())
		return
	}

	credJSON, err := auth.SerializeCredential(credential)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "保存凭据数据失败")
		return
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	name := fmt.Sprintf("Passkey (%s)", time.Now().Format("2006-01-02 15:04"))

	rec, err := s.db.AddPasskey(user.ID, name, credIDStr, credJSON)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "写入数据库失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, rec)
}

func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	records, err := s.db.GetPasskeys(user.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if records == nil {
		records = []db.PasskeyRecord{}
	}
	jsonResponse(w, http.StatusOK, records)
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("argus_session")
	user, _ := s.db.ValidateSession(cookie.Value)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效 ID")
		return
	}

	if err := s.db.DeletePasskey(id, user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handlePasskeyLoginStart(w http.ResponseWriter, r *http.Request) {
	wa, err := s.passkeyMgr.GetWebAuthnForRequest(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	records, err := s.db.GetAllPasskeys()
	if err != nil || len(records) == 0 {
		jsonError(w, http.StatusBadRequest, "系统中尚未注册任何 Passkey 凭据")
		return
	}

	var allowList []protocol.CredentialDescriptor
	for _, rec := range records {
		if c, err := auth.DeserializeCredential(rec.CredentialData); err == nil {
			allowList = append(allowList, c.Descriptor())
		}
	}

	options, sessionData, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials(allowList))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "启动 Passkey 验证失败: "+err.Error())
		return
	}

	sessKey := auth.GenerateRandomKey()
	s.passkeyMgr.Sessions().Save("pk_login:"+sessKey, sessionData)

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_pk_login",
		Value:    sessKey,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
	})

	jsonResponse(w, http.StatusOK, options)
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	loginCookie, err := r.Cookie("argus_pk_login")
	if err != nil || loginCookie.Value == "" {
		jsonError(w, http.StatusBadRequest, "登录会话已失效")
		return
	}

	sessionData := s.passkeyMgr.Sessions().Get("pk_login:" + loginCookie.Value)
	if sessionData == nil {
		jsonError(w, http.StatusBadRequest, "Passkey 会话已超时，请重试")
		return
	}
	defer s.passkeyMgr.Sessions().Delete("pk_login:" + loginCookie.Value)

	wa, err := s.passkeyMgr.GetWebAuthnForRequest(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	admin, err := s.db.GetAdminUser()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "管理员用户不存在")
		return
	}

	records, _ := s.db.GetPasskeys(admin.ID)
	var creds []webauthn.Credential
	for _, rec := range records {
		if c, err := auth.DeserializeCredential(rec.CredentialData); err == nil {
			creds = append(creds, *c)
		}
	}

	passUser := &auth.PasskeyUser{
		ID:          []byte(strconv.FormatInt(admin.ID, 10)),
		Username:    admin.Username,
		DisplayName: "Argus Admin",
		Credentials: creds,
	}

	credential, err := wa.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		for _, c := range passUser.Credentials {
			if bytes.Equal(c.ID, rawID) {
				return passUser, nil
			}
		}
		return nil, fmt.Errorf("credential not recognized")
	}, *sessionData, r)

	if err != nil {
		jsonError(w, http.StatusUnauthorized, "Passkey 身份核验失败: "+err.Error())
		return
	}

	_ = credential

	token, err := s.db.CreateSession(admin.ID, 30*24*time.Hour)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "argus_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(30 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": admin.Username,
	})
}

// Domain handlers
func (s *Server) handleGetDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetAllDomains()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "获取域名列表失败: "+err.Error())
		return
	}
	if domains == nil {
		domains = []db.Domain{}
	}

	// 置顶排序：置顶目标 (IsPinned == true) 排在最前，同级按 ID 升序
	sort.SliceStable(domains, func(i, j int) bool {
		if domains[i].IsPinned != domains[j].IsPinned {
			return domains[i].IsPinned
		}
		return domains[i].ID < domains[j].ID
	})

	jsonResponse(w, http.StatusOK, domains)
}

func (s *Server) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host           string `json:"host"`
		Port           string `json:"port"`
		CheckSSL       *bool  `json:"check_ssl"`
		CheckDomain    bool   `json:"check_domain"`
		MultiHost      bool   `json:"multi_host"`
		HostsList      string `json:"hosts_list"`
		IsPinned       bool   `json:"is_pinned"`
		NotifyDisabled bool   `json:"notify_disabled"`
		CronSpec       string `json:"cron_spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		jsonError(w, http.StatusBadRequest, "域名或主机地址不能为空")
		return
	}

	req.Host = strings.TrimPrefix(req.Host, "https://")
	req.Host = strings.TrimPrefix(req.Host, "http://")
	req.Host = strings.TrimRight(req.Host, "/")

	if req.Port == "" {
		req.Port = "443"
	}

	checkSSL := true
	if req.CheckSSL != nil {
		checkSSL = *req.CheckSSL
	}

	if !checkSSL && !req.CheckDomain {
		jsonError(w, http.StatusBadRequest, "请至少开启 SSL 证书检查或域名过期检查其中一项")
		return
	}

	req.CronSpec = strings.TrimSpace(req.CronSpec)
	if req.CronSpec != "" {
		if err := schedule.ValidateSpec(req.CronSpec); err != nil {
			jsonError(w, http.StatusBadRequest, "巡检计划格式错误: "+err.Error())
			return
		}
	}

	dom, err := s.db.AddDomain(req.Host, req.Port, checkSSL, req.CheckDomain, req.MultiHost, req.HostsList, req.IsPinned, req.NotifyDisabled, req.CronSpec)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "添加域名失败（可能已存在该域名）: "+err.Error())
		return
	}

	go func(d *db.Domain) {
		if s.checkSingle != nil {
			_, _ = s.checkSingle(d)
		}
	}(dom)

	jsonResponse(w, http.StatusCreated, dom)
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效的域名 ID")
		return
	}

	currentDom, err := s.db.GetDomainByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "目标域名不存在")
		return
	}

	var req struct {
		Host           string  `json:"host"`
		Port           string  `json:"port"`
		CheckSSL       *bool   `json:"check_ssl"`
		CheckDomain    *bool   `json:"check_domain"`
		MultiHost      bool    `json:"multi_host"`
		HostsList      string  `json:"hosts_list"`
		IsPinned       *bool   `json:"is_pinned"`
		NotifyDisabled *bool   `json:"notify_disabled"`
		CronSpec       *string `json:"cron_spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		jsonError(w, http.StatusBadRequest, "域名不能为空")
		return
	}
	req.Host = strings.TrimPrefix(req.Host, "https://")
	req.Host = strings.TrimPrefix(req.Host, "http://")
	req.Host = strings.TrimRight(req.Host, "/")

	if req.Port == "" {
		req.Port = "443"
	}

	checkSSL := currentDom.CheckSSL
	if req.CheckSSL != nil {
		checkSSL = *req.CheckSSL
	}

	checkDomain := currentDom.CheckDomain
	if req.CheckDomain != nil {
		checkDomain = *req.CheckDomain
	}

	if !checkSSL && !checkDomain {
		jsonError(w, http.StatusBadRequest, "请至少开启 SSL 证书检查或域名过期检查其中一项")
		return
	}

	isPinned := currentDom.IsPinned
	if req.IsPinned != nil {
		isPinned = *req.IsPinned
	}

	notifyDisabled := currentDom.NotifyDisabled
	if req.NotifyDisabled != nil {
		notifyDisabled = *req.NotifyDisabled
	}

	cronSpec := currentDom.CronSpec
	if req.CronSpec != nil {
		trimmed := strings.TrimSpace(*req.CronSpec)
		if trimmed != "" {
			if err := schedule.ValidateSpec(trimmed); err != nil {
				jsonError(w, http.StatusBadRequest, "巡检计划格式错误: "+err.Error())
				return
			}
		}
		cronSpec = trimmed
	}

	if err := s.db.UpdateDomain(id, req.Host, req.Port, checkSSL, checkDomain, req.MultiHost, req.HostsList, isPinned, notifyDisabled, cronSpec); err != nil {
		jsonError(w, http.StatusInternalServerError, "更新域名失败: "+err.Error())
		return
	}

	dom, err := s.db.GetDomainByID(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	go func(d *db.Domain) {
		if s.checkSingle != nil {
			_, _ = s.checkSingle(d)
		}
	}(dom)

	jsonResponse(w, http.StatusOK, dom)
}

func (s *Server) handleTogglePinDomain(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效的域名 ID")
		return
	}

	pinned, err := s.db.ToggleDomainPin(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "切换置顶状态失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"is_pinned": pinned,
	})
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效的域名 ID")
		return
	}

	if err := s.db.DeleteDomain(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleCheckDomain(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效的域名 ID")
		return
	}

	dom, err := s.db.GetDomainByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "未找到目标域名")
		return
	}

	if s.checkSingle == nil {
		jsonError(w, http.StatusInternalServerError, "检测处理器未注册")
		return
	}

	updated, err := s.checkSingle(dom)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "检测执行失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, updated)
}

func (s *Server) handleCheckAll(w http.ResponseWriter, r *http.Request) {
	if s.triggerCheck != nil {
		go s.triggerCheck()
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "全量巡检任务已触发并在后台运行"})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	interval := s.db.GetSetting("interval", "12h")
	timeout := s.db.GetSetting("timeout", "10s")
	thresholdStr := s.db.GetSetting("threshold_days", "15")
	threshold, _ := strconv.Atoi(thresholdStr)
	if threshold <= 0 {
		threshold = 15
	}
	alertThresholds := s.db.GetSetting("alert_thresholds", "30,15,10,7,5,3,1")
	alertRuleMode := s.db.GetSetting("alert_rule_mode", "tier_once")

	notificationMode := s.db.GetSetting("notification_mode", "realtime")
	notificationBatchInterval := s.db.GetSetting("notification_batch_interval", "1h")
	pendingAggregated := 0
	if s.getAggregatedCount != nil {
		pendingAggregated = s.getAggregatedCount()
	}

	shoutrrrRaw := s.db.GetSetting("shoutrrr_urls", "[]")
	var shoutrrrURLs []string
	_ = json.Unmarshal([]byte(shoutrrrRaw), &shoutrrrURLs)

	appriseAvailable := isAppriseReachable()
	appriseEnabled := s.db.GetSetting("apprise_enabled", "false") == "true"
	if !appriseAvailable {
		appriseEnabled = false
	}
	appriseAPIURL := s.db.GetSetting("apprise_api_url", "http://apprise:8000/notify")
	appriseRaw := s.db.GetSetting("apprise_urls", "[]")
	var appriseURLs []string
	_ = json.Unmarshal([]byte(appriseRaw), &appriseURLs)

	turnstileEnabled := s.db.GetSetting("turnstile_enabled", "false") == "true"
	turnstileSiteKey := s.db.GetSetting("turnstile_site_key", "")
	turnstileSecretKey := s.db.GetSetting("turnstile_secret_key", "")
	icp := s.db.GetSetting("icp", "")
	mps := s.db.GetSetting("mps", "")
	defaultTheme := s.db.GetSetting("default_theme", "auto")

	settings := map[string]interface{}{
		"version":                     s.version,
		"interval":                    interval,
		"threshold_days":              threshold,
		"alert_thresholds":            alertThresholds,
		"alert_rule_mode":             alertRuleMode,
		"timeout":                     timeout,
		"notification_mode":           notificationMode,
		"notification_batch_interval": notificationBatchInterval,
		"pending_aggregated":          pendingAggregated,
		"shoutrrr_urls":               shoutrrrURLs,
		"apprise_available":           appriseAvailable,
		"apprise_enabled":             appriseEnabled,
		"apprise_api_url":             appriseAPIURL,
		"apprise_urls":                appriseURLs,
		"turnstile_enabled":           turnstileEnabled,
		"turnstile_site_key":          turnstileSiteKey,
		"turnstile_secret_key":        turnstileSecretKey,
		"icp":                         icp,
		"mps":                         mps,
		"default_theme":               defaultTheme,
	}
	jsonResponse(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interval                  string   `json:"interval"`
		ThresholdDays             int      `json:"threshold_days"`
		AlertThresholds           string   `json:"alert_thresholds"`
		AlertRuleMode             string   `json:"alert_rule_mode"`
		Timeout                   string   `json:"timeout"`
		NotificationMode          string   `json:"notification_mode"`
		NotificationBatchInterval string   `json:"notification_batch_interval"`
		ShoutrrrURLs              []string `json:"shoutrrr_urls"`
		AppriseEnabled            bool     `json:"apprise_enabled"`
		AppriseAPIURL             string   `json:"apprise_api_url"`
		AppriseURLs               []string `json:"apprise_urls"`
		TurnstileEnabled          bool     `json:"turnstile_enabled"`
		TurnstileSiteKey          string   `json:"turnstile_site_key"`
		TurnstileSecretKey        string   `json:"turnstile_secret_key"`
		ICP                       string   `json:"icp"`
		MPS                       string   `json:"mps"`
		DefaultTheme              string   `json:"default_theme"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析错误")
		return
	}

	if req.Interval == "" {
		req.Interval = "12h"
	}
	if _, err := time.ParseDuration(req.Interval); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("无效的巡检周期格式 %q (例如: 1h, 12h, 24h)", req.Interval))
		return
	}

	if req.Timeout == "" {
		req.Timeout = "10s"
	}
	if _, err := time.ParseDuration(req.Timeout); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("无效的超时时间格式 %q (例如: 5s, 10s)", req.Timeout))
		return
	}

	if req.ThresholdDays <= 0 {
		req.ThresholdDays = 15
	}
	if req.AlertThresholds == "" {
		req.AlertThresholds = "30,15,10,7,5,3,1"
	}

	if req.AlertRuleMode != "" {
		if req.AlertRuleMode != "tier_once" && req.AlertRuleMode != "daily" {
			req.AlertRuleMode = "tier_once"
		}
		_ = s.db.SetSetting("alert_rule_mode", req.AlertRuleMode)
	}

	if req.NotificationMode != "" {
		if req.NotificationMode != "realtime" && req.NotificationMode != "batch" {
			req.NotificationMode = "realtime"
		}
		_ = s.db.SetSetting("notification_mode", req.NotificationMode)
	}
	if req.NotificationBatchInterval != "" {
		if _, err := time.ParseDuration(req.NotificationBatchInterval); err == nil {
			_ = s.db.SetSetting("notification_batch_interval", req.NotificationBatchInterval)
		}
	}

	shoutrrrJSON, _ := json.Marshal(req.ShoutrrrURLs)
	appriseJSON, _ := json.Marshal(req.AppriseURLs)

	_ = s.db.SetSetting("interval", req.Interval)
	_ = s.db.SetSetting("threshold_days", strconv.Itoa(req.ThresholdDays))
	_ = s.db.SetSetting("alert_thresholds", req.AlertThresholds)
	_ = s.db.SetSetting("timeout", req.Timeout)
	_ = s.db.SetSetting("shoutrrr_urls", string(shoutrrrJSON))
	_ = s.db.SetSetting("apprise_enabled", strconv.FormatBool(req.AppriseEnabled))
	_ = s.db.SetSetting("apprise_api_url", req.AppriseAPIURL)
	_ = s.db.SetSetting("apprise_urls", string(appriseJSON))
	_ = s.db.SetSetting("turnstile_enabled", strconv.FormatBool(req.TurnstileEnabled))
	_ = s.db.SetSetting("turnstile_site_key", strings.TrimSpace(req.TurnstileSiteKey))
	if req.TurnstileSecretKey != "" {
		_ = s.db.SetSetting("turnstile_secret_key", strings.TrimSpace(req.TurnstileSecretKey))
	}
	_ = s.db.SetSetting("icp", strings.TrimSpace(req.ICP))
	_ = s.db.SetSetting("mps", strings.TrimSpace(req.MPS))
	if req.DefaultTheme != "" {
		_ = s.db.SetSetting("default_theme", strings.TrimSpace(req.DefaultTheme))
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

type TestNotificationRequest struct {
	URL string `json:"url"` // 可选，若指定则仅对该单个 URL 进行独立测试
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	n := s.notifierFunc()
	if n == nil {
		jsonError(w, http.StatusInternalServerError, "通知组件未就绪")
		return
	}

	var req TestNotificationRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	title := "[Argus 测试通知] 监控告警链路测试"
	body := fmt.Sprintf("这是一条来自 Argus 的测试通知。\n发送时间: %s\n如果您收到此消息，说明此告警渠道配置有效。",
		time.Now().Format("2006-01-02 15:04:05"))

	// 记录系统内部测试消息通知
	_, _ = s.db.AddNotification(title, body, "info", "系统测试")

	singleURL := strings.TrimSpace(req.URL)
	if singleURL != "" {
		if err := n.SendSingle(singleURL, title, body); err != nil {
			jsonError(w, http.StatusInternalServerError, fmt.Sprintf("测试发送失败: %v", err))
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{
			"message": "测试通知已成功推送到该渠道",
		})
		return
	}

	count := n.ChannelCount()
	if count == 0 {
		jsonError(w, http.StatusBadRequest, "当前未配置任何有效的通知渠道，请先在“通知渠道”中添加配置并保存")
		return
	}

	err := n.Send(title, body)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("发送失败: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("测试通知已成功推送到 %d 个已配置的通知渠道", count),
	})
}

func (s *Server) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
	}
	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	unreadOnly := false
	if u := r.URL.Query().Get("unread_only"); u == "true" || u == "1" {
		unreadOnly = true
	}

	list, total, unreadCount, err := s.db.GetNotifications(limit, offset, unreadOnly)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "获取通知列表失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"list":         list,
		"total":        total,
		"unread_count": unreadCount,
	})
}

func (s *Server) handleGetUnreadNotificationCount(w http.ResponseWriter, r *http.Request) {
	unreadCount, _ := s.db.GetUnreadNotificationCount()
	pendingAggregated := 0
	if s.getAggregatedCount != nil {
		pendingAggregated = s.getAggregatedCount()
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"unread_count":       unreadCount,
		"pending_aggregated": pendingAggregated,
	})
}

func (s *Server) handleMarkNotificationsRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  int64 `json:"id"`
		All bool  `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "参数解析失败")
		return
	}

	if req.All {
		if err := s.db.MarkAllNotificationsRead(); err != nil {
			jsonError(w, http.StatusInternalServerError, "更新失败: "+err.Error())
			return
		}
	} else if req.ID > 0 {
		if err := s.db.MarkNotificationRead(req.ID); err != nil {
			jsonError(w, http.StatusInternalServerError, "更新失败: "+err.Error())
			return
		}
	}

	unreadCount, _ := s.db.GetUnreadNotificationCount()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"unread_count": unreadCount,
	})
}

func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "无效的通知ID")
		return
	}
	if err := s.db.DeleteNotification(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}
	unreadCount, _ := s.db.GetUnreadNotificationCount()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"unread_count": unreadCount,
	})
}

func (s *Server) handleClearNotifications(w http.ResponseWriter, r *http.Request) {
	readOnly := r.URL.Query().Get("read_only") == "true"
	if err := s.db.ClearNotifications(readOnly); err != nil {
		jsonError(w, http.StatusInternalServerError, "清空失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"unread_count": 0,
	})
}

func (s *Server) handleFlushBatchNotifications(w http.ResponseWriter, r *http.Request) {
	if s.flushAggregated == nil {
		jsonError(w, http.StatusBadRequest, "当前未启用或未配置合并通知汇总推送")
		return
	}
	count, err := s.flushAggregated()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("执行合并推送失败: %v", err))
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   count,
		"message": fmt.Sprintf("已成功合并推送 %d 项待处理告警", count),
	})
}

// Batch Import Domains
type BatchImportRequest struct {
	Content     string `json:"content"`
	Mode        string `json:"mode"`         // "auto", "all", "none"
	DefaultPort string `json:"default_port"` // default "443"
}

func (s *Server) handleBatchImportDomains(w http.ResponseWriter, r *http.Request) {
	var req BatchImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	lines := strings.Split(req.Content, "\n")
	var items []db.DomainImportItem
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip schemes
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")
		if idx := strings.Index(line, "/"); idx != -1 {
			line = line[:idx]
		}
		port := strings.TrimSpace(req.DefaultPort)
		if port == "" {
			port = "443"
		}
		host := line
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			host = parts[0]
			if len(parts) > 1 && parts[1] != "" {
				port = parts[1]
			}
		}
		host = strings.TrimSpace(strings.ToLower(host))
		host = strings.TrimRight(host, ".")
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true

		isPinned := checker.IsRootOrWWW(host)
		checkSSL := true
		checkDomain := false
		switch req.Mode {
		case "all":
			checkDomain = true
		case "none":
			checkDomain = false
		case "domain-only":
			checkDomain = true
			checkSSL = false
		default: // "auto"
			checkDomain = checker.IsApexDomain(host)
		}

		bCheckSSL := checkSSL
		items = append(items, db.DomainImportItem{
			Host:        host,
			Port:        port,
			CheckSSL:    &bCheckSSL,
			CheckDomain: checkDomain,
			IsPinned:    isPinned,
		})
	}

	if len(items) == 0 {
		jsonError(w, http.StatusBadRequest, "未找到有效的域名，请在文本框中输入，每行一个域名")
		return
	}

	res, err := s.db.BatchAddDomains(items)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "批量导入执行失败: "+err.Error())
		return
	}

	// Trigger async check for newly added domains
	if len(res.NewIDs) > 0 {
		go func(ids []int64) {
			for _, id := range ids {
				dom, err := s.db.GetDomainByID(id)
				if err == nil {
					_, _ = s.checkSingle(dom)
				}
			}
		}(res.NewIDs)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"total":   res.Total,
		"added":   res.Added,
		"skipped": res.Skipped,
		"message": fmt.Sprintf("批量导入完成：成功添加 %d 个新目标，跳过 %d 个已有域名", res.Added, res.Skipped),
	})
}

// Parse DNS Export File
func (s *Server) handleParseDNSFile(w http.ResponseWriter, r *http.Request) {
	var filename string
	var data []byte

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB limit
			jsonError(w, http.StatusBadRequest, "文件上传解析失败: "+err.Error())
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			jsonError(w, http.StatusBadRequest, "未找到上传的文件")
			return
		}
		defer file.Close()
		filename = header.Filename
		content, err := io.ReadAll(file)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "读取上传文件失败: "+err.Error())
			return
		}
		data = content
	} else {
		filename = r.URL.Query().Get("filename")
		content, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "读取文件内容失败: "+err.Error())
			return
		}
		data = content
	}

	if len(data) == 0 {
		jsonError(w, http.StatusBadRequest, "上传的文件内容为空")
		return
	}

	result, err := checker.ParseDNSExportFile(filename, data)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "文件解析失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, result)
}

// Backup & Export / Import
type BackupFile struct {
	Version    string                `json:"version"`
	ExportTime time.Time             `json:"export_time"`
	Domains    []db.DomainImportItem `json:"domains"`
	Settings   map[string]string     `json:"settings"`
}

func (s *Server) handleExportBackup(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	now := time.Now()
	timeTag := now.Format("20060102-150405")

	domains, err := s.db.GetAllDomains()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "读取监控域名失败: "+err.Error())
		return
	}

	if format == "txt" {
		var lines []string
		for _, d := range domains {
			if d.Port == "443" || d.Port == "" {
				lines = append(lines, d.Host)
			} else {
				lines = append(lines, fmt.Sprintf("%s:%s", d.Host, d.Port))
			}
		}
		filename := fmt.Sprintf("argus-domains-%s.txt", timeTag)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
		return
	}

	settings, err := s.db.GetAllSettings()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "读取系统配置失败: "+err.Error())
		return
	}

	var backupDomains []db.DomainImportItem
	for _, d := range domains {
		checkSSL := d.CheckSSL
		backupDomains = append(backupDomains, db.DomainImportItem{
			Host:           d.Host,
			Port:           d.Port,
			CheckSSL:       &checkSSL,
			CheckDomain:    d.CheckDomain,
			MultiHost:      d.MultiHost,
			HostsList:      d.HostsList,
			IsPinned:       d.IsPinned,
			NotifyDisabled: d.NotifyDisabled,
			CronSpec:       d.CronSpec,
		})
	}

	backup := BackupFile{
		Version:    s.version,
		ExportTime: now.UTC(),
		Domains:    backupDomains,
		Settings:   settings,
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "生成备份文件失败: "+err.Error())
		return
	}

	filename := fmt.Sprintf("argus-backup-%s.json", timeTag)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	_, _ = w.Write(data)
}

type ImportBackupRequest struct {
	RestoreDomains  bool       `json:"restore_domains"`
	RestoreSettings bool       `json:"restore_settings"`
	Data            BackupFile `json:"data"`
}

func (s *Server) handleImportBackup(w http.ResponseWriter, r *http.Request) {
	var req ImportBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "解析备份数据失败: "+err.Error())
		return
	}

	addedDomains := 0
	skippedDomains := 0
	restoredSettings := 0

	// 1. Restore domains
	if req.RestoreDomains && len(req.Data.Domains) > 0 {
		res, err := s.db.BatchAddDomains(req.Data.Domains)
		if err == nil {
			addedDomains = res.Added
			skippedDomains = res.Skipped
			if len(res.NewIDs) > 0 {
				go func(ids []int64) {
					for _, id := range ids {
						dom, err := s.db.GetDomainByID(id)
						if err == nil {
							_, _ = s.checkSingle(dom)
						}
					}
				}(res.NewIDs)
			}
		}
	}

	// 2. Restore settings
	if req.RestoreSettings && len(req.Data.Settings) > 0 {
		allowedKeys := map[string]bool{
			"interval":             true,
			"threshold_days":       true,
			"alert_thresholds":     true,
			"alert_rule_mode":      true,
			"timeout":              true,
			"shoutrrr_urls":        true,
			"apprise_enabled":      true,
			"apprise_api_url":      true,
			"apprise_urls":         true,
			"turnstile_enabled":    true,
			"turnstile_site_key":   true,
			"turnstile_secret_key": true,
		}
		for k, v := range req.Data.Settings {
			if allowedKeys[k] {
				_ = s.db.SetSetting(k, v)
				restoredSettings++
			}
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"domains_added":     addedDomains,
		"domains_skipped":   skippedDomains,
		"settings_restored": restoredSettings,
		"message": fmt.Sprintf("备份恢复成功：导入 %d 个新域名 (跳过 %d 个已有目标)，恢复 %d 项系统配置",
			addedDomains, skippedDomains, restoredSettings),
	})
}

// -------------------------------------------------------------
// DNS Providers & Dynamic API Sync Handlers
// -------------------------------------------------------------

func (s *Server) handleGetDNSProvidersMeta(w http.ResponseWriter, r *http.Request) {
	metas := dns_provider.ListProviders()
	jsonResponse(w, http.StatusOK, metas)
}

func (s *Server) handleListDNSProviders(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListDNSProviders()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "获取 DNS 凭据失败: "+err.Error())
		return
	}

	// 敏感信息脱敏处理
	type safeProvider struct {
		ID           int64     `json:"id"`
		Name         string    `json:"name"`
		ProviderType string    `json:"provider_type"`
		AuthKeyMask  string    `json:"auth_key_mask"`
		HasSecret    bool      `json:"has_secret"`
		Extra        string    `json:"extra,omitempty"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
	}

	res := make([]safeProvider, 0, len(list))
	for _, p := range list {
		maskedKey := p.AuthKey
		if len(maskedKey) > 8 {
			maskedKey = maskedKey[:4] + "****" + maskedKey[len(maskedKey)-4:]
		} else if len(maskedKey) > 0 {
			maskedKey = "****"
		}
		res = append(res, safeProvider{
			ID:           p.ID,
			Name:         p.Name,
			ProviderType: p.ProviderType,
			AuthKeyMask:  maskedKey,
			HasSecret:    p.AuthSecret != "",
			Extra:        p.Extra,
			CreatedAt:    p.CreatedAt,
			UpdatedAt:    p.UpdatedAt,
		})
	}

	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleSaveDNSProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		ProviderType string `json:"provider_type"`
		AuthKey      string `json:"auth_key"`
		AuthSecret   string `json:"auth_secret"`
		Extra        string `json:"extra"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.ProviderType = strings.TrimSpace(req.ProviderType)
	if req.Name == "" || req.ProviderType == "" {
		jsonError(w, http.StatusBadRequest, "凭据名称与 DNS 厂商类型不能为空")
		return
	}

	var p db.DNSProviderAccount
	if req.ID > 0 {
		old, err := s.db.GetDNSProviderByID(req.ID)
		if err != nil {
			jsonError(w, http.StatusNotFound, "未找到指定的 DNS 凭据")
			return
		}
		p = *old
	}

	p.Name = req.Name
	p.ProviderType = req.ProviderType
	p.Extra = req.Extra

	// 如果传入了新的非脱敏 Key/Secret 则更新，否则保留原有
	if req.AuthKey != "" && !strings.Contains(req.AuthKey, "****") {
		p.AuthKey = strings.TrimSpace(req.AuthKey)
	}
	if req.AuthSecret != "" && !strings.Contains(req.AuthSecret, "****") {
		p.AuthSecret = strings.TrimSpace(req.AuthSecret)
	}

	if p.AuthKey == "" {
		jsonError(w, http.StatusBadRequest, "API Key / Token 不能为空")
		return
	}

	if err := s.db.SaveDNSProvider(&p); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存 DNS 凭据失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"id":      p.ID,
		"message": "DNS 接口凭据保存成功",
	})
}

func (s *Server) handleDeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, http.StatusBadRequest, "无效的凭据 ID")
		return
	}

	if err := s.db.DeleteDNSProvider(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleListDNSSyncConfigs(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListDNSSyncConfigs()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "获取动态同步规则列表失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, list)
}

func (s *Server) handleSaveDNSSyncConfig(w http.ResponseWriter, r *http.Request) {
	var c db.DNSSyncConfig
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	c.Domain = strings.TrimRight(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	if c.Domain == "" {
		jsonError(w, http.StatusBadRequest, "主域名不能为空")
		return
	}

	c.CronSpec = strings.TrimSpace(c.CronSpec)
	if c.CronSpec != "" {
		if err := schedule.ValidateSpec(c.CronSpec); err != nil {
			jsonError(w, http.StatusBadRequest, "巡检计划格式错误: "+err.Error())
			return
		}
	}

	if c.AutoSync && c.ProviderID <= 0 {
		jsonError(w, http.StatusBadRequest, "开启后台定时自动同步时必须选择关联的 DNS 账号凭据")
		return
	}

	if err := s.db.SaveDNSSyncConfig(&c); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存同步规则失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"id":      c.ID,
		"message": "主域名配置与任务计划已保存",
	})
}

func (s *Server) handleSetApexSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		CronSpec string `json:"cron_spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	req.Domain = strings.TrimRight(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if req.Domain == "" {
		jsonError(w, http.StatusBadRequest, "主域名不能为空")
		return
	}
	req.CronSpec = strings.TrimSpace(req.CronSpec)
	if req.CronSpec != "" {
		if err := schedule.ValidateSpec(req.CronSpec); err != nil {
			jsonError(w, http.StatusBadRequest, "巡检计划格式错误: "+err.Error())
			return
		}
	}
	if err := s.db.SetApexCronSpec(req.Domain, req.CronSpec); err != nil {
		jsonError(w, http.StatusInternalServerError, "保存主域名巡检计划失败: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "已更新主域名巡检计划",
	})
}

func (s *Server) handleCheckApex(w http.ResponseWriter, r *http.Request) {
	apex := r.PathValue("apex")
	if apex == "" {
		apex = r.URL.Query().Get("apex")
	}
	apex = strings.TrimRight(strings.ToLower(strings.TrimSpace(apex)), ".")
	if apex == "" {
		jsonError(w, http.StatusBadRequest, "主域名不能为空")
		return
	}

	res, err := s.RunApexCheckAndSync(apex)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "执行主域名巡检失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleDeleteDNSSyncConfig(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, http.StatusBadRequest, "无效的同步规则 ID")
		return
	}

	if err := s.db.DeleteDNSSyncConfig(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "删除失败: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]bool{"success": true})
}

// FetchDNSRecordsRequest parameters for previewing or syncing DNS records
type FetchDNSRecordsRequest struct {
	ProviderID   int64             `json:"provider_id"`
	ProviderType string            `json:"provider_type"`
	AuthKey      string            `json:"auth_key"`
	AuthSecret   string            `json:"auth_secret"`
	ZoneID       string            `json:"zone_id"`
	Extra        map[string]string `json:"extra"`
	Domain       string            `json:"domain"`
	Blacklist    []string          `json:"blacklist"`
}

func (s *Server) resolveProviderConfig(req *FetchDNSRecordsRequest) (dns_provider.ProviderConfig, error) {
	cfg := dns_provider.ProviderConfig{
		ProviderType: req.ProviderType,
		AuthKey:      req.AuthKey,
		AuthSecret:   req.AuthSecret,
		ZoneID:       req.ZoneID,
		Extra:        req.Extra,
	}

	if req.ProviderID > 0 {
		p, err := s.db.GetDNSProviderByID(req.ProviderID)
		if err != nil {
			return cfg, fmt.Errorf("找不到指定的 DNS 凭据 (ID: %d)", req.ProviderID)
		}
		cfg.ProviderType = p.ProviderType
		if cfg.AuthKey == "" || strings.Contains(cfg.AuthKey, "****") {
			cfg.AuthKey = p.AuthKey
		}
		if cfg.AuthSecret == "" || strings.Contains(cfg.AuthSecret, "****") {
			cfg.AuthSecret = p.AuthSecret
		}
	}

	if cfg.ProviderType == "" {
		return cfg, fmt.Errorf("请选择 DNS 厂商类型")
	}
	if cfg.AuthKey == "" {
		return cfg, fmt.Errorf("API 访问凭据 (Token/Key) 不能为空")
	}

	return cfg, nil
}

// Preview DNS Records from API and test blacklist filtering
func (s *Server) handleFetchDNSRecords(w http.ResponseWriter, r *http.Request) {
	var req FetchDNSRecordsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	domain := strings.TrimRight(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if domain == "" {
		jsonError(w, http.StatusBadRequest, "目标主域名不能为空")
		return
	}

	cfg, err := s.resolveProviderConfig(&req)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	provider, err := dns_provider.GetProvider(cfg.ProviderType)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	records, err := provider.FetchRecords(ctx, cfg, domain)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "从 DNS API 拉取解析记录失败: "+err.Error())
		return
	}

	// 提取全部子域名并去重
	var rawNames []string
	seen := make(map[string]bool)
	for _, rec := range records {
		norm := dns_provider.NormalizeDomainName(rec.Name, domain)
		if norm != "" && !seen[norm] {
			seen[norm] = true
			rawNames = append(rawNames, norm)
		}
	}

	// 结合黑名单过滤
	allowed, blocked := dns_provider.FilterBlacklist(rawNames, domain, req.Blacklist)
	sort.Strings(allowed)
	sort.Strings(blocked)

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"total_records":   len(records),
		"extracted_count": len(rawNames),
		"allowed_count":   len(allowed),
		"blocked_count":   len(blocked),
		"allowed_domains": allowed,
		"blocked_domains": blocked,
		"records":         records,
	})
}

// Sync DNS Records and import directly into Argus monitoring
func (s *Server) handleSyncDNSNow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SyncConfigID int64                  `json:"sync_config_id"`
		FetchParams  FetchDNSRecordsRequest `json:"fetch_params"`
		CheckSSL     *bool                  `json:"check_ssl"`
		CheckDomain  bool                   `json:"check_domain"`
		DefaultPort  string                 `json:"default_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "请求参数解析失败")
		return
	}

	var syncConf *db.DNSSyncConfig
	if req.SyncConfigID > 0 {
		c, err := s.db.GetDNSSyncConfigByID(req.SyncConfigID)
		if err == nil {
			syncConf = c
			req.FetchParams.ProviderID = c.ProviderID
			req.FetchParams.Domain = c.Domain
			req.FetchParams.ZoneID = c.ZoneID
			req.FetchParams.Blacklist = c.Blacklist
			req.CheckDomain = c.CheckDomain
			if req.DefaultPort == "" {
				req.DefaultPort = c.DefaultPort
			}
		}
	}

	domain := strings.TrimRight(strings.ToLower(strings.TrimSpace(req.FetchParams.Domain)), ".")
	if domain == "" {
		jsonError(w, http.StatusBadRequest, "目标主域名不能为空")
		return
	}

	cfg, err := s.resolveProviderConfig(&req.FetchParams)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	provider, err := dns_provider.GetProvider(cfg.ProviderType)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	records, err := provider.FetchRecords(ctx, cfg, domain)
	if err != nil {
		if syncConf != nil {
			_ = s.db.UpdateDNSSyncResult(syncConf.ID, "拉取失败: "+err.Error(), time.Now().UTC())
		}
		jsonError(w, http.StatusBadRequest, "从 DNS API 拉取解析失败: "+err.Error())
		return
	}

	var rawNames []string
	seen := make(map[string]bool)
	for _, rec := range records {
		norm := dns_provider.NormalizeDomainName(rec.Name, domain)
		if norm != "" && !seen[norm] {
			seen[norm] = true
			rawNames = append(rawNames, norm)
		}
	}

	allowed, blocked := dns_provider.FilterBlacklist(rawNames, domain, req.FetchParams.Blacklist)

	port := strings.TrimSpace(req.DefaultPort)
	if port == "" {
		port = "443"
	}

	bCheckSSL := true
	if req.CheckSSL != nil {
		bCheckSSL = *req.CheckSSL
	}

	var items []db.DomainImportItem
	for _, dom := range allowed {
		isPinned := checker.IsRootOrWWW(dom)
		items = append(items, db.DomainImportItem{
			Host:        dom,
			Port:        port,
			CheckSSL:    &bCheckSSL,
			CheckDomain: req.CheckDomain,
			IsPinned:    isPinned,
		})
	}

	res, err := s.db.BatchAddDomains(items)
	if err != nil {
		if syncConf != nil {
			_ = s.db.UpdateDNSSyncResult(syncConf.ID, "导入失败: "+err.Error(), time.Now().UTC())
		}
		jsonError(w, http.StatusInternalServerError, "导入监控目标失败: "+err.Error())
		return
	}

	if len(res.NewIDs) > 0 {
		go func(ids []int64) {
			for _, id := range ids {
				dom, err := s.db.GetDomainByID(id)
				if err == nil {
					_, _ = s.checkSingle(dom)
				}
			}
		}(res.NewIDs)
	}

	statusMsg := fmt.Sprintf("同步成功：新增 %d 个目标，跳过 %d 个已有目标，黑名单过滤 %d 个子域名", res.Added, res.Skipped, len(blocked))
	if syncConf != nil {
		_ = s.db.UpdateDNSSyncResult(syncConf.ID, statusMsg, time.Now().UTC())
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"total_fetched":   len(rawNames),
		"allowed_count":   len(allowed),
		"blocked_count":   len(blocked),
		"added":           res.Added,
		"skipped":         res.Skipped,
		"blocked_domains": blocked,
		"message":         statusMsg,
	})
}

// SyncDNSTasksForConfig runs DNS pull and auto-import for a single DNS sync config
func (s *Server) SyncDNSTasksForConfig(c *db.DNSSyncConfig) (*db.BatchImportResult, error) {
	if c.IsDisabled || c.ProviderID <= 0 {
		return &db.BatchImportResult{}, nil
	}

	p, err := s.db.GetDNSProviderByID(c.ProviderID)
	if err != nil {
		errMsg := "未找到关联的凭据"
		_ = s.db.UpdateDNSSyncResult(c.ID, errMsg, time.Now().UTC())
		return nil, fmt.Errorf(errMsg)
	}

	provider, err := dns_provider.GetProvider(p.ProviderType)
	if err != nil {
		errMsg := "不支持的厂商类型"
		_ = s.db.UpdateDNSSyncResult(c.ID, errMsg, time.Now().UTC())
		return nil, fmt.Errorf(errMsg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	records, err := provider.FetchRecords(ctx, dns_provider.ProviderConfig{
		ProviderType: p.ProviderType,
		AuthKey:      p.AuthKey,
		AuthSecret:   p.AuthSecret,
		ZoneID:       c.ZoneID,
	}, c.Domain)
	cancel()

	if err != nil {
		errMsg := "自动拉取失败: " + err.Error()
		_ = s.db.UpdateDNSSyncResult(c.ID, errMsg, time.Now().UTC())
		return nil, fmt.Errorf(errMsg)
	}

	var rawNames []string
	seen := make(map[string]bool)
	for _, rec := range records {
		norm := dns_provider.NormalizeDomainName(rec.Name, c.Domain)
		if norm != "" && !seen[norm] {
			seen[norm] = true
			rawNames = append(rawNames, norm)
		}
	}

	allowed, blocked := dns_provider.FilterBlacklist(rawNames, c.Domain, c.Blacklist)
	bCheckSSL := true
	var items []db.DomainImportItem
	for _, dom := range allowed {
		items = append(items, db.DomainImportItem{
			Host:        dom,
			Port:        c.DefaultPort,
			CheckSSL:    &bCheckSSL,
			CheckDomain: c.CheckDomain,
			IsPinned:    checker.IsRootOrWWW(dom),
		})
	}

	res, err := s.db.BatchAddDomains(items)
	if err != nil {
		errMsg := "自动导入失败: " + err.Error()
		_ = s.db.UpdateDNSSyncResult(c.ID, errMsg, time.Now().UTC())
		return nil, fmt.Errorf(errMsg)
	}

	statusMsg := fmt.Sprintf("DNS 同步完成：新增 %d 个目标，跳过 %d 个已有目标，过滤 %d 个黑名单子域名", res.Added, res.Skipped, len(blocked))
	_ = s.db.UpdateDNSSyncResult(c.ID, statusMsg, time.Now().UTC())
	return res, nil
}

// SyncAllAutoDNSTasks is called periodically to synchronize domains with auto_sync = true
func (s *Server) SyncAllAutoDNSTasks() {
	configs, err := s.db.ListDNSSyncConfigs()
	if err != nil || len(configs) == 0 {
		return
	}

	for _, c := range configs {
		if c.IsDisabled || !c.AutoSync || c.ProviderID <= 0 {
			continue
		}
		res, err := s.SyncDNSTasksForConfig(&c)
		if err == nil && res != nil && len(res.NewIDs) > 0 {
			go func(ids []int64) {
				for _, id := range ids {
					dom, err := s.db.GetDomainByID(id)
					if err == nil && s.checkSingle != nil {
						_, _ = s.checkSingle(dom)
					}
				}
			}(res.NewIDs)
		}
	}
}

type ApexCheckResult struct {
	Apex        string `json:"apex"`
	SyncedAdded int    `json:"synced_added"`
	TotalTarget int    `json:"total_target"`
	CheckCount  int    `json:"check_count"`
	Message     string `json:"message"`
}

// RunApexCheckAndSync performs DNS sync first (if DNS API is configured), then checks all subdomains under apex
func (s *Server) RunApexCheckAndSync(apex string) (*ApexCheckResult, error) {
	normApex := strings.TrimRight(strings.ToLower(strings.TrimSpace(apex)), ".")
	if normApex == "" {
		return nil, fmt.Errorf("apex domain cannot be empty")
	}

	result := &ApexCheckResult{Apex: normApex}

	// 1. 若配置了主域名同步规则且有有效 API 凭据，先从 DNS 同步一次域名并过滤黑名单
	conf, err := s.db.GetDNSSyncConfigByDomain(normApex)
	if err == nil && conf != nil && !conf.IsDisabled && conf.ProviderID > 0 {
		syncRes, syncErr := s.SyncDNSTasksForConfig(conf)
		if syncErr == nil && syncRes != nil {
			result.SyncedAdded = syncRes.Added
		}
	}

	// 2. 加载属于该主域名的所有子域名
	allDomains, err := s.db.GetAllDomains()
	if err != nil {
		return nil, err
	}

	var apexTargets []db.Domain
	for _, d := range allDomains {
		if checker.GetApexDomain(d.Host) == normApex {
			apexTargets = append(apexTargets, d)
		}
	}
	result.TotalTarget = len(apexTargets)

	if len(apexTargets) == 0 {
		result.Message = fmt.Sprintf("主域名 %s 下暂无监控目标", normApex)
		return result, nil
	}

	// 3. 并发发起巡检
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, target := range apexTargets {
		wg.Add(1)
		go func(d db.Domain) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if s.checkSingle != nil {
				_, _ = s.checkSingle(&d)
			}
		}(target)
	}
	wg.Wait()

	result.CheckCount = len(apexTargets)
	result.Message = fmt.Sprintf("已完成 %s 巡检：同步新增 %d 个目标，检测 %d 个监控目标", normApex, result.SyncedAdded, result.CheckCount)
	return result, nil
}


