package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/containrrr/shoutrrr"
)

type Config struct {
	ShoutrrrURLs []string      `yaml:"shoutrrr_urls"`
	Apprise      AppriseConfig `yaml:"apprise"`
}

type AppriseConfig struct {
	Enabled bool     `yaml:"enabled"`
	APIURL  string   `yaml:"api_url"`
	URLs    []string `yaml:"urls"`
}

type Notifier struct {
	cfg        Config
	httpClient *http.Client
}

func New(cfg Config) *Notifier {
	return &Notifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// ChannelCount returns the total number of configured active notification endpoints
func (n *Notifier) ChannelCount() int {
	count := 0
	for _, rawURL := range n.cfg.ShoutrrrURLs {
		if strings.TrimSpace(rawURL) != "" {
			count++
		}
	}
	if n.cfg.Apprise.Enabled && n.cfg.Apprise.APIURL != "" {
		for _, rawURL := range n.cfg.Apprise.URLs {
			if strings.TrimSpace(rawURL) != "" {
				count++
			}
		}
	}
	return count
}

// sendGotify sends a notification directly to Gotify server using its native REST API.
// This completely avoids Shoutrrr's hardcoded legacy token regex validation failure (e.g. gtfya.* tokens).
func (n *Notifier) sendGotify(rawURL, title, message string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("gotify url parse error: %w", err)
	}

	cleanPath := strings.Trim(u.Path, "/")
	if cleanPath == "" {
		return fmt.Errorf("gotify url 缺少 App Token 路径")
	}

	pathParts := strings.Split(cleanPath, "/")
	token := pathParts[len(pathParts)-1]
	subPath := ""
	if len(pathParts) > 1 {
		subPath = "/" + strings.Join(pathParts[:len(pathParts)-1], "/")
	}

	scheme := "http"
	if u.Scheme == "gotifys" || u.Query().Get("tls") == "true" || u.Query().Get("disableTLS") == "no" {
		scheme = "https"
	} else if u.Scheme == "gotify" {
		if strings.HasSuffix(u.Host, ":443") {
			scheme = "https"
		}
	}

	endpoint := fmt.Sprintf("%s://%s%s/message", scheme, u.Host, subPath)

	payload := map[string]interface{}{
		"title":    title,
		"message":  message,
		"priority": 5,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("gotify json marshal 失败: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("gotify 创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", token)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gotify 网络请求失败 (%s): %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gotify API 响应状态码 %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return nil
}

// SendSingle sends a notification to a single endpoint URL.
func (n *Notifier) SendSingle(rawURL, title, message string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("通知渠道 URL 不能为空")
	}

	// 1. Gotify 原生 HTTP API 投递 (支持新版 gtfya.* 等任意 Token 格式)
	if strings.HasPrefix(trimmed, "gotify://") || strings.HasPrefix(trimmed, "gotifys://") {
		return n.sendGotify(trimmed, title, message)
	}

	// 2. SMTP 邮件处理 (若未指定 subject 参数，动态追加通知标题作为邮件主题，避免邮件客户端显示无主题)
	targetURL := trimmed
	if strings.HasPrefix(trimmed, "smtp://") || strings.HasPrefix(trimmed, "smtps://") {
		if u, err := url.Parse(trimmed); err == nil {
			q := u.Query()
			if q.Get("subject") == "" && title != "" {
				q.Set("subject", title)
				u.RawQuery = q.Encode()
				targetURL = u.String()
			}
		}
	}

	// 3. 通用 Shoutrrr 发送
	formatted := fmt.Sprintf("%s\n\n%s", title, message)
	if err := shoutrrr.Send(targetURL, formatted); err != nil {
		return fmt.Errorf("shoutrrr: %w", err)
	}
	return nil
}

// Send broadcasts message to all configured notification providers
func (n *Notifier) Send(title, message string) error {
	var errMsgs []string

	// 1. Built-in: Shoutrrr / Native Gotify
	for _, rawURL := range n.cfg.ShoutrrrURLs {
		trimmed := strings.TrimSpace(rawURL)
		if trimmed == "" {
			continue
		}
		if err := n.SendSingle(trimmed, title, message); err != nil {
			log.Printf("[Notifier] Send error (%s): %v", trimmed, err)
			errMsgs = append(errMsgs, err.Error())
		}
	}

	// 2. Optional extension: Apprise API
	if n.cfg.Apprise.Enabled && n.cfg.Apprise.APIURL != "" && len(n.cfg.Apprise.URLs) > 0 {
		payload := map[string]interface{}{
			"urls":  n.cfg.Apprise.URLs,
			"title": title,
			"body":  message,
			"type":  "warning",
		}
		data, err := json.Marshal(payload)
		if err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("apprise json marshal: %v", err))
		} else {
			resp, err := n.httpClient.Post(n.cfg.Apprise.APIURL, "application/json", bytes.NewBuffer(data))
			if err != nil {
				log.Printf("[Notifier] Apprise API request failed: %v", err)
				errMsgs = append(errMsgs, fmt.Sprintf("apprise post: %v", err))
			} else {
				defer resp.Body.Close()
				if resp.StatusCode >= 400 {
					body, _ := io.ReadAll(resp.Body)
					log.Printf("[Notifier] Apprise API error status %d: %s", resp.StatusCode, string(body))
					errMsgs = append(errMsgs, fmt.Sprintf("apprise status %d", resp.StatusCode))
				}
			}
		}
	}

	if len(errMsgs) > 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, "; "))
	}
	return nil
}
