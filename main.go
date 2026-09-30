package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"argus/checker"
	"argus/db"
	"argus/notifier"
	"argus/server"
)

//go:embed web/*
var embeddedWebFS embed.FS

// Version 由编译时 -ldflags "-X main.Version=..." 动态注入，默认为 dev
var Version = "dev"

func main() {
	portFlag := flag.String("port", "42905", "Web server listening port")
	dbFlag := flag.String("db", "data/argus.db", "Path to SQLite database file")
	flag.Parse()

	log.Printf("[Argus] Starting Argus %s", Version)

	port := *portFlag
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	dbPath := *dbFlag
	if envDB := os.Getenv("DB_PATH"); envDB != "" {
		dbPath = envDB
	}

	log.Printf("[Argus] Initializing database at %s", dbPath)
	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("[Argus] Database initialization failed: %v", err)
	}
	defer database.Close()

	database.EnsureDefaultSettings()

	// Clean up expired sessions periodically
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			database.CleanExpiredSessions()
		}
	}()

	// Notifier factory that always reads the latest settings from database
	getNotifier := func() *notifier.Notifier {
		shoutrrrRaw := database.GetSetting("shoutrrr_urls", "[]")
		var shoutrrrURLs []string
		_ = json.Unmarshal([]byte(shoutrrrRaw), &shoutrrrURLs)

		appriseEnabled := database.GetSetting("apprise_enabled", "false") == "true"
		appriseAPIURL := database.GetSetting("apprise_api_url", "http://apprise:8000/notify")
		appriseRaw := database.GetSetting("apprise_urls", "[]")
		var appriseURLs []string
		_ = json.Unmarshal([]byte(appriseRaw), &appriseURLs)

		return notifier.New(notifier.Config{
			ShoutrrrURLs: shoutrrrURLs,
			Apprise: notifier.AppriseConfig{
				Enabled: appriseEnabled,
				APIURL:  appriseAPIURL,
				URLs:    appriseURLs,
			},
		})
	}

	// Alert aggregator for batch notifications
	alertAggregator := notifier.NewAlertAggregator()

	// Flush aggregated alerts helper
	flushAggregated := func() (int, error) {
		items := alertAggregator.Flush()
		if len(items) == 0 {
			return 0, nil
		}
		intervalStr := database.GetSetting("notification_batch_interval", "1h")
		title, body, severity := notifier.FormatSummary(items, intervalStr)
		n := getNotifier()
		if n == nil {
			return len(items), fmt.Errorf("通知组件未初始化")
		}
		// 记录一条合并汇总到系统消息中心
		_, _ = database.AddNotification(title, body, severity, "合并通知汇总")
		log.Printf("[Argus] Flushing %d aggregated alerts: %s", len(items), title)
		return len(items), n.Send(title, body)
	}

	getAggregatedCount := func() int {
		return alertAggregator.Count()
	}

	// 统一告警信息解析辅助函数
	extractTargetAlert := func(updated *db.Domain) (worstLevel string, messages []string) {
		levelWeight := map[string]int{
			"expired":  100,
			"critical": 90,
			"warning":  80,
			"error":    70,
			"notice":   60,
			"info":     50,
			"healthy":  10,
		}
		currentWeight := 0

		updateLevel := func(lvl string) {
			w := levelWeight[lvl]
			if w > currentWeight {
				currentWeight = w
				if lvl == "expired" || lvl == "critical" || lvl == "error" {
					worstLevel = "critical"
				} else {
					worstLevel = lvl
				}
			}
		}

		if updated.CheckSSL {
			if updated.MultiHost && updated.SSLDetails != "" {
				var nodes []checker.NodeResult
				_ = json.Unmarshal([]byte(updated.SSLDetails), &nodes)
				for _, n := range nodes {
					if n.Status != "healthy" {
						updateLevel(n.Status)
						label := n.Node
						if n.Alias != "" {
							label = fmt.Sprintf("%s (%s)", n.Node, n.Alias)
						}
						expStr := ""
						if n.ExpiresAt != nil {
							expStr = n.ExpiresAt.Format("2006-01-02")
						}
						if n.Status == "error" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 检测失败: %s", label, n.Error))
						} else if n.Status == "expired" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 严重过期: 证书已失效！", label))
						} else if n.Status == "critical" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 红色紧急告警: 仅剩 %d 天 (到期: %s, 颁发者: %s)",
								label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "warning" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 橙色警告: 仅剩 %d 天 (到期: %s, 颁发者: %s)",
								label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "notice" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 15天临期提醒: 剩余 %d 天 (到期: %s, 颁发者: %s)",
								label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "info" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 30天到期提醒: 剩余 %d 天 (到期: %s, 颁发者: %s)",
								label, n.DaysLeft, expStr, n.Issuer))
						}
					}
				}
			} else {
				if updated.SSLStatus != "healthy" && updated.SSLStatus != "skipped" {
					updateLevel(updated.SSLStatus)
					if updated.SSLStatus == "error" {
						messages = append(messages, fmt.Sprintf("- SSL 证书 [检测失败]: %s", updated.SSLError))
					} else if updated.SSLStatus == "expired" {
						messages = append(messages, "- SSL 证书 [严重过期]: 证书已失效！")
					} else if updated.SSLStatus == "critical" {
						expStr := ""
						if updated.SSLExpiresAt != nil {
							expStr = updated.SSLExpiresAt.Format("2006-01-02")
						}
						messages = append(messages, fmt.Sprintf("- SSL 证书 [红色紧急告警]: 仅剩 %d 天 (到期: %s, 颁发者: %s)",
							updated.SSLDaysLeft, expStr, updated.SSLIssuer))
					} else if updated.SSLStatus == "warning" {
						expStr := ""
						if updated.SSLExpiresAt != nil {
							expStr = updated.SSLExpiresAt.Format("2006-01-02")
						}
						messages = append(messages, fmt.Sprintf("- SSL 证书 [橙色警告]: 仅剩 %d 天 (到期: %s, 颁发者: %s)",
							updated.SSLDaysLeft, expStr, updated.SSLIssuer))
					} else if updated.SSLStatus == "notice" {
						expStr := ""
						if updated.SSLExpiresAt != nil {
							expStr = updated.SSLExpiresAt.Format("2006-01-02")
						}
						messages = append(messages, fmt.Sprintf("- SSL 证书 [15天临期提醒]: 剩余 %d 天 (到期: %s, 颁发者: %s)",
							updated.SSLDaysLeft, expStr, updated.SSLIssuer))
					} else if updated.SSLStatus == "info" {
						expStr := ""
						if updated.SSLExpiresAt != nil {
							expStr = updated.SSLExpiresAt.Format("2006-01-02")
						}
						messages = append(messages, fmt.Sprintf("- SSL 证书 [30天到期提醒]: 剩余 %d 天 (到期: %s, 颁发者: %s)",
							updated.SSLDaysLeft, expStr, updated.SSLIssuer))
					}
				}
			}
		}

		if updated.CheckDomain {
			if updated.DomainStatus != "healthy" && updated.DomainStatus != "skipped" {
				updateLevel(updated.DomainStatus)
				if updated.DomainStatus == "error" {
					messages = append(messages, fmt.Sprintf("- 域名注册 [RDAP查询失败]: %s", updated.DomainError))
				} else if updated.DomainStatus == "expired" {
					messages = append(messages, "- 域名注册 [已超过注册期]: 域名已过期！")
				} else if updated.DomainStatus == "critical" {
					expStr := ""
					if updated.DomainExpiresAt != nil {
						expStr = updated.DomainExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- 域名注册 [红色紧急告警]: 仅剩 %d 天 (到期: %s)",
						updated.DomainDaysLeft, expStr))
				} else if updated.DomainStatus == "warning" {
					expStr := ""
					if updated.DomainExpiresAt != nil {
						expStr = updated.DomainExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- 域名注册 [橙色警告]: 仅剩 %d 天 (到期: %s)",
						updated.DomainDaysLeft, expStr))
				} else if updated.DomainStatus == "notice" {
					expStr := ""
					if updated.DomainExpiresAt != nil {
						expStr = updated.DomainExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- 域名注册 [15天临期提醒]: 剩余 %d 天 (到期: %s)",
						updated.DomainDaysLeft, expStr))
				} else if updated.DomainStatus == "info" {
					expStr := ""
					if updated.DomainExpiresAt != nil {
						expStr = updated.DomainExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- 域名注册 [30天到期提醒]: 剩余 %d 天 (到期: %s)",
						updated.DomainDaysLeft, expStr))
				}
			}
		}

		if worstLevel == "" {
			worstLevel = "info"
		}
		return worstLevel, messages
	}

	// 统一告警分发函数：记录内部历史通知，并根据实时/合并模式推送外部渠道
	dispatchTargetAlert := func(updated *db.Domain, level string, messages []string) {
		if len(messages) == 0 {
			return
		}
		title := fmt.Sprintf("[Argus 告警] 监控目标 %s 状态异常", updated.Host)
		content := fmt.Sprintf("目标: %s\n%s", updated.Host, strings.Join(messages, "\n"))

		// 1. 系统内部消息系统：登录后可查看历史通知，始终记录
		_, _ = database.AddNotification(title, content, level, updated.Host)

		// 2. 外部通知推送
		if updated.NotifyDisabled {
			log.Printf("[Argus] 目标 %s 发生异常但已设置关闭通知，已静音外部推送", updated.Host)
			return
		}

		mode := database.GetSetting("notification_mode", "realtime")
		if mode == "batch" {
			alertAggregator.Add(updated.Host, messages, level)
			log.Printf("[Argus] 目标 %s 异常已加入合并通知队列 (待发送队列: %d 项)", updated.Host, alertAggregator.Count())
		} else {
			n := getNotifier()
			if n != nil {
				if err := n.Send(title, content); err != nil {
					log.Printf("[Argus] 实时通知发送失败 (%s): %v", updated.Host, err)
				} else {
					log.Printf("[Argus] 目标 %s 实时告警已发送", updated.Host)
				}
			}
		}
	}

	// Single domain check logic with 30/15/7/3 tier support
	checkSingleDomain := func(dom *db.Domain) (*db.Domain, error) {
		timeoutStr := database.GetSetting("timeout", "10s")
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			timeout = 10 * time.Second
		}

		targetStr := dom.Host
		if dom.Port != "" && dom.Port != "443" {
			targetStr = fmt.Sprintf("%s:%s", dom.Host, dom.Port)
		}

		// 1. SSL check
		var sslExpiresAt *time.Time
		sslStatus := "skipped"
		sslError := ""
		sslDaysLeft := 0
		sslIssuer := ""
		sslDetails := ""

		if dom.CheckSSL {
			sslStatus = "healthy"
			if dom.MultiHost && strings.TrimSpace(dom.HostsList) != "" {
			nodeConfigs := checker.ParseHostsList(dom.HostsList)
			var nodeResults []checker.NodeResult

			worstDaysLeft := 999999
			var earliestExpiresAt *time.Time
			var allIssuers []string
			var errMsgs []string

			statusWeight := map[string]int{
				"expired":  100,
				"critical": 90,
				"warning":  80,
				"error":    70,
				"notice":   60,
				"info":     50,
				"healthy":  10,
			}
			worstWeight := 0

			for _, nc := range nodeConfigs {
				nRes := checker.CheckSSLWithSNI(dom.Host, nc.Address, dom.Port, timeout)
				nr := checker.NodeResult{
					Type:     nc.Type,
					Node:     nc.Address,
					Alias:    nc.Alias,
					DaysLeft: nRes.DaysLeft,
					Issuer:   nRes.Issuer,
				}
				if nRes.Error != nil {
					nr.Status = "error"
					nr.Error = nRes.Error.Error()
					errMsgs = append(errMsgs, fmt.Sprintf("%s: %s", nc.Address, nRes.Error.Error()))
				} else {
					nr.ExpiresAt = &nRes.ExpiresAt
					if nRes.IsExpired || nRes.DaysLeft < 0 {
						nr.Status = "expired"
					} else if nRes.DaysLeft <= 3 {
						nr.Status = "critical"
					} else if nRes.DaysLeft <= 7 {
						nr.Status = "warning"
					} else if nRes.DaysLeft <= 15 {
						nr.Status = "notice"
					} else if nRes.DaysLeft <= 30 {
						nr.Status = "info"
					} else {
						nr.Status = "healthy"
					}

					if nRes.DaysLeft < worstDaysLeft {
						worstDaysLeft = nRes.DaysLeft
						earliestExpiresAt = &nRes.ExpiresAt
					}
					if nRes.Issuer != "" {
						found := false
						for _, isr := range allIssuers {
							if isr == nRes.Issuer {
								found = true
								break
							}
						}
						if !found {
							allIssuers = append(allIssuers, nRes.Issuer)
						}
					}
				}

				w := statusWeight[nr.Status]
				if w > worstWeight {
					worstWeight = w
					sslStatus = nr.Status
				}
				nodeResults = append(nodeResults, nr)
			}

			if len(nodeResults) > 0 {
				detailsBytes, _ := json.Marshal(nodeResults)
				sslDetails = string(detailsBytes)

				if worstDaysLeft != 999999 {
					sslDaysLeft = worstDaysLeft
					sslExpiresAt = earliestExpiresAt
				}
				if len(allIssuers) == 1 {
					sslIssuer = allIssuers[0]
				} else if len(allIssuers) > 1 {
					sslIssuer = fmt.Sprintf("多证书 (%d 个节点)", len(allIssuers))
				}
				if len(errMsgs) > 0 {
					sslError = strings.Join(errMsgs, "; ")
				}
			}
		} else {
			sslRes := checker.CheckSSL(targetStr, timeout)
			sslDaysLeft = sslRes.DaysLeft
			sslIssuer = sslRes.Issuer

			if sslRes.Error != nil {
				sslStatus = "error"
				sslError = sslRes.Error.Error()
			} else {
				sslExpiresAt = &sslRes.ExpiresAt
				if sslRes.IsExpired || sslRes.DaysLeft < 0 {
					sslStatus = "expired"
				} else if sslRes.DaysLeft <= 3 {
					sslStatus = "critical" // 红色警告 (<= 3 天)
				} else if sslRes.DaysLeft <= 7 {
					sslStatus = "warning" // 橙色警告 (<= 7 天)
				} else if sslRes.DaysLeft <= 15 {
					sslStatus = "notice" // 黄色注意 (<= 15 天)
				} else if sslRes.DaysLeft <= 30 {
					sslStatus = "info" // 临期关注 (<= 30 天)
				} else {
					sslStatus = "healthy" // 正常 (> 30 天)
				}
			}
		}
	}

		// 2. Domain check
		var domainExpiresAt *time.Time
		domainStatus := "skipped"
		domainError := ""
		domainDaysLeft := 0

		if dom.CheckDomain {
			dRes := checker.CheckDomain(dom.Host, timeout)
			if dRes.Error != nil {
				domainStatus = "error"
				domainError = dRes.Error.Error()
			} else {
				domainExpiresAt = &dRes.ExpiresAt
				domainDaysLeft = dRes.DaysLeft
				if dRes.IsExpired || dRes.DaysLeft < 0 {
					domainStatus = "expired"
				} else if dRes.DaysLeft <= 3 {
					domainStatus = "critical"
				} else if dRes.DaysLeft <= 7 {
					domainStatus = "warning"
				} else if dRes.DaysLeft <= 15 {
					domainStatus = "notice"
				} else if dRes.DaysLeft <= 30 {
					domainStatus = "info"
				} else {
					domainStatus = "healthy"
				}
			}
		}

		// Save to DB
		err = database.UpdateDomainCheckResult(
			dom.ID,
			sslDaysLeft, sslExpiresAt, sslIssuer, sslStatus, sslError, sslDetails,
			domainDaysLeft, domainExpiresAt, domainStatus, domainError,
		)
		if err != nil {
			return nil, err
		}

		return database.GetDomainByID(dom.ID)
	}

	// Full scheduled / manual check logic
	var checkLock sync.Mutex
	runAllChecks := func() {
		if !checkLock.TryLock() {
			log.Printf("[Argus] Another check task is already in progress, skipping.")
			return
		}
		defer checkLock.Unlock()

		domains, err := database.GetAllDomains()
		if err != nil {
			log.Printf("[Argus] Failed to load domains for scheduled check: %v", err)
			return
		}

		if len(domains) == 0 {
			log.Printf("[Argus] No monitored domains configured.")
			return
		}

		log.Printf("[Argus] Starting scan across %d targets...", len(domains))

		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)

		// 目标列表随机乱序，打乱连续的主域名聚集
		shuffledDomains := make([]db.Domain, len(domains))
		copy(shuffledDomains, domains)
		rand.Shuffle(len(shuffledDomains), func(i, j int) {
			shuffledDomains[i], shuffledDomains[j] = shuffledDomains[j], shuffledDomains[i]
		})

		for _, item := range shuffledDomains {
			wg.Add(1)
			go func(d db.Domain) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// 发起检测前加入随机微延迟 (50ms ~ 1200ms)，让探测请求平滑交错发起，避免瞬间突发网络洪峰
				staggerDelay := time.Duration(50+rand.Intn(1150)) * time.Millisecond
				time.Sleep(staggerDelay)

				updated, err := checkSingleDomain(&d)
				if err != nil {
					log.Printf("[Argus] Error checking %s: %v", d.Host, err)
					return
				}

				level, messages := extractTargetAlert(updated)
				if len(messages) > 0 {
					dispatchTargetAlert(updated, level, messages)
				}
			}(item)
		}

		wg.Wait()
		log.Printf("[Argus] Check completed across %d targets.", len(domains))
	}

	// Static assets from embed
	assetsFS, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		log.Fatalf("[Argus] Failed to sub embedded assets: %v", err)
	}

	// Initialize HTTP Server
	srv := server.NewServer(database, Version, getNotifier, runAllChecks, checkSingleDomain, assetsFS, flushAggregated, getAggregatedCount)
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start HTTP Server
	go func() {
		log.Printf("[Argus] Web dashboard listening on http://0.0.0.0:%s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Argus] HTTP server failed: %v", err)
		}
	}()

	// Background batch notification flush scheduler
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		lastFlushTime := time.Now()

		for range ticker.C {
			mode := database.GetSetting("notification_mode", "realtime")
			if mode != "batch" {
				continue
			}
			intervalStr := database.GetSetting("notification_batch_interval", "1h")
			interval, err := time.ParseDuration(intervalStr)
			if err != nil || interval < 1*time.Minute {
				interval = 1 * time.Hour
			}

			if time.Since(lastFlushTime) >= interval {
				lastFlushTime = time.Now()
				if alertAggregator.Count() > 0 {
					count, err := flushAggregated()
					if err != nil {
						log.Printf("[Argus] 定期合并通知推送失败 (%d 项): %v", count, err)
					} else {
						log.Printf("[Argus] 定期合并通知已推送，共汇总 %d 项告警", count)
					}
				}
			}
		}
	}()

	// 辅助函数：根据 Host 计算稳定的哈希值，用于打散每个监控目标的起始检测时间
	hashHost := func(s string) uint64 {
		var h uint64 = 14695981039346656037
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= 1099511628211
		}
		return h
	}

	// 单目标独立检测与告警发送函数
	checkAndAlertSingle := func(d *db.Domain) {
		updated, err := checkSingleDomain(d)
		if err != nil {
			log.Printf("[Argus] Error checking %s: %v", d.Host, err)
			return
		}

		level, messages := extractTargetAlert(updated)
		if len(messages) > 0 {
			dispatchTargetAlert(updated, level, messages)
		}
	}

	// Background per-target staggered scheduler: 每个监控目标用不同的起始时间，按统一间隔独立检测
	go func() {
		bootTime := time.Now()
		nextCheckMap := make(map[int64]time.Time)
		var mapMu sync.Mutex
		lastDNSSyncTime := time.Now()

		log.Printf("[Argus] 独立错峰调度器已就绪：每个监控目标将具有不同的起始时间，按统一间隔独立检测")

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			intervalStr := database.GetSetting("interval", "12h")
			interval, err := time.ParseDuration(intervalStr)
			if err != nil || interval <= 0 {
				interval = 12 * time.Hour
			}

			// 定时同步 DNS API（每小时）
			if time.Since(lastDNSSyncTime) >= 1*time.Hour {
				lastDNSSyncTime = time.Now()
				go srv.SyncAllAutoDNSTasks()
			}

			domains, err := database.GetAllDomains()
			if err != nil || len(domains) == 0 {
				continue
			}

			now := time.Now()
			currentIDs := make(map[int64]bool)

			mapMu.Lock()
			for _, d := range domains {
				currentIDs[d.ID] = true
				scheduledTime, exists := nextCheckMap[d.ID]
				if !exists {
					// 每一个监控目标计算唯一稳定哈希偏移，打散起始时间在 [30s, interval] 之间
					var minWait time.Duration = 30 * time.Second
					if interval > 2*time.Minute {
						randRange := interval - minWait
						offset := minWait + time.Duration(hashHost(d.Host)%uint64(randRange))
						scheduledTime = bootTime.Add(offset)
					} else {
						scheduledTime = bootTime.Add(interval)
					}
					nextCheckMap[d.ID] = scheduledTime
					log.Printf("[Argus] 目标 %s 调度已排期：首次检测计划于 %s (约 %v 后)", d.Host, scheduledTime.Format("15:04:05"), scheduledTime.Sub(now).Round(time.Second))
				}

				if now.After(scheduledTime) {
					// 到期，触发检测并更新下一次检测时间（统一间隔）
					nextTime := scheduledTime.Add(interval)
					if now.After(nextTime) {
						nextTime = now.Add(interval)
					}
					nextCheckMap[d.ID] = nextTime

					targetCopy := d
					go func(target db.Domain) {
						checkAndAlertSingle(&target)
					}(targetCopy)
				}
			}

			// 清理已被删除的域名 ID
			for id := range nextCheckMap {
				if !currentIDs[id] {
					delete(nextCheckMap, id)
				}
			}
			mapMu.Unlock()
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[Argus] Received signal %v. Shutting down gracefully...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[Argus] HTTP server shutdown error: %v", err)
	}

	log.Printf("[Argus] Server stopped.")
}
