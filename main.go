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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"argus/checker"
	"argus/db"
	"argus/notifier"
	"argus/schedule"
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
		batchTimeStr := database.GetSetting("notification_batch_time", "")
		if batchTimeStr == "" {
			batchTimeStr = database.GetSetting("notification_batch_interval", "09:00")
		}
		loc := notifier.GetServerLocation()
		title, body, severity := notifier.FormatSummary(items, batchTimeStr, loc)
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

	// 阶梯解析与匹配工具函数
	parseAlertThresholds := func(raw string) []int {
		parts := strings.Split(raw, ",")
		seen := make(map[int]bool)
		var list []int
		for _, p := range parts {
			val, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil && val > 0 && !seen[val] {
				seen[val] = true
				list = append(list, val)
			}
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i] > list[j]
		})
		if len(list) == 0 {
			return []int{30, 15, 10, 7, 5, 3, 1}
		}
		return list
	}

	// 匹配所处的阶梯档位：返回 <= 阶梯中最小的阈值，例如 [30, 15, 10, 7, 5, 3, 1]
	// daysLeft=25 -> 30, daysLeft=15 -> 15, daysLeft=12 -> 15, daysLeft=6 -> 7
	// daysLeft > 30 -> 0 (正常/健康), daysLeft <= 0 -> -1 (已过期)
	matchAlertTier := func(daysLeft int, tiers []int) int {
		if len(tiers) == 0 {
			return 0
		}
		if daysLeft <= 0 {
			return -1
		}
		matched := 0
		for _, t := range tiers {
			if daysLeft <= t {
				matched = t
			}
		}
		return matched
	}

	// 单项检测（SSL 或 RDAP）告警决策引擎
	evaluateTargetAlert := func(
		status string,
		daysLeft int,
		lastTier int,
		lastAlertAt *time.Time,
		ruleMode string,
		tiers []int,
		now time.Time,
	) (shouldNotify bool, newTier int, newAlertAt *time.Time, tierLabel string) {
		// 1. 正常健康或跳过检测：重置 tier 为 0，不发通知
		if status == "healthy" || status == "skipped" {
			return false, 0, nil, ""
		}

		// 2. 检测错误：网络异常或 SNI 不符等
		if status == "error" {
			if ruleMode == "daily" {
				if lastAlertAt == nil || now.Sub(*lastAlertAt) >= 20*time.Hour || now.Format("2006-01-02") != lastAlertAt.Format("2006-01-02") {
					return true, -99, &now, "检测失败"
				}
				return false, -99, lastAlertAt, ""
			}
			// tier_once 模式：仅在首次发生错误时通知一次
			if lastTier != -99 {
				return true, -99, &now, "检测失败"
			}
			return false, -99, lastAlertAt, ""
		}

		// 3. 证书或域名已过期
		if status == "expired" || daysLeft <= 0 {
			if ruleMode == "daily" {
				if lastAlertAt == nil || now.Sub(*lastAlertAt) >= 20*time.Hour || now.Format("2006-01-02") != lastAlertAt.Format("2006-01-02") {
					return true, -1, &now, "已失效过期"
				}
				return false, -1, lastAlertAt, ""
			}
			// tier_once 模式：仅在跨入过期时通知一次
			if lastTier != -1 {
				return true, -1, &now, "已失效过期"
			}
			return false, -1, lastAlertAt, ""
		}

		// 4. 临期阶梯判断
		currTier := matchAlertTier(daysLeft, tiers)
		if currTier == 0 {
			// 天数已超出最大阶梯天数（例如已续期为 90 天），静默重置档位为 0，不通知
			return false, 0, nil, ""
		}

		if currTier <= 3 {
			tierLabel = fmt.Sprintf("红色紧急告警 (<=%d天)", currTier)
		} else if currTier <= 7 {
			tierLabel = fmt.Sprintf("橙色警告 (<=%d天)", currTier)
		} else {
			tierLabel = fmt.Sprintf("%d天临期提醒", currTier)
		}

		// 证书续期更新检测：若当前档位大于上一次记录的档位（说明天数变大/证书在两档中间续期了）
		if lastTier > 0 && currTier > lastTier {
			// 证书已完成更新续期，静默重置当前档位，不触发到期通知
			return false, currTier, lastAlertAt, ""
		}

		// 模式 1: 按阶梯单次通知 (tier_once)
		// 第一档通知一次，第二档再通知一次，中间天数不通知
		if ruleMode != "daily" {
			if lastTier == 0 || currTier < lastTier {
				return true, currTier, &now, tierLabel
			}
			// 处于同一档位内（如 30 天通知后，29、28 天），跳过通知
			return false, currTier, lastAlertAt, ""
		}

		// 模式 2: 每天通知 (daily)
		// 只要处于设定的阶梯天数内，每天巡检均发送一次通知
		if lastAlertAt == nil || now.Sub(*lastAlertAt) >= 20*time.Hour || now.Format("2006-01-02") != lastAlertAt.Format("2006-01-02") {
			return true, currTier, &now, tierLabel
		}
		return false, currTier, lastAlertAt, ""
	}

	// 统一告警信息提取函数
	extractTargetAlertMessages := func(
		updated *db.Domain,
		includeSSL bool,
		sslLabel string,
		includeDomain bool,
		domainLabel string,
	) (worstLevel string, messages []string) {
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

		if includeSSL && updated.CheckSSL {
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
						} else {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] %s: 剩余 %d 天 (到期: %s, 颁发者: %s)",
								label, sslLabel, n.DaysLeft, expStr, n.Issuer))
						}
					}
				}
			} else {
				if updated.SSLStatus != "healthy" && updated.SSLStatus != "skipped" {
					updateLevel(updated.SSLStatus)
					expStr := ""
					if updated.SSLExpiresAt != nil {
						expStr = updated.SSLExpiresAt.Format("2006-01-02")
					}
					if updated.SSLStatus == "error" {
						messages = append(messages, fmt.Sprintf("- SSL 证书 [检测失败]: %s", updated.SSLError))
					} else if updated.SSLStatus == "expired" {
						messages = append(messages, "- SSL 证书 [严重过期]: 证书已失效！")
					} else {
						messages = append(messages, fmt.Sprintf("- SSL 证书 [%s]: 剩余 %d 天 (到期: %s, 颁发者: %s)",
							sslLabel, updated.SSLDaysLeft, expStr, updated.SSLIssuer))
					}
				}
			}
		}

		if includeDomain && updated.CheckDomain {
			if updated.DomainStatus != "healthy" && updated.DomainStatus != "skipped" {
				updateLevel(updated.DomainStatus)
				expStr := ""
				if updated.DomainExpiresAt != nil {
					expStr = updated.DomainExpiresAt.Format("2006-01-02")
				}
				if updated.DomainStatus == "error" {
					messages = append(messages, fmt.Sprintf("- 域名注册 [RDAP查询失败]: %s", updated.DomainError))
				} else if updated.DomainStatus == "expired" {
					messages = append(messages, "- 域名注册 [已超过注册期]: 域名已过期！")
				} else {
					messages = append(messages, fmt.Sprintf("- 域名注册 [%s]: 剩余 %d 天 (到期: %s)",
						domainLabel, updated.DomainDaysLeft, expStr))
				}
			}
		}

		if worstLevel == "" {
			worstLevel = "warning"
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

	// 目标巡检后的告警决策与分发流水线
	processDomainAlert := func(updated *db.Domain) {
		ruleMode := database.GetSetting("alert_rule_mode", "tier_once")
		tiersStr := database.GetSetting("alert_thresholds", "30,15,10,7,5,3,1")
		tiers := parseAlertThresholds(tiersStr)
		now := time.Now().UTC()

		shouldNotifySSL := false
		newSSLTier := updated.LastAlertSSLTier
		newSSLAt := updated.LastAlertSSLAt
		var sslTierLabel string

		if updated.CheckSSL {
			shouldNotifySSL, newSSLTier, newSSLAt, sslTierLabel = evaluateTargetAlert(
				updated.SSLStatus,
				updated.SSLDaysLeft,
				updated.LastAlertSSLTier,
				updated.LastAlertSSLAt,
				ruleMode,
				tiers,
				now,
			)
		} else {
			newSSLTier = 0
			newSSLAt = nil
		}

		shouldNotifyDomain := false
		newDomainTier := updated.LastAlertDomainTier
		newDomainAt := updated.LastAlertDomainAt
		var domainTierLabel string

		if updated.CheckDomain {
			shouldNotifyDomain, newDomainTier, newDomainAt, domainTierLabel = evaluateTargetAlert(
				updated.DomainStatus,
				updated.DomainDaysLeft,
				updated.LastAlertDomainTier,
				updated.LastAlertDomainAt,
				ruleMode,
				tiers,
				now,
			)
		} else {
			newDomainTier = 0
			newDomainAt = nil
		}

		// 检查状态是否有变更（包括证书更新续期重置为 0，或跨入新阶梯），持久化至数据库
		stateChanged := (newSSLTier != updated.LastAlertSSLTier) ||
			(newDomainTier != updated.LastAlertDomainTier) ||
			(shouldNotifySSL && newSSLAt != updated.LastAlertSSLAt) ||
			(shouldNotifyDomain && newDomainAt != updated.LastAlertDomainAt)

		if stateChanged {
			_ = database.UpdateDomainAlertState(updated.ID, newSSLTier, newDomainTier, newSSLAt, newDomainAt)
			updated.LastAlertSSLTier = newSSLTier
			updated.LastAlertDomainTier = newDomainTier
			updated.LastAlertSSLAt = newSSLAt
			updated.LastAlertDomainAt = newDomainAt
		}

		// 仅当存在需要通知的项目时，提取消息并分发
		if !shouldNotifySSL && !shouldNotifyDomain {
			return
		}

		level, messages := extractTargetAlertMessages(updated, shouldNotifySSL, sslTierLabel, shouldNotifyDomain, domainTierLabel)
		if len(messages) > 0 {
			dispatchTargetAlert(updated, level, messages)
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

		tiersList := parseAlertThresholds(database.GetSetting("alert_thresholds", "30,15,10,7,5,3,1"))
		maxTier := 30
		if len(tiersList) > 0 {
			maxTier = tiersList[0]
		}

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
					} else if nRes.DaysLeft <= maxTier {
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
				} else if sslRes.DaysLeft <= maxTier {
					sslStatus = "info" // 临期关注 (<= maxTier 天)
				} else {
					sslStatus = "healthy" // 正常 (> maxTier 天)
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
				} else if dRes.DaysLeft <= maxTier {
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

				processDomainAlert(updated)
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

	// Background batch notification flush scheduler (按 TZ 时区每日定时发送)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			mode := database.GetSetting("notification_mode", "realtime")
			if mode != "batch" {
				continue
			}

			batchTimeStr := database.GetSetting("notification_batch_time", "")
			if batchTimeStr == "" {
				batchTimeStr = database.GetSetting("notification_batch_interval", "09:00")
			}
			targetH, targetM, _ := notifier.ParseBatchTime(batchTimeStr)

			loc := notifier.GetServerLocation()
			now := time.Now().In(loc)
			todayStr := now.Format("2006-01-02")
			lastSentDate := database.GetSetting("last_batch_sent_date", "")

			// 检查当前时刻是否匹配目标小时与分钟（支持 2 分钟窗口 [targetM, targetM+1] 容错）
			isTargetWindow := now.Hour() == targetH && (now.Minute() == targetM || now.Minute() == (targetM+1)%60)
			if isTargetWindow && lastSentDate != todayStr {
				_ = database.SetSetting("last_batch_sent_date", todayStr)
				if alertAggregator.Count() > 0 {
					count, err := flushAggregated()
					if err != nil {
						log.Printf("[Argus] 定期合并通知推送失败 (%d 项): %v", count, err)
					} else {
						log.Printf("[Argus] 定期合并通知已推送 (%s %02d:%02d, TZ: %s)，共汇总 %d 项告警", todayStr, targetH, targetM, loc.String(), count)
					}
				} else {
					log.Printf("[Argus] 今日合并通知定时已到达 (%02d:%02d, TZ: %s)，当前无待合并告警", targetH, targetM, loc.String())
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

		processDomainAlert(updated)
	}

	// Background multi-tier scheduler:
	// 1. Apex Domain Scheduled Tasks (先从 DNS 同步一次新子域名，再发起全量巡检)
	// 2. Individual Subdomain Scheduled Tasks (独立 cron/自然语言周期)
	// 3. Fallback: 默认随机一个时间（错峰哈希散列）配合系统设置的统一间隔
	go func() {
		bootTime := time.Now()

		type scheduleEntry struct {
			spec          string
			scheduledTime time.Time
		}

		apexNextCheckMap := make(map[string]scheduleEntry) // apex -> entry
		subNextCheckMap := make(map[int64]scheduleEntry)   // domainID -> entry
		var schedMu sync.Mutex
		lastDNSSyncTime := time.Now()

		log.Printf("[Argus] 多层级任务调度器已就绪：支持主域名/子域名自定义计划，无独立计划目标自动随机打散错峰巡检")

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			intervalStr := database.GetSetting("interval", "12h")
			interval, err := time.ParseDuration(intervalStr)
			if err != nil || interval <= 0 {
				interval = 12 * time.Hour
			}

			// 定时同步 DNS API 保底（每小时）
			if time.Since(lastDNSSyncTime) >= 1*time.Hour {
				lastDNSSyncTime = time.Now()
				go srv.SyncAllAutoDNSTasks()
			}

			// 获取所有主域名配置
			dnsConfigs, _ := database.ListDNSSyncConfigs()
			apexCronMap := make(map[string]string)
			activeApex := make(map[string]bool)
			for _, c := range dnsConfigs {
				normApex := strings.TrimRight(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
				if normApex == "" {
					continue
				}
				if c.CronSpec != "" {
					apexCronMap[normApex] = c.CronSpec
					activeApex[normApex] = true
				}
			}

			now := time.Now()

			schedMu.Lock()

			// 1. 调度配置了 CronSpec 的主域名
			for apex, spec := range apexCronMap {
				entry, exists := apexNextCheckMap[apex]
				if !exists || entry.spec != spec {
					// 重新排期
					nextTime, err := schedule.NextExecutionTime(spec, now)
					if err != nil {
						log.Printf("[Argus] 主域名 %s 计划解析失败: %v", apex, err)
						continue
					}
					entry = scheduleEntry{spec: spec, scheduledTime: nextTime}
					apexNextCheckMap[apex] = entry
					log.Printf("[Argus] 主域名 %s 计划任务已排期: 规则 [%s], 下次执行时间 %s (约 %v 后)",
						apex, spec, nextTime.Format("2006-01-02 15:04:05"), nextTime.Sub(now).Round(time.Second))
				}

				if now.After(entry.scheduledTime) {
					// 到期触发主域名检测：先从 DNS 同步一次，再巡检所有子域名
					nextTime, err := schedule.NextExecutionTime(spec, now)
					if err == nil {
						entry.scheduledTime = nextTime
						apexNextCheckMap[apex] = entry
					}
					log.Printf("[Argus] 触发主域名 %s 任务计划巡检 (先同步 DNS 再巡检)", apex)
					targetApex := apex
					go func(a string) {
						res, err := srv.RunApexCheckAndSync(a)
						if err != nil {
							log.Printf("[Argus] 主域名 %s 任务计划执行失败: %v", a, err)
						} else if res != nil {
							log.Printf("[Argus] 主域名 %s 任务计划执行完毕: %s", a, res.Message)
						}
					}(targetApex)
				}
			}

			// 清理失效的主域名
			for a := range apexNextCheckMap {
				if !activeApex[a] {
					delete(apexNextCheckMap, a)
				}
			}

			// 2. 调度子域名
			domains, err := database.GetAllDomains()
			if err == nil && len(domains) > 0 {
				currentIDs := make(map[int64]bool)

				for _, d := range domains {
					currentIDs[d.ID] = true
					dApex := checker.GetApexDomain(d.Host)
					apexHasCron := apexCronMap[dApex] != ""

					// 若子域名无独立计划，但所属主域名有计划，则由主域名集中统筹巡检，子域名自身不在单域名调度中重复排期
					if d.CronSpec == "" && apexHasCron {
						delete(subNextCheckMap, d.ID)
						continue
					}

					entry, exists := subNextCheckMap[d.ID]

					if d.CronSpec != "" {
						// 分支 A: 单个子域名拥有独立计划
						if !exists || entry.spec != d.CronSpec {
							nextTime, err := schedule.NextExecutionTime(d.CronSpec, now)
							if err != nil {
								log.Printf("[Argus] 目标 %s 独立计划解析失败: %v", d.Host, err)
								continue
							}
							entry = scheduleEntry{spec: d.CronSpec, scheduledTime: nextTime}
							subNextCheckMap[d.ID] = entry
							log.Printf("[Argus] 目标 %s 独立计划已排期: 规则 [%s], 下次执行时间 %s (约 %v 后)",
								d.Host, d.CronSpec, nextTime.Format("2006-01-02 15:04:05"), nextTime.Sub(now).Round(time.Second))
						}

						if now.After(entry.scheduledTime) {
							nextTime, err := schedule.NextExecutionTime(d.CronSpec, now)
							if err == nil {
								entry.scheduledTime = nextTime
								subNextCheckMap[d.ID] = entry
							}
							targetCopy := d
							go func(target db.Domain) {
								checkAndAlertSingle(&target)
							}(targetCopy)
						}
					} else {
						// 分支 B: 无任何独立计划，默认随机一个时间（哈希错峰打散），配合系统设置的统一间隔
						if !exists || entry.spec != "default_staggered" {
							var minWait time.Duration = 30 * time.Second
							var scheduledTime time.Time
							if interval > 2*time.Minute {
								randRange := interval - minWait
								offset := minWait + time.Duration(hashHost(d.Host)%uint64(randRange))
								scheduledTime = bootTime.Add(offset)
							} else {
								scheduledTime = bootTime.Add(interval)
							}
							entry = scheduleEntry{spec: "default_staggered", scheduledTime: scheduledTime}
							subNextCheckMap[d.ID] = entry
							log.Printf("[Argus] 目标 %s (默认错峰打散) 首次检测计划于 %s (约 %v 后)",
								d.Host, scheduledTime.Format("15:04:05"), scheduledTime.Sub(now).Round(time.Second))
						}

						if now.After(entry.scheduledTime) {
							nextTime := entry.scheduledTime.Add(interval)
							if now.After(nextTime) {
								nextTime = now.Add(interval)
							}
							entry.scheduledTime = nextTime
							subNextCheckMap[d.ID] = entry

							targetCopy := d
							go func(target db.Domain) {
								checkAndAlertSingle(&target)
							}(targetCopy)
						}
					}
				}

				// 清理已被删除的域名 ID
				for id := range subNextCheckMap {
					if !currentIDs[id] {
						delete(subNextCheckMap, id)
					}
				}
			}

			schedMu.Unlock()
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
