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

func main() {
	portFlag := flag.String("port", "42905", "Web server listening port")
	dbFlag := flag.String("db", "data/argus.db", "Path to SQLite database file")
	flag.Parse()

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
		var alertBlocks []string
		var alertMu sync.Mutex

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

				// Check tier alerts
				var messages []string
				if updated.CheckSSL {
					if updated.MultiHost && updated.SSLDetails != "" {
						var nodes []checker.NodeResult
						_ = json.Unmarshal([]byte(updated.SSLDetails), &nodes)
						for _, n := range nodes {
							if n.Status != "healthy" {
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

				if updated.CheckDomain {
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

				if len(messages) > 0 {
					if !updated.NotifyDisabled {
						alertMu.Lock()
						alertBlocks = append(alertBlocks, fmt.Sprintf("目标: %s\n%s", d.Host, strings.Join(messages, "\n")))
						alertMu.Unlock()
					} else {
						log.Printf("[Argus] 目标 %s 发生异常但已设置关闭通知，已静音跳过推送", d.Host)
					}
				}
			}(item)
		}

		wg.Wait()

		if len(alertBlocks) > 0 {
			title := fmt.Sprintf("[Argus 告警] 发现 %d 项域名/证书异常", len(alertBlocks))
			body := strings.Join(alertBlocks, "\n\n")
			log.Printf("[Argus] %s. Broadcasting notifications...", title)
			n := getNotifier()
			if err := n.Send(title, body); err != nil {
				log.Printf("[Argus] Alert notification error: %v", err)
			} else {
				log.Printf("[Argus] Alert notifications sent successfully.")
			}
		} else {
			log.Printf("[Argus] Check completed. All monitored targets are healthy.")
		}
	}

	// Static assets from embed
	assetsFS, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		log.Fatalf("[Argus] Failed to sub embedded assets: %v", err)
	}

	// Initialize HTTP Server
	srv := server.NewServer(database, getNotifier, runAllChecks, checkSingleDomain, assetsFS)
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

		var messages []string
		if updated.CheckSSL {
			if updated.MultiHost && updated.SSLDetails != "" {
				var nodes []checker.NodeResult
				_ = json.Unmarshal([]byte(updated.SSLDetails), &nodes)
				for _, n := range nodes {
					if n.Status != "healthy" {
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
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 红色紧急告警: 仅剩 %d 天 (到期: %s, 颁发者: %s)", label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "warning" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 橙色警告: 仅剩 %d 天 (到期: %s, 颁发者: %s)", label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "notice" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 15天临期提醒: 剩余 %d 天 (到期: %s, 颁发者: %s)", label, n.DaysLeft, expStr, n.Issuer))
						} else if n.Status == "info" {
							messages = append(messages, fmt.Sprintf("- SSL 节点 [%s] 30天到期提醒: 剩余 %d 天 (到期: %s, 颁发者: %s)", label, n.DaysLeft, expStr, n.Issuer))
						}
					}
				}
			} else {
				if updated.SSLStatus == "error" {
					messages = append(messages, fmt.Sprintf("- SSL 证书 [检测失败]: %s", updated.SSLError))
				} else if updated.SSLStatus == "expired" {
					messages = append(messages, "- SSL 证书 [严重过期]: 证书已失效！")
				} else if updated.SSLStatus == "critical" {
					expStr := ""
					if updated.SSLExpiresAt != nil {
						expStr = updated.SSLExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- SSL 证书 [红色紧急告警]: 仅剩 %d 天 (到期: %s, 颁发者: %s)", updated.SSLDaysLeft, expStr, updated.SSLIssuer))
				} else if updated.SSLStatus == "warning" {
					expStr := ""
					if updated.SSLExpiresAt != nil {
						expStr = updated.SSLExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- SSL 证书 [橙色警告]: 仅剩 %d 天 (到期: %s, 颁发者: %s)", updated.SSLDaysLeft, expStr, updated.SSLIssuer))
				} else if updated.SSLStatus == "notice" {
					expStr := ""
					if updated.SSLExpiresAt != nil {
						expStr = updated.SSLExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- SSL 证书 [15天临期提醒]: 剩余 %d 天 (到期: %s, 颁发者: %s)", updated.SSLDaysLeft, expStr, updated.SSLIssuer))
				} else if updated.SSLStatus == "info" {
					expStr := ""
					if updated.SSLExpiresAt != nil {
						expStr = updated.SSLExpiresAt.Format("2006-01-02")
					}
					messages = append(messages, fmt.Sprintf("- SSL 证书 [30天到期提醒]: 剩余 %d 天 (到期: %s, 颁发者: %s)", updated.SSLDaysLeft, expStr, updated.SSLIssuer))
				}
			}
		}

		if updated.CheckDomain {
			if updated.DomainStatus == "error" {
				messages = append(messages, fmt.Sprintf("- 域名注册 [RDAP查询失败]: %s", updated.DomainError))
			} else if updated.DomainStatus == "expired" {
				messages = append(messages, "- 域名注册 [已超过注册期]: 域名已过期！")
			} else if updated.DomainStatus == "critical" {
				expStr := ""
				if updated.DomainExpiresAt != nil {
					expStr = updated.DomainExpiresAt.Format("2006-01-02")
				}
				messages = append(messages, fmt.Sprintf("- 域名注册 [红色紧急告警]: 仅剩 %d 天 (到期: %s)", updated.DomainDaysLeft, expStr))
			} else if updated.DomainStatus == "warning" {
				expStr := ""
				if updated.DomainExpiresAt != nil {
					expStr = updated.DomainExpiresAt.Format("2006-01-02")
				}
				messages = append(messages, fmt.Sprintf("- 域名注册 [橙色警告]: 仅剩 %d 天 (到期: %s)", updated.DomainDaysLeft, expStr))
			} else if updated.DomainStatus == "notice" {
				expStr := ""
				if updated.DomainExpiresAt != nil {
					expStr = updated.DomainExpiresAt.Format("2006-01-02")
				}
				messages = append(messages, fmt.Sprintf("- 域名注册 [15天临期提醒]: 剩余 %d 天 (到期: %s)", updated.DomainDaysLeft, expStr))
			} else if updated.DomainStatus == "info" {
				expStr := ""
				if updated.DomainExpiresAt != nil {
					expStr = updated.DomainExpiresAt.Format("2006-01-02")
				}
				messages = append(messages, fmt.Sprintf("- 域名注册 [30天到期提醒]: 剩余 %d 天 (到期: %s)", updated.DomainDaysLeft, expStr))
			}
		}

		if len(messages) > 0 && !updated.NotifyDisabled {
			n := getNotifier()
			if n != nil {
				title := fmt.Sprintf("[Argus 告警] 监控目标 %s 状态异常", updated.Host)
				content := fmt.Sprintf("目标: %s\n%s", updated.Host, strings.Join(messages, "\n"))
				_ = n.Send(title, content)
			}
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
