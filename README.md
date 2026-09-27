# Argus - SSL 证书与域名到期监控系统

基于 Go 开发的轻量级、全功能 SSL 证书与域名到期监控系统。提供现代化 Web 控制台、单管理员账号安全鉴权、嵌入式 SQLite 数据持久化与多渠道告警通知。所有配置均直接在 Web 界面完成，无需任何繁琐的 YAML 配置文件。

---

## 核心特性

- **可视化 Web 控制台**：单二进制内嵌 SPA 前端（纯 HTML5 + Vanilla CSS + 原生 JS），深色质感设计，实时仪表盘与目标状态色标展示。
- **开箱即用，零配置启动**：无需预先编写或挂载任何 YAML 文件，启动容器即可在 Web 界面完成域名增删、周期调整与通知配置。
- **安全与防护体系**：
  - 首次运行自动引导初始化管理员账号与高强度密码，基于 HTTP-Only Cookie 与安全 Session 鉴权。
  - **Passkey 无密码认证**：支持 Bitwarden 密码管理器插件、Touch ID、Windows Hello、YubiKey 等硬件生物识别凭证。
  - **两步验证 (2FA / TOTP)**：支持 Bitwarden、1Password、Google Authenticator 等动态 6 位口令二次防护。
  - **Cloudflare Turnstile 人机验证**：登录页智能防撞库防护，且验证通过后若密码输错免除重复验证。
- **SSL 证书巡检**：基于 Go 标准库 `crypto/tls` 与 `crypto/x509` 进行直连握手与验证，精确检测证书有效天数、过期状态及颁发者，即使过期亦能完整提取并准确报告。
- **分区解析与多主机模式 (Multi-Host SNI)**：针对境内外不同 CDN、多机房独立申请维护证书的场景，支持为单个域名配置多个探测主机/IP 列表（含备注别名），直连各节点独立完成 SNI 握手与证书巡检，告警精准定位到具体异常节点。
- **域名到期巡检 (RDAP)**：采用标准 RDAP 协议（RFC 7483 / 9083）解析注册到期时间，输入根域名时自动开启，子域（含 `www.` 域名）智能跳过。
- **阶梯式告警策略**：四级预警阶梯（30 天临期关注、15 天预警注意、7 天橙色警告、3 天红色极危告警）。
- **批量导入与数据备份**：
  - **文本列表批量导入**：支持一行一个域名快速批量录入，自动剥离 URL 协议头、自动提取自定义端口、自动跳过重复已有项。
  - **全量配置备份 (JSON)**：一键导出所有监控目标与系统/通知/安全配置，支持备份文件上传一键恢复。
  - **纯文本域名导出 (TXT)**：导出干净的一行一个域名文本，便于二次整理与跨平台迁移。
- **多渠道通知服务**：
  - **下拉式便捷添加**：支持 Telegram、Bark (iOS)、Discord、Slack、SMTP 邮件、Ntfy、Gotify 及通用 Webhook，告别手写复杂 URL。
  - **扩展 Apprise 架构**：可选联动 Apprise API 扩展飞书、钉钉、企业微信等 100+ 渠道。
  - **无死角在线测试**：自带有效渠道前置校验，防止空跑误报。
- **嵌入式数据持久化**：采用纯 Go 驱动的嵌入式 SQLite（`modernc.org/sqlite`，无需 CGO），数据安全保存在单文件数据库中。
- **现代化多架构容器**：支持 `linux/amd64` 与 `linux/arm64`，利用 Buildx 原生交叉编译极速构建，内置健康检查探针。

---

## 快速开始

### 方式一：Docker Compose 运行（推荐）

1. **启动容器**：
   ```bash
   docker compose up -d
   ```
2. **访问控制台**：
   在浏览器中打开 `http://localhost:42905`，首次访问将引导创建管理员账号。

### 方式二：本地开发与调试 (Go 原生)

1. **拉取依赖并启动服务**：
   ```bash
   go run .
   ```
2. 服务将在本地 `http://localhost:42905` 启动，SQLite 数据库将自动创建在 `./data/argus.db`。

---

## 目录结构

```
.
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # 多架构 Docker 镜像自动构建与发布工作流
├── auth/                       # 安全与鉴权防护模块
│   ├── totp.go                 # TOTP (RFC 6238) 算法与 OTP 验证
│   ├── turnstile.go            # Cloudflare Turnstile 验证与防重试签名
│   └── webauthn.go             # WebAuthn / Passkey 凭证管理与反向代理适配
├── checker/                    # 网络巡检引擎
│   ├── ssl.go                  # SSL 证书 TLS 握手与 x509 解析
│   └── domain.go               # 域名 RDAP 到期查询与根域名智能识别
├── db/
│   └── db.go                   # SQLite 数据库管理模块（modernc.org/sqlite 纯 Go）
├── notifier/
│   └── notifier.go             # 统一通知调度器（Shoutrrr + Apprise）
├── server/
│   └── server.go               # HTTP API 服务端、鉴权中间件与备份恢复路由
├── web/                        # 前端单页面应用 (SPA)
│   ├── index.html              # 控制台前端页面与模态框
│   ├── style.css               # 深色玻璃质感样式与响应式布局
│   ├── app.js                  # 前端交互、API 联动与 WebAuthn 客户端逻辑
│   └── favicon.svg             # 项目矢量图标
├── .gitignore                  # Git 忽略配置
├── compose.yml                 # Docker 编排配置（映射 42905 端口与 ./data 目录）
├── Dockerfile                  # 多阶段跨架构轻量镜像构建文件
├── go.mod                      # Go 模块定义
├── go.sum                      # Go 依赖校验和锁文件
├── main.go                     # 主守护进程、调度引擎与 Web 服务整合
└── README.md                   # 项目说明文档
```
