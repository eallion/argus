# 构建阶段：利用 BuildKit 原生平台执行交叉编译，大幅提升多架构构建速度
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG APP_VERSION=dev

WORKDIR /src

# 安装必要的编译工具与证书
RUN apk add --no-cache git ca-certificates tzdata

# 利用 Docker 缓存层预下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源码并进行跨架构静态编译 (禁用 CGO，剥离调试符号，注入构建版本号)
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X 'main.Version=${APP_VERSION}'" -o argus .

# 运行阶段：轻量化 Alpine 镜像
FROM alpine:3.24

ARG APP_VERSION=dev

WORKDIR /app

# 安装时区数据与根证书（用于 HTTPS / RDAP / Shoutrrr 外发通信）
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /app/data

# 从构建阶段复制可执行文件
COPY --from=builder /src/argus /app/argus

# 默认环境配置与版本信息
ENV PORT=42905
ENV DB_PATH=/app/data/argus.db
ENV APP_VERSION=${APP_VERSION}

LABEL org.opencontainers.image.version="${APP_VERSION}"

# 数据持久化目录声明
VOLUME ["/app/data"]

EXPOSE 42905

# 容器健康检查（利用 Alpine 自带轻量 wget 检测无需鉴权的探针）
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:${PORT}/api/auth/status || exit 1

ENTRYPOINT ["/app/argus"]
