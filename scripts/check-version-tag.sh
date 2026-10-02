#!/bin/bash
set -e

# scripts/check-version-tag.sh
# 自动化检查 web/index.html 中的静态资源版本缓存参数 (?v=X.Y.Z)
# 若版本递增或未打对应 tag，自动执行 git add、git commit 与 git tag

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INDEX_FILE="$REPO_ROOT/web/index.html"

if [ ! -f "$INDEX_FILE" ]; then
    echo "错误: 未找到 $INDEX_FILE" >&2
    exit 1
fi

# 从 web/index.html 中提取 ?v=X.Y.Z 版本号
VERSION=$(grep -oE '\?v=[0-9]+\.[0-9]+\.[0-9]+' "$INDEX_FILE" | head -n 1 | sed 's/?v=//')

if [ -z "$VERSION" ]; then
    echo "警告: 在 web/index.html 中未检测到形如 ?v=X.Y.Z 的版本号" >&2
    exit 0
fi

TAG_NAME="v${VERSION}"
COMMIT_MSG="release: ${TAG_NAME}"

echo "[Version Check] 当前 web/index.html 静态资源缓存版本: ${TAG_NAME}"

cd "$REPO_ROOT"

# 检查当前 git tag 是否已存在
TAG_EXISTS=false
if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
    TAG_EXISTS=true
fi

# 检查工作区是否有修改（包括暂存和未暂存）
HAS_CHANGES=false
if [ -n "$(git status --porcelain)" ]; then
    HAS_CHANGES=true
fi

if [ "$TAG_EXISTS" = true ]; then
    if [ "$HAS_CHANGES" = true ]; then
        echo "[Version Check] 标签 ${TAG_NAME} 已存在，但当前工作区存在未提交修改，请确认是否需要升级版本号后再发布。"
    else
        echo "[Version Check] 标签 ${TAG_NAME} 已就绪且工作区干净。"
    fi
    exit 0
fi

# 标签尚不存在：执行自动化 git add, git commit, git tag 流程
echo "[Version Check] 检测到新版本 ${TAG_NAME}，开始执行自动化发布流..."

# 1. git add
git add .
echo "  ✓ git add 完成"

# 2. git commit (若有修改则提交，若已提前 commit 则跳过 commit 直接打 tag)
if [ -n "$(git status --porcelain)" ]; then
    git commit -m "$COMMIT_MSG"
    echo "  ✓ git commit 完成: ${COMMIT_MSG}"
else
    echo "  - 工作区无新增变更，直接基于当前 HEAD 创建标签"
fi

# 3. git tag
git tag "$TAG_NAME"
echo "  ✓ git tag 完成: ${TAG_NAME}"

echo "=========================================================="
echo "发布流程完成: 已创建 commit 并打上标签 ${TAG_NAME}"
echo "请执行以下命令推送标签以触发 Docker 镜像自动化构建发布:"
echo "    git push origin ${TAG_NAME}"
echo "=========================================================="
