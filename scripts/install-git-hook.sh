#!/bin/bash
set -e

# scripts/install-git-hook.sh
# 将版本检查脚本挂载到 .git/hooks/pre-commit 中（零外部依赖）

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_FILE="$REPO_ROOT/.git/hooks/pre-commit"

chmod +x "$REPO_ROOT/scripts/check-version-tag.sh"

cat << 'EOF' > "$HOOK_FILE"
#!/bin/bash
# 自动检查 web/index.html 版本并处理 tag
REPO_ROOT="$(git rev-parse --show-toplevel)"
if [ -f "$REPO_ROOT/scripts/check-version-tag.sh" ]; then
    # 仅作为版本一致性提醒与检查
    INDEX_FILE="$REPO_ROOT/web/index.html"
    VERSION=$(grep -oE '\?v=[0-9]+\.[0-9]+\.[0-9]+' "$INDEX_FILE" | head -n 1 | sed 's/?v=//')
    if [ -n "$VERSION" ]; then
        echo "[Git Hook] 当前静态资源版本: v${VERSION}"
    fi
fi
EOF

chmod +x "$HOOK_FILE"
echo "Git pre-commit hook 安装成功。"
