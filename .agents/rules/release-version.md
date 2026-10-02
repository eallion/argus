# 静态资源版本缓存递增与自动化 Git 发布规则

当对 `web/index.html` 中的静态资源缓存查询参数进行递增或修改时（例如将 `?v=1.0.3` 递增至 `?v=1.0.4`），必须严格遵循以下发布规范：

## 1. 触发条件
- 修改了 `web/index.html` 中的静态资源链接（如 `<link rel="stylesheet" href="/style.css?v=X.Y.Z" />` 或 `<script src="/app.js?v=X.Y.Z"></script>`）中的版本号参数 `v`；
- 版本号格式遵循语义化版本：`X.Y.Z`。

## 2. 自动化执行步骤
1. **提取版本号**：从 `web/index.html` 中解析最新版本号 `vX.Y.Z`（例如 `v1.0.4`）；
2. **加入暂存区**：执行 `git add .` 将本次及之前的所有变更全部加入暂存区；
3. **提交 Commit**：执行 `git commit -m "release: vX.Y.Z"`，提交信息严格固定为 `release: vX.Y.Z`，禁止使用其他格式；
4. **添加 Git Tag**：为该 Commit 创建对应的 Git 标签：`git tag vX.Y.Z`（例如 `git tag v1.0.4`）；
5. **通知与提示**：明确提示用户本地已完成 Commit 与 Tag 的创建，由用户决定并手动执行 `git push origin vX.Y.Z` 以触发 GitHub Actions 自动化 Docker 镜像构建（遵守安全规则：未经明确授权禁止自动执行 push 操作）。

## 3. 辅助自动化工具与执行授权
- 项目已提供自动化检查与打标脚本：`scripts/check-version-tag.sh`。
- 用户已明确长期授权：本项目打包、编译测试及版本打标脚本（如 `go test ./...`、`./scripts/check-version-tag.sh` 等）自动同意执行，无需重复逐次确认。
