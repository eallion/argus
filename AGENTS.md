# Argus 项目智能体规范 (AGENTS.md)

本项目适用于 Antigravity AI 编程助手。在本项目中操作时，必须严格遵守以下规则：

## 1. 静态资源版本缓存递增与自动化 Git 发布规则
当对 `web/index.html` 中的静态资源缓存查询参数进行递增或修改时（例如将 `?v=1.0.3` 递增至 `?v=1.0.4`）：
1. **提取版本号**：从 `web/index.html` 中解析最新版本号 `vX.Y.Z`（例如 `v1.0.4`）；
2. **加入暂存区**：执行 `git add .` 将本次及之前的所有变更全部加入暂存区；
3. **提交 Commit**：执行 `git commit -m "release: vX.Y.Z"`，提交信息严格固定为 `release: vX.Y.Z`；
4. **添加 Git Tag**：为该 Commit 创建对应的 Git 标签：`git tag vX.Y.Z`（例如 `git tag v1.0.4`）；
5. **安全与推送限制**：禁止自动执行任何 `git push` 命令，必须由用户确认并手动推送以触发 GitHub Actions 镜像构建；
6. **自动化脚本支持**：可调用 `scripts/check-version-tag.sh` 自动化执行上述版本检查与打标流程。

## 2. 交互与环境约束
1. 始终使用简体中文回答，严禁使用 Emoji；
2. 严肃严谨，禁止没有根据的话；
3. 所有命令只在当前项目内运行，严禁跨目录运行；
4. 运行任何 Linux 命令前必须征得用户同意；
5. 文件链接必须使用标准 Markdown 链接格式 `file:///...`。
