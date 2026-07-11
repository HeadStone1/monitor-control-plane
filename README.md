# Monitor Control Plane

Monitor Control Plane 是一个轻量级的 Linux / Docker 监控与控制面板。它采用 `Agent -> Server -> WebUI` 架构：Agent 主动连接 Server，上报主机指标和 Docker 容器状态；WebUI 通过同源 API 和 WebSocket 查看节点、指标、容器、命令、告警和审计日志，并在授权后下发有限的容器控制命令。

> 当前项目适合个人实验室、内网测试、学习和原型验证。不要在未完成安全评估、网络隔离、备份和权限收敛前直接暴露到公网或生产环境。

## 功能概览

- 分布式 Agent 主动上报：主机信息、心跳、CPU、内存、磁盘、Docker 容器清单和容器资源统计。
- WebUI 控制台：节点概览、指标折线图、容器列表、命令记录、审计日志、告警列表。
- 多页面 WebUI：`Overview`、`Containers`、`Commands`、`Audit` 独立页面切换，不再只是锚点跳转。
- Google / Material 风格界面：浅色/深色模式、可折叠导航、响应式布局、操作确认弹窗。
- 中英文切换：顶部 `EN / 中文` 语言选择，静态文案和动态提示都会切换。
- 指标图表：支持 `1h / 7d / 30d` 范围、阈值线、悬浮提示和拖拽缩放。
- 服务端阈值和告警：阈值持久化在 Server，指标超过阈值后创建 active alert，恢复后 resolved。
- 容器控制：仅支持白名单动作 `start / stop / restart`，且 Agent 端要求容器带允许控制的 label。
- 命令闭环：命令状态支持 `pending / sent / acknowledged / running / success / failed / timeout`。
- 审计日志：记录登录、认证失败、CSRF 失败、命令、Agent 连接、告警、配置重载等事件。
- Prometheus：Server 提供 `/metrics` 文本端点，需要 `metrics:read` 权限。
- SQLite 数据层：WAL 模式、原始指标保留、小时/天 rollup、备份脚本。

## 架构

```text
Linux Server A [monitor-agent] --\
Linux Server B [monitor-agent] ----> [monitor-server + SQLite + WebUI] <--- Browser
Linux Server C [monitor-agent] --/
```

设计原则：

- Agent 只主动连出，不开放入站端口。
- Server 负责认证、授权、数据存储、WebUI API、WebSocket 推送和命令下发。
- WebUI 只连接同源 HTTP/WebSocket 接口，CSP 使用更收敛的 `connect-src 'self'`。
- 生产部署应放在 Nginx/Caddy 等 HTTPS/WSS 反向代理后面。

## 技术栈

- Python 3.10+ / 3.11 推荐
- FastAPI + WebSocket
- SQLite
- Agent: `psutil`、`docker`、`websockets`
- WebUI: 原生 HTML/CSS/JavaScript，无前端框架
- 密码和 token 哈希：Argon2id

## 安全边界

这个项目包含远程查看和控制 Docker 容器的能力，必须认真理解下面的边界：

- Agent 能访问 Docker socket 时，通常接近宿主机高权限能力。应用层白名单和 label 限制只能约束正常代码路径，不能抵消 Agent 进程被攻破后的 Docker socket 风险。
- 建议 Agent 以最小权限运行，限制网络访问，优先考虑 Rootless Docker，或长期迁移到 Docker API over TLS + 授权代理。
- 真实配置文件 `server.yaml`、`agent.yaml` 不应提交到 Git。
- 生产模式默认禁用长期静态 `admin_token`，自动化访问应使用 scoped `api_tokens`。
- 管理员密码、API token、Agent token 均应使用 Argon2id 哈希存储在 Server 配置中。
- Agent 本地配置仍需要保存明文 token 用于认证，应限制配置文件权限，避免普通用户可读。
- WebUI 使用 HttpOnly SameSite Cookie session + CSRF token；所有修改类请求都需要 `X-CSRF-Token`。

## 快速开始

### 1. 安装依赖

```powershell
cd G:\33258\Desktop\Monitor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. 创建本地配置

```powershell
Copy-Item server.example.yaml server.yaml
Copy-Item agent.example.yaml agent.yaml
```

`server.yaml` 和 `agent.yaml` 已被 `.gitignore` 忽略，不要提交。

### 3. 生成哈希

管理员密码、Agent token、API token 都用同一个命令生成 Argon2id 哈希：

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-admin-password"
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-agent-token"
```

把输出分别填入：

- `server.yaml` 的 `admin_password_hash`
- `server.yaml` 的 `users[].password_hash`
- `server.yaml` 的 `agents[].token_hash`
- 如需要 API token，则填入 `api_tokens[].token_hash`

Agent 端 `agent.yaml` 的 `token` 要填写生成 Agent hash 时输入的明文 token。

### 4. 启动 Server

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m server.monitor_server --config server.yaml
```

浏览器打开：

```text
http://127.0.0.1:8000
```

### 5. 启动 Agent

新开一个 PowerShell：

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m agent.monitor_agent --config agent.yaml
```

默认开发登录账号通常是：

```text
username: admin
password: 你在 server.yaml 中配置的管理员密码
```

## 示例配置

最小开发配置结构：

```yaml
host: 127.0.0.1
port: 8000
environment: development
allowed_hosts:
  - 127.0.0.1
  - localhost
database_path: data/monitor.db
secure_cookies: false
trust_proxy_headers: false
require_secure_transport: false

admin_username: admin
admin_password_hash: replace-with-generated-admin-password-hash
session_secret: replace-with-long-random-secret

users:
  - username: admin
    password_hash: replace-with-generated-admin-password-hash
    role: admin
    enabled: true

roles:
  viewer:
    - nodes:read
    - containers:read
    - metrics:read
    - commands:read
    - audit:read
  operator:
    - nodes:read
    - containers:read
    - metrics:read
    - commands:read
    - commands:create
    - audit:read
  admin:
    - "*"

agents:
  - node_id: dev-agent
    name: dev-agent
    token_id: token-2026-05
    token_hash: replace-with-generated-agent-token-hash
    enabled: true
```

Agent 配置示例：

```yaml
server_url: ws://127.0.0.1:8000/agent/ws
agent_id: dev-agent
agent_name: dev-agent
token: replace-with-plain-agent-token
tls_verify: true
allow_insecure_transport: false

docker:
  enabled: true
  allowed_labels:
    monitor.control-plane.allow: "true"
```

如果要允许某个容器被远程 start/stop/restart，需要给容器加 label：

```text
monitor.control-plane.allow=true
```

没有这个 label 的容器可以展示，但 Agent 不会执行控制动作。

## WebUI 页面

- `Overview`：全局节点统计、节点概览卡片、节点列表、指标图表、阈值配置和图表缩放。
- `Containers`：容器运行/停止/高 CPU/内存摘要、搜索、状态过滤、授权后的 start/stop/restart 操作。
- `Commands`：命令总数、成功数、进行中、失败/超时、最近状态和命令列表。
- `Audit`：可见日志、安全事件、来源 IP、失败事件、筛选和 CSV 导出。

顶部工具：

- `Alerts`：查看 active/resolved 告警摘要。
- `EN / 中文`：切换界面语言。
- `Dark / Light`：切换深色/浅色模式。
- `Refresh`：手动刷新数据。

## 运维接口

- `GET /health`：低细节健康检查，适合负载均衡器。
- `GET /api/admin/health`：管理员运维详情。
- `POST /api/admin/config/reload`：运行时重载用户、角色、Agent、API token 等认证配置。
- `POST /api/admin/agents/{node_id}/revoke`：运行时吊销指定 Agent，并断开当前 WebSocket。
- `GET /metrics`：Prometheus 文本指标，需要 `metrics:read` 权限。

运行时 revoke 不会自动改写 `server.yaml`。如果要持久吊销，需要手动把对应 Agent 配置改成 `enabled: false`，再 reload。

Linux/systemd 部署还支持通过 `SIGHUP` 触发配置重载。

## 数据库与备份

默认 SQLite 路径：

```text
data/monitor.db
```

数据库初始化时启用：

```text
PRAGMA journal_mode=WAL
PRAGMA synchronous=NORMAL
```

Windows 备份：

```powershell
.\scripts\backup_sqlite.ps1
```

Linux 备份：

```bash
./scripts/backup_sqlite.sh
```

恢复时建议先停止 Server，再用备份文件替换当前数据库文件。

## 测试与检查

本地建议在提交前运行：

```powershell
.\.venv\Scripts\python.exe -m compileall agent server tests
.\.venv\Scripts\python.exe -m pytest
node --check web/app.js
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
```

当前测试覆盖重点：

- 明文密码和旧 hash 拒绝启动。
- CSRF、session、RBAC、scoped API token。
- Agent token 绑定 node_id。
- Agent A 不能回填 Agent B 的命令结果。
- 重复 Agent 连接拒绝。
- WebSocket 安全传输判断。
- Pydantic payload 校验。
- Docker allowed label 限制。
- 命令 ACK/running/result/timeout 状态机。
- SQLite WAL、metrics rollup、告警创建/恢复。
- WebUI 页面切换、语言切换、操作确认、容器筛选、图表缩放。

## CI 与部署材料

仓库包含：

- `.github/workflows/security.yml`
- `.github/dependabot.yml`
- `Dockerfile`
- `docker-compose.yml`
- `deploy/systemd/monitor-server.service`
- `deploy/systemd/monitor-agent.service`
- `deploy/systemd/monitor-db-backup.service`
- `deploy/systemd/monitor-db-backup.timer`
- `docs/deployment.md`
- `scripts/backup_sqlite.ps1`
- `scripts/backup_sqlite.sh`

## 生产部署前检查

- 替换所有默认密码、token、`session_secret`。
- 使用 `environment: production`。
- 使用 HTTPS/WSS，设置 `secure_cookies: true` 和 `require_secure_transport: true`。
- 如果在反向代理后面运行，设置 `trust_proxy_headers: true`，并只信任自己的代理。
- 配置真实 `allowed_hosts`。
- 不要在 production 配置 `admin_token`。
- 限制 WebUI 访问来源，例如 VPN、堡垒机、内网网段或反向代理认证。
- 为 `data/monitor.db` 做定期备份和恢复演练。
- 严格限制 Agent 所在机器的 Docker socket 权限。
- 给允许远程控制的容器显式添加 `monitor.control-plane.allow=true` label。
- 定期运行依赖漏洞扫描并更新依赖。

## Git 提交建议

这轮前端和文档改动建议一起提交：

```text
README.md
web/index.html
web/app.js
web/styles.css
tests/test_security_hardening.py
```

不建议提交：

```text
server.yaml
agent.yaml
data/
.venv/
```

这些文件包含本地配置、数据库或虚拟环境，已经在 `.gitignore` 中忽略。

## License

This project is source-available under the Monitor Personal Use License v0.1.

- Personal, educational, research, and other non-commercial use is allowed.
- Commercial use requires prior written authorization from the copyright holder.
- This is not an OSI open source license.

See [LICENSE](LICENSE) for details.
