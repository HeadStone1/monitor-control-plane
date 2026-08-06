# Monitor Control Plane

Monitor Control Plane 是一个轻量级的 Linux / Docker 监控与控制面板。它采用 `Agent -> Server -> WebUI` 架构：Agent 主动连接 Server，上报主机指标和 Docker 容器状态；WebUI 通过同源 API 和 WebSocket 查看节点、指标、容器、命令、告警和审计日志，并在授权后下发有限的容器控制命令。

> 当前项目适合个人实验室、内网测试、学习和原型验证。不要在未完成安全评估、网络隔离、备份和权限收敛前直接暴露到公网或生产环境。

## 功能概览

- 分布式 Agent 主动上报：主机信息、心跳、CPU、内存、磁盘、Docker 容器清单和容器资源统计。
- WebUI 控制台：节点概览、指标折线图、容器列表、命令记录、审计日志、告警列表和管理员健康页。
- 多页面 WebUI：`Overview`、`Containers`、`Commands`、`Audit`、`Admin` 独立页面切换，不再只是锚点跳转。
- Google / Material 风格界面：浅色/深色模式、桌面折叠导航、移动端抽屉、响应式容器信息块、操作确认弹窗和完整空状态。
- 中英文切换：顶部 `EN / 中文` 语言选择，静态文案和动态提示都会切换。
- 指标图表：可独立显示 CPU、内存和磁盘，支持近 `1h / 24h / 7d / 15d / 30d / 60d / 90d`、阈值线、悬浮提示和拖拽缩放。
- 服务端阈值和告警：阈值持久化在 Server，指标超过阈值后创建 active alert，恢复后 resolved。
- 外部告警 Webhook：可将创建/恢复事件异步发送到一个或多个签名端点，带有界队列、短超时和有限重试。
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
- Webhook 签名密钥只能通过环境变量提供；生产端点强制 HTTPS，客户端不读取系统代理且不会跟随重定向。

## 快速开始

### 1. 安装依赖

```powershell
cd G:\33258\Desktop\Monitor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. 创建本地配置

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --init-config
```

向导会提示输入管理员密码，然后生成：

- `server.yaml`：包含管理员 Argon2id 密码哈希、随机 session secret、Agent token hash、角色和安全默认项。
- `agent.yaml`：包含 Agent 连接地址和明文 Agent token。

默认不会覆盖已有配置。如果你明确要重新生成：

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --init-config --force
```

也可以指定初始 Agent：

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --init-config --agent-id dev-agent --agent-name dev-agent
```

`server.yaml` 和 `agent.yaml` 已被 `.gitignore` 忽略，不要提交。

### 3. 手动生成哈希

如果不使用向导，管理员密码、Agent token、API token 都用同一个命令生成 Argon2id 哈希：

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
  api_timeout_seconds: 10
  collection_timeout_seconds: 15
  collection_workers: 3
  allowed_labels:
    monitor.control-plane.allow: "true"
```

如果要允许某个容器被远程 start/stop/restart，需要给容器加 label：

```text
monitor.control-plane.allow=true
```

没有这个 label 的容器可以展示，但 Agent 不会执行控制动作。

Docker 和系统指标采集会在线程池中执行，不会阻塞 Agent 心跳和命令接收。`api_timeout_seconds` 限制单次 Docker API 请求，`collection_timeout_seconds` 限制 Agent 等待一次采集的时间，`collection_workers` 限制同时运行的采集线程数量。超时的容器清单会标记为过期并保留最后一次成功结果。

Agent 建立 WebSocket 后会先等待 Server 返回 `auth_ok` 并确认协议版本，认证完成前不会发送主机或 Docker 数据。断线重连采用指数退避和随机抖动，避免多个节点同时恢复时集中冲击 Server；连接稳定达到指定时间后会重置退避：

```yaml
reconnect:
  initial_seconds: 1
  max_seconds: 30
  stable_reset_seconds: 60
  jitter_percent: 20
  auth_timeout_seconds: 5
```

当前 Agent 协议版本为 `1`。显式发送不兼容版本的 Agent 会被 Server 拒绝并写入安全审计。

Server 的命令执行与 WebSocket 投递超时可以分别配置：

```yaml
command:
  timeout_seconds: 60
  send_timeout_seconds: 5
```

`send_timeout_seconds` 只限制 Server 向 WebSocket 写入一条消息的时间。投递失败的命令会立即标记为 `send_failed`，不会长期停留在 `pending`；对应失效连接会从连接中心清理并写入审计。

## 外部告警 Webhook

Webhook 默认关闭。签名密钥不写入 YAML，只在启动 Server 前通过环境变量提供：

```powershell
$env:MONITOR_ALERT_WEBHOOK_SECRET = "replace-with-a-long-random-secret"
```

然后在 `server.yaml` 中配置：

```yaml
alert_notifications:
  enabled: true
  queue_size: 100
  worker_count: 2
  request_timeout_seconds: 5
  max_attempts: 3
  retry_base_seconds: 2
  webhooks:
    - name: operations
      url: https://alerts.example.com/monitor
      secret_env: MONITOR_ALERT_WEBHOOK_SECRET
      enabled: true
```

生产环境只接受 `https://` webhook；开发环境额外允许 `http://127.0.0.1`、`http://localhost` 和 `http://[::1]`。URL 不允许内嵌用户名/密码或 fragment。配置 reload 会重新读取环境变量并原子替换通知 worker。

每个请求包含完整的 `alert_created` 或 `alert_resolved` JSON 事件，并附带：

- `X-Monitor-Event`
- `X-Monitor-Timestamp`
- `X-Monitor-Signature: sha256=<hex>`

签名内容为 `timestamp + "." + raw_request_body`，使用对应环境变量中的密钥执行 HMAC-SHA256。接收方应校验签名并限制时间戳偏差，防止伪造和重放。

通知使用独立有界队列，不阻塞指标入库和 WebSocket 推送。网络错误、HTTP `429` 和 `5xx` 会指数退避重试；其他 `4xx`、`3xx` 直接失败，重定向不会被跟随。投递成功、最终失败和队列满丢弃都会写入审计，管理员健康接口会显示队列深度和累计计数。

## WebUI 页面

- `Overview`：全局节点统计、节点概览卡片、节点列表、可选指标与时间范围、阈值配置和图表缩放。
- `Containers`：容器运行/停止/高 CPU/内存摘要、搜索、状态过滤、授权后的 start/stop/restart 操作。
- `Commands`：命令总数、成功数、进行中、失败/超时、最近状态和命令列表。
- `Audit`：可见日志、安全事件、来源 IP、失败事件、筛选和 CSV 导出。
- `Admin`：仅管理员可见，展示数据库 WAL 状态、后台任务、配置路径、保留策略、容量统计、监视器故障与重试状态，并提供运行时配置重载按钮。

顶部工具：

- `Alerts`：查看 active/resolved 告警摘要。
- `EN / 中文`：切换界面语言。
- `Dark / Light`：切换深色/浅色模式。
- `Refresh`：手动刷新数据。

## 运维接口

- `GET /health`：低细节健康检查，适合负载均衡器。
- `GET /api/admin/health`：管理员运维详情，包括告警通知 worker、队列和投递计数。
- `POST /api/admin/config/reload`：运行时重载用户、角色、Agent、API token 等认证配置。
- `POST /api/admin/agents/{node_id}/revoke`：持久吊销指定 Agent 凭据，并断开当前 WebSocket。
- `GET /metrics`：Prometheus 文本指标，需要 `metrics:read` 权限。

WebUI 的 `Admin / Health` 页面已接入 `/api/admin/health` 和 `/api/admin/config/reload`，普通 viewer/operator 角色不会显示该入口。

revoke 会把凭据指纹和 `token_id` 写入 SQLite，Server 重启或 reload 后旧 token 仍会被拒绝；数据库不保存明文 token。Server 不会自动改写 `server.yaml`，建议同时把旧凭据改成 `enabled: false` 以保持配置含义清晰。轮换时必须生成新 token，并使用新的 `token_id` 和 `token_hash`。

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

指标维护默认使用增量 SQL 汇总，只重新计算最近的小时/天时间桶，不再把整张原始指标表读入 Python。汇总和清理在线程及独立 SQLite 连接中执行，避免占用 API、心跳和 WebSocket 的异步主循环；原始指标与汇总数据每轮最多删除 `maintenance_batch_size` 行。可在 `server.yaml` 调整：

```yaml
retention:
  raw_metrics_days: 7
  hourly_rollup_days: 90
  daily_rollup_days: 365
  rollup_interval_seconds: 3600
  maintenance_batch_size: 5000
```

`Admin / Health` 页面会显示最近一次指标维护时间、耗时和错误。大幅缩短保留周期时，旧数据会分批清理，避免一次大事务长时间锁住 SQLite。

后台状态监视器按循环隔离故障。节点状态更新、命令超时或维护流程出现临时异常时，监视器会记录审计事件并自动退避重试，不会因单次异常永久退出；连续成功后自动恢复为健康状态。公共 `/health` 会在监视器任务停止时报告 `degraded`，管理员健康页还会显示累计失败、最近成功和最近错误。

Windows 备份：

```powershell
.\scripts\backup_sqlite.ps1
```

Linux 备份：

```bash
./scripts/backup_sqlite.sh
```

恢复时建议先停止 Server，再用备份文件替换当前数据库文件。

SQLite 备份包含 Agent token 吊销记录。恢复到某次吊销之前的旧备份会回滚对应吊销状态；恢复后应核对 `server.yaml` 中旧凭据已经禁用，必要时重新调用 revoke。

## 测试与检查

本地建议在提交前运行：

```powershell
.\.venv\Scripts\python.exe -m compileall agent server tests
.\.venv\Scripts\python.exe -m pytest
node --check web/app.js
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
```

如果已启动 Server，也可以运行真实浏览器 UI smoke check：

```powershell
$env:MONITOR_UI_PASSWORD = "your-admin-password"
.\scripts\ui_smoke_check.ps1 -BaseUrl http://127.0.0.1:8000 -Username admin
```

这个脚本会用 Playwright 打开真实 Chromium，覆盖登录、页面切换、语言切换、主题切换和移动端宽度。它需要本机有 Node.js/npm 提供的 `npx`；如果缺少，脚本会提示安装方式。

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
- WebUI 页面切换、Admin / Health 页面、语言切换、操作确认、容器筛选、移动端抽屉与信息块、加载/失败/空状态、图表缩放。
- 可选真实浏览器 smoke check 脚本。

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
- `scripts/ui_smoke_check.ps1`
- `scripts/ui_smoke_check.mjs`

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

这轮 Admin / Health 页面和文档改动建议一起提交：

```text
README.md
CHANGELOG.md
scripts/ui_smoke_check.mjs
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
