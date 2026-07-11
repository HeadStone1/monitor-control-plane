# Monitor Control Plane

Monitor Control Plane 是一个通过 vibe coding 启动的轻量级分布式 Linux / Docker 监控与控制原型。它用于验证 `Agent -> Server -> WebUI` 的基本闭环：Agent 主动连接中心端，上报主机与 Docker 状态，WebUI 展示节点和容器，并通过 Server 下发容器启停命令。

> 当前项目仍是 MVP / 学习型原型，不建议直接暴露到公网或用于生产环境。

## 适合谁

- 想学习分布式监控系统基本架构的人。
- 想研究 Agent、Server、WebUI 如何协作的人。
- 想在个人实验室、内网、测试环境中监控 Linux/Docker 的个人用户。
- 想基于 Python 快速验证运维控制台原型的开发者。

## 不适合谁

- 需要立刻上线生产环境的团队。
- 需要强合规、多租户、细粒度 RBAC 的企业场景。
- 需要替代 Prometheus、Grafana、Zabbix、Datadog 等成熟监控平台的场景。
- 无法接受 Docker socket 权限风险的环境。

## 主要风险与责任边界

该项目包含远程控制 Docker 容器的能力，存在较高安全风险。

- Agent 访问 Docker socket 时，通常等同于获得目标机器上的高权限能力。
- 如果 token、密码或 session secret 泄露，攻击者可能查看节点状态或执行容器操作。
- 如果没有启用 HTTPS/WSS，网络中间人可能窃听或篡改通信。
- 如果依赖库、Python 运行时、Docker、浏览器、TLS 栈或操作系统存在 0day 漏洞，本项目无法保证完全防护。
- 使用者需要自行评估风险、备份数据、限制网络访问、替换默认密钥，并承担部署和使用后果。

项目负责人/作者不对以下情况承担责任：

- 数据丢失、服务中断、容器误操作。
- 因错误配置、弱密码、泄露 token 导致的安全事件。
- 因第三方依赖、操作系统、Docker、网络环境或 0day 漏洞导致的损失。
- 将本 MVP 直接用于生产或商业环境带来的风险。

## 架构

```text
Linux Server A [monitor-agent] --\
Linux Server B [monitor-agent] ----> [monitor-server + SQLite + WebUI] <--- Browser
Linux Server C [monitor-agent] --/
```

核心原则：

- Agent 主动连接 Server，Agent 不开放入站端口。
- Server 负责认证、数据存储、WebUI API、WebSocket 推送和命令下发。
- WebUI 通过同源 API 和 WebSocket 与 Server 通信。
- 生产环境必须把 Server 放在 Caddy/Nginx 等 HTTPS 反向代理后面，并使用 WSS。

## 技术栈

- Python 3.11+
- FastAPI + WebSocket
- SQLite
- Python Agent: `psutil`, `docker`, `websockets`
- 原生 HTML/CSS/JS WebUI，偏 Google / Material 风格
- JSON over WebSocket

## 指标时间范围

WebUI 支持按时间范围查看节点指标：

- 近 1 小时：展示原始采样点。
- 近 7 天：按小时聚合，折线展示每小时平均值，悬浮提示展示平均值、最高值和峰值时间。
- 近 30 天：按天聚合，折线展示每日平均值，悬浮提示展示平均值、最高值和峰值时间。

Server 会保留原始指标数据，并定时写入 `metrics_hourly` / `metrics_daily` 汇总表。`1h` 查询读取原始数据，`7d` 优先读取小时汇总，`30d` 优先读取天汇总；如果汇总尚未生成，会自动回退到原始数据动态聚合。

WebUI 支持设置 CPU、Memory、Disk 安全阈值，并在图表中显示对应虚线界限。阈值会持久化在 Server 侧，Agent 上报指标后由 Server 评估告警，WebUI 顶部会显示当前告警数量。

## 安全设计现状

已实现：

- WebUI 登录验证，服务端签名 session token。
- Web 会话使用 `HttpOnly + SameSite=Strict` Cookie，降低 XSS 后直接窃取 token 的风险。
- Agent/UI WebSocket 连接后发送首条 `auth` 消息，避免 token 出现在 URL query 中。
- Server 添加基础安全响应头，包括 CSP、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`。
- Server 使用 `TrustedHostMiddleware` 限制 Host header，默认只允许 `127.0.0.1` 和 `localhost`。
- WebUI 动态内容使用 DOM API 和 `textContent` 写入，避免直接拼接 HTML。
- 状态 class 使用 allowlist，避免把服务端原始值拼进 CSS class。
- 容器命令有服务端动作白名单，并确认容器属于当前节点。
- Agent 侧再次校验动作白名单和容器 ID 格式。
- 危险容器操作写入审计日志。
- 真实配置文件不应提交到 Git，仓库只保留 `*.example.yaml`。
- 管理员密码仅支持 `admin_password_hash`，不允许在服务端配置中保存明文密码。
- Agent token 支持 `token_hash`，并绑定到具体 `node_id`。
- 非本机 `ws://` Agent 连接默认被拒绝，生产模式要求安全传输和 Secure Cookie。
- 登录和 WebSocket 认证失败有基础限速，Agent 容器清单/状态消息有数量上限。

仍需加强：

- Agent token 轮换/吊销流程和更细粒度审计。
- 更完整的 Agent token 运行时热重载、吊销 API 和轮换流程。
- 增加命令 ACK 状态机、RBAC、审计筛选导出和服务端告警。
- 增加依赖漏洞扫描、自动化浏览器安全测试和发布流程。
- 为 Server/Agent 制作 systemd、Docker、升级、回滚和备份方案。

## 首次使用

创建虚拟环境并安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

这会在当前项目目录创建 `.venv`，并把依赖安装到项目虚拟环境里，不会安装到系统 Python。

创建本地配置：

```powershell
Copy-Item server.example.yaml server.yaml
Copy-Item agent.example.yaml agent.yaml
```

这会复制示例配置。`server.yaml` 和 `agent.yaml` 是本机真实配置，已被 `.gitignore` 忽略，不应提交。

然后修改 `server.yaml`：

先生成管理员密码和 Agent token 的哈希：

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-admin-password"
.\.venv\Scripts\python.exe -m server.monitor_server --hash-secret "your-agent-token"
```

这条命令会打印 Argon2id 哈希。把打印结果分别填入 `admin_password_hash` 和 `agents[].token_hash`。旧版 PBKDF2 hash 不再接受，升级后需要一次性重新生成并替换配置里的 hash。

```yaml
allowed_hosts:
  - 127.0.0.1
  - localhost
admin_token: replace-with-long-random-value
admin_username: admin
admin_password_hash: replace-with-generated-admin-password-hash
session_secret: replace-with-long-random-secret
agents:
  - node_id: dev-agent
    name: dev-agent
    token_hash: replace-with-generated-agent-token-hash
    enabled: true
```

再修改 `agent.yaml`，让 `token` 与生成 `token_hash` 时输入的明文 Agent token 一致：

```yaml
server_url: ws://127.0.0.1:8000/agent/ws
agent_id: dev-agent
agent_name: dev-agent
token: replace-with-long-random-agent-token
allow_insecure_transport: false
```

启动 Server：

```powershell
.\.venv\Scripts\python.exe -m server.monitor_server --config server.yaml
```

这条命令会启动中心端 API、WebSocket 和 WebUI。启动后打开：

```text
http://127.0.0.1:8000
```

启动 Agent：

```powershell
.\.venv\Scripts\python.exe -m agent.monitor_agent --config agent.yaml
```

这条命令会启动本机 Agent，主动连接 Server，并上报系统指标与 Docker 容器信息。

## 环境变量覆盖

Server 支持用环境变量覆盖敏感配置：

```text
MONITOR_ADMIN_TOKEN
MONITOR_ADMIN_USERNAME
MONITOR_ADMIN_PASSWORD_HASH
MONITOR_SESSION_SECRET
MONITOR_SESSION_TTL_HOURS
MONITOR_ALLOWED_HOSTS
MONITOR_DATABASE_PATH
MONITOR_HOST
MONITOR_PORT
MONITOR_ENV
MONITOR_SECURE_COOKIES
MONITOR_TRUST_PROXY_HEADERS
MONITOR_REQUIRE_SECURE_TRANSPORT
```

`MONITOR_AGENT_TOKENS` is no longer supported. The Server does not accept plaintext Agent tokens; use `agents[].token_hash`. `MONITOR_ALLOWED_HOSTS` supports comma-separated values:

```text
monitor.example.com,127.0.0.1,localhost
```

## 生产前必须修改

- 替换所有默认密码、token、`session_secret`。
- 使用 HTTPS/WSS，禁止明文公网访问。
- 把 `allowed_hosts` 改成你的真实域名或内网 IP。
- 将 Server 绑定到内网地址或放在反向代理后。
- 限制 WebUI 访问来源，例如 VPN、堡垒机、内网网段。
- 让 Agent 以最小权限运行，并谨慎授予 Docker socket 访问权；优先考虑 Rootless Docker，或使用 Docker API over TLS + 授权代理限制可调用 API。
- 配置日志轮转和数据库备份；SQLite 默认启用 WAL，建议每天备份 `data/monitor.db`。
- 定期更新依赖、Python、Docker 和操作系统补丁。

## 数据库备份

Server 使用 SQLite，默认数据库路径是 `data/monitor.db`。建议在停机窗口或低峰期定期备份：

```powershell
.\scripts\backup_sqlite.ps1
```

脚本会调用 SQLite CLI 的 `.backup` 命令，把数据库备份到 `backups/monitor-YYYYMMDD-HHMMSS.db`。恢复时先停止 Server，再用备份文件替换当前数据库文件。

## Deployment

Deployment-ready examples are included:

- `deploy/systemd/monitor-server.service`
- `deploy/systemd/monitor-agent.service`
- `deploy/systemd/monitor-db-backup.service`
- `deploy/systemd/monitor-db-backup.timer`
- `Dockerfile`
- `docker-compose.yml`
- `scripts/backup_sqlite.sh`

See `docs/deployment.md` for systemd, Docker Compose, SQLite backup, and Docker socket hardening notes.

## Prometheus

The Server exposes a Prometheus text endpoint at `/metrics`. It requires
`metrics:read`, so use a scoped API token instead of anonymous scraping:

```yaml
api_tokens:
  - name: prometheus
    token_hash: replace-with-generated-token-hash
    scopes:
      - metrics:read
    enabled: true
```

Then configure Prometheus with a Bearer token for the scrape target.

## License

This project is source-available under the Monitor Personal Use License v0.1.

- Personal, educational, research, and other non-commercial use is allowed.
- Commercial use requires prior written authorization from the copyright holder.
- This is not an OSI open source license.

See [LICENSE](LICENSE) for details.

## Latest Update

The latest release hardens the project from a local MVP into a safer
single-instance control plane. The main changes are:

- Authentication now rejects plaintext admin passwords and legacy PBKDF2
  hashes. Admin passwords, Agent tokens, and API tokens must use Argon2id
  hashes generated with `python -m server.monitor_server --hash-secret`.
- Browser sessions include CSRF protection, scoped RBAC permissions, and
  production startup checks for secure cookies, secure transport, and disabled
  static `admin_token`.
- Agent authentication is bound to `node_id`, duplicate Agent connections are
  rejected, WebSocket secure-transport checks understand trusted proxy headers,
  and Agent payloads are schema-validated before database writes.
- Container commands now have a full `sent -> acknowledged -> running ->
  success/failed/timeout` lifecycle, with node-bound command result updates and
  timeout auditing.
- Docker control actions require allowed container labels, so unlabeled
  containers remain visible but cannot be started, stopped, or restarted by the
  Agent.
- SQLite now uses WAL mode, includes backup scripts, raw metric retention, and
  hourly/daily rollup tables for long-range metric queries.
- The server CLI includes `--doctor` for preflight config checks. `/health`
  stays low-detail for load balancers, while `/api/admin/health` exposes
  authenticated operational details for administrators.
- Thresholds are stored on the Server, alerts are evaluated server-side, and the
  WebUI shows alert counts, audit filters, CSV export, node overview cards,
  command confirmation dialogs, dark mode, container filters, and chart
  drag-to-zoom.
- CI now runs compile checks, pytest, JavaScript syntax checks, and `pip-audit`;
  Dependabot is enabled for GitHub Actions and Python dependencies.
- Deployment examples now include systemd units, Dockerfile, Docker Compose,
  SQLite backup scripts, and deployment notes.

## Development Workflow

The `main` branch should be protected. Do not push feature or security work
directly to `main`.

Recommended workflow:

```text
create a feature branch -> push the branch -> open a pull request -> wait for CI -> merge
```

Required local checks before opening a pull request:

```powershell
.\.venv\Scripts\python.exe -m compileall agent server tests
.\.venv\Scripts\python.exe -m pytest tests
node --check web/app.js
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
```

The GitHub Actions workflow runs the same core checks on pull requests.

## Security Hardening Update

The current security baseline is stricter than the initial MVP:

- Admin login only supports `admin_password_hash`; generate it with `python -m server.monitor_server --hash-secret "your-password"`.
- Plaintext `admin_password`, `users[].password`, and `MONITOR_ADMIN_PASSWORD` are rejected at config load time.
- Password and token hashes must be Argon2id. Legacy PBKDF2 hashes and plaintext Agent token fields are rejected; regenerate hashes with `--hash-secret` during upgrade.
- Agent credentials are bound to specific node IDs through the `agents` config list.
- A leaked token for one Agent can no longer claim an arbitrary `agent_id`.
- Agent token hashes are required through `token_hash`; `agent_tokens`, `MONITOR_AGENT_TOKENS`, and `agents[].token` are rejected.
- Admins can reload runtime auth config with `POST /api/admin/config/reload`; Linux deployments can also send `SIGHUP`.
- Admins can revoke an Agent at runtime with `POST /api/admin/agents/{node_id}/revoke`, which disables the in-memory credential and disconnects the current Agent WebSocket.
- Runtime revoke does not rewrite `server.yaml`; persist revocation by setting the matching `agents[].enabled: false` in config, then reload.
- Container commands now report `sent`, `acknowledged`, `running`, `success`, `failed`, or `timeout`; timeout messages distinguish commands that were never acknowledged from commands that started but did not finish.
- Metrics rollup stores hourly and daily summaries, and long-range queries prefer those summaries before falling back to raw metrics.
- Threshold settings are stored on the Server and drive active/resolved alert events pushed to WebUI.
- Audit logs can be filtered by node, action, and time range, and the current WebUI result set can be exported as CSV.
- Metric charts support drag-to-zoom selection and reset without adding a frontend framework.
- Production mode requires `secure_cookies: true` and `require_secure_transport: true`.
- Non-loopback Agent `ws://` connections are blocked unless explicitly opted in with `allow_insecure_transport: true`.
- Login and WebSocket authentication failures are rate limited.
- Agent inventory/stat payloads are capped to reduce resource-exhaustion risk.

Recommended production server config shape:

```yaml
environment: production
host: 127.0.0.1
secure_cookies: true
trust_proxy_headers: true
require_secure_transport: true
admin_username: admin
admin_password_hash: replace-with-generated-hash
session_secret: replace-with-long-random-secret
agents:
  - node_id: prod-linux-01
    name: prod-linux-01
    token_hash: replace-with-generated-agent-token-hash
    enabled: true
```
