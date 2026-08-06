# Monitor Control Plane 功能审计报告

审计日期：2026-07-09  
审计范围：当前本地 `main` 分支代码、配置示例、WebUI、Agent、测试、部署材料。  
审计目标：确认项目作为轻量 Linux / Docker 监控控制面时，核心功能是否形成可运行闭环，哪些能力已有代码与测试证据，哪些能力仍需手动验证或后续增强。

## 总体结论

项目已经从早期 MVP 发展成一个具备基本生产化轮廓的单实例监控控制面：

- Server 提供登录、RBAC、节点、指标、容器、命令、审计、告警、配置热重载和 Prometheus 导出接口。
- Agent 主动连接 Server，上报主机指标、Docker 清单和容器状态，并能接收容器启停重启命令。
- WebUI 已覆盖日常操作入口：总览、节点详情、指标图表、告警、容器操作、命令记录、审计日志、深色模式和图表缩放。
- SQLite 已具备 WAL、原始指标保留、小时/天 rollup 和备份脚本。
- 测试重点覆盖认证安全、命令状态机、告警、rollup、部署文件、前端关键交互静态检查。

功能可用性判断：**核心闭环已具备，适合个人实验室、内网测试、小规模节点监控；暂不建议作为多人生产级平台直接使用。**

主要原因：

- 自动化测试覆盖偏安全和后端逻辑，真实浏览器端到端测试不足。
- Docker socket 架构风险仍然存在，虽然已有 label 控制边界。
- 配置和首次启动流程对普通用户仍偏复杂，尤其是 Argon2id hash 生成、Server/Agent token 对齐。
- README 当前存在中文编码显示问题，影响新用户阅读体验。

## 功能模块审计

| 模块 | 当前实现 | 证据 | 结论 | 后续建议 |
| --- | --- | --- | --- | --- |
| 启动入口 | Server 通过 `python -m server.monitor_server --config server.yaml` 启动；Agent 通过 `python -m agent.monitor_agent --config agent.yaml` 启动。 | `server/monitor_server/__main__.py`、`agent/monitor_agent/__main__.py`、README 启动命令。 | 部分通过 | 需要补一份中文无乱码的 `快速启动` 文档，并明确开发默认账号、hash 生成和常见错误。 |
| 配置加载 | Server 支持 YAML + 环境变量；拒绝明文 admin password、明文 Agent token 和非 Argon2id hash。 | `server/monitor_server/config.py`、`tests/test_security_hardening.py`。 | 通过 | 可增加 `config doctor` 命令，启动前一次性检查配置。 |
| 登录与会话 | Cookie session、CSRF、RBAC scopes、logout、`/api/auth/me` 已实现。 | `server/monitor_server/security.py`、`server/monitor_server/app.py`、前端 `api()` helper、CSRF 测试。 | 通过 | 建议补真实浏览器测试，验证刷新、过期、logout 后 UI 状态。 |
| Server API | 已有健康检查、节点、指标、容器、命令、审计、告警、阈值、Prometheus、管理接口。 | `server/monitor_server/app.py` 路由列表。 | 通过 | 建议生成 OpenAPI 文档说明和 API token 使用示例。 |
| Agent WebSocket | Agent 首包 auth，等待 `auth_ok` 和协议版本确认后再发送 hello、heartbeat、metrics、docker_inventory、docker_stats、命令回执；断线使用带抖动的指数退避。 | `agent/monitor_agent/client.py`、`server/monitor_server/app.py`。 | 通过 | 后续发布新协议版本时补充兼容矩阵和升级顺序。 |
| UI WebSocket | UI 使用 cookie/session auth 接入 `/ws/ui`，接收节点、指标、容器、命令、告警等刷新事件。 | `web/app.js`、`server/monitor_server/app.py`。 | 部分通过 | 目前缺少浏览器端实时推送自动化测试。 |
| 节点监控 | Server 存节点状态，支持 online/warning/offline，Agent 心跳驱动状态更新。 | `server/monitor_server/db.py`、`_status_watcher()`。 | 通过 | 可在 UI 图表上增加离线时间标记。 |
| 指标采集与查询 | Agent 上报 CPU、内存、磁盘、load、网络；Server 支持 1h raw、7d hourly、30d daily。 | `agent/monitor_agent/collectors/system.py`、`server/monitor_server/db.py`、rollup 测试。 | 通过 | 可增加更细粒度时间范围和手动刷新/暂停刷新。 |
| 指标 rollup | `metrics_hourly`、`metrics_daily` 表和后台 rollup 已实现，查询优先读 rollup。 | `server/monitor_server/db.py`、`test_metric_rollup_populates_hourly_and_daily_series`。 | 通过 | 后续可增加 rollup 运行状态页面。 |
| 阈值与告警 | 阈值服务端持久化，metrics 入库后评估 active/resolved alert，WebUI 显示告警计数；可通过带 HMAC 签名的异步 webhook 发送创建/恢复事件。 | `server/monitor_server/db.py`、`server/monitor_server/notifications.py`、`web/app.js`、告警及 webhook 测试。 | 通过 | 邮件、飞书/钉钉可由接收 webhook 的适配服务完成，避免在主进程中增加多套供应商 SDK。 |
| Docker 清单 | Agent 读取 Docker 容器清单和运行容器 stats，上报到 Server，WebUI 展示。 | `docker_collector.py`、`replace_inventory()`、`update_container_stats()`。 | 通过 | Docker 不可用时 UI 可以更明确展示错误原因。 |
| 容器操作 | 支持 start/stop/restart；Server 白名单 + 容器归属校验；Agent 二次校验 action、container_id、allowed label。 | `create_command()`、`DockerCollector.execute()`、label 测试。 | 通过 | 建议 UI 标出“不可操作原因”，例如缺少 label。 |
| 命令状态机 | 命令流转为 pending/sent/acknowledged/running/success/failed/timeout。 | `db.mark_command_*`、Agent command_ack/running/result、状态机测试。 | 通过 | 可在 UI 命令列表显示更清晰的进度时间线。 |
| 审计日志 | 命令、登录、配置 reload、revoke、告警、非法 payload 等写入审计；支持筛选和 CSV 导出。 | `add_audit_log()`、`add_security_event()`、`web/app.js exportAuditCsv()`。 | 通过 | 建议增加服务端 CSV/JSON 导出接口，前端导出适合小数据量。 |
| WebUI 总览 | 已有节点 overview 卡片、状态、CPU/MEM/DISK ring、告警计数。 | `web/index.html`、`web/app.js renderNodeOverview()`。 | 通过 | 可增加节点排序、分组和搜索。 |
| WebUI 图表 | Canvas 折线图、范围切换、阈值线、tooltip、拖拽缩放、reset zoom、深色模式。 | `web/app.js renderChart()`、drag zoom 静态测试。 | 部分通过 | 缺少真实浏览器截图/交互测试；移动端手势体验需实测。 |
| WebUI 容器列表 | 支持名称/镜像搜索、running/stopped/all 过滤、操作确认 modal。 | `web/app.js`、前端静态测试。 | 通过 | 建议增加按状态/名称排序。 |
| RBAC 体验 | viewer 隐藏/禁用变更类控件，operator/admin 按 scope 放行。 | `require_permission()`、`web/app.js hasScope()`、RBAC 测试。 | 通过 | 多用户管理 UI 仍缺失，需要编辑 YAML 或 reload。 |
| 配置热重载 | 管理员可调用 `/api/admin/config/reload`；Linux 支持 SIGHUP；会断开凭据过期 Agent。 | `_reload_runtime_config()`、reload 测试。 | 通过 | Windows 只能 API reload，文档需强调。 |
| Agent 吊销 | `/api/admin/agents/{node_id}/revoke` 将凭据指纹和 token ID 持久写入 SQLite，立即断开连接，并在重启/reload 后继续拒绝旧 token。 | `_revoke_agent_runtime()`、`agent_token_revocations`、重启后拒绝测试。 | 通过 | 轮换时使用新的 token ID，并同步禁用 YAML 中的旧凭据以保持配置清晰。 |
| Prometheus | `/metrics` 需要 `metrics:read`，导出节点在线、CPU、内存、磁盘、Docker 等 gauge。 | `_prometheus_metrics()`、Prometheus 测试。 | 通过 | 可增加 alert/command 指标。 |
| SQLite 数据层 | WAL、foreign keys、commands、metrics、rollup、alerts、settings、audit_logs 等表齐全。 | `Database.init()`、WAL 测试。 | 通过 | 大规模部署应迁移到 PostgreSQL 或至少增加 DB health/backup 检测。 |
| 备份与部署 | 提供 PowerShell/Shell 备份脚本、systemd units、Dockerfile、docker-compose。 | `scripts/`、`deploy/systemd/`、`Dockerfile`、`docker-compose.yml`。 | 通过 | 建议补“恢复演练”步骤和 Windows 服务化方案。 |
| CI 与依赖 | GitHub Actions 执行安装、compileall、node check、pytest、pip-audit；Dependabot 已配置。 | `.github/workflows/security.yml`、`.github/dependabot.yml`。 | 通过 | 可加入覆盖率统计和 browser E2E。 |

## 启动闭环手动验证清单

以下是建议真实跑一遍的功能验证顺序。每一步都应记录结果、截图或错误日志。

### 1. 环境检查

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m compileall agent server tests
.\.venv\Scripts\python.exe -m pytest tests
```

预期结果：

- compileall 无语法错误。
- pytest 全部通过。

### 2. Server 启动

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m server.monitor_server --config server.yaml
```

预期结果：

- Server 监听 `http://127.0.0.1:8000`。
- 不出现 `admin_password`、非 Argon2id hash、production 安全配置错误。

浏览器访问：

```text
http://127.0.0.1:8000
```

### 3. Agent 启动

另开 PowerShell：

```powershell
cd G:\33258\Desktop\Monitor
.\.venv\Scripts\python.exe -m agent.monitor_agent --config agent.yaml
```

预期结果：

- Agent 连接成功。
- WebUI 节点列表出现对应节点。
- 指标和 Docker 状态逐步刷新。

### 4. WebUI 功能验证

建议逐项点击：

- 登录、刷新页面、退出登录。
- 查看 Dashboard 节点卡片。
- 切换指标范围：1h、7d、30d。
- 拖拽图表区域后点击 `Reset zoom`。
- 修改 CPU/Memory/Disk 阈值并观察告警栏。
- 搜索容器、按状态过滤容器。
- 对带 label 的测试容器执行 start/stop/restart。
- 查看命令状态从 sent 到 acknowledged/running/success 或 failed。
- 筛选审计日志并导出 CSV。
- 切换深色模式。

### 5. Docker 操作前置条件

容器必须带允许 label 才能被 Agent 控制：

```text
monitor.control-plane.allow=true
```

未带该 label 的容器应当只展示，不允许启停重启。

## 当前主要缺口

| 优先级 | 缺口 | 影响 | 建议 |
| --- | --- | --- | --- |
| P0 | README 中文内容在当前终端显示为乱码 | 新用户阅读和启动排错困难 | 重写 README 中文段落或拆出 `docs/quickstart.zh-CN.md`。 |
| P0 | 缺少真实端到端启动记录 | 无法证明本机当前配置一定能跑通 | 按手动验证清单跑一遍并记录结果。 |
| P1 | WebUI 缺少浏览器自动化测试 | 图表、modal、告警栏、缩放等交互只能靠静态测试证明 | 增加 Playwright smoke test。 |
| P1 | Docker 错误原因 UI 展示不足 | Docker 不可用或容器缺 label 时用户需要看日志排查 | 在容器列表或节点详情显示 Docker error / control disabled reason。 |
| P2 | 缺少多用户管理 UI | RBAC 需要编辑 YAML | 增加用户/角色只读查看和管理员编辑页面。 |
| P2 | 缺少正式 release 包 | 新机器部署仍需手动 clone + venv | 后续提供版本化 zip、Docker image 或安装脚本。 |

## Go 重构必要性评估

短期不建议全量重构成 Go。

当前项目的主要问题不是 Python 性能，而是功能闭环、启动体验、浏览器测试、部署说明和运维流程。全量重写 Server 会带来 API、WebSocket、数据库、RBAC、审计、WebUI 集成和测试的大迁移风险。

更合理的路线：

1. 继续稳定 Python Server 和现有 WebUI。
2. 固化 WebSocket 协议、配置格式和测试样例。
3. 如果需要更容易分发，优先把 Agent 重写成 Go。
4. 只有当 Server 并发、内存或部署形态成为明确瓶颈时，再评估 Go Server。

Go Agent 的潜在收益：

- 单二进制部署，不依赖 Python 环境。
- 更适合 Linux systemd 长期运行。
- 跨平台 release 更容易。
- 资源占用更低，升级分发更简单。

结论：**后期可以考虑 Go Agent；暂不建议 Go 全量重构。**

## 建议下一步

建议按以下顺序推进：

1. 先按本文手动验证清单跑通本机 Server + Agent + WebUI。
2. 修复 README 中文乱码或新增中文快速启动文档。
3. 增加 Playwright smoke test，覆盖登录、Dashboard、图表、容器列表、审计导出。
4. 补 Docker 错误原因展示，并对接一个实际 webhook 接收端做通知演练。
5. 再评估是否启动 Go Agent 原型。
