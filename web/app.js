const METRIC_KEYS = ["cpu", "memory", "disk"];
const METRIC_RANGES = new Set(["1h", "24h", "7d", "15d", "30d", "60d", "90d"]);

const state = {
  username: "",
  csrfToken: "",
  role: "",
  scopes: [],
  nodes: [],
  containers: [],
  commands: [],
  auditLogs: [],
  alerts: [],
  adminHealth: null,
  metrics: [],
  metricPayload: null,
  metricRange: loadMetricRange(),
  visibleMetrics: loadVisibleMetrics(),
  language: loadLanguage(),
  theme: loadTheme(),
  thresholds: loadThresholds(),
  auditFilters: { nodeId: "", action: "", from: "", to: "" },
  containerFilters: { query: "", status: "all" },
  metricZoom: null,
  chartSelection: null,
  chartModel: null,
  chartHoverX: null,
  hasLoaded: false,
  isLoading: false,
  refreshError: "",
  currentPage: loadPage(),
  sidebarCollapsed: loadSidebarCollapsed(),
  selectedNodeId: localStorage.getItem("monitor.selectedNodeId") || null,
  ws: null,
  wsReconnectTimer: null,
  wsReconnectAttempts: 0,
  refreshTimer: null,
  thresholdSaveTimer: null,
  auditFilterTimer: null,
  chartResizeTimer: null,
};

const els = {
  loginView: document.querySelector("#login-view"),
  appView: document.querySelector("#app-view"),
  loginForm: document.querySelector("#login-form"),
  username: document.querySelector("#login-username"),
  password: document.querySelector("#login-password"),
  pageTitle: document.querySelector(".page-header h1"),
  logout: document.querySelector("#logout"),
  sidebarToggle: document.querySelector("#sidebar-toggle"),
  mobileNavToggle: document.querySelector("#mobile-nav-toggle"),
  sidebarScrim: document.querySelector("#sidebar-scrim"),
  navLinks: document.querySelectorAll("[data-page-link]"),
  pages: document.querySelectorAll("[data-page]"),
  refresh: document.querySelector("#refresh"),
  wsState: document.querySelector("#ws-state"),
  currentUser: document.querySelector("#current-user"),
  nodeCount: document.querySelector("#node-count"),
  onlineCount: document.querySelector("#online-count"),
  containerCount: document.querySelector("#container-count"),
  commandCount: document.querySelector("#command-count"),
  adminHealthStatus: document.querySelector("#admin-health-status"),
  adminHealthVersion: document.querySelector("#admin-health-version"),
  adminDbMode: document.querySelector("#admin-db-mode"),
  adminDbPath: document.querySelector("#admin-db-path"),
  adminWatcherStatus: document.querySelector("#admin-watcher-status"),
  adminActiveAlerts: document.querySelector("#admin-active-alerts"),
  adminPendingCommands: document.querySelector("#admin-pending-commands"),
  adminDbDetails: document.querySelector("#admin-db-details"),
  adminConfigDetails: document.querySelector("#admin-config-details"),
  adminCapacityDetails: document.querySelector("#admin-capacity-details"),
  adminControlDetails: document.querySelector("#admin-control-details"),
  adminReloadConfig: document.querySelector("#admin-reload-config"),
  containersTotal: document.querySelector("#containers-total"),
  containersScope: document.querySelector("#containers-scope"),
  containersRunningCount: document.querySelector("#containers-running-count"),
  containersStoppedCount: document.querySelector("#containers-stopped-count"),
  containersHotCount: document.querySelector("#containers-hot-count"),
  containersMemoryTotal: document.querySelector("#containers-memory-total"),
  commandsTotal: document.querySelector("#commands-total"),
  commandsSuccessCount: document.querySelector("#commands-success-count"),
  commandsActiveCount: document.querySelector("#commands-active-count"),
  commandsProblemCount: document.querySelector("#commands-problem-count"),
  commandsLatestStatus: document.querySelector("#commands-latest-status"),
  auditTotal: document.querySelector("#audit-total"),
  auditSecurityCount: document.querySelector("#audit-security-count"),
  auditSourceCount: document.querySelector("#audit-source-count"),
  auditFailureCount: document.querySelector("#audit-failure-count"),
  alertCount: document.querySelector("#alert-count"),
  alertsToggle: document.querySelector("#alerts-toggle"),
  alertPanel: document.querySelector("#alert-panel"),
  themeToggle: document.querySelector("#theme-toggle"),
  languageSelect: document.querySelector("#language-select"),
  nodeOverview: document.querySelector("#node-overview"),
  nodes: document.querySelector("#nodes"),
  containerSearch: document.querySelector("#container-search"),
  containerStatusFilter: document.querySelector("#container-status-filter"),
  containers: document.querySelector("#containers-table"),
  commands: document.querySelector("#commands-list"),
  auditLogs: document.querySelector("#audit-list"),
  auditNodeFilter: document.querySelector("#audit-node-filter"),
  auditActionFilter: document.querySelector("#audit-action-filter"),
  auditFromFilter: document.querySelector("#audit-from-filter"),
  auditToFilter: document.querySelector("#audit-to-filter"),
  auditExport: document.querySelector("#audit-export"),
  title: document.querySelector("#selected-node-title"),
  meta: document.querySelector("#selected-node-meta"),
  status: document.querySelector("#selected-node-status"),
  miniCpu: document.querySelector("#mini-cpu"),
  miniMemory: document.querySelector("#mini-memory"),
  miniDisk: document.querySelector("#mini-disk"),
  miniDocker: document.querySelector("#mini-docker"),
  metricSeries: document.querySelector("#metric-series"),
  metricRange: document.querySelector("#metric-range"),
  chartZoomReset: document.querySelector("#chart-zoom-reset"),
  thresholdCpu: document.querySelector("#threshold-cpu"),
  thresholdMemory: document.querySelector("#threshold-memory"),
  thresholdDisk: document.querySelector("#threshold-disk"),
  metricSummary: document.querySelector("#metric-summary"),
  chartContext: document.querySelector("#chart-context"),
  chart: document.querySelector("#metric-chart"),
  chartTooltip: document.querySelector("#chart-tooltip"),
  toast: document.querySelector("#toast"),
  commandDialog: document.querySelector("#command-dialog"),
  commandDialogMessage: document.querySelector("#command-dialog-message"),
  commandDialogCancel: document.querySelector("#command-dialog-cancel"),
  commandDialogConfirm: document.querySelector("#command-dialog-confirm"),
};

let commandDialogResolve = null;

const translations = {
  en: {
    "actions.refresh": "Refresh",
    "actions.restart": "Restart",
    "actions.start": "Start",
    "actions.stop": "Stop",
    "alerts.active": "Active",
    "alerts.alert": "Alert",
    "alerts.none": "No alerts.",
    "alerts.resolved": "Resolved",
    "alerts.title": "Alerts",
    "admin.activeAlerts": "Active Alerts",
    "admin.background": "Background",
    "admin.capacity": "Capacity",
    "admin.configPath": "Config path",
    "admin.configReloaded": "Config reloaded.",
    "admin.configReloadFailed": "Config reload failed: {message}",
    "admin.controls": "Controls",
    "admin.database": "Database",
    "admin.databaseDetails": "Database Details",
    "admin.degraded": "degraded",
    "admin.dbDailyRollups": "Daily rollups",
    "admin.dbHourlyRollups": "Hourly rollups",
    "admin.dbJournalMode": "Journal mode",
    "admin.dbNodes": "Nodes",
    "admin.dbOnlineNodes": "Online nodes",
    "admin.dbPath": "Path",
    "admin.dbPendingCommands": "Pending commands",
    "admin.dbRawMetrics": "Raw metrics",
    "admin.dbRevokedAgentTokens": "Revoked Agent tokens",
    "admin.dbSynchronous": "Synchronous",
    "admin.environment": "Environment",
    "admin.healthUnavailable": "Admin health is available to administrator roles only.",
    "admin.maintenanceBatch": "Maintenance batch",
    "admin.maintenanceDuration": "Last maintenance duration",
    "admin.maintenanceError": "Last maintenance error",
    "admin.maintenanceIdle": "idle",
    "admin.maintenanceLastRun": "Last maintenance",
    "admin.maintenanceRunning": "running",
    "admin.metricsMaintenance": "Metrics maintenance",
    "admin.pendingCommands": "pending commands",
    "admin.rawMetricsDays": "Raw metrics days",
    "admin.reloadConfig": "Reload config",
    "admin.reloadDescription": "Reload runtime auth config from the configured YAML file without restarting the server.",
    "admin.rollupInterval": "Rollup interval",
    "admin.runtimeConfig": "Runtime Config",
    "admin.status": "Status",
    "admin.statusWatcher": "status watcher",
    "admin.stopped": "stopped",
    "admin.subtitle": "Operational health and runtime controls",
    "admin.timeout": "Command timeout",
    "admin.watcherCycles": "Completed cycles",
    "admin.watcherFailures": "Watcher failures",
    "admin.watcherLastError": "Last watcher error",
    "admin.watcherLastSuccess": "Last watcher success",
    "admin.watcherRetry": "Next retry",
    "audit.action": "Action",
    "audit.exportCsv": "Export CSV",
    "audit.node": "Node",
    "audit.none": "No audit logs yet.",
    "auth.signOut": "Sign out",
    "brand.subtitle": "Control Plane",
    "chart.context": "{source} / {count} points",
    "chart.metricRequired": "Keep at least one metric visible.",
    "chart.metrics": "Metrics",
    "chart.noMetrics": "No metrics yet",
    "chart.range": "Time range",
    "chart.resetZoom": "Reset zoom",
    "chart.source.daily": "Daily aggregation",
    "chart.source.hourly": "Hourly aggregation",
    "chart.source.raw": "Raw samples",
    "chart.thresholds": "Thresholds",
    "chart.zoomed": "Zoomed",
    "commands.confirmMessage": "Confirm {action} for container {container} on node {node}. This command will be sent immediately.",
    "commands.none": "No commands yet.",
    "commands.selectNodeFirst": "Select a node first.",
    "containers.allStatuses": "All statuses",
    "containers.noMatches": "No containers match the current filters.",
    "containers.noneVisible": "No visible containers on the selected node.",
    "containers.readOnly": "read only",
    "containers.running": "Running",
    "containers.search": "Search name or image",
    "containers.stopped": "Stopped",
    "dialog.cancel": "Cancel",
    "dialog.confirm": "Confirm",
    "dialog.confirmCommand": "Confirm command",
    "docker.available": "Docker available",
    "docker.inventoryStale": "Container inventory stale",
    "docker.unavailable": "Docker unavailable",
    "empty.errorDetail": "The latest data could not be loaded.",
    "empty.errorTitle": "Data unavailable",
    "empty.loadingDetail": "Fetching the latest control-plane state.",
    "empty.loadingTitle": "Loading data",
    "empty.noAgentsDetail": "Agent data has not been received yet.",
    "empty.noAuditDetail": "No audit events match the current view.",
    "empty.noCommandsDetail": "No commands are recorded in the current window.",
    "empty.noContainersDetail": "The selected node has not reported any containers.",
    "empty.noAgentSummary": "No agent nodes to summarize.",
    "empty.retry": "Retry",
    "errors.commandFailed": "Command failed: {message}",
    "errors.invalidLogin": "Invalid username or password.",
    "errors.refreshFailed": "Refresh failed: {message}",
    "errors.sessionExpired": "Session expired. Sign in again.",
    "errors.signInFailed": "Sign in failed.",
    "header.eyebrow": "Distributed Monitoring",
    "header.title": "Server Dashboard",
    "insights.auditFailures": "Failures",
    "insights.auditSecurity": "Security",
    "insights.auditSources": "Sources",
    "insights.auditVisible": "Visible Logs",
    "insights.awaitingAgent": "awaiting agent",
    "insights.commandsActive": "In flight",
    "insights.commandsProblem": "Problem",
    "insights.commandsSuccess": "Success",
    "insights.commandsTotal": "Total",
    "insights.containersHot": "Hot CPU",
    "insights.containersRunning": "Running",
    "insights.containersStopped": "Stopped",
    "insights.containersVisible": "Visible",
    "insights.currentNode": "current node",
    "insights.failedTimeout": "failed / timeout",
    "insights.filteredResult": "filtered result",
    "insights.memoryUsed": "{value} used",
    "insights.needsAttention": "needs attention",
    "insights.recentWindow": "recent window",
    "insights.reviewFailures": "review first",
    "insights.scopeAll": "all nodes",
    "insights.scopeNode": "{node}",
    "insights.securityEvents": "security events",
    "insights.uniqueClients": "unique clients",
    "page.auditTitle": "Audit Logs",
    "page.adminTitle": "Admin / Health",
    "page.commandsTitle": "Commands",
    "page.containersTitle": "Containers",
    "page.overviewTitle": "Server Dashboard",
    "login.hint": "Development account: admin / dev-admin-password",
    "login.password": "Password",
    "login.signIn": "Sign in",
    "login.subtitle": "Linux and Docker control plane",
    "login.username": "Username",
    "metrics.avgMax": "Avg {avg} / Max {max}",
    "metrics.cpu": "CPU",
    "metrics.disk": "Disk",
    "metrics.memory": "Memory",
    "metrics.peak": "Peak {time}",
    "metrics.samples": "Samples: {count}",
    "metrics.tooltip": "{label}: avg {avg} / max {max} / peak {peak}",
    "range.1h": "Last hour",
    "range.24h": "Last 24 hours",
    "range.7d": "Last 7 days",
    "range.15d": "Last 15 days",
    "range.30d": "Last 30 days",
    "range.60d": "Last 60 days",
    "range.90d": "Last 90 days",
    "nav.audit": "Audit",
    "nav.admin": "Admin",
    "nav.commands": "Commands",
    "nav.containers": "Containers",
    "nav.overview": "Overview",
    "nav.short": "Nav",
    "node.alertCount": "{count} alerts",
    "node.available": "available",
    "node.lastSeen": "last seen {time}",
    "node.never": "never",
    "node.none": "No agents connected yet.",
    "node.unknown": "unknown",
    "node.unknownHost": "unknown host",
    "node.unknownNode": "unknown-node",
    "node.unknownOs": "unknown os",
    "node.unavailable": "unavailable",
    "nodes.noneSelected": "No node selected",
    "nodes.waiting": "Waiting for an agent connection",
    "panels.auditLogs": "Audit Logs",
    "panels.adminHealth": "Admin / Health",
    "panels.commands": "Commands",
    "panels.containers": "Containers",
    "panels.nodes": "Nodes",
    "readonly.role": "Read-only role",
    "sidebar.collapse": "Collapse navigation",
    "sidebar.expand": "Expand navigation",
    "sidebar.realtime": "Realtime",
    "stats.commands": "Commands",
    "stats.containers": "Containers",
    "stats.healthyConnections": "healthy connections",
    "stats.online": "Online",
    "stats.recentOperations": "recent operations",
    "stats.registeredAgents": "registered agents",
    "stats.totalNodes": "Total Nodes",
    "stats.visibleContainers": "visible containers",
    "table.actions": "Actions",
    "table.image": "Image",
    "table.name": "Name",
    "table.status": "Status",
    "theme.dark": "Dark",
    "theme.light": "Light",
    "toasts.commandSubmitted": "Command submitted.",
    "toasts.signedOut": "Signed out.",
    "toasts.thresholdsLocal": "Thresholds were kept locally.",
    "user.signedInAs": "Signed in as {username}{suffix}",
    "ws.connected": "connected",
    "ws.connecting": "connecting",
    "ws.disconnected": "disconnected",
  },
  zh: {
    "actions.refresh": "刷新",
    "actions.restart": "重启",
    "actions.start": "启动",
    "actions.stop": "停止",
    "alerts.active": "活跃",
    "alerts.alert": "告警",
    "alerts.none": "暂无告警。",
    "alerts.resolved": "已恢复",
    "alerts.title": "告警",
    "admin.activeAlerts": "活跃告警",
    "admin.background": "后台任务",
    "admin.capacity": "容量",
    "admin.configPath": "配置路径",
    "admin.configReloaded": "配置已重载。",
    "admin.configReloadFailed": "配置重载失败：{message}",
    "admin.controls": "控制",
    "admin.database": "数据库",
    "admin.databaseDetails": "数据库详情",
    "admin.degraded": "降级",
    "admin.dbDailyRollups": "天级汇总",
    "admin.dbHourlyRollups": "小时汇总",
    "admin.dbJournalMode": "日志模式",
    "admin.dbNodes": "节点",
    "admin.dbOnlineNodes": "在线节点",
    "admin.dbPath": "路径",
    "admin.dbPendingCommands": "待处理命令",
    "admin.dbRawMetrics": "原始指标",
    "admin.dbRevokedAgentTokens": "已吊销 Agent token",
    "admin.dbSynchronous": "同步级别",
    "admin.environment": "环境",
    "admin.healthUnavailable": "Admin Health 仅管理员角色可用。",
    "admin.maintenanceBatch": "维护批量",
    "admin.maintenanceDuration": "最近维护耗时",
    "admin.maintenanceError": "最近维护错误",
    "admin.maintenanceIdle": "空闲",
    "admin.maintenanceLastRun": "最近维护",
    "admin.maintenanceRunning": "运行中",
    "admin.metricsMaintenance": "指标维护",
    "admin.pendingCommands": "待处理命令",
    "admin.rawMetricsDays": "原始指标天数",
    "admin.reloadConfig": "重载配置",
    "admin.reloadDescription": "从配置 YAML 重载运行时认证配置，无需重启服务。",
    "admin.rollupInterval": "汇总间隔",
    "admin.runtimeConfig": "运行配置",
    "admin.status": "状态",
    "admin.statusWatcher": "状态 watcher",
    "admin.stopped": "已停止",
    "admin.subtitle": "运行健康状态与运行时控制",
    "admin.timeout": "命令超时",
    "admin.watcherCycles": "已完成循环",
    "admin.watcherFailures": "监视器失败次数",
    "admin.watcherLastError": "最近监视器错误",
    "admin.watcherLastSuccess": "最近监视器成功",
    "admin.watcherRetry": "下次重试",
    "audit.action": "操作",
    "audit.exportCsv": "导出 CSV",
    "audit.node": "节点",
    "audit.none": "暂无审计日志。",
    "auth.signOut": "退出登录",
    "brand.subtitle": "控制平面",
    "chart.context": "{source} / {count} 个数据点",
    "chart.metricRequired": "至少保留一个可见指标。",
    "chart.metrics": "指标",
    "chart.noMetrics": "暂无指标",
    "chart.range": "时间范围",
    "chart.resetZoom": "重置缩放",
    "chart.source.daily": "按天汇总",
    "chart.source.hourly": "按小时汇总",
    "chart.source.raw": "原始采样",
    "chart.thresholds": "告警阈值",
    "chart.zoomed": "已缩放",
    "commands.confirmMessage": "确认对节点 {node} 上的容器 {container} 执行 {action}？命令会立即发送。",
    "commands.none": "暂无命令。",
    "commands.selectNodeFirst": "请先选择节点。",
    "containers.allStatuses": "全部状态",
    "containers.noMatches": "没有匹配当前筛选条件的容器。",
    "containers.noneVisible": "当前节点暂无可见容器。",
    "containers.readOnly": "只读",
    "containers.running": "运行中",
    "containers.search": "搜索名称或镜像",
    "containers.stopped": "已停止",
    "dialog.cancel": "取消",
    "dialog.confirm": "确认",
    "dialog.confirmCommand": "确认命令",
    "docker.available": "Docker 可用",
    "docker.inventoryStale": "容器清单已过期",
    "docker.unavailable": "Docker 不可用",
    "empty.errorDetail": "暂时无法加载最新数据。",
    "empty.errorTitle": "数据不可用",
    "empty.loadingDetail": "正在获取控制面最新状态。",
    "empty.loadingTitle": "正在加载",
    "empty.noAgentsDetail": "尚未收到 Agent 数据。",
    "empty.noAuditDetail": "当前视图中没有匹配的审计事件。",
    "empty.noCommandsDetail": "当前时间范围内没有命令记录。",
    "empty.noContainersDetail": "所选节点尚未上报容器。",
    "empty.noAgentSummary": "暂无可汇总的 Agent 节点。",
    "empty.retry": "重试",
    "errors.commandFailed": "命令失败：{message}",
    "errors.invalidLogin": "用户名或密码错误。",
    "errors.refreshFailed": "刷新失败：{message}",
    "errors.sessionExpired": "会话已过期，请重新登录。",
    "errors.signInFailed": "登录失败。",
    "header.eyebrow": "分布式监控",
    "header.title": "服务端仪表盘",
    "insights.auditFailures": "失败",
    "insights.auditSecurity": "安全",
    "insights.auditSources": "来源",
    "insights.auditVisible": "可见日志",
    "insights.awaitingAgent": "等待 Agent",
    "insights.commandsActive": "执行中",
    "insights.commandsProblem": "异常",
    "insights.commandsSuccess": "成功",
    "insights.commandsTotal": "总数",
    "insights.containersHot": "高 CPU",
    "insights.containersRunning": "运行中",
    "insights.containersStopped": "已停止",
    "insights.containersVisible": "可见",
    "insights.currentNode": "当前节点",
    "insights.failedTimeout": "失败 / 超时",
    "insights.filteredResult": "筛选结果",
    "insights.memoryUsed": "已用 {value}",
    "insights.needsAttention": "需要关注",
    "insights.recentWindow": "近期窗口",
    "insights.reviewFailures": "优先排查",
    "insights.scopeAll": "全部节点",
    "insights.scopeNode": "{node}",
    "insights.securityEvents": "安全事件",
    "insights.uniqueClients": "独立来源",
    "page.auditTitle": "审计日志",
    "page.adminTitle": "管理 / 健康",
    "page.commandsTitle": "命令",
    "page.containersTitle": "容器",
    "page.overviewTitle": "服务端仪表盘",
    "login.hint": "开发账号：admin / dev-admin-password",
    "login.password": "密码",
    "login.signIn": "登录",
    "login.subtitle": "Linux 与 Docker 控制平面",
    "login.username": "用户名",
    "metrics.avgMax": "平均 {avg} / 最高 {max}",
    "metrics.cpu": "CPU",
    "metrics.disk": "磁盘",
    "metrics.memory": "内存",
    "metrics.peak": "峰值 {time}",
    "metrics.samples": "样本：{count}",
    "metrics.tooltip": "{label}：平均 {avg} / 最高 {max} / 峰值 {peak}",
    "range.1h": "近 1 小时",
    "range.24h": "近 24 小时",
    "range.7d": "近 7 天",
    "range.15d": "近 15 天",
    "range.30d": "近 30 天",
    "range.60d": "近 60 天",
    "range.90d": "近 90 天",
    "nav.audit": "审计",
    "nav.admin": "管理",
    "nav.commands": "命令",
    "nav.containers": "容器",
    "nav.overview": "概览",
    "nav.short": "导航",
    "node.alertCount": "{count} 条告警",
    "node.available": "可用",
    "node.lastSeen": "最后在线 {time}",
    "node.never": "从未",
    "node.none": "暂无 Agent 连接。",
    "node.unknown": "未知",
    "node.unknownHost": "未知主机",
    "node.unknownNode": "未知节点",
    "node.unknownOs": "未知系统",
    "node.unavailable": "不可用",
    "nodes.noneSelected": "未选择节点",
    "nodes.waiting": "等待 Agent 连接",
    "panels.auditLogs": "审计日志",
    "panels.adminHealth": "管理 / 健康",
    "panels.commands": "命令",
    "panels.containers": "容器",
    "panels.nodes": "节点",
    "readonly.role": "当前角色只读",
    "sidebar.collapse": "收起导航",
    "sidebar.expand": "展开导航",
    "sidebar.realtime": "实时状态",
    "stats.commands": "命令",
    "stats.containers": "容器",
    "stats.healthyConnections": "健康连接",
    "stats.online": "在线",
    "stats.recentOperations": "近期操作",
    "stats.registeredAgents": "已注册 Agent",
    "stats.totalNodes": "节点总数",
    "stats.visibleContainers": "可见容器",
    "table.actions": "操作",
    "table.image": "镜像",
    "table.name": "名称",
    "table.status": "状态",
    "theme.dark": "深色",
    "theme.light": "浅色",
    "toasts.commandSubmitted": "命令已提交。",
    "toasts.signedOut": "已退出登录。",
    "toasts.thresholdsLocal": "阈值已保留在本地。",
    "user.signedInAs": "当前用户 {username}{suffix}",
    "ws.connected": "已连接",
    "ws.connecting": "连接中",
    "ws.disconnected": "已断开",
  },
};

els.loginForm.addEventListener("submit", login);
els.logout.addEventListener("click", () => logout());
els.sidebarToggle.addEventListener("click", toggleSidebar);
els.mobileNavToggle.addEventListener("click", toggleMobileSidebar);
els.sidebarScrim.addEventListener("click", closeMobileSidebar);
els.navLinks.forEach((link) => link.addEventListener("click", changePage));
els.refresh.addEventListener("click", refreshAll);
els.alertsToggle.addEventListener("click", toggleAlertPanel);
els.themeToggle.addEventListener("click", toggleTheme);
els.languageSelect.addEventListener("change", changeLanguage);
els.metricRange.addEventListener("change", changeMetricRange);
els.metricSeries.addEventListener("click", toggleMetricSeries);
els.chartZoomReset.addEventListener("click", () => resetMetricZoom());
els.thresholdCpu.addEventListener("input", () => updateThreshold("cpu", els.thresholdCpu.value));
els.thresholdMemory.addEventListener("input", () => updateThreshold("memory", els.thresholdMemory.value));
els.thresholdDisk.addEventListener("input", () => updateThreshold("disk", els.thresholdDisk.value));
els.auditNodeFilter.addEventListener("input", updateAuditFilters);
els.auditActionFilter.addEventListener("input", updateAuditFilters);
els.auditFromFilter.addEventListener("input", updateAuditFilters);
els.auditToFilter.addEventListener("input", updateAuditFilters);
els.auditExport.addEventListener("click", exportAuditCsv);
els.adminReloadConfig.addEventListener("click", reloadConfig);
els.containerSearch.addEventListener("input", updateContainerFilters);
els.containerStatusFilter.addEventListener("change", updateContainerFilters);
els.chart.addEventListener("pointerdown", startChartSelection);
els.chart.addEventListener("pointermove", updateChartSelection);
els.chart.addEventListener("pointerup", finishChartSelection);
els.chart.addEventListener("pointercancel", cancelChartSelection);
els.chart.addEventListener("mousemove", showChartTooltip);
els.chart.addEventListener("mouseleave", hideChartTooltip);
els.commandDialogCancel.addEventListener("click", () => closeCommandDialog(false));
els.commandDialogConfirm.addEventListener("click", () => closeCommandDialog(true));
els.commandDialog.addEventListener("click", (event) => {
  if (event.target === els.commandDialog) closeCommandDialog(false);
});
window.addEventListener("hashchange", () => setPage(window.location.hash.slice(1) || "overview"));
window.addEventListener("resize", () => {
  clearTimeout(state.chartResizeTimer);
  state.chartResizeTimer = setTimeout(() => {
    applySidebarState();
    renderChart(metricsForChart());
  }, 120);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && isCompactNavigation() && !state.sidebarCollapsed) {
    closeMobileSidebar();
    return;
  }
  if (event.key === "Escape" && !els.commandDialog.classList.contains("is-hidden")) {
    closeCommandDialog(false);
  }
});

applyLanguage();
applyTheme();
applySidebarState();
applyPage();
boot();

async function boot() {
  localStorage.removeItem("monitor.sessionToken");
  localStorage.removeItem("monitor.username");
  renderMetricControls();

  try {
    const profile = await api("/api/auth/me");
    applyAuthProfile(profile);
    await loadServerThresholds();
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch {
    showLogin();
  }
}

async function login(event) {
  event.preventDefault();
  const username = els.username.value.trim();
  const password = els.password.value;

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      throw new Error(t("errors.invalidLogin"));
    }
    const data = await response.json();
    applyAuthProfile(data);
    await loadServerThresholds();
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch (error) {
    showToast(error.message || t("errors.signInFailed"));
  }
}

function logout(showMessage = true) {
  const csrfToken = state.csrfToken;
  clearTimeout(state.wsReconnectTimer);
  state.wsReconnectTimer = null;
  state.wsReconnectAttempts = 0;
  const websocket = state.ws;
  state.ws = null;
  if (websocket) websocket.close();
  clearInterval(state.refreshTimer);
  state.username = "";
  state.csrfToken = "";
  state.role = "";
  state.scopes = [];
  state.nodes = [];
  state.containers = [];
  state.commands = [];
  state.auditLogs = [];
  state.alerts = [];
  state.metrics = [];
  state.metricPayload = null;
  state.hasLoaded = false;
  state.isLoading = false;
  state.refreshError = "";
  state.containerFilters = { query: "", status: "all" };
  els.containerSearch.value = "";
  els.containerStatusFilter.value = "all";
  state.chartModel = null;
  clearTimeout(state.thresholdSaveTimer);
  clearTimeout(state.auditFilterTimer);
  fetch("/api/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    headers: csrfHeaders("POST", csrfToken),
  }).catch(() => {});
  localStorage.removeItem("monitor.sessionToken");
  localStorage.removeItem("monitor.username");
  showLogin();
  if (showMessage) showToast(t("toasts.signedOut"));
}

function showLogin() {
  if (!state.sidebarCollapsed) {
    state.sidebarCollapsed = true;
    applySidebarState();
  }
  els.loginView.classList.remove("is-hidden");
  els.appView.classList.add("is-hidden");
}

function showApp() {
  els.loginView.classList.add("is-hidden");
  els.appView.classList.remove("is-hidden");
  syncAdminVisibility();
  applyPage();
  const suffix = state.role ? ` / ${state.role}` : "";
  els.currentUser.textContent = state.username
    ? t("user.signedInAs", { username: state.username, suffix })
    : "";
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  localStorage.setItem("monitor.theme", state.theme);
  applyTheme();
  renderChart(metricsForChart());
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  els.themeToggle.textContent = state.theme === "dark" ? t("theme.light") : t("theme.dark");
}

function toggleSidebar() {
  setSidebarCollapsed(!state.sidebarCollapsed);
}

function toggleMobileSidebar() {
  const opening = state.sidebarCollapsed;
  setSidebarCollapsed(!opening);
  if (opening) {
    requestAnimationFrame(() => els.navLinks[0]?.focus());
  }
}

function closeMobileSidebar() {
  if (state.sidebarCollapsed) return;
  setSidebarCollapsed(true);
  els.mobileNavToggle.focus();
}

function setSidebarCollapsed(collapsed) {
  state.sidebarCollapsed = Boolean(collapsed);
  localStorage.setItem("monitor.sidebarCollapsed", state.sidebarCollapsed ? "true" : "false");
  applySidebarState();
}

function changePage(event) {
  event.preventDefault();
  const page = event.currentTarget.dataset.pageLink;
  setPage(page);
  if (isCompactNavigation()) {
    setSidebarCollapsed(true);
  }
}

function setPage(page) {
  const nextPage = normalizePage(page);
  state.currentPage = nextPage;
  localStorage.setItem("monitor.currentPage", nextPage);
  if (window.location.hash !== `#${nextPage}`) {
    window.history.replaceState(null, "", `#${nextPage}`);
  }
  applyPage();
}

function applyPage() {
  if (state.currentPage === "admin" && !hasScope("*")) {
    state.currentPage = "overview";
    localStorage.setItem("monitor.currentPage", state.currentPage);
    if (window.location.hash === "#admin") {
      window.history.replaceState(null, "", "#overview");
    }
  }
  const currentPage = normalizePage(state.currentPage);
  state.currentPage = currentPage;
  els.pages.forEach((page) => {
    page.classList.toggle("is-hidden", page.dataset.page !== currentPage);
  });
  els.navLinks.forEach((link) => {
    const active = link.dataset.pageLink === currentPage;
    link.classList.toggle("active", active);
    link.setAttribute("aria-current", active ? "page" : "false");
  });
  const titleKey = `page.${currentPage}Title`;
  els.pageTitle.textContent = t(titleKey);
  renderChart(metricsForChart());
}

function applySidebarState() {
  els.appView.classList.toggle("sidebar-collapsed", state.sidebarCollapsed);
  const compact = isCompactNavigation();
  const mobileOpen = compact && !state.sidebarCollapsed && !els.appView.classList.contains("is-hidden");
  els.sidebarToggle.setAttribute(
    "aria-label",
    state.sidebarCollapsed ? t("sidebar.expand") : t("sidebar.collapse"),
  );
  els.sidebarToggle.title = state.sidebarCollapsed ? t("sidebar.expand") : t("sidebar.collapse");
  els.sidebarToggle.dataset.label = t("nav.short");
  els.mobileNavToggle.setAttribute("aria-expanded", mobileOpen ? "true" : "false");
  els.mobileNavToggle.setAttribute(
    "aria-label",
    mobileOpen ? t("sidebar.collapse") : t("sidebar.expand"),
  );
  els.mobileNavToggle.title = mobileOpen ? t("sidebar.collapse") : t("sidebar.expand");
  els.sidebarScrim.setAttribute("aria-label", t("sidebar.collapse"));
  els.sidebarScrim.classList.toggle("is-hidden", !mobileOpen);
  document.body.classList.toggle("mobile-nav-open", mobileOpen);
}

function isCompactNavigation() {
  return window.matchMedia("(max-width: 1050px)").matches;
}

function applyAuthProfile(profile) {
  state.username = profile.username || "";
  state.csrfToken = profile.csrf_token || "";
  state.role = profile.role || "";
  state.scopes = Array.isArray(profile.scopes) ? profile.scopes : [];
  syncAdminVisibility();
}

function syncAdminVisibility() {
  const isAdmin = hasScope("*");
  els.navLinks.forEach((link) => {
    if (link.dataset.pageLink === "admin") {
      link.classList.toggle("is-hidden", !isAdmin);
    }
  });
}

function changeLanguage() {
  state.language = els.languageSelect.value === "zh" ? "zh" : "en";
  localStorage.setItem("monitor.language", state.language);
  applyLanguage();
  applyTheme();
  applySidebarState();
  applyPage();
  if (state.username) {
    showApp();
  }
  renderMetricControls();
  if (!els.appView.classList.contains("is-hidden")) {
    render();
  }
}

function applyLanguage() {
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
  els.languageSelect.value = state.language;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.placeholder = t(element.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((element) => {
    element.title = t(element.dataset.i18nTitle);
  });
}

function t(key, values = {}) {
  const table = translations[state.language] || translations.en;
  const template = table[key] || translations.en[key] || key;
  return template.replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ""));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...csrfHeaders(options.method),
      ...(options.headers || {}),
    },
  });
  if (response.status === 401) {
    logout(false);
    throw new Error(t("errors.sessionExpired"));
  }
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function csrfHeaders(method = "GET", token = state.csrfToken) {
  const normalized = String(method || "GET").toUpperCase();
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(normalized) || !token) {
    return {};
  }
  return { "X-CSRF-Token": token };
}

function connectWs() {
  clearTimeout(state.wsReconnectTimer);
  state.wsReconnectTimer = null;
  if (state.ws) {
    state.ws.close();
  }
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/ui`;
  const ws = new WebSocket(url);
  state.ws = ws;
  setWsState("connecting");

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "auth" }));
  });
  ws.addEventListener("close", () => {
    if (state.ws !== ws) return;
    setWsState("disconnected");
    scheduleWsReconnect(ws);
  });
  ws.addEventListener("message", (event) => {
    const message = safeJson(event.data);
    if (message?.type === "auth_ok") {
      state.wsReconnectAttempts = 0;
      setWsState("connected");
      return;
    }
    if (message?.type === "alert_created") {
      showToast(alertTitle(message.alert, t("alerts.alert")));
    }
    if (message?.type === "alert_resolved") {
      showToast(alertTitle(message.alert, t("alerts.resolved")));
    }
    if (message?.type === "thresholds_updated" && message.thresholds) {
      state.thresholds = normalizeThresholdPayload(message.thresholds);
      localStorage.setItem("monitor.thresholds", JSON.stringify(state.thresholds));
      renderMetricControls();
      renderChart(metricsForChart());
    }
    refreshAll();
  });
}

function scheduleWsReconnect(ws) {
  if (!state.username || state.ws !== ws || state.wsReconnectTimer) return;
  const attempt = Math.min(state.wsReconnectAttempts, 5);
  const baseDelay = Math.min(30000, 1000 * (2 ** attempt));
  const delay = Math.round(baseDelay * (0.8 + (Math.random() * 0.4)));
  state.wsReconnectAttempts += 1;
  state.wsReconnectTimer = setTimeout(() => {
    state.wsReconnectTimer = null;
    if (state.username && state.ws === ws) {
      state.ws = null;
      connectWs();
    }
  }, delay);
}

function setWsState(value) {
  els.wsState.textContent = t(`ws.${value}`);
}

async function refreshAll() {
  if (!state.username) return;

  const firstLoad = !state.hasLoaded;
  if (firstLoad) {
    state.isLoading = true;
    state.refreshError = "";
    render();
  }
  els.refresh.disabled = true;

  try {
    const [nodes, commands, auditLogs, alerts, adminHealth] = await Promise.all([
      api("/api/nodes"),
      api("/api/commands?limit=50"),
      api(auditLogPath()),
      api("/api/alerts?limit=30"),
      hasScope("*") ? api("/api/admin/health").catch(() => null) : Promise.resolve(null),
    ]);
    state.nodes = nodes;
    state.commands = commands;
    state.auditLogs = auditLogs;
    state.alerts = alerts;
    state.adminHealth = adminHealth;

    if (!state.selectedNodeId && nodes.length) {
      selectNode(nodes[0].id, false);
    }
    if (state.selectedNodeId && !nodes.some((node) => node.id === state.selectedNodeId)) {
      selectNode(nodes[0]?.id || null, false);
    }

    const containerPath = state.selectedNodeId
      ? `/api/containers?node_id=${encodeURIComponent(state.selectedNodeId)}`
      : "/api/containers";
    state.containers = await api(containerPath);
    state.metricPayload = state.selectedNodeId
      ? await api(`/api/nodes/${encodeURIComponent(state.selectedNodeId)}/metrics?range=${encodeURIComponent(state.metricRange)}`)
      : null;
    state.metrics = state.metricPayload?.points || [];
    state.hasLoaded = true;
    state.isLoading = false;
    state.refreshError = "";
    render();
  } catch (error) {
    state.isLoading = false;
    state.refreshError = error.message || t("empty.errorDetail");
    if (!state.hasLoaded) render();
    showToast(t("errors.refreshFailed", { message: error.message }));
  } finally {
    els.refresh.disabled = false;
  }
}

function selectNode(nodeId, shouldRefresh = true) {
  if (state.selectedNodeId !== nodeId) {
    clearMetricZoom();
  }
  state.selectedNodeId = nodeId;
  if (nodeId) {
    localStorage.setItem("monitor.selectedNodeId", nodeId);
  } else {
    localStorage.removeItem("monitor.selectedNodeId");
  }
  if (shouldRefresh) refreshAll();
}

function render() {
  renderOverview();
  renderAlerts();
  renderPageInsights();
  renderNodes();
  renderSelectedNode();
  renderMetricControls();
  renderMetricSummary();
  renderChart(metricsForChart());
  renderContainers();
  renderEvents();
  renderAdminHealth();
}

function renderPageInsights() {
  renderContainerInsights();
  renderCommandInsights();
  renderAuditInsights();
}

function renderContainerInsights() {
  const running = state.containers.filter((container) => String(container.status || "").toLowerCase() === "running").length;
  const stopped = state.containers.length - running;
  const cpuThreshold = Number(state.thresholds.cpu ?? 80);
  const hot = state.containers.filter((container) => Number(container.cpu_percent || 0) >= cpuThreshold).length;
  const memoryUsed = state.containers.reduce((total, container) => total + Number(container.memory_usage || 0), 0);
  const selectedNode = state.nodes.find((node) => node.id === state.selectedNodeId);

  els.containersTotal.textContent = state.containers.length;
  els.containersRunningCount.textContent = running;
  els.containersStoppedCount.textContent = stopped;
  els.containersHotCount.textContent = hot;
  els.containersMemoryTotal.textContent = t("insights.memoryUsed", { value: bytes(memoryUsed) });
  els.containersScope.textContent = selectedNode
    ? t("insights.scopeNode", { node: selectedNode.name || selectedNode.id })
    : t("insights.scopeAll");
}

function renderCommandInsights() {
  const activeStatuses = new Set(["pending", "sent", "acknowledged", "running"]);
  const problemStatuses = new Set(["failed", "send_failed", "timeout"]);
  const success = state.commands.filter((command) => command.status === "success").length;
  const active = state.commands.filter((command) => activeStatuses.has(command.status)).length;
  const problem = state.commands.filter((command) => problemStatuses.has(command.status)).length;
  const latest = state.commands[0];

  els.commandsTotal.textContent = state.commands.length;
  els.commandsSuccessCount.textContent = success;
  els.commandsActiveCount.textContent = active;
  els.commandsProblemCount.textContent = problem;
  els.commandsLatestStatus.textContent = latest ? `${latest.action} / ${latest.status}` : "-";
}

function renderAuditInsights() {
  const security = state.auditLogs.filter((item) => String(item.event_type || "").includes("security")).length;
  const failures = state.auditLogs.filter((item) => {
    const result = String(item.result || "").toLowerCase();
    return result && !["success", "ok", "allowed"].includes(result);
  }).length;
  const sources = new Set(
    state.auditLogs
      .map((item) => String(item.client_ip || "").trim())
      .filter(Boolean),
  );

  els.auditTotal.textContent = state.auditLogs.length;
  els.auditSecurityCount.textContent = security;
  els.auditSourceCount.textContent = sources.size;
  els.auditFailureCount.textContent = failures;
}

function renderAdminHealth() {
  if (!hasScope("*")) {
    state.adminHealth = null;
    els.adminHealthStatus.textContent = "-";
    els.adminHealthVersion.textContent = t("admin.healthUnavailable");
    els.adminDbMode.textContent = "-";
    els.adminDbPath.textContent = "-";
    els.adminWatcherStatus.textContent = "-";
    els.adminActiveAlerts.textContent = "0";
    els.adminPendingCommands.textContent = pendingCommandsText(0);
    setDetailList(els.adminDbDetails, []);
    setDetailList(els.adminConfigDetails, []);
    setDetailList(els.adminCapacityDetails, []);
    els.adminControlDetails.replaceChildren(createTextBlock("p", "empty", t("admin.healthUnavailable")));
    els.adminReloadConfig.disabled = true;
    return;
  }

  els.adminReloadConfig.disabled = false;
  const health = state.adminHealth || {};
  const database = health.database || {};
  const background = health.background || {};
  const config = health.config || {};
  const watcherRunning = Boolean(background.status_watcher);
  const watcherHealth = background.status_watcher_health || {};
  const watcherDegraded = watcherRunning && Number(watcherHealth.consecutive_failures || 0) > 0;
  const maintenance = background.metrics_maintenance || {};

  els.adminHealthStatus.textContent = health.status || "-";
  els.adminHealthVersion.textContent = health.version ? `v${health.version}` : "-";
  els.adminDbMode.textContent = database.journal_mode || "-";
  els.adminDbPath.textContent = compactPath(database.path);
  els.adminWatcherStatus.textContent = watcherRunning
    ? (watcherDegraded ? t("admin.degraded") : "ok")
    : t("admin.stopped");
  els.adminActiveAlerts.textContent = database.active_alerts ?? 0;
  els.adminPendingCommands.textContent = pendingCommandsText(database.pending_commands ?? 0);

  setDetailList(els.adminDbDetails, [
    [t("admin.dbPath"), database.path || "-"],
    [t("admin.dbJournalMode"), database.journal_mode || "-"],
    [t("admin.dbSynchronous"), database.synchronous ?? "-"],
    [t("admin.dbPendingCommands"), database.pending_commands ?? 0],
    [t("admin.metricsMaintenance"), maintenance.running ? t("admin.maintenanceRunning") : t("admin.maintenanceIdle")],
    [t("admin.maintenanceLastRun"), formatDateTime(maintenance.last_completed_at)],
    [t("admin.maintenanceDuration"), maintenance.last_duration_ms == null ? "-" : `${maintenance.last_duration_ms} ms`],
    [t("admin.maintenanceError"), maintenance.last_error || "-"],
  ]);
  setDetailList(els.adminConfigDetails, [
    [t("admin.environment"), config.environment || "-"],
    [t("admin.configPath"), config.config_path || "-"],
    [t("admin.timeout"), seconds(config.command_timeout_seconds)],
    [t("admin.rollupInterval"), seconds(config.rollup_interval_seconds)],
    [t("admin.rawMetricsDays"), days(config.raw_metrics_days)],
    [t("admin.maintenanceBatch"), config.maintenance_batch_size ?? "-"],
  ]);
  setDetailList(els.adminCapacityDetails, [
    [t("admin.dbNodes"), database.nodes ?? 0],
    [t("admin.dbOnlineNodes"), database.online_nodes ?? 0],
    [t("admin.dbRawMetrics"), database.raw_metrics ?? 0],
    [t("admin.dbHourlyRollups"), database.hourly_rollups ?? 0],
    [t("admin.dbDailyRollups"), database.daily_rollups ?? 0],
    [t("admin.dbRevokedAgentTokens"), database.revoked_agent_tokens ?? 0],
  ]);
  const watcherDetails = document.createElement("dl");
  watcherDetails.className = "detail-list";
  setDetailList(watcherDetails, [
    [t("admin.watcherCycles"), watcherHealth.cycles_completed ?? 0],
    [t("admin.watcherFailures"), watcherHealth.total_failures ?? 0],
    [t("admin.watcherLastSuccess"), formatDateTime(watcherHealth.last_success_at)],
    [t("admin.watcherLastError"), watcherHealth.last_failure_error || "-"],
    [t("admin.watcherRetry"), seconds(watcherHealth.next_retry_seconds)],
  ]);
  els.adminControlDetails.replaceChildren(
    createTextBlock("p", "", t("admin.reloadDescription")),
    watcherDetails,
  );
}

function setDetailList(target, rows) {
  target.replaceChildren();
  if (!rows.length) return;
  rows.forEach(([label, value]) => {
    const term = createTextBlock("dt", "", label);
    const detail = createTextBlock("dd", "", value);
    target.append(term, detail);
  });
}

function renderOverview() {
  els.nodeCount.textContent = state.nodes.length;
  els.onlineCount.textContent = state.nodes.filter((node) => node.status === "online").length;
  els.containerCount.textContent = state.containers.length;
  els.commandCount.textContent = state.commands.length;
  renderNodeOverview();
}

function renderNodeOverview() {
  els.nodeOverview.replaceChildren();
  if (!state.nodes.length) {
    els.nodeOverview.appendChild(createDataEmptyState(
      t("empty.noAgentSummary"),
      t("empty.noAgentsDetail"),
    ));
    return;
  }

  state.nodes.forEach((node) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = `node-overview-card ${statusClass(node.status)}${node.id === state.selectedNodeId ? " active" : ""}`;
    card.dataset.nodeId = String(node.id || "");
    card.addEventListener("click", () => selectNode(card.dataset.nodeId));

    const header = document.createElement("span");
    header.className = "node-overview-header";
    header.append(
      createTextBlock("strong", "", node.name || node.id || t("node.unknownNode")),
      createTextBlock("span", `status-chip ${statusClass(node.status)}`, node.status || t("node.unknown")),
    );

    const meta = createTextBlock(
      "span",
      "node-overview-meta",
      `${node.hostname || t("node.unknownHost")} / ${node.os || t("node.unknownOs")}`,
    );

    const rings = document.createElement("span");
    rings.className = "node-ring-row";
    rings.append(
      createMetricRing("CPU", node.latest_cpu_percent, "blue"),
      createMetricRing("MEM", node.latest_memory_percent, "green"),
      createMetricRing("DISK", node.latest_disk_percent, "yellow"),
    );

    const nodeAlerts = state.alerts.filter((alert) => alert.status === "active" && alert.node_id === node.id);
    const footer = document.createElement("span");
    footer.className = "node-overview-footer";
    const dockerState = createTextBlock("span", "", dockerStatusText(node));
    dockerState.title = node.docker_inventory_error || "";
    footer.append(
      dockerState,
      createTextBlock("span", nodeAlerts.length ? "alert-mini active" : "alert-mini", t("node.alertCount", { count: nodeAlerts.length })),
    );

    card.append(header, meta, rings, footer);
    els.nodeOverview.appendChild(card);
  });
}

function createMetricRing(label, value, tone) {
  const number = Number(value);
  const normalized = Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
  const ring = document.createElement("span");
  ring.className = `metric-ring ${tone}`;
  ring.style.setProperty("--value", `${normalized}`);
  ring.append(
    createTextBlock("strong", "", Number.isFinite(number) ? `${number.toFixed(0)}%` : "-"),
    createTextBlock("em", "", label),
  );
  return ring;
}

function renderAlerts() {
  const active = state.alerts.filter((alert) => alert.status === "active");
  els.alertCount.textContent = active.length;
  els.alertsToggle.classList.toggle("has-alerts", active.length > 0);
  els.alertPanel.replaceChildren();
  if (!state.alerts.length) {
    els.alertPanel.appendChild(createTextBlock("div", "empty", t("alerts.none")));
    return;
  }
  state.alerts.slice(0, 8).forEach((alert) => {
    const item = document.createElement("div");
    item.className = `alert-item ${statusClass(alert.status)}`;
    item.append(
      createTextBlock("strong", "", alertTitle(alert, alert.status === "active" ? t("alerts.active") : t("alerts.resolved"))),
      createTextBlock("span", "", `${formatDateTime(alert.triggered_at)} / value ${percent(alert.value)}`),
    );
    els.alertPanel.appendChild(item);
  });
}

function toggleAlertPanel() {
  els.alertPanel.classList.toggle("is-hidden");
}

function renderMetricControls() {
  const canManageThresholds = hasScope("*");
  els.metricRange.value = state.metricRange;
  els.metricSeries.querySelectorAll("[data-metric]").forEach((button) => {
    button.setAttribute("aria-pressed", String(state.visibleMetrics.includes(button.dataset.metric)));
  });
  els.chartZoomReset.classList.toggle("is-hidden", !state.metricZoom);
  els.thresholdCpu.value = state.thresholds.cpu ?? "";
  els.thresholdMemory.value = state.thresholds.memory ?? "";
  els.thresholdDisk.value = state.thresholds.disk ?? "";
  [els.thresholdCpu, els.thresholdMemory, els.thresholdDisk].forEach((input) => {
    input.disabled = !canManageThresholds;
    input.title = canManageThresholds ? "" : t("readonly.role");
  });
  renderChartContext();
}

function changeMetricRange(event) {
  const nextRange = String(event.target.value || "");
  if (!METRIC_RANGES.has(nextRange) || nextRange === state.metricRange) return;
  state.metricRange = nextRange;
  clearMetricZoom();
  localStorage.setItem("monitor.metricRange", state.metricRange);
  renderMetricControls();
  refreshAll();
}

function toggleMetricSeries(event) {
  const button = event.target.closest("[data-metric]");
  const metric = button?.dataset.metric;
  if (!METRIC_KEYS.includes(metric)) return;

  const isVisible = state.visibleMetrics.includes(metric);
  if (isVisible && state.visibleMetrics.length === 1) {
    showToast(t("chart.metricRequired"));
    return;
  }

  state.visibleMetrics = METRIC_KEYS.filter((key) => (
    key === metric ? !isVisible : state.visibleMetrics.includes(key)
  ));
  localStorage.setItem("monitor.visibleMetrics", JSON.stringify(state.visibleMetrics));
  hideChartTooltip();
  renderMetricControls();
  renderMetricSummary();
  renderChart(metricsForChart());
}

function renderChartContext() {
  if (!els.chartContext) return;
  const bucket = state.metricPayload?.bucket || (state.metricRange === "1h" ? "raw" : "hour");
  const sourceKey = bucket === "day" ? "daily" : bucket === "hour" ? "hourly" : "raw";
  const context = t("chart.context", {
    source: t(`chart.source.${sourceKey}`),
    count: metricsForChart().length,
  });
  els.chartContext.textContent = state.metricZoom ? `${context} / ${t("chart.zoomed")}` : context;
}

function updateAuditFilters() {
  state.auditFilters = {
    nodeId: els.auditNodeFilter.value.trim(),
    action: els.auditActionFilter.value.trim(),
    from: els.auditFromFilter.value,
    to: els.auditToFilter.value,
  };
  clearTimeout(state.auditFilterTimer);
  state.auditFilterTimer = setTimeout(refreshAll, 350);
}

function auditLogPath() {
  const params = new URLSearchParams({ limit: "50" });
  if (state.auditFilters.nodeId) params.set("node_id", state.auditFilters.nodeId);
  if (state.auditFilters.action) params.set("action", state.auditFilters.action);
  const from = localDateTimeToIso(state.auditFilters.from);
  const to = localDateTimeToIso(state.auditFilters.to);
  if (from) params.set("from", from);
  if (to) params.set("to", to);
  return `/api/audit-logs?${params.toString()}`;
}

function updateContainerFilters() {
  state.containerFilters = {
    query: els.containerSearch.value.trim().toLowerCase(),
    status: els.containerStatusFilter.value || "all",
  };
  renderContainers();
}

function updateThreshold(metric, rawValue) {
  const value = String(rawValue).trim();
  if (value === "") {
    state.thresholds[metric] = null;
  } else {
    const number = Number(value);
    state.thresholds[metric] = Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : null;
  }
  localStorage.setItem("monitor.thresholds", JSON.stringify(state.thresholds));
  scheduleThresholdSave();
  renderChart(metricsForChart());
}

async function loadServerThresholds() {
  try {
    const payload = await api("/api/settings/thresholds");
    if (payload.configured) {
      state.thresholds = normalizeThresholdPayload(payload.thresholds || {});
      localStorage.setItem("monitor.thresholds", JSON.stringify(state.thresholds));
      return;
    }
    if (hasScope("*")) {
      state.thresholds = loadThresholds();
      await saveThresholds();
      return;
    }
    state.thresholds = normalizeThresholdPayload(payload.thresholds || {});
    localStorage.setItem("monitor.thresholds", JSON.stringify(state.thresholds));
  } catch {
    state.thresholds = loadThresholds();
  } finally {
    renderMetricControls();
  }
}

function scheduleThresholdSave() {
  clearTimeout(state.thresholdSaveTimer);
  state.thresholdSaveTimer = setTimeout(() => {
    saveThresholds().catch(() => showToast(t("toasts.thresholdsLocal")));
  }, 450);
}

async function saveThresholds() {
  await api("/api/settings/thresholds", {
    method: "PUT",
    body: JSON.stringify(state.thresholds),
  });
}

async function reloadConfig() {
  if (!hasScope("*")) {
    showToast(t("admin.healthUnavailable"));
    return;
  }

  els.adminReloadConfig.disabled = true;
  try {
    await api("/api/admin/config/reload", { method: "POST" });
    state.adminHealth = await api("/api/admin/health");
    renderAdminHealth();
    showToast(t("admin.configReloaded"));
  } catch (error) {
    showToast(t("admin.configReloadFailed", { message: error.message }));
  } finally {
    els.adminReloadConfig.disabled = false;
  }
}

function renderMetricSummary() {
  els.metricSummary.replaceChildren();
  const summary = state.metricZoom ? summarizeMetrics(metricsForChart()) : state.metricPayload?.summary;
  metricDefinitions().forEach(({ id, label }) => {
    const item = summary?.[id];
    const card = document.createElement("div");
    card.className = `summary-item ${id}`;
    card.append(
      createTextBlock("span", "", label),
      createTextBlock("strong", "", t("metrics.avgMax", { avg: percent(item?.avg), max: percent(item?.max) })),
      createTextBlock("em", "", t("metrics.peak", { time: formatDateTime(item?.peak_at) })),
    );
    els.metricSummary.appendChild(card);
  });
}

function metricDefinitions() {
  const definitions = [
    {
      id: "cpu",
      label: t("metrics.cpu"),
      key: "cpu_percent",
      avgKey: "cpu_avg",
      maxKey: "cpu_max",
      peakKey: "cpu_peak_at",
      color: cssVar("--blue") || "#1a73e8",
      threshold: state.thresholds.cpu,
    },
    {
      id: "memory",
      label: t("metrics.memory"),
      key: "memory_percent",
      avgKey: "memory_avg",
      maxKey: "memory_max",
      peakKey: "memory_peak_at",
      color: cssVar("--green") || "#188038",
      threshold: state.thresholds.memory,
    },
    {
      id: "disk",
      label: t("metrics.disk"),
      key: "disk_percent",
      avgKey: "disk_avg",
      maxKey: "disk_max",
      peakKey: "disk_peak_at",
      color: cssVar("--yellow") || "#f9ab00",
      threshold: state.thresholds.disk,
    },
  ];
  return definitions.filter((definition) => state.visibleMetrics.includes(definition.id));
}

function renderNodes() {
  els.nodes.replaceChildren();
  if (!state.nodes.length) {
    els.nodes.appendChild(createDataEmptyState(t("node.none"), t("empty.noAgentsDetail"), true));
    return;
  }

  state.nodes.forEach((node) => {
    const button = document.createElement("button");
    button.className = `node-item${node.id === state.selectedNodeId ? " active" : ""}`;
    button.type = "button";
    button.dataset.nodeId = String(node.id || "");
    button.addEventListener("click", () => selectNode(button.dataset.nodeId));

    const nameRow = document.createElement("span");
    nameRow.className = "node-name-row";
    nameRow.append(
      createTextBlock("span", "node-name", node.name || node.id),
      createTextBlock("span", `status-chip ${statusClass(node.status)}`, node.status || t("node.unknown")),
    );

    const meta = createTextBlock(
      "span",
      "node-meta",
      `${node.hostname || t("node.unknownHost")} / ${node.os || t("node.unknownOs")}`,
    );

    const metricRow = document.createElement("span");
    metricRow.className = "node-metrics-row";
    metricRow.append(
      createTextBlock("span", "", `CPU ${percent(node.latest_cpu_percent)}`),
      createTextBlock("span", "", `MEM ${percent(node.latest_memory_percent)}`),
      createTextBlock("span", "", `DISK ${percent(node.latest_disk_percent)}`),
    );

    button.append(nameRow, meta, metricRow);
    els.nodes.appendChild(button);
  });
}

function renderSelectedNode() {
  const node = state.nodes.find((item) => item.id === state.selectedNodeId);
  if (!node) {
    els.title.textContent = t("nodes.noneSelected");
    els.meta.textContent = t("nodes.waiting");
    els.status.textContent = t("node.unknown");
    els.status.className = "status-chip neutral";
    els.miniCpu.textContent = "-";
    els.miniMemory.textContent = "-";
    els.miniDisk.textContent = "-";
    els.miniDocker.textContent = "-";
    return;
  }

  els.title.textContent = node.name || node.id;
  els.meta.textContent = `${node.id} / ${node.hostname || t("node.unknownHost")} / ${t("node.lastSeen", { time: node.last_seen || t("node.never") })}`;
  els.status.textContent = node.status || t("node.unknown");
  els.status.className = `status-chip ${statusClass(node.status)}`;
  els.miniCpu.textContent = percent(node.latest_cpu_percent);
  els.miniMemory.textContent = percent(node.latest_memory_percent);
  els.miniDisk.textContent = percent(node.latest_disk_percent);
  els.miniDocker.textContent = node.docker_inventory_status === "stale"
    ? t("docker.inventoryStale")
    : node.docker_available
      ? node.docker_version || t("node.available")
      : t("node.unavailable");
  els.miniDocker.title = node.docker_inventory_error || "";
}

function dockerStatusText(node) {
  if (node.docker_inventory_status === "stale") return t("docker.inventoryStale");
  return node.docker_available ? t("docker.available") : t("docker.unavailable");
}

function renderChart(metrics) {
  const canvas = els.chart;
  const surface = resizeChartCanvas(canvas);
  if (!surface) return;
  const { ctx, width, height } = surface;
  const left = 56;
  const right = width - 20;
  const top = 38;
  const bottom = height - 44;
  const colors = chartColors();
  const series = metricDefinitions();
  const points = buildChartPoints(metrics, left, right);

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = colors.bg;
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = colors.grid;
  ctx.lineWidth = 1;
  ctx.fillStyle = colors.text;
  ctx.font = "12px system-ui";
  for (let i = 0; i <= 4; i += 1) {
    const value = 100 - i * 25;
    const y = yForValue(value, top, bottom);
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
    ctx.stroke();
    ctx.textAlign = "right";
    ctx.fillText(`${value}%`, left - 10, y + 4);
  }

  drawTimeAxis(ctx, points, left, right, bottom);
  drawThresholds(ctx, series, left, right, top, bottom);
  state.chartModel = {
    left,
    right,
    top,
    bottom,
    points,
    series,
  };
  renderChartContext();

  if (!metrics.length) {
    ctx.fillStyle = colors.text;
    ctx.font = "14px system-ui";
    ctx.textAlign = "left";
    ctx.fillText(t("chart.noMetrics"), left, 86);
    return;
  }

  series.forEach((definition) => drawSeries(ctx, points, definition, top, bottom, series.length === 1));
  drawChartHover(ctx, points, series, top, bottom);
  drawChartSelection(ctx, left, right, top, bottom);
}

function resizeChartCanvas(canvas) {
  const rect = canvas.getBoundingClientRect();
  const width = Math.round(rect.width);
  const height = Math.round(rect.height);
  if (width < 280 || height < 220) return null;
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  const pixelWidth = Math.round(width * ratio);
  const pixelHeight = Math.round(height * ratio);
  if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
  if (canvas.height !== pixelHeight) canvas.height = pixelHeight;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  return { ctx, width, height };
}

function buildChartPoints(metrics, left, right) {
  const timestamps = metrics.map(pointTime);
  const validTimes = timestamps.filter((value) => value !== null);
  const minimum = validTimes.length ? Math.min(...validTimes) : null;
  const maximum = validTimes.length ? Math.max(...validTimes) : null;
  return metrics.map((point, index) => {
    const timestamp = timestamps[index];
    const ratio = timestamp !== null && minimum !== null && maximum !== null && maximum > minimum
      ? (timestamp - minimum) / (maximum - minimum)
      : index / Math.max(1, metrics.length - 1);
    return { point, x: left + (right - left) * ratio };
  });
}

function drawSeries(ctx, points, definition, top, bottom, fillArea) {
  const coordinates = points.flatMap(({ point, x }) => {
    const value = metricNumber(point[definition.key] ?? point[definition.avgKey]);
    return Number.isFinite(value) ? [{ x, y: yForValue(value, top, bottom) }] : [];
  });
  if (!coordinates.length) return;

  ctx.save();
  if (fillArea && coordinates.length > 1) {
    const gradient = ctx.createLinearGradient(0, top, 0, bottom);
    gradient.addColorStop(0, colorWithAlpha(definition.color, 0.18));
    gradient.addColorStop(1, colorWithAlpha(definition.color, 0.015));
    ctx.beginPath();
    ctx.moveTo(coordinates[0].x, bottom);
    ctx.lineTo(coordinates[0].x, coordinates[0].y);
    traceSmoothLine(ctx, coordinates);
    ctx.lineTo(coordinates.at(-1).x, bottom);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();
  }

  ctx.beginPath();
  ctx.moveTo(coordinates[0].x, coordinates[0].y);
  traceSmoothLine(ctx, coordinates);
  ctx.strokeStyle = definition.color;
  ctx.lineWidth = 2.5;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.shadowColor = colorWithAlpha(definition.color, 0.18);
  ctx.shadowBlur = 5;
  ctx.stroke();
  ctx.shadowBlur = 0;

  if (coordinates.length <= 40) {
    coordinates.forEach(({ x, y }) => {
      ctx.beginPath();
      ctx.arc(x, y, 2.4, 0, Math.PI * 2);
      ctx.fillStyle = chartColors().bg;
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = definition.color;
      ctx.stroke();
    });
  }
  ctx.restore();
}

function traceSmoothLine(ctx, coordinates) {
  if (coordinates.length < 2) return;
  for (let index = 1; index < coordinates.length; index += 1) {
    const previous = coordinates[index - 1];
    const current = coordinates[index];
    const midpointX = (previous.x + current.x) / 2;
    const midpointY = (previous.y + current.y) / 2;
    ctx.quadraticCurveTo(previous.x, previous.y, midpointX, midpointY);
  }
  const last = coordinates.at(-1);
  ctx.lineTo(last.x, last.y);
}

function drawThresholds(ctx, items, left, right, top, bottom) {
  ctx.save();
  items.forEach((item) => {
    const threshold = Number(item.threshold);
    if (!Number.isFinite(threshold)) return;
    const y = yForValue(threshold, top, bottom);
    ctx.strokeStyle = colorWithAlpha(item.color, 0.62);
    ctx.lineWidth = 1.4;
    ctx.setLineDash([6, 5]);
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = item.color;
    ctx.font = "12px system-ui";
    ctx.textAlign = "right";
    ctx.fillText(`${item.label} ${threshold}%`, right, y - 7);
  });
  ctx.restore();
}

function drawTimeAxis(ctx, points, left, right, bottom) {
  const colors = chartColors();
  ctx.save();
  ctx.strokeStyle = colors.grid;
  ctx.fillStyle = colors.text;
  ctx.lineWidth = 1;
  ctx.font = "12px system-ui";
  ctx.textBaseline = "top";

  ctx.beginPath();
  ctx.moveTo(left, bottom);
  ctx.lineTo(right, bottom);
  ctx.stroke();

  pickAxisIndexes(points.length).forEach((index) => {
    const item = points[index];
    const x = item.x;
    ctx.beginPath();
    ctx.moveTo(x, bottom);
    ctx.lineTo(x, bottom + 6);
    ctx.stroke();

    if (index === 0) ctx.textAlign = "left";
    else if (index === points.length - 1) ctx.textAlign = "right";
    else ctx.textAlign = "center";
    ctx.fillText(formatAxisLabel(item.point?.captured_at || item.point?.bucket_start), x, bottom + 10);
  });

  ctx.restore();
}

function drawChartHover(ctx, points, series, top, bottom) {
  if (state.chartHoverX === null || !points.length || state.chartSelection) return;
  const nearest = nearestChartPoint(points, state.chartHoverX);
  if (!nearest) return;
  const colors = chartColors();

  ctx.save();
  ctx.strokeStyle = colors.hover;
  ctx.lineWidth = 1;
  ctx.setLineDash([3, 4]);
  ctx.beginPath();
  ctx.moveTo(nearest.x, top);
  ctx.lineTo(nearest.x, bottom);
  ctx.stroke();
  ctx.setLineDash([]);

  series.forEach((definition) => {
    const value = metricNumber(nearest.point[definition.key] ?? nearest.point[definition.avgKey]);
    if (!Number.isFinite(value)) return;
    const y = yForValue(value, top, bottom);
    ctx.beginPath();
    ctx.arc(nearest.x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = colors.bg;
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = definition.color;
    ctx.stroke();
  });
  ctx.restore();
}

function pickAxisIndexes(length) {
  if (!length) return [];
  if (length === 1) return [0];
  const count = Math.min(5, length);
  const indexes = new Set();
  for (let i = 0; i < count; i += 1) {
    indexes.add(Math.round((i * (length - 1)) / (count - 1)));
  }
  return [...indexes].sort((a, b) => a - b);
}

function drawChartSelection(ctx, left, right, top, bottom) {
  const selection = state.chartSelection;
  if (!selection) return;
  const start = clamp(selection.startX, left, right);
  const end = clamp(selection.currentX, left, right);
  const x = Math.min(start, end);
  const width = Math.abs(end - start);
  if (width < 2) return;

  ctx.save();
  ctx.fillStyle = cssVar("--chart-selection") || "rgba(26, 115, 232, 0.14)";
  ctx.strokeStyle = cssVar("--blue") || "#1a73e8";
  ctx.lineWidth = 1.5;
  ctx.setLineDash([5, 4]);
  ctx.fillRect(x, top, width, bottom - top);
  ctx.strokeRect(x, top, width, bottom - top);
  ctx.restore();
}

function metricsForChart() {
  const metrics = state.metrics || [];
  if (!state.metricZoom) return metrics;
  const filtered = metrics.filter((point) => {
    const timestamp = pointTime(point);
    return timestamp !== null && timestamp >= state.metricZoom.start && timestamp <= state.metricZoom.end;
  });
  return filtered.length ? filtered : metrics;
}

function clearMetricZoom() {
  state.metricZoom = null;
  state.chartSelection = null;
  hideChartTooltip();
}

function resetMetricZoom() {
  clearMetricZoom();
  renderMetricControls();
  renderMetricSummary();
  renderChart(state.metrics);
}

function startChartSelection(event) {
  const model = state.chartModel;
  if (!model || model.points.length < 2) return;
  const x = chartEventX(event);
  if (x < model.left || x > model.right) return;
  state.chartSelection = { startX: x, currentX: x };
  els.chart.setPointerCapture?.(event.pointerId);
  hideChartTooltip();
  event.preventDefault();
}

function updateChartSelection(event) {
  if (!state.chartSelection || !state.chartModel) return;
  state.chartSelection.currentX = chartEventX(event);
  renderChart(metricsForChart());
  event.preventDefault();
}

function finishChartSelection(event) {
  if (!state.chartSelection || !state.chartModel) return;
  state.chartSelection.currentX = chartEventX(event);
  const selection = state.chartSelection;
  const start = Math.min(selection.startX, selection.currentX);
  const end = Math.max(selection.startX, selection.currentX);
  const selected = pointsBetweenX(state.chartModel.points, start, end);

  state.chartSelection = null;
  els.chart.releasePointerCapture?.(event.pointerId);
  if (selected.length >= 2 && Math.abs(end - start) >= 12) {
    const timestamps = selected.map((item) => pointTime(item.point)).filter((value) => value !== null);
    if (timestamps.length >= 2) {
      state.metricZoom = {
        start: Math.min(...timestamps),
        end: Math.max(...timestamps),
      };
    }
  }
  renderMetricControls();
  renderMetricSummary();
  renderChart(metricsForChart());
  event.preventDefault();
}

function cancelChartSelection(event) {
  if (!state.chartSelection) return;
  state.chartSelection = null;
  els.chart.releasePointerCapture?.(event.pointerId);
  renderChart(metricsForChart());
}

function pointsBetweenX(points, start, end) {
  const selected = points.filter((item) => item.x >= start && item.x <= end);
  if (selected.length) return selected;
  const midpoint = (start + end) / 2;
  return [nearestChartPoint(points, midpoint)].filter(Boolean);
}

function nearestChartPoint(points, x) {
  if (!points.length) return null;
  return points.reduce((best, item) => (
    Math.abs(item.x - x) < Math.abs(best.x - x) ? item : best
  ));
}

function chartEventX(event) {
  const rect = els.chart.getBoundingClientRect();
  return event.clientX - rect.left;
}

function pointTime(point) {
  const date = new Date(point?.captured_at || point?.bucket_start || "");
  return Number.isNaN(date.getTime()) ? null : date.getTime();
}

function summarizeMetrics(metrics) {
  return {
    cpu: summarizeMetric(metrics, "cpu"),
    memory: summarizeMetric(metrics, "memory"),
    disk: summarizeMetric(metrics, "disk"),
  };
}

function summarizeMetric(metrics, prefix) {
  let weightedTotal = 0;
  let sampleTotal = 0;
  let maxValue = null;
  let peakAt = null;

  metrics.forEach((point) => {
    const avg = metricNumber(point[`${prefix}_avg`] ?? point[`${prefix}_percent`]);
    const sampleCount = Number(point.sample_count || 1);
    if (Number.isFinite(avg) && sampleCount > 0) {
      weightedTotal += avg * sampleCount;
      sampleTotal += sampleCount;
    }

    const peak = metricNumber(point[`${prefix}_max`] ?? point[`${prefix}_percent`]);
    if (Number.isFinite(peak) && (maxValue === null || peak > maxValue)) {
      maxValue = peak;
      peakAt = point[`${prefix}_peak_at`] || point.captured_at || point.bucket_start;
    }
  });

  return {
    avg: sampleTotal ? weightedTotal / sampleTotal : null,
    max: maxValue,
    peak_at: peakAt,
  };
}

function metricNumber(value) {
  if (value === null || value === undefined || value === "") return NaN;
  return Number(value);
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function formatAxisLabel(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  if (state.metricRange === "1h") {
    return date.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" });
  }
  if (state.metricRange === "24h") {
    return date.toLocaleString(locale(), { month: "2-digit", day: "2-digit", hour: "2-digit" });
  }
  return date.toLocaleDateString(locale(), { month: "2-digit", day: "2-digit" });
}

function yForValue(value, top, bottom) {
  const bounded = Math.min(100, Math.max(0, Number(value) || 0));
  return bottom - ((bottom - top) * bounded) / 100;
}

function renderContainers() {
  els.containers.replaceChildren();
  if (!state.containers.length) {
    const row = document.createElement("tr");
    row.className = "table-empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.appendChild(createDataEmptyState(
      t("containers.noneVisible"),
      t("empty.noContainersDetail"),
    ));
    row.appendChild(cell);
    els.containers.appendChild(row);
    return;
  }

  const filtered = state.containers.filter(containerMatchesFilters);
  if (!filtered.length) {
    const row = document.createElement("tr");
    row.className = "table-empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.appendChild(createEmptyState(t("containers.noMatches"), ""));
    row.appendChild(cell);
    els.containers.appendChild(row);
    return;
  }

  filtered.forEach((container) => {
    const row = document.createElement("tr");
    const name = createTextBlock("td", "name-cell", container.name || container.container_id);
    name.title = String(container.container_id || "");
    setTableCellLabel(name, t("table.name"));

    const statusCell = document.createElement("td");
    setTableCellLabel(statusCell, t("table.status"));
    statusCell.appendChild(createTextBlock("span", `status-chip ${statusClass(container.status)}`, container.status || "-"));

    const actions = createContainerActions(container);
    setTableCellLabel(actions, t("table.actions"));
    const image = createTextBlock("td", "", container.image || "-");
    const cpu = createTextBlock("td", "", percent(container.cpu_percent));
    const memory = createTextBlock(
      "td",
      "",
      `${bytes(container.memory_usage)}${container.memory_limit ? ` / ${bytes(container.memory_limit)}` : ""}`,
    );
    setTableCellLabel(image, t("table.image"));
    setTableCellLabel(cpu, t("metrics.cpu"));
    setTableCellLabel(memory, t("metrics.memory"));

    row.append(
      name,
      image,
      statusCell,
      cpu,
      memory,
      actions,
    );
    els.containers.appendChild(row);
  });
}

function setTableCellLabel(cell, label) {
  cell.dataset.label = String(label || "");
}

function createContainerActions(container) {
  const actions = document.createElement("td");
  if (!hasScope("commands:create")) {
    actions.appendChild(createTextBlock("span", "status-chip neutral", t("containers.readOnly")));
    return actions;
  }

  const actionRow = document.createElement("div");
  actionRow.className = "action-row";
  actionRow.append(
    createActionButton(t("actions.start"), "container.start", container),
    createActionButton(t("actions.stop"), "container.stop", container, "danger"),
    createActionButton(t("actions.restart"), "container.restart", container),
  );
  actions.appendChild(actionRow);
  return actions;
}

function containerMatchesFilters(container) {
  const query = state.containerFilters.query;
  if (query) {
    const haystack = [
      container.name,
      container.image,
      container.container_id,
      container.status,
    ]
      .map((value) => String(value || "").toLowerCase())
      .join(" ");
    if (!haystack.includes(query)) return false;
  }

  if (state.containerFilters.status === "running") {
    return String(container.status || "").toLowerCase() === "running";
  }
  if (state.containerFilters.status === "stopped") {
    return String(container.status || "").toLowerCase() !== "running";
  }
  return true;
}

function createActionButton(label, action, container, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.dataset.action = action;
  button.dataset.container = String(container.container_id || "");
  button.addEventListener("click", () => sendCommand(button.dataset.action, button.dataset.container));
  return button;
}

async function sendCommand(action, containerId) {
  if (!state.selectedNodeId) {
    showToast(t("commands.selectNodeFirst"));
    return;
  }
  const confirmed = await confirmCommand(action, containerId);
  if (!confirmed) return;

  try {
    await api(`/api/nodes/${encodeURIComponent(state.selectedNodeId)}/commands`, {
      method: "POST",
      body: JSON.stringify({
        action,
        payload: { container_id: containerId },
      }),
    });
    showToast(t("toasts.commandSubmitted"));
    await refreshAll();
  } catch (error) {
    showToast(t("errors.commandFailed", { message: error.message }));
  }
}

function confirmCommand(action, containerId) {
  const container = state.containers.find((item) => String(item.container_id) === String(containerId));
  const node = state.nodes.find((item) => item.id === state.selectedNodeId);
  const actionKey = action.replace("container.", "");
  const actionLabel = t(`actions.${actionKey}`);
  const containerLabel = container?.name || containerId;
  const nodeLabel = node?.name || state.selectedNodeId;
  const destructive = action.endsWith(".stop") || action.endsWith(".restart");
  if (commandDialogResolve) {
    closeCommandDialog(false);
  }
  els.commandDialogMessage.textContent = t("commands.confirmMessage", {
    action: actionLabel,
    container: containerLabel,
    node: nodeLabel,
  });
  els.commandDialogConfirm.textContent = actionLabel;
  els.commandDialogConfirm.className = destructive ? "danger" : "";
  els.commandDialog.classList.remove("is-hidden");
  els.commandDialogConfirm.focus();
  return new Promise((resolve) => {
    commandDialogResolve = resolve;
  });
}

function closeCommandDialog(confirmed) {
  els.commandDialog.classList.add("is-hidden");
  if (commandDialogResolve) {
    commandDialogResolve(Boolean(confirmed));
    commandDialogResolve = null;
  }
}

function renderEvents() {
  renderEventList(
    els.commands,
    state.commands,
    (item) => `${item.action} / ${item.status}`,
    (item) => `${item.node_id} / ${item.created_at} / ${item.result_message || ""}`,
    t("commands.none"),
    t("empty.noCommandsDetail"),
  );
  renderEventList(
    els.auditLogs,
    state.auditLogs,
    (item) => `${item.action} / ${item.result || ""}`,
    (item) => `${item.user} / ${item.node_id || "-"} / ${item.client_ip || "-"} / ${item.created_at}`,
    t("audit.none"),
    t("empty.noAuditDetail"),
  );
}

function exportAuditCsv() {
  const headers = ["created_at", "event_type", "action", "result", "actor", "user", "node_id", "target", "client_ip"];
  const rows = state.auditLogs.map((item) => headers.map((key) => csvCell(item[key])));
  const csv = [headers.join(","), ...rows.map((row) => row.join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `monitor-audit-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function renderEventList(target, items, title, detail, emptyText, emptyDetail) {
  target.replaceChildren();
  if (!items.length) {
    target.appendChild(createDataEmptyState(emptyText, emptyDetail));
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "event-item";
    row.append(
      createTextBlock("strong", "", title(item)),
      createTextBlock("span", "", detail(item)),
    );
    target.appendChild(row);
  });
}

function createDataEmptyState(title, detail, compact = false) {
  if (state.isLoading) {
    return createEmptyState(t("empty.loadingTitle"), t("empty.loadingDetail"), {
      compact,
      variant: "loading",
    });
  }
  if (state.refreshError && !state.hasLoaded) {
    return createEmptyState(t("empty.errorTitle"), t("empty.errorDetail"), {
      action: t("empty.retry"),
      compact,
      variant: "error",
    });
  }
  return createEmptyState(title, detail, { compact });
}

function createEmptyState(title, detail, options = {}) {
  const container = document.createElement("div");
  const variant = options.variant || "neutral";
  container.className = `empty-state ${variant}${options.compact ? " compact" : ""}`;

  const marker = document.createElement("span");
  marker.className = "empty-state-marker";
  marker.setAttribute("aria-hidden", "true");

  const copy = document.createElement("div");
  copy.className = "empty-state-copy";
  copy.appendChild(createTextBlock("strong", "", title));
  if (detail) copy.appendChild(createTextBlock("span", "", detail));
  container.append(marker, copy);

  if (options.action) {
    const action = createTextBlock("button", "empty-state-action", options.action);
    action.type = "button";
    action.addEventListener("click", refreshAll);
    container.appendChild(action);
  }
  return container;
}

function createTextBlock(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  element.textContent = String(text ?? "");
  return element;
}

function statusClass(value) {
  if (String(value || "").toLowerCase() === "send_failed") return "failed";
  const allowed = new Set([
    "online",
    "warning",
    "offline",
    "success",
    "running",
    "pending",
    "sent",
    "acknowledged",
    "active",
    "resolved",
    "failed",
    "timeout",
    "exited",
  ]);
  const normalized = String(value || "neutral").toLowerCase();
  return allowed.has(normalized) ? normalized : "neutral";
}

function safeJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function showChartTooltip(event) {
  if (state.chartSelection) return;
  const model = state.chartModel;
  if (!model || !model.points.length) {
    hideChartTooltip();
    return;
  }

  const rect = els.chart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const nearest = nearestChartPoint(model.points, x);
  state.chartHoverX = nearest.x;
  renderChart(metricsForChart());

  const point = nearest.point;
  const tooltipLines = [
    createTextBlock("strong", "", formatBucket(point)),
    createTextBlock("span", "", t("metrics.samples", { count: point.sample_count || 0 })),
    ...metricDefinitions().map((definition) => createTextBlock(
      "span",
      "",
      metricTooltipLine(
        definition.label,
        point[definition.avgKey] ?? point[definition.key],
        point[definition.maxKey] ?? point[definition.key],
        point[definition.peakKey] ?? point.captured_at ?? point.bucket_start,
      ),
    )),
  ];
  els.chartTooltip.replaceChildren(...tooltipLines);
  els.chartTooltip.classList.remove("is-hidden");
  const tooltipWidth = Math.min(300, Math.max(220, rect.width - 24));
  let left = event.clientX - rect.left + 14;
  if (left + tooltipWidth > rect.width - 12) {
    left = event.clientX - rect.left - tooltipWidth - 14;
  }
  els.chartTooltip.style.left = `${Math.max(12, left)}px`;
  els.chartTooltip.style.top = `${Math.max(12, event.clientY - rect.top - 24)}px`;
}

function hideChartTooltip() {
  els.chartTooltip.classList.add("is-hidden");
  if (state.chartHoverX !== null) {
    state.chartHoverX = null;
    renderChart(metricsForChart());
  }
}

function metricTooltipLine(label, avg, max, peakAt) {
  return t("metrics.tooltip", {
    label,
    avg: percent(avg),
    max: percent(max),
    peak: formatDateTime(peakAt),
  });
}

function formatBucket(point) {
  if (state.metricRange === "1h") return formatDateTime(point.captured_at);
  const start = formatDateTime(point.bucket_start);
  const end = formatDateTime(point.bucket_end);
  return `${start} - ${end}`;
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(locale());
}

function seconds(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  return `${number}s`;
}

function days(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  return `${number}d`;
}

function pendingCommandsText(value) {
  return `${value} ${t("admin.pendingCommands")}`;
}

function compactPath(value) {
  const text = String(value || "");
  if (!text) return "-";
  const parts = text.split(/[\\/]/).filter(Boolean);
  if (parts.length <= 2) return text;
  return `.../${parts.slice(-2).join("/")}`;
}

function loadThresholds() {
  const fallback = { cpu: 60, memory: 80, disk: 85 };
  const raw = localStorage.getItem("monitor.thresholds");
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return {
      cpu: normalizeThreshold(parsed.cpu, fallback.cpu),
      memory: normalizeThreshold(parsed.memory, fallback.memory),
      disk: normalizeThreshold(parsed.disk, fallback.disk),
    };
  } catch {
    return fallback;
  }
}

function loadTheme() {
  const stored = localStorage.getItem("monitor.theme");
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function loadLanguage() {
  const stored = localStorage.getItem("monitor.language");
  if (stored === "zh" || stored === "en") return stored;
  return navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";
}

function loadMetricRange() {
  const stored = localStorage.getItem("monitor.metricRange");
  return METRIC_RANGES.has(stored) ? stored : "1h";
}

function loadVisibleMetrics() {
  try {
    const parsed = JSON.parse(localStorage.getItem("monitor.visibleMetrics") || "[]");
    const metrics = METRIC_KEYS.filter((key) => parsed.includes(key));
    return metrics.length ? metrics : [...METRIC_KEYS];
  } catch {
    return [...METRIC_KEYS];
  }
}

function loadPage() {
  return normalizePage(window.location.hash.slice(1) || localStorage.getItem("monitor.currentPage"));
}

function normalizePage(page) {
  const allowed = new Set(["overview", "containers", "commands", "audit", "admin"]);
  return allowed.has(page) ? page : "overview";
}

function loadSidebarCollapsed() {
  const stored = localStorage.getItem("monitor.sidebarCollapsed");
  if (stored === "false") return false;
  return true;
}

function locale() {
  return state.language === "zh" ? "zh-CN" : "en";
}

function chartColors() {
  return {
    bg: cssVar("--chart-bg") || "#ffffff",
    grid: cssVar("--chart-grid") || "#e0e3eb",
    text: cssVar("--chart-text") || "#5f6368",
    ink: cssVar("--chart-ink") || "#202124",
    hover: cssVar("--chart-hover") || "rgba(95, 99, 104, 0.5)",
  };
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function colorWithAlpha(color, alpha) {
  const value = String(color || "").trim();
  const shortHex = /^#([0-9a-f]{3})$/i.exec(value);
  const longHex = /^#([0-9a-f]{6})$/i.exec(value);
  const rgb = /^rgba?\((\d+)[, ]+(\d+)[, ]+(\d+)/i.exec(value);
  let channels = null;
  if (shortHex) {
    channels = [...shortHex[1]].map((channel) => parseInt(channel + channel, 16));
  } else if (longHex) {
    channels = [0, 2, 4].map((offset) => parseInt(longHex[1].slice(offset, offset + 2), 16));
  } else if (rgb) {
    channels = rgb.slice(1, 4).map(Number);
  }
  return channels ? `rgba(${channels.join(", ")}, ${alpha})` : value;
}

function normalizeThresholdPayload(value) {
  const fallback = { cpu: 60, memory: 80, disk: 85 };
  const payload = value || {};
  return {
    cpu: normalizeThreshold(payload.cpu, fallback.cpu),
    memory: normalizeThreshold(payload.memory, fallback.memory),
    disk: normalizeThreshold(payload.disk, fallback.disk),
  };
}

function normalizeThreshold(value, fallback) {
  if (value === null) return null;
  if (value === undefined) return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : fallback;
}

function localDateTimeToIso(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function alertTitle(alert, prefix) {
  if (!alert) return prefix;
  const metric = String(alert.metric || "metric").toUpperCase();
  const operator = alert.status === "resolved" ? "<=" : ">";
  return `${prefix}: ${alert.node_id || "-"} ${metric} ${percent(alert.value)} ${operator} ${percent(alert.threshold)}`;
}

function hasScope(scope) {
  return state.scopes.includes("*") || state.scopes.includes(scope);
}

function percent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "-";
  return `${Number(value).toFixed(1)}%`;
}

function bytes(value) {
  const number = Number(value || 0);
  if (!number) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = number;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
}

let toastTimer = null;
function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove("show"), 3200);
}
