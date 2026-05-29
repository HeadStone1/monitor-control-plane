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
  metrics: [],
  metricPayload: null,
  metricRange: localStorage.getItem("monitor.metricRange") || "1h",
  theme: loadTheme(),
  thresholds: loadThresholds(),
  auditFilters: { nodeId: "", action: "", from: "", to: "" },
  containerFilters: { query: "", status: "all" },
  metricZoom: null,
  chartSelection: null,
  chartModel: null,
  selectedNodeId: localStorage.getItem("monitor.selectedNodeId") || null,
  ws: null,
  refreshTimer: null,
  thresholdSaveTimer: null,
  auditFilterTimer: null,
};

const els = {
  loginView: document.querySelector("#login-view"),
  appView: document.querySelector("#app-view"),
  loginForm: document.querySelector("#login-form"),
  username: document.querySelector("#login-username"),
  password: document.querySelector("#login-password"),
  logout: document.querySelector("#logout"),
  refresh: document.querySelector("#refresh"),
  wsState: document.querySelector("#ws-state"),
  currentUser: document.querySelector("#current-user"),
  nodeCount: document.querySelector("#node-count"),
  onlineCount: document.querySelector("#online-count"),
  containerCount: document.querySelector("#container-count"),
  commandCount: document.querySelector("#command-count"),
  alertCount: document.querySelector("#alert-count"),
  alertsToggle: document.querySelector("#alerts-toggle"),
  alertPanel: document.querySelector("#alert-panel"),
  themeToggle: document.querySelector("#theme-toggle"),
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
  metricRange: document.querySelector("#metric-range"),
  chartZoomReset: document.querySelector("#chart-zoom-reset"),
  thresholdCpu: document.querySelector("#threshold-cpu"),
  thresholdMemory: document.querySelector("#threshold-memory"),
  thresholdDisk: document.querySelector("#threshold-disk"),
  metricSummary: document.querySelector("#metric-summary"),
  chart: document.querySelector("#metric-chart"),
  chartTooltip: document.querySelector("#chart-tooltip"),
  toast: document.querySelector("#toast"),
  commandDialog: document.querySelector("#command-dialog"),
  commandDialogMessage: document.querySelector("#command-dialog-message"),
  commandDialogCancel: document.querySelector("#command-dialog-cancel"),
  commandDialogConfirm: document.querySelector("#command-dialog-confirm"),
};

let commandDialogResolve = null;

els.loginForm.addEventListener("submit", login);
els.logout.addEventListener("click", () => logout());
els.refresh.addEventListener("click", refreshAll);
els.alertsToggle.addEventListener("click", toggleAlertPanel);
els.themeToggle.addEventListener("click", toggleTheme);
els.metricRange.addEventListener("click", changeMetricRange);
els.chartZoomReset.addEventListener("click", () => resetMetricZoom());
els.thresholdCpu.addEventListener("input", () => updateThreshold("cpu", els.thresholdCpu.value));
els.thresholdMemory.addEventListener("input", () => updateThreshold("memory", els.thresholdMemory.value));
els.thresholdDisk.addEventListener("input", () => updateThreshold("disk", els.thresholdDisk.value));
els.auditNodeFilter.addEventListener("input", updateAuditFilters);
els.auditActionFilter.addEventListener("input", updateAuditFilters);
els.auditFromFilter.addEventListener("input", updateAuditFilters);
els.auditToFilter.addEventListener("input", updateAuditFilters);
els.auditExport.addEventListener("click", exportAuditCsv);
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
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.commandDialog.classList.contains("is-hidden")) {
    closeCommandDialog(false);
  }
});

applyTheme();
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
      throw new Error("Invalid username or password.");
    }
    const data = await response.json();
    applyAuthProfile(data);
    await loadServerThresholds();
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch (error) {
    showToast(error.message || "Sign in failed.");
  }
}

function logout(showMessage = true) {
  const csrfToken = state.csrfToken;
  if (state.ws) {
    state.ws.close();
  }
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
  if (showMessage) showToast("Signed out.");
}

function showLogin() {
  els.loginView.classList.remove("is-hidden");
  els.appView.classList.add("is-hidden");
}

function showApp() {
  els.loginView.classList.add("is-hidden");
  els.appView.classList.remove("is-hidden");
  const suffix = state.role ? ` / ${state.role}` : "";
  els.currentUser.textContent = state.username ? `Signed in as ${state.username}${suffix}` : "";
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  localStorage.setItem("monitor.theme", state.theme);
  applyTheme();
  renderChart(metricsForChart());
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  els.themeToggle.textContent = state.theme === "dark" ? "Light" : "Dark";
}

function applyAuthProfile(profile) {
  state.username = profile.username || "";
  state.csrfToken = profile.csrf_token || "";
  state.role = profile.role || "";
  state.scopes = Array.isArray(profile.scopes) ? profile.scopes : [];
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
    throw new Error("Session expired. Sign in again.");
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
    setWsState("disconnected");
    if (state.username) {
      setTimeout(() => {
        if (state.ws === ws) connectWs();
      }, 3000);
    }
  });
  ws.addEventListener("message", (event) => {
    const message = safeJson(event.data);
    if (message?.type === "auth_ok") {
      setWsState("connected");
      return;
    }
    if (message?.type === "alert_created") {
      showToast(alertTitle(message.alert, "Alert"));
    }
    if (message?.type === "alert_resolved") {
      showToast(alertTitle(message.alert, "Resolved"));
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

function setWsState(value) {
  els.wsState.textContent = value;
}

async function refreshAll() {
  if (!state.username) return;

  try {
    const [nodes, commands, auditLogs, alerts] = await Promise.all([
      api("/api/nodes"),
      api("/api/commands?limit=50"),
      api(auditLogPath()),
      api("/api/alerts?limit=30"),
    ]);
    state.nodes = nodes;
    state.commands = commands;
    state.auditLogs = auditLogs;
    state.alerts = alerts;

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
    render();
  } catch (error) {
    showToast(`Refresh failed: ${error.message}`);
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
  renderNodes();
  renderSelectedNode();
  renderMetricControls();
  renderMetricSummary();
  renderChart(metricsForChart());
  renderContainers();
  renderEvents();
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
    els.nodeOverview.appendChild(createTextBlock("div", "empty", "No agent nodes to summarize."));
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
      createTextBlock("strong", "", node.name || node.id || "unknown-node"),
      createTextBlock("span", `status-chip ${statusClass(node.status)}`, node.status || "unknown"),
    );

    const meta = createTextBlock(
      "span",
      "node-overview-meta",
      `${node.hostname || "unknown host"} / ${node.os || "unknown os"}`,
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
    footer.append(
      createTextBlock("span", "", node.docker_available ? "Docker available" : "Docker unavailable"),
      createTextBlock("span", nodeAlerts.length ? "alert-mini active" : "alert-mini", `${nodeAlerts.length} alerts`),
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
    els.alertPanel.appendChild(createTextBlock("div", "empty", "No alerts."));
    return;
  }
  state.alerts.slice(0, 8).forEach((alert) => {
    const item = document.createElement("div");
    item.className = `alert-item ${statusClass(alert.status)}`;
    item.append(
      createTextBlock("strong", "", alertTitle(alert, alert.status === "active" ? "Active" : "Resolved")),
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
  els.metricRange.querySelectorAll("[data-range]").forEach((button) => {
    button.classList.toggle("active", button.dataset.range === state.metricRange);
  });
  els.chartZoomReset.classList.toggle("is-hidden", !state.metricZoom);
  els.thresholdCpu.value = state.thresholds.cpu ?? "";
  els.thresholdMemory.value = state.thresholds.memory ?? "";
  els.thresholdDisk.value = state.thresholds.disk ?? "";
  [els.thresholdCpu, els.thresholdMemory, els.thresholdDisk].forEach((input) => {
    input.disabled = !canManageThresholds;
    input.title = canManageThresholds ? "" : "Read-only role";
  });
}

function changeMetricRange(event) {
  const button = event.target.closest("[data-range]");
  if (!button) return;
  state.metricRange = button.dataset.range;
  clearMetricZoom();
  localStorage.setItem("monitor.metricRange", state.metricRange);
  renderMetricControls();
  refreshAll();
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
    saveThresholds().catch(() => showToast("Thresholds were kept locally."));
  }, 450);
}

async function saveThresholds() {
  await api("/api/settings/thresholds", {
    method: "PUT",
    body: JSON.stringify(state.thresholds),
  });
}

function renderMetricSummary() {
  els.metricSummary.replaceChildren();
  const summary = state.metricZoom ? summarizeMetrics(metricsForChart()) : state.metricPayload?.summary;
  const items = [
    ["CPU", summary?.cpu],
    ["Memory", summary?.memory],
    ["Disk", summary?.disk],
  ];
  items.forEach(([label, item]) => {
    const card = document.createElement("div");
    card.className = "summary-item";
    card.append(
      createTextBlock("span", "", label),
      createTextBlock("strong", "", `Avg ${percent(item?.avg)} / Max ${percent(item?.max)}`),
      createTextBlock("em", "", `Peak ${formatDateTime(item?.peak_at)}`),
    );
    els.metricSummary.appendChild(card);
  });
}

function renderNodes() {
  els.nodes.replaceChildren();
  if (!state.nodes.length) {
    els.nodes.appendChild(createTextBlock("div", "empty", "No agents connected yet."));
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
      createTextBlock("span", `status-chip ${statusClass(node.status)}`, node.status || "unknown"),
    );

    const meta = createTextBlock(
      "span",
      "node-meta",
      `${node.hostname || "unknown host"} / ${node.os || "unknown os"}`,
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
    els.title.textContent = "No node selected";
    els.meta.textContent = "Waiting for an agent connection";
    els.status.textContent = "unknown";
    els.status.className = "status-chip neutral";
    els.miniCpu.textContent = "-";
    els.miniMemory.textContent = "-";
    els.miniDisk.textContent = "-";
    els.miniDocker.textContent = "-";
    return;
  }

  els.title.textContent = node.name || node.id;
  els.meta.textContent = `${node.id} / ${node.hostname || "unknown host"} / last seen ${node.last_seen || "never"}`;
  els.status.textContent = node.status || "unknown";
  els.status.className = `status-chip ${statusClass(node.status)}`;
  els.miniCpu.textContent = percent(node.latest_cpu_percent);
  els.miniMemory.textContent = percent(node.latest_memory_percent);
  els.miniDisk.textContent = percent(node.latest_disk_percent);
  els.miniDocker.textContent = node.docker_available ? node.docker_version || "available" : "unavailable";
}

function renderChart(metrics) {
  const canvas = els.chart;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const left = 52;
  const right = width - 24;
  const top = 36;
  const bottom = height - 48;
  const colors = chartColors();
  const series = [
    ["CPU", "cpu_percent", cssVar("--blue") || "#1a73e8", state.thresholds.cpu],
    ["Memory", "memory_percent", cssVar("--green") || "#188038", state.thresholds.memory],
    ["Disk", "disk_percent", cssVar("--yellow") || "#f9ab00", state.thresholds.disk],
  ];

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
    ctx.fillText(String(value), 16, y + 4);
  }

  drawTimeAxis(ctx, metrics, left, right, bottom);
  drawLegend(ctx, series);
  drawThresholds(ctx, series, left, right, top, bottom);
  state.chartModel = {
    left,
    right,
    top,
    bottom,
    points: metrics.map((point, index) => ({
      point,
      x: left + ((right - left) * index) / Math.max(1, metrics.length - 1),
    })),
  };

  if (!metrics.length) {
    ctx.fillStyle = colors.text;
    ctx.font = "14px system-ui";
    ctx.fillText("No metrics yet", left, 86);
    return;
  }

  series.forEach((item) => drawSeries(ctx, metrics, item[1], item[2], left, right, top, bottom));
  drawChartSelection(ctx, left, right, top, bottom);
}

function drawSeries(ctx, metrics, key, color, left, right, top, bottom) {
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  metrics.forEach((point, index) => {
    const value = Number(point[key] || 0);
    const x = left + ((right - left) * index) / Math.max(1, metrics.length - 1);
    const y = yForValue(value, top, bottom);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawLegend(ctx, items) {
  const colors = chartColors();
  ctx.font = "12px system-ui";
  items.forEach((item, index) => {
    const x = 56 + index * 96;
    ctx.fillStyle = item[2];
    ctx.fillRect(x, 17, 18, 4);
    ctx.fillStyle = colors.ink;
    ctx.fillText(item[0], x + 24, 22);
  });
}

function drawThresholds(ctx, items, left, right, top, bottom) {
  ctx.save();
  items.forEach((item) => {
    const threshold = Number(item[3]);
    if (!Number.isFinite(threshold)) return;
    const y = yForValue(threshold, top, bottom);
    ctx.strokeStyle = item[2];
    ctx.lineWidth = 1.4;
    ctx.setLineDash([6, 5]);
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = item[2];
    ctx.font = "12px system-ui";
    ctx.fillText(`${item[0]} ${threshold}%`, right - 86, y - 6);
  });
  ctx.restore();
}

function drawTimeAxis(ctx, metrics, left, right, bottom) {
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

  pickAxisIndexes(metrics.length).forEach((index) => {
    const point = metrics[index];
    const x = left + ((right - left) * index) / Math.max(1, metrics.length - 1);
    ctx.beginPath();
    ctx.moveTo(x, bottom);
    ctx.lineTo(x, bottom + 6);
    ctx.stroke();

    if (index === 0) ctx.textAlign = "left";
    else if (index === metrics.length - 1) ctx.textAlign = "right";
    else ctx.textAlign = "center";
    ctx.fillText(formatAxisLabel(point?.captured_at || point?.bucket_start), x, bottom + 10);
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
  const scaleX = els.chart.width / rect.width;
  return (event.clientX - rect.left) * scaleX;
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
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  if (state.metricRange === "7d") {
    return date.toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit" });
  }
  return date.toLocaleDateString([], { month: "2-digit", day: "2-digit" });
}

function yForValue(value, top, bottom) {
  const bounded = Math.min(100, Math.max(0, Number(value) || 0));
  return bottom - ((bottom - top) * bounded) / 100;
}

function renderContainers() {
  els.containers.replaceChildren();
  if (!state.containers.length) {
    const row = document.createElement("tr");
    const cell = createTextBlock("td", "empty", "No visible containers on the selected node.");
    cell.colSpan = 6;
    row.appendChild(cell);
    els.containers.appendChild(row);
    return;
  }

  const filtered = state.containers.filter(containerMatchesFilters);
  if (!filtered.length) {
    const row = document.createElement("tr");
    const cell = createTextBlock("td", "empty", "No containers match the current filters.");
    cell.colSpan = 6;
    row.appendChild(cell);
    els.containers.appendChild(row);
    return;
  }

  filtered.forEach((container) => {
    const row = document.createElement("tr");
    const name = createTextBlock("td", "name-cell", container.name || container.container_id);
    name.title = String(container.container_id || "");

    const statusCell = document.createElement("td");
    statusCell.appendChild(createTextBlock("span", `status-chip ${statusClass(container.status)}`, container.status || "-"));

    const actions = createContainerActions(container);

    row.append(
      name,
      createTextBlock("td", "", container.image || "-"),
      statusCell,
      createTextBlock("td", "", percent(container.cpu_percent)),
      createTextBlock(
        "td",
        "",
        `${bytes(container.memory_usage)}${container.memory_limit ? ` / ${bytes(container.memory_limit)}` : ""}`,
      ),
      actions,
    );
    els.containers.appendChild(row);
  });
}

function createContainerActions(container) {
  const actions = document.createElement("td");
  if (!hasScope("commands:create")) {
    actions.appendChild(createTextBlock("span", "status-chip neutral", "read only"));
    return actions;
  }

  const actionRow = document.createElement("div");
  actionRow.className = "action-row";
  actionRow.append(
    createActionButton("Start", "container.start", container),
    createActionButton("Stop", "container.stop", container, "danger"),
    createActionButton("Restart", "container.restart", container),
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
    showToast("Select a node first.");
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
    showToast("Command submitted.");
    await refreshAll();
  } catch (error) {
    showToast(`Command failed: ${error.message}`);
  }
}

function confirmCommand(action, containerId) {
  const container = state.containers.find((item) => String(item.container_id) === String(containerId));
  const node = state.nodes.find((item) => item.id === state.selectedNodeId);
  const actionLabel = action.replace("container.", "");
  const containerLabel = container?.name || containerId;
  const nodeLabel = node?.name || state.selectedNodeId;
  const destructive = action.endsWith(".stop") || action.endsWith(".restart");
  if (commandDialogResolve) {
    closeCommandDialog(false);
  }
  els.commandDialogMessage.textContent = `Confirm ${actionLabel} for container ${containerLabel} on node ${nodeLabel}. This command will be sent immediately.`;
  els.commandDialogConfirm.textContent = actionLabel.charAt(0).toUpperCase() + actionLabel.slice(1);
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
    "No commands yet.",
  );
  renderEventList(
    els.auditLogs,
    state.auditLogs,
    (item) => `${item.action} / ${item.result || ""}`,
    (item) => `${item.user} / ${item.node_id || "-"} / ${item.client_ip || "-"} / ${item.created_at}`,
    "No audit logs yet.",
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

function renderEventList(target, items, title, detail, emptyText) {
  target.replaceChildren();
  if (!items.length) {
    target.appendChild(createTextBlock("div", "empty", emptyText));
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

function createTextBlock(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  element.textContent = String(text ?? "");
  return element;
}

function statusClass(value) {
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
  const scaleX = els.chart.width / rect.width;
  const x = (event.clientX - rect.left) * scaleX;
  const nearest = model.points.reduce((best, item) => (
    Math.abs(item.x - x) < Math.abs(best.x - x) ? item : best
  ));

  const point = nearest.point;
  els.chartTooltip.replaceChildren(
    createTextBlock("strong", "", formatBucket(point)),
    createTextBlock("span", "", `Samples: ${point.sample_count || 0}`),
    createTextBlock("span", "", metricTooltipLine("CPU", point.cpu_avg, point.cpu_max, point.cpu_peak_at)),
    createTextBlock("span", "", metricTooltipLine("Memory", point.memory_avg, point.memory_max, point.memory_peak_at)),
    createTextBlock("span", "", metricTooltipLine("Disk", point.disk_avg, point.disk_max, point.disk_peak_at)),
  );
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
}

function metricTooltipLine(label, avg, max, peakAt) {
  return `${label}: avg ${percent(avg)} / max ${percent(max)} / peak ${formatDateTime(peakAt)}`;
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
  return date.toLocaleString();
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

function chartColors() {
  return {
    bg: cssVar("--chart-bg") || "#ffffff",
    grid: cssVar("--chart-grid") || "#e0e3eb",
    text: cssVar("--chart-text") || "#5f6368",
    ink: cssVar("--chart-ink") || "#202124",
  };
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
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
