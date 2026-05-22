const state = {
  username: "",
  csrfToken: "",
  nodes: [],
  containers: [],
  commands: [],
  auditLogs: [],
  metrics: [],
  metricPayload: null,
  metricRange: localStorage.getItem("monitor.metricRange") || "1h",
  thresholds: loadThresholds(),
  chartModel: null,
  selectedNodeId: localStorage.getItem("monitor.selectedNodeId") || null,
  ws: null,
  refreshTimer: null,
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
  nodes: document.querySelector("#nodes"),
  containers: document.querySelector("#containers-table"),
  commands: document.querySelector("#commands-list"),
  auditLogs: document.querySelector("#audit-list"),
  title: document.querySelector("#selected-node-title"),
  meta: document.querySelector("#selected-node-meta"),
  status: document.querySelector("#selected-node-status"),
  miniCpu: document.querySelector("#mini-cpu"),
  miniMemory: document.querySelector("#mini-memory"),
  miniDisk: document.querySelector("#mini-disk"),
  miniDocker: document.querySelector("#mini-docker"),
  metricRange: document.querySelector("#metric-range"),
  thresholdCpu: document.querySelector("#threshold-cpu"),
  thresholdMemory: document.querySelector("#threshold-memory"),
  thresholdDisk: document.querySelector("#threshold-disk"),
  metricSummary: document.querySelector("#metric-summary"),
  chart: document.querySelector("#metric-chart"),
  chartTooltip: document.querySelector("#chart-tooltip"),
  toast: document.querySelector("#toast"),
};

els.loginForm.addEventListener("submit", login);
els.logout.addEventListener("click", () => logout());
els.refresh.addEventListener("click", refreshAll);
els.metricRange.addEventListener("click", changeMetricRange);
els.thresholdCpu.addEventListener("input", () => updateThreshold("cpu", els.thresholdCpu.value));
els.thresholdMemory.addEventListener("input", () => updateThreshold("memory", els.thresholdMemory.value));
els.thresholdDisk.addEventListener("input", () => updateThreshold("disk", els.thresholdDisk.value));
els.chart.addEventListener("mousemove", showChartTooltip);
els.chart.addEventListener("mouseleave", hideChartTooltip);

boot();

async function boot() {
  localStorage.removeItem("monitor.sessionToken");
  localStorage.removeItem("monitor.username");
  renderMetricControls();

  try {
    const profile = await api("/api/auth/me");
    state.username = profile.username;
    state.csrfToken = profile.csrf_token || "";
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
    state.username = data.username;
    state.csrfToken = data.csrf_token || "";
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch (error) {
    showToast(error.message || "Sign in failed.");
  }
}

function logout(showMessage = true) {
  if (state.ws) {
    state.ws.close();
  }
  clearInterval(state.refreshTimer);
  state.username = "";
  state.csrfToken = "";
  state.nodes = [];
  state.containers = [];
  state.commands = [];
  state.auditLogs = [];
  state.metrics = [];
  state.metricPayload = null;
  state.chartModel = null;
  fetch("/api/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    headers: csrfHeaders("POST"),
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
  els.currentUser.textContent = state.username ? `Signed in as ${state.username}` : "";
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

function csrfHeaders(method = "GET") {
  const normalized = String(method || "GET").toUpperCase();
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(normalized) || !state.csrfToken) {
    return {};
  }
  return { "X-CSRF-Token": state.csrfToken };
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
    refreshAll();
  });
}

function setWsState(value) {
  els.wsState.textContent = value;
}

async function refreshAll() {
  if (!state.username) return;

  try {
    const [nodes, commands, auditLogs] = await Promise.all([
      api("/api/nodes"),
      api("/api/commands?limit=50"),
      api("/api/audit-logs?limit=50"),
    ]);
    state.nodes = nodes;
    state.commands = commands;
    state.auditLogs = auditLogs;

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
  renderNodes();
  renderSelectedNode();
  renderMetricControls();
  renderMetricSummary();
  renderChart(state.metrics);
  renderContainers();
  renderEvents();
}

function renderOverview() {
  els.nodeCount.textContent = state.nodes.length;
  els.onlineCount.textContent = state.nodes.filter((node) => node.status === "online").length;
  els.containerCount.textContent = state.containers.length;
  els.commandCount.textContent = state.commands.length;
}

function renderMetricControls() {
  els.metricRange.querySelectorAll("[data-range]").forEach((button) => {
    button.classList.toggle("active", button.dataset.range === state.metricRange);
  });
  els.thresholdCpu.value = state.thresholds.cpu ?? "";
  els.thresholdMemory.value = state.thresholds.memory ?? "";
  els.thresholdDisk.value = state.thresholds.disk ?? "";
}

function changeMetricRange(event) {
  const button = event.target.closest("[data-range]");
  if (!button) return;
  state.metricRange = button.dataset.range;
  localStorage.setItem("monitor.metricRange", state.metricRange);
  renderMetricControls();
  refreshAll();
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
  renderChart(state.metrics);
}

function renderMetricSummary() {
  els.metricSummary.replaceChildren();
  const summary = state.metricPayload?.summary;
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
  const series = [
    ["CPU", "cpu_percent", "#1a73e8", state.thresholds.cpu],
    ["Memory", "memory_percent", "#188038", state.thresholds.memory],
    ["Disk", "disk_percent", "#f9ab00", state.thresholds.disk],
  ];

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "#e0e3eb";
  ctx.lineWidth = 1;
  ctx.fillStyle = "#5f6368";
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
    ctx.fillStyle = "#5f6368";
    ctx.font = "14px system-ui";
    ctx.fillText("No metrics yet", left, 86);
    return;
  }

  series.forEach((item) => drawSeries(ctx, metrics, item[1], item[2], left, right, top, bottom));
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
  ctx.font = "12px system-ui";
  items.forEach((item, index) => {
    const x = 56 + index * 96;
    ctx.fillStyle = item[2];
    ctx.fillRect(x, 17, 18, 4);
    ctx.fillStyle = "#202124";
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
  ctx.save();
  ctx.strokeStyle = "#e0e3eb";
  ctx.fillStyle = "#5f6368";
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

  state.containers.forEach((container) => {
    const row = document.createElement("tr");
    const name = createTextBlock("td", "name-cell", container.name || container.container_id);
    name.title = String(container.container_id || "");

    const statusCell = document.createElement("td");
    statusCell.appendChild(createTextBlock("span", `status-chip ${statusClass(container.status)}`, container.status || "-"));

    const actions = document.createElement("td");
    const actionRow = document.createElement("div");
    actionRow.className = "action-row";
    actionRow.append(
      createActionButton("Start", "container.start", container.container_id),
      createActionButton("Stop", "container.stop", container.container_id, "danger"),
      createActionButton("Restart", "container.restart", container.container_id),
    );
    actions.appendChild(actionRow);

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

function createActionButton(label, action, containerId, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.dataset.action = action;
  button.dataset.container = String(containerId || "");
  button.addEventListener("click", () => sendCommand(button.dataset.action, button.dataset.container));
  return button;
}

async function sendCommand(action, containerId) {
  if (!state.selectedNodeId) {
    showToast("Select a node first.");
    return;
  }
  const confirmed = window.confirm(`${action} ${containerId}?`);
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
    (item) => `${item.user} / ${item.node_id || "-"} / ${item.created_at}`,
    "No audit logs yet.",
  );
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
  const allowed = new Set(["online", "warning", "offline", "success", "running", "pending", "sent", "failed", "exited"]);
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

function normalizeThreshold(value, fallback) {
  if (value === null) return null;
  if (value === undefined) return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : fallback;
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
