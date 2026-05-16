const state = {
  token: localStorage.getItem("monitor.sessionToken") || "",
  username: localStorage.getItem("monitor.username") || "",
  nodes: [],
  containers: [],
  commands: [],
  auditLogs: [],
  metrics: [],
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
  chart: document.querySelector("#metric-chart"),
  toast: document.querySelector("#toast"),
};

els.loginForm.addEventListener("submit", login);
els.logout.addEventListener("click", logout);
els.refresh.addEventListener("click", refreshAll);

boot();

async function boot() {
  if (!state.token) {
    showLogin();
    return;
  }

  try {
    const profile = await api("/api/auth/me");
    state.username = profile.username;
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch {
    logout(false);
  }
}

async function login(event) {
  event.preventDefault();
  const username = els.username.value.trim();
  const password = els.password.value;

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      throw new Error("用户名或密码不正确");
    }
    const data = await response.json();
    state.token = data.token;
    state.username = data.username;
    localStorage.setItem("monitor.sessionToken", state.token);
    localStorage.setItem("monitor.username", state.username);
    showApp();
    connectWs();
    await refreshAll();
    state.refreshTimer = setInterval(refreshAll, 5000);
  } catch (error) {
    showToast(error.message || "登录失败");
  }
}

function logout(showMessage = true) {
  if (state.ws) {
    state.ws.close();
  }
  clearInterval(state.refreshTimer);
  state.token = "";
  state.username = "";
  state.nodes = [];
  state.containers = [];
  state.commands = [];
  state.auditLogs = [];
  state.metrics = [];
  localStorage.removeItem("monitor.sessionToken");
  localStorage.removeItem("monitor.username");
  showLogin();
  if (showMessage) showToast("已退出登录");
}

function showLogin() {
  els.loginView.classList.remove("is-hidden");
  els.appView.classList.add("is-hidden");
}

function showApp() {
  els.loginView.classList.add("is-hidden");
  els.appView.classList.remove("is-hidden");
  els.currentUser.textContent = state.username ? `当前用户：${state.username}` : "";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${state.token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (response.status === 401) {
    logout(false);
    throw new Error("登录已过期，请重新登录");
  }
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function connectWs() {
  if (state.ws) {
    state.ws.close();
  }
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${window.location.host}/ws/ui?token=${encodeURIComponent(state.token)}`;
  const ws = new WebSocket(url);
  state.ws = ws;
  setWsState("connecting");

  ws.addEventListener("open", () => setWsState("connected"));
  ws.addEventListener("close", () => {
    setWsState("disconnected");
    if (state.token) {
      setTimeout(() => {
        if (state.ws === ws) connectWs();
      }, 3000);
    }
  });
  ws.addEventListener("message", () => refreshAll());
}

function setWsState(value) {
  els.wsState.textContent = value;
}

async function refreshAll() {
  if (!state.token) return;

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
    state.metrics = state.selectedNodeId
      ? await api(`/api/nodes/${encodeURIComponent(state.selectedNodeId)}/metrics?limit=120`)
      : [];
    render();
  } catch (error) {
    showToast(`刷新失败：${error.message}`);
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

function renderNodes() {
  if (!state.nodes.length) {
    els.nodes.innerHTML = `<div class="empty">还没有 Agent 连接。</div>`;
    return;
  }

  els.nodes.innerHTML = state.nodes
    .map((node) => {
      const active = node.id === state.selectedNodeId ? " active" : "";
      return `
        <button class="node-item${active}" type="button" data-node-id="${escapeHtml(node.id)}">
          <span class="node-name-row">
            <span class="node-name">${escapeHtml(node.name || node.id)}</span>
            <span class="status-chip ${escapeHtml(node.status || "neutral")}">${escapeHtml(node.status || "unknown")}</span>
          </span>
          <span class="node-meta">${escapeHtml(node.hostname || "unknown host")} · ${escapeHtml(node.os || "unknown os")}</span>
          <span class="node-metrics-row">
            <span>CPU ${percent(node.latest_cpu_percent)}</span>
            <span>MEM ${percent(node.latest_memory_percent)}</span>
            <span>DISK ${percent(node.latest_disk_percent)}</span>
          </span>
        </button>
      `;
    })
    .join("");

  document.querySelectorAll("[data-node-id]").forEach((button) => {
    button.addEventListener("click", () => selectNode(button.dataset.nodeId));
  });
}

function renderSelectedNode() {
  const node = state.nodes.find((item) => item.id === state.selectedNodeId);
  if (!node) {
    els.title.textContent = "未选择节点";
    els.meta.textContent = "等待 Agent 连接";
    els.status.textContent = "unknown";
    els.status.className = "status-chip neutral";
    els.miniCpu.textContent = "-";
    els.miniMemory.textContent = "-";
    els.miniDisk.textContent = "-";
    els.miniDocker.textContent = "-";
    return;
  }

  els.title.textContent = node.name || node.id;
  els.meta.textContent = `${node.id} · ${node.hostname || "unknown host"} · last seen ${node.last_seen || "never"}`;
  els.status.textContent = node.status || "unknown";
  els.status.className = `status-chip ${node.status || "neutral"}`;
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
  const bottom = height - 36;

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "#dbe5ef";
  ctx.lineWidth = 1;
  ctx.fillStyle = "#68758a";
  ctx.font = "12px system-ui";
  for (let i = 0; i <= 4; i += 1) {
    const value = 100 - i * 25;
    const y = top + ((bottom - top) * i) / 4;
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(right, y);
    ctx.stroke();
    ctx.fillText(String(value), 16, y + 4);
  }

  drawLegend(ctx);
  if (!metrics.length) {
    ctx.fillStyle = "#68758a";
    ctx.font = "14px system-ui";
    ctx.fillText("暂无指标数据", left, 86);
    return;
  }

  drawSeries(ctx, metrics, "cpu_percent", "#1769aa", left, right, top, bottom);
  drawSeries(ctx, metrics, "memory_percent", "#168052", left, right, top, bottom);
  drawSeries(ctx, metrics, "disk_percent", "#b76d12", left, right, top, bottom);
}

function drawSeries(ctx, metrics, key, color, left, right, top, bottom) {
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  metrics.forEach((point, index) => {
    const value = Number(point[key] || 0);
    const x = left + ((right - left) * index) / Math.max(1, metrics.length - 1);
    const y = bottom - ((bottom - top) * Math.min(100, Math.max(0, value))) / 100;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawLegend(ctx) {
  const items = [
    ["CPU", "#1769aa"],
    ["Memory", "#168052"],
    ["Disk", "#b76d12"],
  ];
  ctx.font = "12px system-ui";
  items.forEach((item, index) => {
    const x = 56 + index * 96;
    ctx.fillStyle = item[1];
    ctx.fillRect(x, 17, 18, 4);
    ctx.fillStyle = "#142033";
    ctx.fillText(item[0], x + 24, 22);
  });
}

function renderContainers() {
  if (!state.containers.length) {
    els.containers.innerHTML = `<tr><td colspan="6" class="empty">当前节点没有可见容器。</td></tr>`;
    return;
  }

  els.containers.innerHTML = state.containers
    .map((container) => {
      const memory = bytes(container.memory_usage);
      const limit = bytes(container.memory_limit);
      return `
        <tr>
          <td class="name-cell" title="${escapeHtml(container.container_id)}">${escapeHtml(container.name || container.container_id)}</td>
          <td>${escapeHtml(container.image || "-")}</td>
          <td><span class="status-chip ${escapeHtml(container.status || "neutral")}">${escapeHtml(container.status || "-")}</span></td>
          <td>${percent(container.cpu_percent)}</td>
          <td>${memory}${container.memory_limit ? ` / ${limit}` : ""}</td>
          <td>
            <div class="action-row">
              <button type="button" data-action="container.start" data-container="${escapeHtml(container.container_id)}">Start</button>
              <button type="button" data-action="container.stop" data-container="${escapeHtml(container.container_id)}" class="danger">Stop</button>
              <button type="button" data-action="container.restart" data-container="${escapeHtml(container.container_id)}">Restart</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");

  document.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => sendCommand(button.dataset.action, button.dataset.container));
  });
}

async function sendCommand(action, containerId) {
  if (!state.selectedNodeId) {
    showToast("请先选择一个节点");
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
    showToast("命令已提交");
    await refreshAll();
  } catch (error) {
    showToast(`命令失败：${error.message}`);
  }
}

function renderEvents() {
  els.commands.innerHTML = renderEventList(
    state.commands,
    (item) => `${item.action} · ${item.status}`,
    (item) => `${item.node_id} · ${item.created_at} · ${item.result_message || ""}`,
    "还没有命令记录。",
  );
  els.auditLogs.innerHTML = renderEventList(
    state.auditLogs,
    (item) => `${item.action} · ${item.result || ""}`,
    (item) => `${item.user} · ${item.node_id || "-"} · ${item.created_at}`,
    "还没有审计日志。",
  );
}

function renderEventList(items, title, detail, emptyText) {
  if (!items.length) return `<div class="empty">${emptyText}</div>`;
  return items
    .map(
      (item) => `
        <div class="event-item">
          <strong>${escapeHtml(title(item))}</strong>
          <span>${escapeHtml(detail(item))}</span>
        </div>
      `,
    )
    .join("");
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

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

let toastTimer = null;
function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove("show"), 3200);
}
