"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const app = {
  session: null,
  state: null,
  lastStateAt: 0,
  eventSource: null,
  tab: "rotations",
  activity: null,
  activityLoading: false,
  activitySeq: 0,
  lastActivityAt: 0,
  activityError: "",
  filter: "",
  busy: new Set(),
  editing: null,
  savingTunnel: false,
  savingRotation: false,
  rotating: false,
  fleetDirty: false,
  copyTimer: 0,
};

const METHOD_LABELS = { l2tp: "L2TP", sstp: "SSTP", pptp: "PPTP" };
const MODE_LABELS = { manual: "Manual", timer: "Timer", failover: "Failover" };

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function methodLabel(method) {
  return METHOD_LABELS[method] || String(method || "—").toUpperCase();
}

function titleCase(value) {
  const s = String(value || "");
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

async function api(path, options = {}) {
  const opts = { ...options, headers: { Accept: "application/json", ...(options.headers || {}) } };
  if (opts.body !== undefined && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
    opts.headers["Content-Type"] = "application/json";
  }
  if (opts.method && opts.method.toUpperCase() !== "GET" && app.session) {
    opts.headers["X-CSRF-Token"] = app.session.csrf_token;
  }
  const response = await fetch(path, { ...opts, credentials: "same-origin", cache: "no-store" });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Session expired. Sign in again.");
  }
  if (!response.ok) {
    throw new Error((data && data.error) || `Request failed (${response.status})`);
  }
  return data;
}

/* ---------- boot ---------- */

document.addEventListener("DOMContentLoaded", boot);

async function boot() {
  bindUI();
  tickClock();
  setInterval(tickClock, 1000);

  try {
    app.session = await api("/api/session");
  } catch {
    return;
  }

  if (app.session.username) {
    const user = $("#session-user");
    user.textContent = app.session.username;
    user.hidden = false;
  }
  if (app.session.demo) {
    $("#demo-banner").hidden = false;
    $("#footer-demo").hidden = false;
  }
  $("#footer-version").textContent = app.session.version ? `v${app.session.version}` : "";

  await loadState();
  connectEvents();
  loadActivity(true);

  setInterval(() => {
    if (document.hidden) return;
    if (Date.now() - app.lastStateAt > 7000) loadState();
  }, 5000);

  setInterval(() => {
    if (document.hidden || app.tab === "") return;
    loadActivity(true);
  }, 15000);
}

function bindUI() {
  $("#logout-button").addEventListener("click", logout);
  $("#rotate-button").addEventListener("click", rotateNow);
  $("#save-interval").addEventListener("click", saveInterval);
  $("#rotation-modes").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-mode]");
    if (!button || app.savingRotation) return;
    const mode = button.dataset.mode;
    if (app.state && app.state.rotation.mode === mode) return;
    changeRotationMode(mode);
  });

  $("#add-tunnel").addEventListener("click", () => openTunnelDialog(null));
  $("#tunnel-filter").addEventListener("input", (event) => {
    app.filter = event.target.value;
    renderFleet();
  });
  $("#tunnel-grid").addEventListener("click", onTunnelAction);
  $("#tunnel-grid").addEventListener("focusout", () => {
    window.setTimeout(() => {
      if (app.fleetDirty) renderFleet();
    }, 0);
  });

  $("#activity-tabs").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-tab]");
    if (!button) return;
    switchTab(button.dataset.tab);
  });
  $("#refresh-activity").addEventListener("click", () => loadActivity(true));
  $("#log-filter").addEventListener("change", () => loadActivity(true));

  $("#copy-ip").addEventListener("click", copyPublicIP);

  $$("[data-close-dialog]").forEach((button) => {
    button.addEventListener("click", () => {
      const dialog = button.closest("dialog");
      if (dialog) dialog.close();
    });
  });
  $$("dialog").forEach((dialog) => {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  });

  $("#tunnel-form").addEventListener("submit", saveTunnel);
  $("#field-method").addEventListener("change", syncTunnelFields);
  $("#field-use-ipsec").addEventListener("change", syncTunnelFields);
  $("#field-ignore-cert").addEventListener("change", syncTunnelFields);
  $("#field-enabled").addEventListener("change", syncTunnelFields);
}

/* ---------- state and stream ---------- */

async function loadState() {
  try {
    const state = await api("/api/state");
    applyState(state);
  } catch (error) {
    if (!String(error.message).includes("Session expired")) {
      setLive("reconnecting");
    }
  }
}

function connectEvents() {
  if (app.eventSource) app.eventSource.close();
  setLive("connecting");
  const source = new EventSource("/api/events");
  app.eventSource = source;
  source.addEventListener("open", () => setLive("live"));
  source.addEventListener("error", () => setLive("reconnecting"));
  source.addEventListener("state", (event) => {
    try {
      applyState(JSON.parse(event.data));
      setLive("live");
    } catch {
      setLive("reconnecting");
    }
  });
}

function setLive(mode) {
  const node = $("#live-state");
  const label = $("#live-label");
  node.dataset.state = mode;
  label.textContent = mode === "live" ? "Live" : mode === "connecting" ? "Connecting" : "Reconnecting";
}

function applyState(state) {
  if (!state || !Array.isArray(state.tunnels)) return;
  app.state = state;
  app.lastStateAt = Date.now();
  if (state.demo) {
    $("#demo-banner").hidden = false;
    $("#footer-demo").hidden = false;
  }
  renderHero();
  renderStats();
  renderRotation();
  renderFleet();
  syncLogFilterOptions();
  if (app.session && app.session.version) {
    $("#footer-version").textContent = `v${app.session.version}`;
  }
}

/* ---------- rendering: hero and summary ---------- */

function renderHero() {
  const state = app.state;
  const active = state.tunnels.find((t) => t.active) || null;
  const ip = state.public_ip || "";
  const verified = Boolean(active && active.health_ok && ip);

  const ipNode = $("#hero-ip");
  ipNode.textContent = ip || "—";
  ipNode.classList.toggle("is-empty", !ip);

  const pill = $("#verified-pill");
  const pillLabel = $("#verified-label");
  if (verified) {
    pill.dataset.state = "verified";
    pillLabel.textContent = "Verified exit";
  } else if (active) {
    pill.dataset.state = "pending";
    pillLabel.textContent = "Verifying route";
  } else {
    pill.dataset.state = "offline";
    pillLabel.textContent = "Original uplink";
  }

  const summary = $("#hero-summary");
  if (active && ip) {
    summary.innerHTML = `Traffic exits through <strong>${esc(active.server)}</strong> on <strong>${esc(methodLabel(active.method))}</strong>. The public address was confirmed through the active tunnel.`;
  } else if (active) {
    summary.innerHTML = `Traffic is routed through <strong>${esc(active.server)}</strong>, but the exit has not been verified yet.`;
  } else {
    summary.textContent = "No tunnel is carrying traffic. The server is using its original uplink.";
  }

  $("#hero-tunnel").textContent = active ? active.name : "—";
  $("#hero-method").textContent = active ? methodLabel(active.method) : "—";
  $("#hero-verified").textContent = active ? relativeTime(active.active_since || active.last_check) : "—";
  $("#hero-latency").textContent = active && active.latency_ms > 0 ? `${active.latency_ms} ms` : "—";

  const copy = $("#copy-ip");
  copy.disabled = !ip;
  const previous = $("#previous-ip");
  if (state.previous_public_ip && state.previous_public_ip !== ip) {
    previous.hidden = false;
    previous.textContent = `Previous ${state.previous_public_ip}`;
  } else {
    previous.hidden = true;
  }

  const proof = $("#hero-proof");
  const proofBadge = $("#proof-badge");
  const proofText = $("#proof-text");
  if (verified) {
    proof.dataset.state = "verified";
    proofBadge.textContent = "Verified";
    proofText.textContent = "The tunnel interface and the system default route returned the same public IP.";
  } else if (active) {
    proof.dataset.state = "pending";
    proofBadge.textContent = "Pending";
    proofText.textContent = "The tunnel is connected, but the exit has not passed a consistent public IP check.";
  } else {
    proof.dataset.state = "idle";
    proofBadge.textContent = "Idle";
    proofText.textContent = "No tunnel route is active. Traffic exits through the original uplink.";
  }
}

function renderStats() {
  const state = app.state;
  $("#stat-total").textContent = state.counts.total;
  $("#stat-connected").textContent = state.counts.connected;
  $("#stat-healthy").textContent = state.counts.healthy;
  $("#stat-standby").textContent = state.counts.standby;
  $("#stat-uptime").textContent = humanDuration(state.uptime_seconds);
}

/* ---------- rendering: rotation ---------- */

function renderRotation() {
  const state = app.state;
  if (!state) return;
  const rotation = state.rotation;
  const mode = rotation.mode || "manual";

  $$("#rotation-modes button").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.mode === mode ? "true" : "false");
    button.disabled = app.savingRotation;
  });
  $("#mode-readout").textContent = MODE_LABELS[mode] || titleCase(mode);

  const interval = $("#interval-input");
  interval.min = rotation.min_interval;
  interval.max = rotation.max_interval;
  if (document.activeElement !== interval) interval.value = rotation.interval_minutes;
  $("#save-interval").disabled = app.savingRotation;

  const label = $("#countdown-label");
  const countdown = $("#countdown");
  const note = $("#countdown-note");

  if (mode === "timer") {
    label.textContent = "Next rotation";
    countdown.classList.remove("is-idle");
    if (!rotation.next_at) countdown.textContent = "—";
    note.textContent = rotation.next_at
      ? `Scheduled for ${formatClock(rotation.next_at)} UTC. Only healthy standbys are used.`
      : "The timer will rotate when a healthy standby is available.";
  } else if (mode === "failover") {
    label.textContent = "Automatic switch";
    countdown.classList.add("is-idle");
    countdown.textContent = "On failure";
    note.textContent = "Switches only after the active tunnel repeatedly fails health checks.";
  } else {
    label.textContent = "Next rotation";
    countdown.classList.add("is-idle");
    countdown.textContent = "On demand";
    note.textContent = "Rotations happen only when requested.";
  }

  const rotating = app.rotating || rotation.running;
  const rotateButton = $("#rotate-button");
  rotateButton.disabled = rotating;
  rotateButton.classList.toggle("is-loading", rotating);
  $("#rotate-label").textContent = rotating ? "Verifying new route…" : "Rotate now";

  const reason = $("#last-reason");
  if (rotation.last_reason) {
    reason.hidden = false;
    reason.textContent = `Last rotation reason: ${rotation.last_reason}`;
  } else {
    reason.hidden = true;
  }

  updateCountdown();
}

function updateCountdown() {
  if (!app.state) return;
  const rotation = app.state.rotation;
  if (rotation.mode !== "timer" || !rotation.next_at) return;
  const elapsed = (Date.now() - app.lastStateAt) / 1000;
  const remaining = Math.max(0, Number(rotation.countdown_seconds || 0) - elapsed);
  const countdown = $("#countdown");
  countdown.textContent = formatCountdown(remaining);
  if (remaining <= 0) {
    $("#countdown-note").textContent = "Rotation is due. Waiting for the new route to be verified.";
  }
}

function formatCountdown(seconds) {
  const total = Math.max(0, Math.ceil(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/* ---------- rendering: tunnel fleet ---------- */

function statusOf(tunnel) {
  if (!tunnel.enabled) return { key: "offline", label: "Disabled" };
  switch (tunnel.status) {
    case "connected":
      return tunnel.health_ok
        ? { key: "connected", label: "Connected" }
        : { key: "degraded", label: "Unverified" };
    case "connecting":
      return { key: "connecting", label: "Connecting" };
    case "disconnecting":
      return { key: "connecting", label: "Stopping" };
    case "failed":
      return { key: "failed", label: "Failed" };
    default:
      return { key: "offline", label: "Offline" };
  }
}

function renderFleet() {
  const state = app.state;
  const grid = $("#tunnel-grid");
  if (!state) return;
  if (grid.contains(document.activeElement)) {
    app.fleetDirty = true;
    return;
  }
  app.fleetDirty = false;

  const query = app.filter.trim().toLowerCase();
  const tunnels = state.tunnels.filter((tunnel) => {
    if (!query) return true;
    return (
      tunnel.name.toLowerCase().includes(query) ||
      tunnel.server.toLowerCase().includes(query) ||
      tunnel.method.toLowerCase().includes(query) ||
      String(tunnel.public_ip || "").includes(query)
    );
  });

  $("#fleet-empty").hidden = tunnels.length !== 0;
  grid.innerHTML = tunnels.map(tunnelCard).join("");
}

function tunnelCard(tunnel) {
  const status = statusOf(tunnel);
  const busy = app.busy.has(tunnel.name);
  const active = Boolean(tunnel.active);
  const warnings = [];
  if (!app.state.demo) {
    if (!tunnel.has_password) warnings.push("No password is stored. Edit the tunnel to set one.");
    if (tunnel.use_ipsec && !tunnel.has_psk) warnings.push("No IPsec pre-shared key is stored.");
  }
  if (tunnel.warning) warnings.push(tunnel.warning);

  let actions = "";
  if (active) {
    actions += `<span class="active-flag">Active egress</span>`;
  }
  if (tunnel.enabled) {
    if (tunnel.status === "connected" || tunnel.status === "connecting" || tunnel.status === "disconnecting") {
      const cancelLabel = tunnel.status === "connecting" ? "Cancel" : "Disconnect";
      actions += `<button class="btn btn-quiet" type="button" data-action="disconnect" data-name="${esc(tunnel.name)}" ${busy ? "disabled" : ""}>${cancelLabel}</button>`;
    } else {
      const connectLabel = tunnel.status === "failed" ? "Retry" : "Connect";
      actions += `<button class="btn btn-quiet" type="button" data-action="connect" data-name="${esc(tunnel.name)}" ${busy ? "disabled" : ""}>${connectLabel}</button>`;
    }
    if (!active && tunnel.status === "connected" && tunnel.health_ok) {
      actions += `<button class="btn btn-accent" type="button" data-action="activate" data-name="${esc(tunnel.name)}" ${busy ? "disabled" : ""}>Use route</button>`;
    }
  }
  actions += `<span class="spacer"></span>`;
  actions += `<button class="icon-button" type="button" data-action="edit" data-name="${esc(tunnel.name)}" aria-label="Edit ${esc(tunnel.name)}" title="Edit tunnel" ${busy ? "disabled" : ""}>
    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true">
      <path d="M10.8 2.7 13.3 5.2M3 13l.5-2.6 7.5-7.5a1.1 1.1 0 0 1 1.6 0l1.5 1.5a1.1 1.1 0 0 1 0 1.6l-7.5 7.5L3 13Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/>
    </svg>
  </button>`;
  actions += `<button class="icon-button" type="button" data-action="delete" data-name="${esc(tunnel.name)}" aria-label="Delete ${esc(tunnel.name)}" title="Delete tunnel" ${busy ? "disabled" : ""}>
    <svg viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true">
      <path d="M3.5 5h9M6 5V3.5h4V5M5 5l.5 8h5L11 5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </button>`;

  const uptime = tunnel.status === "connected" || tunnel.status === "failed"
    ? (tunnel.uptime_seconds > 0 ? humanDuration(tunnel.uptime_seconds) : "—")
    : "—";
  const ip = tunnel.public_ip || (tunnel.status === "connected" ? "Verifying…" : "—");
  const error = tunnel.last_error
    ? `<div class="card-error" title="${esc(tunnel.last_error)}">${esc(tunnel.last_error)}</div>`
    : "";

  return `<article class="tunnel-card${active ? " is-active" : ""}${tunnel.enabled ? "" : " is-disabled"}" data-name="${esc(tunnel.name)}" aria-busy="${busy ? "true" : "false"}">
    <div class="card-head">
      <div class="card-identity">
        <h3 title="${esc(tunnel.name)}">${esc(tunnel.name)}</h3>
        <span class="badge badge-${esc(tunnel.method)}">${esc(methodLabel(tunnel.method))}</span>
        ${active ? `<span class="badge badge-active">Active</span>` : ""}
      </div>
      <span class="card-status" data-state="${status.key}"><span class="status-dot" aria-hidden="true"></span>${status.label}</span>
    </div>

    <div class="card-ip-row">
      <span class="card-ip-label">Public exit</span>
      <span class="card-ip${tunnel.public_ip ? "" : " is-empty"}">${esc(ip)}</span>
    </div>

    <div class="card-meta">
      <div class="card-meta-item"><span class="card-meta-label">Server</span><span class="card-meta-value" title="${esc(tunnel.server)}">${esc(tunnel.server)}</span></div>
      <div class="card-meta-item"><span class="card-meta-label">Local IP</span><span class="card-meta-value">${esc(tunnel.local_ip || "—")}</span></div>
      <div class="card-meta-item"><span class="card-meta-label">Latency</span><span class="card-meta-value">${tunnel.latency_ms > 0 ? `${tunnel.latency_ms} ms` : "—"}</span></div>
      <div class="card-meta-item"><span class="card-meta-label">Uptime</span><span class="card-meta-value">${esc(uptime)}</span></div>
    </div>

    ${warnings.length ? `<div class="card-warning">${esc(warnings.join(" "))}</div>` : ""}
    ${error}

    <div class="card-actions">${actions}</div>
  </article>`;
}

/* ---------- tunnel actions ---------- */

async function onTunnelAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const name = button.dataset.name;
  const action = button.dataset.action;
  const tunnel = app.state ? app.state.tunnels.find((t) => t.name === name) : null;
  if (!tunnel) return;

  if (action === "edit") {
    openTunnelDialog(tunnel);
    return;
  }
  if (action === "delete") {
    const confirmed = await confirmAction({
      title: "Delete tunnel?",
      message: `Delete “${name}”? It will be disconnected first, its generated system configuration removed, and its stored credentials deleted. This cannot be undone.`,
      label: "Delete tunnel",
      destructive: true,
    });
    if (!confirmed) return;
    await runTunnelAction(name, "delete", `/api/tunnels/${encodeURIComponent(name)}`, "DELETE");
    return;
  }
  if (action === "disconnect" && tunnel.active) {
    const confirmed = await confirmAction({
      title: "Disconnect active egress?",
      message: `“${name}” is the active egress. Traffic will return to the original uplink before the tunnel is torn down.`,
      label: "Disconnect",
    });
    if (!confirmed) return;
  }
  if (action === "disconnect") {
    await runTunnelAction(name, "disconnect", `/api/tunnels/${encodeURIComponent(name)}/disconnect`, "POST", "Tunnel disconnected. Traffic is using the original uplink.");
    return;
  }
  if (action === "connect") {
    await runTunnelAction(name, "connect", `/api/tunnels/${encodeURIComponent(name)}/connect`, "POST", null);
    return;
  }
  if (action === "activate") {
    await runTunnelAction(name, "activate", `/api/tunnels/${encodeURIComponent(name)}/activate`, "POST", `Default route switched to ${name}.`);
  }
}

async function runTunnelAction(name, action, path, method, successMessage) {
  if (app.busy.has(name)) return;
  app.busy.add(name);
  renderFleet();
  try {
    await api(path, { method });
    await loadState();
    const tunnel = app.state ? app.state.tunnels.find((t) => t.name === name) : null;
    if (action === "connect") {
      if (tunnel && tunnel.health_ok) {
        toast(`Connected to ${name}. Public IP verified.`, "success");
      } else {
        toast(`Connected to ${name}, but the first health check has not passed.`, "info");
      }
    } else if (successMessage) {
      toast(successMessage, "success");
    }
    if (action !== "connect" || (tunnel && tunnel.health_ok)) {
      loadActivity(true);
    }
  } catch (error) {
    toast(error.message, "error");
    await loadState();
  } finally {
    app.busy.delete(name);
    renderFleet();
  }
}

/* ---------- rotation actions ---------- */

async function rotateNow() {
  if (app.rotating || (app.state && app.state.rotation.running)) return;
  const confirmed = await confirmAction({
    title: "Rotate egress now?",
    message: "A healthy standby tunnel will be activated only after its public IP is verified. If verification fails, the current route is restored automatically.",
    label: "Rotate egress",
  });
  if (!confirmed) return;
  app.rotating = true;
  renderRotation();
  try {
    await api("/api/rotate", { method: "POST" });
    await loadState();
    const ip = app.state && app.state.public_ip;
    toast(ip ? `Rotation complete. Egress now exits from ${ip}.` : "Rotation complete. New route verified.", "success");
    loadActivity(true);
  } catch (error) {
    toast(error.message, "error");
    await loadState();
  } finally {
    app.rotating = false;
    renderRotation();
  }
}

async function changeRotationMode(mode) {
  const interval = Number.parseInt($("#interval-input").value, 10);
  await setRotation(mode, interval);
}

async function saveInterval() {
  if (!app.state) return;
  const interval = Number.parseInt($("#interval-input").value, 10);
  await setRotation(app.state.rotation.mode, interval);
}

async function setRotation(mode, interval) {
  if (app.savingRotation) return;
  if (!Number.isInteger(interval)) {
    toast("Enter a rotation interval in whole minutes.", "error");
    return;
  }
  app.savingRotation = true;
  renderRotation();
  try {
    await api("/api/rotation", { method: "POST", body: { mode, interval_minutes: interval } });
    await loadState();
    toast(`Rotation mode set to ${MODE_LABELS[mode] || mode}.`, "success");
    loadActivity(true);
  } catch (error) {
    toast(error.message, "error");
    await loadState();
  } finally {
    app.savingRotation = false;
    renderRotation();
  }
}

/* ---------- tunnel dialog ---------- */

function openTunnelDialog(tunnel) {
  app.editing = tunnel || null;
  const form = $("#tunnel-form");
  form.reset();

  $("#tunnel-dialog-eyebrow").textContent = tunnel ? "Existing definition" : "New definition";
  $("#tunnel-dialog-title").textContent = tunnel ? `Edit ${tunnel.name}` : "Add tunnel";
  $("#tunnel-save").textContent = tunnel ? "Save changes" : "Save tunnel";

  const name = $("#field-name");
  name.value = tunnel ? tunnel.name : "";
  name.readOnly = Boolean(tunnel);

  $("#field-method").value = tunnel ? tunnel.method : "l2tp";
  $("#field-server").value = tunnel ? tunnel.server : "";
  $("#field-username").value = tunnel ? tunnel.username : "";
  $("#field-password").value = "";
  $("#field-use-ipsec").checked = Boolean(tunnel && tunnel.use_ipsec);
  $("#field-psk").value = "";
  $("#field-sstp-port").value = tunnel && tunnel.sstp_port ? tunnel.sstp_port : 443;
  $("#field-ignore-cert").checked = Boolean(tunnel && tunnel.sstp_ignore_cert);
  $("#field-ca-cert").value = tunnel ? tunnel.sstp_ca_cert || "" : "";
  $("#field-phone").value = tunnel ? tunnel.pptp_phone || "" : "";
  $("#field-mtu").value = tunnel ? tunnel.mtu : 1400;
  $("#field-mru").value = tunnel ? tunnel.mru : 1400;
  $("#field-require-mppe").checked = Boolean(tunnel && tunnel.require_mpe);
  $("#field-enabled").checked = tunnel ? tunnel.enabled : true;

  const passwordLabel = $("#password-label");
  const passwordHint = $("#password-hint");
  if (tunnel) {
    passwordLabel.textContent = "New password";
    passwordHint.textContent = tunnel.has_password
      ? "A password is stored. Leave this blank to keep it."
      : "No password is stored. Enter one before connecting.";
    $("#field-password").placeholder = tunnel.has_password ? "Leave blank to keep stored password" : "Password required";
  } else {
    passwordLabel.textContent = "Password";
    passwordHint.textContent = "Stored server-side in a 0600 credential file. Never returned by the API.";
    $("#field-password").placeholder = "Required";
  }

  const pskLabel = $("#psk-label");
  const pskHint = $("#psk-hint");
  if (tunnel) {
    pskLabel.textContent = "New IPsec pre-shared key";
    pskHint.textContent = tunnel.has_psk ? "A key is stored. Leave blank to keep it." : "No key is stored. Enter one for L2TP over IPsec.";
    $("#field-psk").placeholder = tunnel.has_psk ? "Leave blank to keep stored key" : "Pre-shared key";
  } else {
    pskLabel.textContent = "IPsec pre-shared key";
    pskHint.textContent = "Kept separate from the tunnel password.";
    $("#field-psk").placeholder = "";
  }

  $("#modal-note").textContent = tunnel
    ? "Leave credentials blank to keep the stored values."
    : "The password is required. Credentials are written with mode 0600.";
  hideFormError();
  syncTunnelFields();

  const dialog = $("#tunnel-dialog");
  if (!dialog.open) dialog.showModal();
  window.setTimeout(() => {
    if (tunnel) $("#field-server").focus();
    else name.focus();
  }, 30);
}

function syncTunnelFields() {
  const method = $("#field-method").value;
  $("#ipsec-group").hidden = method !== "l2tp";
  $("#sstp-group").hidden = method !== "sstp";
  $("#pptp-group").hidden = method !== "pptp";

  const useIPSec = $("#field-use-ipsec").checked;
  $("#psk-field").hidden = !useIPSec;
  $("#l2tp-warning").hidden = useIPSec;
  $("#sstp-warning").hidden = !$("#field-ignore-cert").checked;

  const editing = Boolean(app.editing);
  const password = $("#field-password");
  const psk = $("#field-psk");
  password.required = !editing;
  psk.required = !editing && method === "l2tp" && useIPSec;
  $("#field-name").required = true;
}

async function saveTunnel(event) {
  event.preventDefault();
  if (app.savingTunnel) return;
  const form = $("#tunnel-form");
  if (!form.reportValidity()) return;

  const editing = app.editing;
  const payload = {
    name: $("#field-name").value.trim(),
    method: $("#field-method").value,
    server: $("#field-server").value.trim(),
    username: $("#field-username").value.trim(),
    password: $("#field-password").value,
    use_ipsec: $("#field-use-ipsec").checked,
    psk: $("#field-psk").value,
    sstp_port: Number.parseInt($("#field-sstp-port").value, 10) || 443,
    sstp_ignore_cert: $("#field-ignore-cert").checked,
    sstp_ca_cert: $("#field-ca-cert").value.trim(),
    pptp_phone: $("#field-phone").value.trim(),
    mtu: Number.parseInt($("#field-mtu").value, 10),
    mru: Number.parseInt($("#field-mru").value, 10),
    require_mppe: $("#field-require-mppe").checked,
    enabled: $("#field-enabled").checked,
  };

  app.savingTunnel = true;
  const button = $("#tunnel-save");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Saving…";
  hideFormError();

  try {
    if (editing) {
      await api(`/api/tunnels/${encodeURIComponent(editing.name)}`, { method: "PUT", body: payload });
    } else {
      await api("/api/tunnels", { method: "POST", body: payload });
    }
    $("#tunnel-dialog").close();
    toast(editing ? `Saved ${payload.name}.` : `Added ${payload.name}.`, "success");
    await loadState();
    loadActivity(true);
  } catch (error) {
    showFormError(error.message);
  } finally {
    app.savingTunnel = false;
    button.disabled = false;
    button.textContent = original;
  }
}

function showFormError(message) {
  const box = $("#tunnel-form-error");
  box.textContent = message;
  box.hidden = false;
  box.scrollIntoView({ block: "nearest" });
}

function hideFormError() {
  const box = $("#tunnel-form-error");
  box.hidden = true;
  box.textContent = "";
}

/* ---------- activity ---------- */

function switchTab(tab) {
  if (!tab || tab === app.tab) return;
  app.tab = tab;
  app.activity = null;
  app.lastActivityAt = 0;
  $$("#activity-tabs button").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.tab === tab ? "true" : "false");
  });
  $("#log-filter-wrap").hidden = tab !== "logs";
  $("#activity-body").innerHTML = `<div class="skeleton-row"></div><div class="skeleton-row"></div><div class="skeleton-row"></div>`;
  $("#activity-summary").textContent = "Loading activity…";
  loadActivity(true);
}

async function loadActivity(force) {
  if (!app.state) return;
  if (!force && Date.now() - app.lastActivityAt < 4000) return;
  const tab = app.tab;
  const seq = ++app.activitySeq;
  app.activityLoading = true;
  app.activityError = "";

  let path = "/api/history?limit=100";
  if (tab === "logs") {
    const tunnel = $("#log-filter").value;
    path = `/api/logs?limit=200${tunnel ? `&tunnel=${encodeURIComponent(tunnel)}` : ""}`;
  } else if (tab === "audit") {
    path = "/api/audit?limit=100";
  }

  try {
    const rows = await api(path);
    if (seq !== app.activitySeq || tab !== app.tab) return;
    app.activity = { tab, rows: Array.isArray(rows) ? rows : [] };
    app.lastActivityAt = Date.now();
    renderActivity();
  } catch (error) {
    if (seq !== app.activitySeq || tab !== app.tab) return;
    app.activityError = error.message;
    app.activity = { tab, rows: [] };
    renderActivity();
  } finally {
    if (seq === app.activitySeq) app.activityLoading = false;
  }
}

function renderActivity() {
  const body = $("#activity-body");
  const summary = $("#activity-summary");
  if (app.activityError) {
    body.innerHTML = `<div class="table-error">${esc(app.activityError)}</div>`;
    summary.textContent = "Could not load activity";
    return;
  }
  if (!app.activity) {
    summary.textContent = "Loading activity…";
    return;
  }
  const { tab, rows } = app.activity;
  const suffix = rows.length === 1 ? "entry" : "entries";
  summary.textContent = `${rows.length} ${suffix} · most recent first`;

  if (!rows.length) {
    body.innerHTML = `<div class="table-empty">No ${esc(tab)} recorded yet.</div>`;
    return;
  }

  if (tab === "rotations") {
    body.innerHTML = rotationsTable(rows);
  } else if (tab === "logs") {
    body.innerHTML = logsTable(rows);
  } else {
    body.innerHTML = auditTable(rows);
  }
}

function rotationsTable(rows) {
  const body = rows.map((row) => {
    const route = row.to_tunnel
      ? `${esc(row.from_tunnel || "—")}<span class="route-arrow">→</span>${esc(row.to_tunnel)}`
      : `${esc(row.from_tunnel || "—")}<span class="route-arrow">→</span>original uplink`;
    const ips = row.new_public_ip
      ? `${esc(row.old_public_ip || "—")}<span class="route-arrow">→</span>${esc(row.new_public_ip)}`
      : esc(row.old_public_ip || "—");
    return `<tr>
      <td class="cell-time" title="${esc(fullTime(row.at))}">${esc(relativeTime(row.at))}</td>
      <td class="cell-strong">${route}</td>
      <td class="cell-mono">${esc(row.reason || "—")}</td>
      <td class="cell-mono">${ips}</td>
      <td><span class="pill ${row.success ? "pill-success" : "pill-fail"}">${row.success ? "Verified" : "Failed"}</span></td>
      <td class="cell-detail" title="${esc(row.detail || "")}">${esc(row.detail || "—")}</td>
    </tr>`;
  }).join("");
  return `<table class="data-table">
    <thead><tr><th>Time</th><th>Route</th><th>Reason</th><th>Public IP</th><th>Result</th><th>Detail</th></tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

function logsTable(rows) {
  const body = rows.map((row) => {
    const level = String(row.level || "info").toLowerCase();
    return `<tr>
      <td class="cell-time" title="${esc(fullTime(row.at))}">${esc(relativeTime(row.at))}</td>
      <td><span class="level-badge level-${esc(level)}">${esc(level)}</span></td>
      <td class="cell-strong cell-nowrap">${esc(row.tunnel || "system")}</td>
      <td><div class="log-message">${esc(row.message)}</div></td>
    </tr>`;
  }).join("");
  return `<table class="data-table">
    <thead><tr><th>Time</th><th>Level</th><th>Tunnel</th><th>Message</th></tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

function auditTable(rows) {
  const body = rows.map((row) => {
    return `<tr>
      <td class="cell-time" title="${esc(fullTime(row.at))}">${esc(relativeTime(row.at))}</td>
      <td class="cell-strong cell-nowrap">${esc(row.actor || "—")}</td>
      <td class="cell-mono">${esc(row.action || "—")}</td>
      <td class="cell-nowrap">${esc(row.tunnel || "—")}</td>
      <td class="cell-detail" title="${esc(row.detail || "")}">${esc(row.detail || "—")}</td>
      <td class="cell-mono cell-nowrap">${esc(row.ip || "—")}</td>
    </tr>`;
  }).join("");
  return `<table class="data-table">
    <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Tunnel</th><th>Detail</th><th>Source IP</th></tr></thead>
    <tbody>${body}</tbody>
  </table>`;
}

function syncLogFilterOptions() {
  if (!app.state) return;
  const select = $("#log-filter");
  const current = select.value;
  const names = app.state.tunnels.map((tunnel) => tunnel.name);
  const existing = $$("option", select).slice(1).map((option) => option.value);
  if (names.length !== existing.length || names.some((name, index) => name !== existing[index])) {
    select.innerHTML = `<option value="">All tunnels</option>` + names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
    if (names.includes(current)) select.value = current;
  }
}

/* ---------- confirmation ---------- */

function confirmAction({ title, message, label, destructive = false }) {
  const dialog = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  const button = $("#confirm-button");
  button.textContent = label || "Confirm";
  button.className = `btn ${destructive ? "btn-danger" : "btn-primary"}`;
  dialog.returnValue = "";
  if (!dialog.open) dialog.showModal();
  return new Promise((resolve) => {
    const onClose = () => {
      resolve(dialog.returnValue === "confirm");
    };
    dialog.addEventListener("close", onClose, { once: true });
  });
}

/* ---------- utilities ---------- */

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } catch {
    /* The cookie is cleared server-side when the session still exists. */
  }
  window.location.assign("/login");
}

async function copyPublicIP() {
  const ip = app.state && app.state.public_ip;
  if (!ip) return;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(ip);
    } else {
      const area = document.createElement("textarea");
      area.value = ip;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    toast(`Copied ${ip}.`, "success");
    const label = $("#copy-label");
    label.textContent = "Copied";
    window.clearTimeout(app.copyTimer);
    app.copyTimer = window.setTimeout(() => {
      label.textContent = "Copy public IP";
    }, 1600);
  } catch {
    toast("Could not access the clipboard.", "error");
  }
}

function toast(message, kind = "info") {
  const region = $("#toast-region");
  const node = document.createElement("div");
  node.className = "toast";
  node.dataset.kind = kind;
  node.textContent = message;
  region.appendChild(node);
  const life = kind === "error" ? 6500 : 3800;
  window.setTimeout(() => {
    node.classList.add("is-leaving");
    window.setTimeout(() => node.remove(), 220);
  }, life);
}

function humanDuration(seconds) {
  let total = Math.max(0, Math.floor(Number(seconds) || 0));
  if (total < 60) return `${total}s`;
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function relativeTime(value) {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (!Number.isFinite(then)) return "—";
  const diff = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diff < 10) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function fullTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function formatClock(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return date.toISOString().slice(11, 16);
}

function tickClock() {
  const now = new Date();
  $("#topbar-clock").textContent = `${now.toISOString().slice(11, 19)} UTC`;
  updateCountdown();
}
