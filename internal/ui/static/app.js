"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

let state = { servers: [], namespaces: [], endpoints: [], keys: [], mappings: {} };
let editingServer = null;
let editingEndpoint = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (res.status === 401) {
    showLogin();
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// --- auth ---

function showLogin() {
  $("#main-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
}
function showMain(name) {
  $("#login-view").classList.add("hidden");
  $("#main-view").classList.remove("hidden");
  $("#session-name").textContent = name || "";
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const key = $("#login-key").value.trim();
  $("#login-error").classList.add("hidden");
  try {
    const res = await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ key }),
    });
    showMain(res.name);
    $("#login-key").value = "";
    await loadOverview();
  } catch (err) {
    $("#login-error").textContent = "Invalid API key";
    $("#login-error").classList.remove("hidden");
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try { await api("/api/admin/logout", { method: "POST" }); } catch (_) {}
  showLogin();
});

// --- tabs ---

$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    $$(".tab-panel").forEach((p) => p.classList.add("hidden"));
    $("#tab-" + btn.dataset.tab).classList.remove("hidden");
  });
});

// --- overview ---

async function loadOverview() {
  const data = await api("/api/admin/overview");
  state = data;
  renderStats();
  renderOverviewServers();
  renderOverviewEndpoints();
  renderServers();
  renderNamespaces();
  renderEndpoints();
  renderKeys();
}

function renderStats() {
  const tools = state.tool_count || 0;
  $("#stat-row").innerHTML = [
    ["Servers", state.servers.length],
    ["Namespaces", state.namespaces.length],
    ["Endpoints", state.endpoints.length],
    ["API keys", state.keys.length],
    ["Tools", tools],
  ].map(([lbl, num]) => `<div class="stat"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`).join("");
}

function renderOverviewServers() {
  const el = $("#overview-servers");
  if (!state.servers.length) { el.innerHTML = '<p class="muted">No servers yet.</p>'; return; }
  el.innerHTML = state.servers.map((s) => `
    <div class="card"><div class="row">
      <div>
        <div class="name">${esc(s.name)} <span class="badge ${s.error_status === "NONE" ? "ok" : "error"}">${esc(s.error_status)}</span></div>
        <div class="sub">${esc(s.type)}${s.url ? " · " + esc(s.url) : ""}</div>
      </div>
      <div class="actions">
        <button class="small" data-test="${s.uuid}">Test</button>
        <button class="small" data-edit-server="${s.uuid}">Edit</button>
        <button class="small danger" data-del-server="${s.uuid}">Delete</button>
      </div>
    </div></div>`).join("");
  el.querySelectorAll("[data-test]").forEach((b) => b.addEventListener("click", () => testServer(b.dataset.test, b)));
  el.querySelectorAll("[data-edit-server]").forEach((b) => b.addEventListener("click", () => openServerForm(b.dataset.editServer)));
  el.querySelectorAll("[data-del-server]").forEach((b) => b.addEventListener("click", () => delServer(b.dataset.delServer)));
}

function renderOverviewEndpoints() {
  const el = $("#overview-endpoints");
  if (!state.endpoints.length) { el.innerHTML = '<p class="muted">No endpoints yet.</p>'; return; }
  el.innerHTML = state.endpoints.map((e) => {
    const ns = state.namespaces.find((n) => n.uuid === e.namespace_uuid);
    return `<div class="card"><div class="row">
      <div>
        <div class="name">/metamcp/${esc(e.name)}/mcp</div>
        <div class="sub">namespace: ${esc(ns ? ns.name : e.namespace_uuid)} · auth: ${e.enable_api_key_auth ? "API key" : "open"}</div>
      </div>
    </div></div>`;
  }).join("");
}

// --- servers ---

function renderServers() {
  const el = $("#servers-list");
  if (!state.servers.length) { el.innerHTML = '<p class="muted">No servers yet.</p>'; return; }
  el.innerHTML = state.servers.map((s) => `
    <div class="card"><div class="row">
      <div>
        <div class="name">${esc(s.name)} <span class="badge ${s.error_status === "NONE" ? "ok" : "error"}">${esc(s.error_status)}</span></div>
        <div class="sub">${esc(s.type)}${s.url ? " · " + esc(s.url) : ""}${s.description ? " · " + esc(s.description) : ""}</div>
      </div>
      <div class="actions">
        <button class="small" data-test="${s.uuid}">Test</button>
        <button class="small" data-edit-server="${s.uuid}">Edit</button>
        <button class="small danger" data-del-server="${s.uuid}">Delete</button>
      </div>
    </div></div>`).join("");
  el.querySelectorAll("[data-test]").forEach((b) => b.addEventListener("click", () => testServer(b.dataset.test, b)));
  el.querySelectorAll("[data-edit-server]").forEach((b) => b.addEventListener("click", () => openServerForm(b.dataset.editServer)));
  el.querySelectorAll("[data-del-server]").forEach((b) => b.addEventListener("click", () => delServer(b.dataset.delServer)));
}

async function testServer(uuid, btn) {
  const old = btn.textContent;
  btn.textContent = "…";
  btn.disabled = true;
  try {
    const r = await api(`/api/admin/servers/${uuid}/test`, { method: "POST", body: "{}" });
    btn.textContent = r.ok ? `✓ ${r.tools} tools` : "✗ fail";
    btn.className = "small " + (r.ok ? "ok" : "danger");
  } catch (_) {
    btn.textContent = "✗ fail";
    btn.className = "small danger";
  } finally {
    setTimeout(() => { btn.textContent = old; btn.className = "small"; btn.disabled = false; }, 4000);
  }
}

$("#server-new").addEventListener("click", () => openServerForm(null));
$("#server-form-cancel").addEventListener("click", () => $("#server-form").classList.add("hidden"));

function openServerForm(uuid) {
  editingServer = uuid ? state.servers.find((s) => s.uuid === uuid) : null;
  $("#server-form-title").textContent = editingServer ? "Edit server" : "Add server";
  const f = $("#server-form-fields");
  f.name.value = editingServer?.name || "";
  f.type.value = editingServer?.type || "STREAMABLE_HTTP";
  f.url.value = editingServer?.url || "";
  f.bearer_token.value = editingServer?.bearer_token || "";
  f.description.value = editingServer?.description || "";
  f.headers.value = editingServer?.headers && editingServer.headers !== "{}" ? JSON.stringify(editingServer.headers) : "";
  $("#server-form-error").classList.add("hidden");
  $("#server-form").classList.remove("hidden");
}

$("#server-form-fields").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = {
    name: f.name.value.trim(),
    type: f.type.value,
    url: f.url.value.trim() || null,
    bearer_token: f.bearer_token.value || null,
    description: f.description.value.trim() || null,
    headers: f.headers.value.trim() ? JSON.parse(f.headers.value) : {},
  };
  try {
    if (editingServer) {
      await api(`/api/admin/servers/${editingServer.uuid}`, { method: "PUT", body: JSON.stringify(body) });
    } else {
      await api("/api/admin/servers", { method: "POST", body: JSON.stringify(body) });
    }
    $("#server-form").classList.add("hidden");
    await loadOverview();
  } catch (err) {
    $("#server-form-error").textContent = err.message;
    $("#server-form-error").classList.remove("hidden");
  }
});

async function delServer(uuid) {
  const s = state.servers.find((x) => x.uuid === uuid);
  if (!confirm(`Delete server "${s?.name}"? This removes its tools and mappings.`)) return;
  await api(`/api/admin/servers/${uuid}`, { method: "DELETE" });
  await loadOverview();
}

// --- namespaces ---

function renderNamespaces() {
  const el = $("#namespaces-list");
  if (!state.namespaces.length) { el.innerHTML = '<p class="muted">No namespaces yet.</p>'; return; }
  el.innerHTML = state.namespaces.map((n) => {
    const ms = state.mappings[n.uuid] || [];
    const rows = state.servers.map((s) => {
      const m = ms.find((x) => x.mcp_server_uuid === s.uuid);
      const active = m ? m.status === "ACTIVE" : false;
      return `<tr>
        <td>${esc(s.name)}</td>
        <td><span class="badge ${active ? "active" : "inactive"} toggle" data-ns="${n.uuid}" data-server="${s.uuid}" data-active="${active}">${active ? "ACTIVE" : "INACTIVE"}</span></td>
      </tr>`;
    }).join("");
    return `<div class="card">
      <div class="row">
        <div><div class="name">${esc(n.name)}</div><div class="sub">${esc(n.description || "")}</div></div>
        <div class="actions"><button class="small danger" data-del-ns="${n.uuid}">Delete</button></div>
      </div>
      <table class="matrix"><thead><tr><th>Server</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`;
  }).join("");
  el.querySelectorAll("[data-del-ns]").forEach((b) => b.addEventListener("click", () => delNamespace(b.dataset.delNs)));
  el.querySelectorAll(".toggle").forEach((b) => b.addEventListener("click", () => toggleMapping(b.dataset.ns, b.dataset.server, b.dataset.active === "true")));
}

async function toggleMapping(ns, server, wasActive) {
  await api(`/api/admin/namespaces/${ns}`, {
    method: "POST",
    body: JSON.stringify({ server_uuid: server, status: wasActive ? "INACTIVE" : "ACTIVE" }),
  });
  await loadOverview();
}

$("#namespace-new").addEventListener("click", () => $("#namespace-form").classList.remove("hidden"));
$("#namespace-form-cancel").addEventListener("click", () => $("#namespace-form").classList.add("hidden"));

$("#namespace-form-fields").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    await api("/api/admin/namespaces", {
      method: "POST",
      body: JSON.stringify({ name: f.name.value.trim(), description: f.description.value.trim() || null }),
    });
    $("#namespace-form").classList.add("hidden");
    f.reset();
    await loadOverview();
  } catch (err) {
    $("#namespace-form-error").textContent = err.message;
    $("#namespace-form-error").classList.remove("hidden");
  }
});

async function delNamespace(uuid) {
  const n = state.namespaces.find((x) => x.uuid === uuid);
  if (!confirm(`Delete namespace "${n?.name}"? Its endpoints and mappings are removed.`)) return;
  await api(`/api/admin/namespaces/${uuid}`, { method: "DELETE" });
  await loadOverview();
}

// --- endpoints ---

function renderEndpoints() {
  const el = $("#endpoints-list");
  if (!state.endpoints.length) { el.innerHTML = '<p class="muted">No endpoints yet.</p>'; return; }
  el.innerHTML = state.endpoints.map((e) => {
    const ns = state.namespaces.find((n) => n.uuid === e.namespace_uuid);
    return `<div class="card"><div class="row">
      <div>
        <div class="name">/metamcp/${esc(e.name)}/mcp</div>
        <div class="sub">namespace: ${esc(ns ? ns.name : e.namespace_uuid)} · auth: ${e.enable_api_key_auth ? "API key" : "open"}${e.use_query_param_auth ? " (+query)" : ""}</div>
      </div>
      <div class="actions">
        <button class="small" data-edit-ep="${e.uuid}">Edit</button>
        <button class="small danger" data-del-ep="${e.uuid}">Delete</button>
      </div>
    </div></div>`;
  }).join("");
  el.querySelectorAll("[data-edit-ep]").forEach((b) => b.addEventListener("click", () => openEndpointForm(b.dataset.editEp)));
  el.querySelectorAll("[data-del-ep]").forEach((b) => b.addEventListener("click", () => delEndpoint(b.dataset.delEp)));
}

$("#endpoint-new").addEventListener("click", () => openEndpointForm(null));
$("#endpoint-form-cancel").addEventListener("click", () => $("#endpoint-form").classList.add("hidden"));

function openEndpointForm(uuid) {
  editingEndpoint = uuid ? state.endpoints.find((e) => e.uuid === uuid) : null;
  $("#endpoint-form-title").textContent = editingEndpoint ? "Edit endpoint" : "Add endpoint";
  const sel = $("#endpoint-ns-select");
  sel.innerHTML = state.namespaces.map((n) => `<option value="${n.uuid}">${esc(n.name)}</option>`).join("");
  const f = $("#endpoint-form-fields");
  f.name.value = editingEndpoint?.name || "";
  f.description.value = editingEndpoint?.description || "";
  f.enable_api_key_auth.checked = editingEndpoint ? editingEndpoint.enable_api_key_auth : true;
  f.use_query_param_auth.checked = editingEndpoint ? editingEndpoint.use_query_param_auth : false;
  if (editingEndpoint) sel.value = editingEndpoint.namespace_uuid;
  $("#endpoint-form-error").classList.add("hidden");
  $("#endpoint-form").classList.remove("hidden");
}

$("#endpoint-form-fields").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = {
    name: f.name.value.trim(),
    namespace_uuid: f.namespace_uuid.value,
    description: f.description.value.trim() || null,
    enable_api_key_auth: f.enable_api_key_auth.checked,
    use_query_param_auth: f.use_query_param_auth.checked,
    enable_oauth: false,
  };
  try {
    if (editingEndpoint) {
      await api(`/api/admin/endpoints/${editingEndpoint.uuid}`, { method: "PUT", body: JSON.stringify(body) });
    } else {
      await api("/api/admin/endpoints", { method: "POST", body: JSON.stringify(body) });
    }
    $("#endpoint-form").classList.add("hidden");
    await loadOverview();
  } catch (err) {
    $("#endpoint-form-error").textContent = err.message;
    $("#endpoint-form-error").classList.remove("hidden");
  }
});

async function delEndpoint(uuid) {
  const e = state.endpoints.find((x) => x.uuid === uuid);
  if (!confirm(`Delete endpoint "/metamcp/${e?.name}/mcp"?`)) return;
  await api(`/api/admin/endpoints/${uuid}`, { method: "DELETE" });
  await loadOverview();
}

// --- keys ---

function renderKeys() {
  const el = $("#keys-list");
  if (!state.keys.length) { el.innerHTML = '<p class="muted">No API keys yet.</p>'; return; }
  el.innerHTML = state.keys.map((k) => `
    <div class="card"><div class="row">
      <div>
        <div class="name">${esc(k.name)} <span class="badge ${k.is_active ? "active" : "inactive"}">${k.is_active ? "ACTIVE" : "INACTIVE"}</span></div>
        <div class="sub"><code>${esc(k.key)}</code> · created ${new Date(k.created_at).toLocaleString()}</div>
      </div>
      <div class="actions">
        <button class="small" data-toggle-key="${k.uuid}" data-active="${k.is_active}">${k.is_active ? "Disable" : "Enable"}</button>
      </div>
    </div></div>`).join("");
  el.querySelectorAll("[data-toggle-key]").forEach((b) => b.addEventListener("click", () => toggleKey(b.dataset.toggleKey, b.dataset.active === "true")));
}

$("#key-new").addEventListener("click", () => $("#key-form").classList.remove("hidden"));
$("#key-form-cancel").addEventListener("click", () => $("#key-form").classList.add("hidden"));

$("#key-form-fields").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  try {
    const r = await api("/api/admin/keys", {
      method: "POST",
      body: JSON.stringify({ name: f.name.value.trim(), key: f.key.value.trim() || null }),
    });
    $("#key-form").classList.add("hidden");
    f.reset();
    if (r.key && r.key.key) alert(`Key created: ${r.key.key}\n\nCopy it now — it won't be shown again.`);
    await loadOverview();
  } catch (err) {
    $("#key-form-error").textContent = err.message;
    $("#key-form-error").classList.remove("hidden");
  }
});

async function toggleKey(uuid, wasActive) {
  await api(`/api/admin/keys/${uuid}`, { method: "POST", body: JSON.stringify({ active: !wasActive }) });
  await loadOverview();
}

// --- boot ---

(async () => {
  try {
    const data = await api("/api/admin/overview");
    state = data;
    showMain("signed in");
    renderStats();
    renderOverviewServers();
    renderOverviewEndpoints();
    renderServers();
    renderNamespaces();
    renderEndpoints();
    renderKeys();
  } catch (_) {
    showLogin();
  }
})();
