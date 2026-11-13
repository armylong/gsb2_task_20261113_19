/* HAR 本地脱敏工具前端(原生 JS)。
 * 安全要点:所有来自 HAR 的数据一律通过 createElement + textContent 渲染,
 * 不使用 innerHTML 插入数据,因此 HAR 内的 HTML/<script> 只会以文本显示,不会执行。
 */
"use strict";

const LOCATION_LABELS = {
  request_header: "请求头",
  response_header: "响应头",
  query: "查询参数",
  request_body: "请求体",
  response_body: "响应体",
};
const TREATMENT_LABELS = {
  mask: "固定遮盖",
  delete: "删除字段",
  pseudo: "一致化代号",
};
const LOCATIONS = Object.keys(LOCATION_LABELS);

const state = {
  selectedIndex: null,
  previewMode: false,
  keyword: "",
  findings: [],
  unchecked: [],
  revealed: new Set(),
  ruleLocations: new Set(LOCATIONS),
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  if (!resp.ok) {
    let msg = `请求失败(${resp.status})`;
    try {
      const data = await resp.json();
      if (data && data.detail) msg = data.detail;
    } catch (_) { /* 保留默认消息 */ }
    throw new Error(msg);
  }
  return resp.status === 204 ? null : resp.json();
}

function toast(message, kind = "") {
  const t = $("toast");
  t.textContent = message;
  t.className = `toast ${kind}`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => t.classList.add("hidden"), 4000);
}

function renderBanner(scan) {
  const banner = $("banner");
  banner.className = "banner hidden";
  if (!scan) return;
  const parts = [];
  if (scan.pending_count > 0) parts.push(`未处理发现项 ${scan.pending_count} 条`);
  if (scan.unchecked_count > 0) parts.push(`未检查内容 ${scan.unchecked_count} 处`);
  if (scan.invalid_rules && scan.invalid_rules.length) {
    parts.push(`非法规则 ${scan.invalid_rules.length} 条(已跳过,旧结果保留)`);
  }
  if (parts.length) {
    banner.textContent = "⚠️ " + parts.join(";") + "。存在遗漏时导出文件可能仍含敏感信息,请先复核。";
    banner.className = "banner danger";
  } else if (scan.finding_count > 0) {
    banner.textContent = `✅ 共 ${scan.finding_count} 条发现项均已确认,且没有未检查内容。`;
    banner.className = "banner";
  }
}

// ---------------- 初始化 ----------------
function initLocationChecks() {
  const box = $("rule-locations");
  box.textContent = "";
  for (const loc of LOCATIONS) {
    const label = el("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = loc;
    cb.checked = true;
    cb.addEventListener("change", () => {
      if (cb.checked) state.ruleLocations.add(loc);
      else state.ruleLocations.delete(loc);
    });
    label.appendChild(cb);
    label.appendChild(el("span", "", LOCATION_LABELS[loc]));
    box.appendChild(label);
  }
}

async function refreshAll() {
  const s = await api("/api/state");
  $("entry-count").textContent = s.loaded ? `${s.entry_count} 条请求 · ${s.source_name}` : "";
  $("btn-export-har").disabled = !s.loaded;
  $("btn-export-summary").disabled = !s.loaded;
  renderBanner(s.scan);
  await loadEntries();
  await loadFindings();
  await loadRules();
  if (state.selectedIndex !== null && s.loaded) {
    await openEntry(state.selectedIndex);
  } else {
    $("detail").classList.add("hidden");
    $("detail-empty").classList.remove("hidden");
  }
}

// ---------------- 条目列表 ----------------
async function loadEntries() {
  const url = "/api/entries" + (state.keyword ? `?keyword=${encodeURIComponent(state.keyword)}` : "");
  const data = await api(url);
  const list = $("entry-list");
  list.textContent = "";
  if (!data.entries.length) {
    list.appendChild(el("li", "empty-hint", "没有匹配的请求"));
    return;
  }
  for (const meta of data.entries) {
    const li = el("li", `entry-item ${meta.broken ? "broken" : ""}`);
    if (meta.index === state.selectedIndex) li.classList.add("active");

    const line1 = el("div", "entry-line1");
    if (meta.broken) {
      line1.appendChild(el("span", "badge broken-badge", "坏条目"));
      line1.appendChild(el("span", "muted", meta.error));
    } else {
      line1.appendChild(el("span", `method ${meta.method}`, meta.method));
      const statusClass = meta.status && meta.status >= 400 ? "status err" : "status";
      line1.appendChild(el("span", statusClass, meta.status === 0 || meta.status == null ? "-" : meta.status));
      line1.appendChild(el("span", "status", meta.time_ms == null ? "" : `${meta.time_ms}ms`));
    }
    li.appendChild(line1);
    li.appendChild(el("div", "url-cell", meta.broken ? `#${meta.index}` : meta.url));

    if (!meta.broken) {
      const badges = el("div", "badges");
      if (meta.finding_count) badges.appendChild(el("span", "badge find", `发现 ${meta.finding_count}`));
      if (meta.unchecked_count) badges.appendChild(el("span", "badge unchecked", `未检查 ${meta.unchecked_count}`));
      li.appendChild(badges);
    }
    li.addEventListener("click", () => openEntry(meta.index));
    list.appendChild(li);
  }
}

// ---------------- 条目详情 ----------------
async function openEntry(index) {
  state.selectedIndex = index;
  state.previewMode = false;
  $("btn-toggle-preview").textContent = "切换到脱敏预览";
  await renderEntryDetail();
  await loadEntries();
}

async function renderEntryDetail() {
  const path = state.previewMode
    ? `/api/entries/${state.selectedIndex}/preview`
    : `/api/entries/${state.selectedIndex}`;
  const d = await api(path);
  const detail = $("detail");
  const empty = $("detail-empty");
  detail.classList.remove("hidden");
  empty.classList.add("hidden");
  const body = $("detail-body");
  body.textContent = "";

  if (d.broken) {
    $("d-title").textContent = `请求 #${d.index}(损坏)`;
    const warn = el("div", "tag danger", `该条目损坏:${d.error},已跳过检查,其他条目不受影响`);
    body.appendChild(warn);
    return;
  }
  $("d-title").textContent = `#${d.index} ${d.method} ${d.url}`;

  if (state.previewMode) {
    const note = el("div", "tag warn", `脱敏预览模式 · 本条目应用 ${d.changes.length} 处改写(与导出文件完全一致)`);
    body.appendChild(note);
  }

  // 请求
  const reqSec = el("div", "section");
  reqSec.appendChild(el("h4", "", "请求头"));
  reqSec.appendChild(renderKv(d.request.headers.map((h) => [h.name, h.value])));
  if (d.request.query.length) {
    reqSec.appendChild(el("h4", "", `查询参数(${d.request.query.length})`));
    reqSec.appendChild(renderKv(d.request.query.map((q) => [q.name, q.value])));
  }
  reqSec.appendChild(el("h4", "", "请求体"));
  reqSec.appendChild(renderBody(d.request.body));
  body.appendChild(reqSec);

  // 响应
  const respSec = el("div", "section");
  respSec.appendChild(el("h4", "", `响应 · ${d.response.status} ${d.response.status_text}`));
  respSec.appendChild(renderKv(d.response.headers.map((h) => [h.name, h.value])));
  respSec.appendChild(el("h4", "", "响应体"));
  respSec.appendChild(renderBody(d.response.body));
  body.appendChild(respSec);

  // 该条目发现项
  if (d.findings && d.findings.length) {
    const fSec = el("div", "section");
    fSec.appendChild(el("h4", "", `本条目发现项(${d.findings.length})`));
    for (const f of d.findings) fSec.appendChild(renderFindingCard(f, true));
    body.appendChild(fSec);
  }
  if (d.unchecked && d.unchecked.length) {
    const uSec = el("div", "section");
    uSec.appendChild(el("h4", "", "未检查内容"));
    for (const u of d.unchecked) {
      uSec.appendChild(el("div", "unchecked-item",
        `${LOCATION_LABELS[u.location] || u.location} · ${u.field_label}:${u.reason}`));
    }
    body.appendChild(uSec);
  }
}

function renderKv(pairs) {
  const box = el("div", "kv");
  for (const [k, v] of pairs) {
    box.appendChild(el("div", "k", k));
    box.appendChild(el("div", "v", v));
  }
  return box;
}

function renderBody(body) {
  const wrap = el("div");
  wrap.appendChild(el("span", "tag", `${body.kind} · ${body.mime || "无 MIME"}`));
  if (body.kind === "empty") {
    wrap.appendChild(el("div", "muted", "(空)"));
  } else if (body.kind === "binary" || body.kind === "base64-error" || body.kind === "json-error") {
    wrap.appendChild(el("div", "tag danger", `未检查:${body.error}`));
    if (body.text) wrap.appendChild(el("pre", "body-text", body.text));
  } else {
    wrap.appendChild(el("pre", "body-text", body.text));
  }
  return wrap;
}

// ---------------- 发现项 ----------------
async function loadFindings() {
  const data = await api("/api/findings");
  state.findings = data.findings;
  state.unchecked = data.unchecked;
  $("finding-count-badge").textContent = data.findings.length ? `(${data.findings.length})` : "";

  const list = $("finding-list");
  list.textContent = "";
  if (!data.findings.length) {
    list.appendChild(el("li", "empty-hint", "没有发现敏感内容"));
  } else {
    for (const f of data.findings) list.appendChild(renderFindingCard(f, false));
  }

  const ulist = $("unchecked-list");
  ulist.textContent = "";
  if (!data.unchecked.length) {
    ulist.appendChild(el("li", "muted", "无"));
  } else {
    for (const u of data.unchecked) {
      ulist.appendChild(el("li", "unchecked-item",
        `#${u.entry_index} ${LOCATION_LABELS[u.location] || u.location}:${u.reason}`));
    }
  }
  renderBanner(data.scan);
}

function renderFindingCard(f, compact) {
  const card = el("div", `finding-item ${f.handled ? "handled" : "pending"}`);
  const head = el("div", "f-head");
  head.appendChild(el("span", "f-loc",
    `#${f.entry_index} · ${LOCATION_LABELS[f.location] || f.location} · ${f.handled ? "已确认" : "未处理"}`));
  card.appendChild(head);
  card.appendChild(el("div", "f-field", f.field_label));
  card.appendChild(el("div", "f-rules", f.rule_names.join(" / ")));

  const valueLine = el("div", "f-value masked");
  const showRaw = state.revealed.has(f.id);
  if (showRaw) {
    valueLine.classList.remove("masked");
    valueLine.textContent = f.raw_value || "";
  } else {
    valueLine.textContent = f.value_preview;
  }
  card.appendChild(valueLine);

  if (f.treatment === "pseudo" && f.pseudo_code) {
    card.appendChild(el("div", "pseudo-hint", `一致化代号:${f.pseudo_code}(同原值同代号)`));
  }

  const controls = el("div", "f-controls");
  const select = document.createElement("select");
  for (const t of ["mask", "delete", "pseudo"]) {
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = TREATMENT_LABELS[t];
    if (f.treatment === t) opt.selected = true;
    select.appendChild(opt);
  }
  select.addEventListener("change", async () => {
    await applyTreatment([f.id], select.value, true);
  });
  controls.appendChild(select);

  const revealBtn = el("button", "btn small", showRaw ? "隐藏原文" : "查看原文");
  revealBtn.addEventListener("click", async () => {
    if (!state.revealed.has(f.id)) {
      const data = await api(`/api/findings/${f.id}/reveal`);
      f.raw_value = data.raw_value;
      state.revealed.add(f.id);
    } else {
      state.revealed.delete(f.id);
    }
    await loadFindings();
    if (state.selectedIndex !== null) await renderEntryDetail();
  });
  controls.appendChild(revealBtn);

  const markBtn = el("button", "btn small", f.handled ? "标记未处理" : "标记已确认");
  markBtn.addEventListener("click", async () => {
    await api("/api/findings/mark", {
      method: "POST",
      body: JSON.stringify({ finding_ids: [f.id], handled: !f.handled }),
    });
    await refreshAll();
  });
  controls.appendChild(markBtn);
  card.appendChild(controls);
  return card;
}

async function applyTreatment(ids, treatment, handled) {
  try {
    await api("/api/findings/treatment", {
      method: "POST",
      body: JSON.stringify({ finding_ids: ids, treatment, handled }),
    });
    toast(`已对 ${ids.length} 项应用「${TREATMENT_LABELS[treatment]}」`, "success");
    await refreshAll();
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------- 规则 ----------------
async function loadRules() {
  const data = await api("/api/rules");
  const list = $("rule-list");
  list.textContent = "";
  for (const r of data.rules) {
    const li = el("li", `rule-item ${r.enabled ? "" : "off"}`);
    li.appendChild(el("div", "r-name", r.name + (r.builtin ? " " : "")));
    if (r.builtin) li.querySelector(".r-name").appendChild(el("span", "pill", "内置"));
    li.appendChild(el("div", "r-meta",
      `${r.match_type === "regex" ? "正则" : "字段名"}:${r.pattern}`));
    li.appendChild(el("div", "r-meta",
      "位置:" + r.locations.map((l) => LOCATION_LABELS[l]).join("、")));

    const actions = el("div", "r-actions");
    const toggle = el("button", "btn small", r.enabled ? "停用" : "启用");
    toggle.addEventListener("click", async () => {
      try {
        await api(`/api/rules/${r.id}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: !r.enabled }),
        });
        await refreshAll();
      } catch (err) { toast(err.message, "error"); }
    });
    actions.appendChild(toggle);

    if (!r.builtin) {
      const del = el("button", "btn small danger", "删除");
      del.addEventListener("click", async () => {
        try {
          await api(`/api/rules/${r.id}`, { method: "DELETE" });
          toast("规则已删除并重新检查", "success");
          await refreshAll();
        } catch (err) { toast(err.message, "error"); }
      });
      actions.appendChild(del);
    }
    li.appendChild(actions);
    list.appendChild(li);
  }
}

$("rule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    name: $("rule-name").value.trim(),
    match_type: $("rule-match-type").value,
    pattern: $("rule-pattern").value,
    locations: Array.from(state.ruleLocations),
    enabled: true,
  };
  try {
    await api("/api/rules", { method: "POST", body: JSON.stringify(body) });
    toast("规则已新增,重新检查完成", "success");
    $("rule-name").value = "";
    $("rule-pattern").value = "";
    await refreshAll();
  } catch (err) {
    toast(err.message, "error");
  }
});

// ---------------- 顶部操作 ----------------
$("file-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  try {
    const resp = await fetch("/api/upload", { method: "POST", body: form });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "上传失败");
    }
    state.selectedIndex = null;
    state.revealed.clear();
    toast(`已加载 ${file.name}`, "success");
    await refreshAll();
  } catch (err) {
    toast(`文件无法解析,当前已打开的文件保留:${err.message}`, "error");
  }
  e.target.value = "";
});

$("btn-demo").addEventListener("click", async () => {
  await api("/api/demo", { method: "POST" });
  state.selectedIndex = null;
  state.revealed.clear();
  toast("演示数据已载入(虚构数据)", "success");
  await refreshAll();
});

$("btn-demo-download").addEventListener("click", () => {
  window.location.href = "/api/demo/download";
});

$("btn-clear").addEventListener("click", async () => {
  if (!confirm("确认清空当前 HAR、发现项与所有自定义规则?原始文件不会被删除。")) return;
  await api("/api/clear", { method: "DELETE" });
  state.selectedIndex = null;
  state.revealed.clear();
  toast("已清空全部临时数据", "success");
  await refreshAll();
});

$("btn-export-har").addEventListener("click", () => {
  window.location.href = "/api/export/har";
});
$("btn-export-summary").addEventListener("click", () => {
  window.location.href = "/api/export/summary";
});

$("btn-bulk-apply").addEventListener("click", async () => {
  const ids = state.findings.map((f) => f.id);
  if (!ids.length) return toast("没有发现项可处理");
  await applyTreatment(ids, $("bulk-treatment").value, true);
});
$("btn-bulk-mark").addEventListener("click", async () => {
  const ids = state.findings.map((f) => f.id);
  if (!ids.length) return;
  await api("/api/findings/mark", {
    method: "POST",
    body: JSON.stringify({ finding_ids: ids, handled: true }),
  });
  await refreshAll();
});

$("btn-toggle-preview").addEventListener("click", async () => {
  state.previewMode = !state.previewMode;
  $("btn-toggle-preview").textContent = state.previewMode ? "返回原始详情" : "切换到脱敏预览";
  await renderEntryDetail();
});

$("keyword").addEventListener("input", (e) => {
  state.keyword = e.target.value;
  clearTimeout($("keyword")._timer);
  $("keyword")._timer = setTimeout(loadEntries, 250);
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    $("tab-findings").classList.toggle("hidden", tab.dataset.tab !== "findings");
    $("tab-rules").classList.toggle("hidden", tab.dataset.tab !== "rules");
  });
});

initLocationChecks();
refreshAll().catch((err) => toast(err.message, "error"));
