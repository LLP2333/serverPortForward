"use strict";

const ui = {
  serviceBadge: document.querySelector("#serviceBadge"),
  refreshButton: document.querySelector("#refreshButton"),
  exitButton: document.querySelector("#exitButton"),
  message: document.querySelector("#message"),
  settingsForm: document.querySelector("#settingsForm"),
  defaultTarget: document.querySelector("#defaultTarget"),
  localAddresses: document.querySelector("#localAddresses"),
  sshExample: document.querySelector("#sshExample"),
  copySSH: document.querySelector("#copySSH"),
  servicePanel: document.querySelector("#servicePanel"),
  serviceDetail: document.querySelector("#serviceDetail"),
  startServiceButton: document.querySelector("#startServiceButton"),
  formTitle: document.querySelector("#formTitle"),
  ruleForm: document.querySelector("#ruleForm"),
  description: document.querySelector("#description"),
  listenAddress: document.querySelector("#listenAddress"),
  listenPort: document.querySelector("#listenPort"),
  connectAddress: document.querySelector("#connectAddress"),
  connectPort: document.querySelector("#connectPort"),
  submitRuleButton: document.querySelector("#submitRuleButton"),
  cancelEditButton: document.querySelector("#cancelEditButton"),
  adoptNotice: document.querySelector("#adoptNotice"),
  rulesBody: document.querySelector("#rulesBody"),
  emptyRules: document.querySelector("#emptyRules"),
  clearManagedButton: document.querySelector("#clearManagedButton"),
  portProxyDump: document.querySelector("#portProxyDump"),
  listenerDump: document.querySelector("#listenerDump"),
  lastError: document.querySelector("#lastError"),
  warnings: document.querySelector("#warnings"),
  copyDiagnostics: document.querySelector("#copyDiagnostics"),
  testDialog: document.querySelector("#testDialog"),
  testResults: document.querySelector("#testResults"),
};

let state = null;
let csrfToken = "";
let editing = null;
let messageTimer = null;

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = new Headers(options.headers || {});
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (method !== "GET") headers.set("X-SPF-CSRF", csrfToken);
  const response = await fetch(path, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    let error = { message: `请求失败 (${response.status})`, details: "" };
    try { error = await response.json(); } catch (_) { /* use fallback */ }
    const detail = error.details ? `\n${error.details}` : "";
    throw new Error(`${error.message || "操作失败"}${detail}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

async function refreshState(showSuccess = false) {
  setBusy(ui.refreshButton, true, "刷新中…");
  try {
    const payload = await api("/api/state");
    csrfToken = payload.csrfToken;
    state = payload;
    renderState();
    if (showSuccess) showMessage("状态已刷新");
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    setBusy(ui.refreshButton, false, "刷新");
  }
}

function renderState() {
  ui.defaultTarget.value = state.defaultTargetIPv4 || "";
  renderService();
  renderLocalAddresses();
  renderListenAddresses();
  renderRules();
  renderDiagnostics();
}

function renderService() {
  const service = state.ipHelper;
  ui.serviceBadge.className = `badge ${service.running ? "good" : service.disabled ? "bad" : "warn"}`;
  ui.serviceBadge.textContent = service.running ? "IP Helper 正常" : service.disabled ? "IP Helper 已禁用" : "IP Helper 未运行";
  ui.servicePanel.hidden = service.running;
  ui.startServiceButton.hidden = service.disabled;
  ui.serviceDetail.textContent = service.disabled
    ? "服务被系统或企业策略禁用。本工具不会修改启动策略，请联系管理员。"
    : `当前启动模式：${service.startMode || "unknown"}。portproxy 必须依赖此服务。`;
}

function renderLocalAddresses() {
  ui.localAddresses.replaceChildren();
  if (!state.localIPv4.length) {
    const text = document.createElement("span");
    text.className = "hint";
    text.textContent = "未发现可用的非回环 IPv4 地址";
    ui.localAddresses.append(text);
  } else {
    state.localIPv4.forEach((address) => {
      const pill = document.createElement("span");
      pill.className = "address-pill";
      pill.textContent = address;
      ui.localAddresses.append(pill);
    });
  }
  const sshRule = state.rules.find((rule) => rule.configured && rule.connectPort === 22);
  const localAddress = state.localIPv4[0];
  ui.sshExample.textContent = sshRule && localAddress
    ? `ssh -p ${sshRule.listenPort} user@${localAddress}`
    : "请先创建一条目标端口为 22 的规则";
}

function renderListenAddresses() {
  const current = editing ? editing.rule.listenAddress : ui.listenAddress.value || "0.0.0.0";
  const values = ["0.0.0.0", ...state.localIPv4];
  if (current && !values.includes(current)) values.push(current);
  ui.listenAddress.replaceChildren();
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value === "0.0.0.0" ? "0.0.0.0（所有网卡）" : value;
    ui.listenAddress.append(option);
  });
  ui.listenAddress.value = current;
}

function renderRules() {
  ui.rulesBody.replaceChildren();
  ui.emptyRules.hidden = state.rules.length > 0;
  const managedCount = state.rules.filter((rule) => rule.managed).length;
  ui.clearManagedButton.disabled = managedCount === 0;

  state.rules.forEach((rule) => {
    const row = document.createElement("tr");

    const nameCell = document.createElement("td");
    const name = document.createElement("div");
    name.className = "rule-name";
    name.textContent = rule.description || (rule.managed ? "未命名规则" : "系统外部规则");
    const source = document.createElement("div");
    source.className = "source-label";
    source.textContent = rule.managed ? "本工具管理" : "外部规则";
    nameCell.append(name, source);

    const listenCell = endpointCell(`${rule.listenAddress}:${rule.listenPort}`);
    const targetCell = endpointCell(`${rule.connectAddress}:${rule.connectPort}`);

    const statusCell = document.createElement("td");
    const stack = document.createElement("div");
    stack.className = "status-stack";
    stack.append(statusChip(rule.configured ? "已配置" : "系统规则缺失", rule.configured ? "good" : "bad"));
    stack.append(statusChip(rule.listening ? "监听中" : "未监听", rule.listening ? "good" : "warn"));
    if (rule.managed) {
      if (rule.firewallOK === true) stack.append(statusChip("防火墙已开放", "good"));
      else if (rule.firewallOK === false) stack.append(statusChip("防火墙缺失", "bad"));
    }
    if (rule.drifted) stack.append(statusChip("系统规则已被外部修改", "warn"));
    statusCell.append(stack);

    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    actions.append(
      actionButton("测试", "test", rule),
      actionButton(rule.managed ? "编辑" : "接管编辑", "edit", rule),
      actionButton("删除", "delete", rule, true),
    );
    actionCell.append(actions);

    row.append(nameCell, listenCell, targetCell, statusCell, actionCell);
    ui.rulesBody.append(row);
  });
}

function endpointCell(text) {
  const cell = document.createElement("td");
  const value = document.createElement("span");
  value.className = "endpoint";
  value.textContent = text;
  cell.append(value);
  return cell;
}

function statusChip(text, kind) {
  const chip = document.createElement("span");
  chip.className = `status-chip ${kind}`;
  chip.textContent = text;
  return chip;
}

function actionButton(label, action, rule, danger = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button small ghost${danger ? " danger-text" : ""}`;
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.address = rule.listenAddress;
  button.dataset.port = String(rule.listenPort);
  return button;
}

function renderDiagnostics() {
  ui.portProxyDump.textContent = state.diagnostics.portProxyDump || "没有 portproxy 输出";
  ui.listenerDump.textContent = state.diagnostics.listenerLines.length
    ? state.diagnostics.listenerLines.join("\n")
    : "未发现 TCP LISTENING 记录";
  ui.lastError.textContent = state.diagnostics.lastError || "无";
  ui.warnings.replaceChildren();
  state.warnings.forEach((warning) => {
    const item = document.createElement("li");
    item.textContent = warning;
    ui.warnings.append(item);
  });
}

function findRule(address, port) {
  return state.rules.find((rule) => rule.listenAddress === address && rule.listenPort === Number(port));
}

function beginEdit(rule) {
  if (!rule.managed) {
    const confirmed = window.confirm("这是系统中的外部规则。继续编辑会由本工具接管它并新增专属防火墙规则，原有未知防火墙规则不会删除。是否继续？");
    if (!confirmed) return;
  }
  editing = { originalAddress: rule.listenAddress, originalPort: rule.listenPort, adopt: !rule.managed, rule };
  ui.formTitle.textContent = rule.managed ? "编辑端口转发" : "接管并编辑外部规则";
  ui.submitRuleButton.textContent = "保存修改";
  ui.cancelEditButton.hidden = false;
  ui.adoptNotice.hidden = rule.managed;
  ui.description.value = rule.description || "";
  renderListenAddresses();
  ui.listenPort.value = rule.listenPort;
  ui.connectAddress.value = rule.connectAddress;
  ui.connectPort.value = rule.connectPort;
  ui.ruleForm.scrollIntoView({ behavior: "smooth", block: "center" });
}

function resetRuleForm() {
  editing = null;
  ui.ruleForm.reset();
  ui.formTitle.textContent = "新增端口转发";
  ui.submitRuleButton.textContent = "创建规则";
  ui.cancelEditButton.hidden = true;
  ui.adoptNotice.hidden = true;
  renderListenAddresses();
  ui.listenAddress.value = "0.0.0.0";
  ui.connectAddress.value = state?.defaultTargetIPv4 || "";
}

function readRuleForm() {
  return {
    description: ui.description.value.trim(),
    listenAddress: ui.listenAddress.value,
    listenPort: Number(ui.listenPort.value),
    connectAddress: ui.connectAddress.value.trim(),
    connectPort: Number(ui.connectPort.value),
  };
}

async function submitRule(event) {
  event.preventDefault();
  const rule = readRuleForm();
  setBusy(ui.submitRuleButton, true, editing ? "保存中…" : "创建中…");
  try {
    if (editing) {
      await api("/api/rules", {
        method: "PUT",
        body: {
          originalListenAddress: editing.originalAddress,
          originalListenPort: editing.originalPort,
          rule,
          adopt: editing.adopt,
        },
      });
      showMessage("规则已更新");
    } else {
      await api("/api/rules", { method: "POST", body: rule });
      showMessage("规则已创建，转发在关闭管理器后仍会继续生效");
    }
    resetRuleForm();
    await refreshState();
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    setBusy(ui.submitRuleButton, false, editing ? "保存修改" : "创建规则");
  }
}

async function deleteRule(rule) {
  const extra = rule.managed
    ? "同时会删除本工具创建的专属防火墙规则。"
    : "只删除 portproxy；任何原有防火墙规则都会保留。";
  if (!window.confirm(`确定删除 ${rule.listenAddress}:${rule.listenPort} → ${rule.connectAddress}:${rule.connectPort}？\n\n${extra}`)) return;
  try {
    await api("/api/rules", {
      method: "DELETE",
      body: { listenAddress: rule.listenAddress, listenPort: rule.listenPort },
    });
    if (editing && editing.originalAddress === rule.listenAddress && editing.originalPort === rule.listenPort) resetRuleForm();
    showMessage("规则已删除");
    await refreshState();
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function testRule(rule) {
  ui.testResults.replaceChildren();
  const loading = document.createElement("p");
  loading.textContent = "正在测试目标、监听、本地映射和防火墙…";
  ui.testResults.append(loading);
  ui.testDialog.showModal();
  try {
    const result = await api("/api/rules/test", {
      method: "POST",
      body: { listenAddress: rule.listenAddress, listenPort: rule.listenPort },
    });
    ui.testResults.replaceChildren(
      testRow("VPN 目标", result.targetReachable, result.targetMessage),
      testRow("Windows 监听", result.listening, result.listenMessage),
      testRow("本地映射", result.proxyReachable, result.proxyMessage),
      testRow("入站防火墙", result.firewallOK === true, result.firewallMessage, result.firewallOK == null),
    );
    const reminder = document.createElement("div");
    reminder.className = "test-reminder";
    reminder.textContent = result.reminder;
    ui.testResults.append(reminder);
  } catch (error) {
    ui.testResults.replaceChildren();
    const failure = document.createElement("div");
    failure.className = "test-reminder";
    failure.textContent = error.message;
    ui.testResults.append(failure);
  }
}

function testRow(label, success, message, neutral = false) {
  const row = document.createElement("div");
  row.className = "test-row";
  const heading = document.createElement("strong");
  heading.className = neutral ? "" : success ? "good" : "bad";
  heading.textContent = `${neutral ? "•" : success ? "✓" : "✕"} ${label}`;
  const detail = document.createElement("span");
  detail.textContent = message;
  row.append(heading, detail);
  return row;
}

async function saveSettings(event) {
  event.preventDefault();
  const button = ui.settingsForm.querySelector("button[type='submit']");
  setBusy(button, true, "保存中…");
  try {
    await api("/api/settings", { method: "PUT", body: { defaultTargetIPv4: ui.defaultTarget.value.trim() } });
    showMessage("默认目标服务器已保存，只影响新规则");
    await refreshState();
    if (!editing) ui.connectAddress.value = state.defaultTargetIPv4 || "";
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    setBusy(button, false, "保存");
  }
}

async function startIPHelper() {
  if (!window.confirm("要以管理员权限启动 Windows IP Helper 服务吗？本工具不会修改它的启动模式。")) return;
  setBusy(ui.startServiceButton, true, "启动中…");
  try {
    await api("/api/iphelper/start", { method: "POST" });
    showMessage("IP Helper 服务已启动");
    await refreshState();
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    setBusy(ui.startServiceButton, false, "确认并启动");
  }
}

async function clearManaged() {
  if (!window.confirm("只会清除本工具登记的规则，外部规则不会受影响。是否继续？")) return;
  const confirmation = window.prompt("这是批量操作。请输入“清除”以确认：", "");
  if (confirmation !== "清除") return;
  setBusy(ui.clearManagedButton, true, "清除中…");
  try {
    await api("/api/managed-rules/clear", { method: "POST" });
    resetRuleForm();
    showMessage("已管理规则已清除，系统外部规则保持不变");
    await refreshState();
  } catch (error) {
    showMessage(error.message, true);
    await refreshState();
  } finally {
    setBusy(ui.clearManagedButton, false, "清除已管理规则");
  }
}

async function exitApp() {
  if (!window.confirm("退出管理器后，Windows 中已经配置的转发规则仍会继续生效。确定退出？")) return;
  try {
    const result = await api("/api/app/exit", { method: "POST" });
    document.body.replaceChildren();
    const message = document.createElement("main");
    message.className = "container";
    const card = document.createElement("section");
    card.className = "card";
    const heading = document.createElement("h1");
    heading.textContent = "管理器已退出";
    const detail = document.createElement("p");
    detail.textContent = result.message;
    card.append(heading, detail);
    message.append(card);
    document.body.append(message);
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function copyText(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    showMessage(successMessage);
  } catch (_) {
    showMessage("浏览器拒绝访问剪贴板，请手动选择复制。", true);
  }
}

function showMessage(text, isError = false) {
  clearTimeout(messageTimer);
  ui.message.hidden = false;
  ui.message.className = `message${isError ? " error" : ""}`;
  ui.message.textContent = text;
  messageTimer = window.setTimeout(() => { ui.message.hidden = true; }, isError ? 9000 : 4500);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

ui.refreshButton.addEventListener("click", () => refreshState(true));
ui.settingsForm.addEventListener("submit", saveSettings);
ui.ruleForm.addEventListener("submit", submitRule);
ui.cancelEditButton.addEventListener("click", resetRuleForm);
ui.startServiceButton.addEventListener("click", startIPHelper);
ui.clearManagedButton.addEventListener("click", clearManaged);
ui.exitButton.addEventListener("click", exitApp);
ui.copySSH.addEventListener("click", () => copyText(ui.sshExample.textContent, "SSH 命令已复制"));
ui.copyDiagnostics.addEventListener("click", () => {
  const text = [
    "=== portproxy dump ===", ui.portProxyDump.textContent,
    "", "=== TCP listeners ===", ui.listenerDump.textContent,
    "", "=== last error ===", ui.lastError.textContent,
    "", "=== warnings ===", ...state.warnings,
  ].join("\n");
  copyText(text, "诊断信息已复制");
});
ui.rulesBody.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const rule = findRule(button.dataset.address, button.dataset.port);
  if (!rule) return;
  if (button.dataset.action === "edit") beginEdit(rule);
  if (button.dataset.action === "delete") deleteRule(rule);
  if (button.dataset.action === "test") testRule(rule);
});

refreshState().then(() => resetRuleForm());
