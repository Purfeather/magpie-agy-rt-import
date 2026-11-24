"use strict";

(() => {
  const MAX_CREDENTIAL_BYTES = 64 * 1024;
  const INVALID_TOKEN_CHARS_RE = /[\s\u0000-\u001f\u007f]/u;
  const MANUAL_PROFILE_PATH_RE = /^(?:[^/]+\/)?([a-z0-9]{8,32})\/\.gemini\/antigravity-cli\/antigravity-oauth-token$/u;
  const EXPORT_ERROR_MESSAGES = {
    invalid_profile: "账号 Profile ID 格式无效。",
    not_found: "未找到该账号的凭据文件，请刷新列表后重试。",
    invalid_token: "该账号的凭据文件已损坏或缺少有效的 Refresh Token。",
    read_failed: "读取本机凭据文件失败，请检查目录权限。",
    forbidden: "本机服务会话已失效，请重新加载页面。",
  };

  let localSession = null;

  async function sessionRequest(route, fields = {}) {
    if (localSession.nonce) {
      return fetch(new URL(route.slice(1), location.href), {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=UTF-8" },
        body: JSON.stringify({ ...fields, nonce: localSession.nonce }),
        credentials: "omit", redirect: "error", signal: AbortSignal.timeout(8000),
      });
    }
    const { key, origin } = localSession;
    const packet = await localSessionCodec.seal(key, "request:" + route, fields);
    const response = await fetch(origin + route, {
      method: "POST", headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify(packet), redirect: "error", credentials: "omit",
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return new Response(null, { status: response.status });
    const reply = await localSessionCodec.unseal(key, "response:" + route + ":" + packet.iv, await response.json());
    return new Response(JSON.stringify(reply.data), { status: reply.status });
  }

  // DOM references
  const connectionBadge = document.getElementById("connection-badge");
  const connectionText = document.getElementById("connection-text");

  const tokenInput = document.getElementById("token");
  const toggleVisibilityBtn = document.getElementById("toggle-visibility");
  const tokenFeedback = document.getElementById("token-feedback");
  const importPreview = document.getElementById("import-preview");
  const copyJsonBtn = document.getElementById("copy-json");
  const downloadJsonBtn = document.getElementById("download-json");
  const clearImportBtn = document.getElementById("clear-import");
  const importStatus = document.getElementById("import-status");
  const importManual = document.getElementById("import-manual");
  const importResult = document.getElementById("import-result");

  const refreshPageBtn = document.getElementById("refresh-page");
  const serviceSection = document.getElementById("service-accounts-section");
  const accountSearch = document.getElementById("account-search");
  const accountCount = document.getElementById("account-count");
  const serviceState = document.getElementById("service-state");
  const serviceAccountsList = document.getElementById("service-accounts-list");

  const manualDrawer = document.getElementById("manual-export");
  const accountsFolder = document.getElementById("accounts-folder");
  const clearFolderBtn = document.getElementById("clear-folder");
  const manualAccountsList = document.getElementById("manual-accounts-list");
  const exportStatus = document.getElementById("export-status");
  const exportManual = document.getElementById("export-manual");
  const exportManualLabel = document.getElementById("export-manual-label");
  const exportResult = document.getElementById("export-result");

  const toastEl = document.getElementById("toast");

  // Utility helpers
  let toastTimer = 0;
  function showToast(message, kind = "ok") {
    clearTimeout(toastTimer);
    toastEl.textContent = message;
    if (kind === "error") {
      toastEl.setAttribute("data-kind", "error");
    } else {
      toastEl.removeAttribute("data-kind");
    }
    toastEl.hidden = false;
    toastTimer = window.setTimeout(() => {
      toastEl.hidden = true;
    }, 2600);
  }

  function setConnectionState(state, label) {
    connectionBadge.dataset.state = state;
    connectionText.textContent = label;
  }

  function buildImportJson(refreshToken) {
    return JSON.stringify(
      { token: { refresh_token: refreshToken }, auth_method: "consumer" },
      null,
      2
    );
  }

  function validateRawToken(value) {
    if (typeof value !== "string") return "";
    const trimmed = value.trim();
    if (!trimmed || INVALID_TOKEN_CHARS_RE.test(trimmed)) return "";
    if ("{[\"".includes(trimmed[0])) return "";
    return trimmed;
  }

  function parseTokenInput(raw) {
    if (typeof raw !== "string") {
      return { kind: "empty" };
    }
    const trimmed = raw.trim();
    if (!trimmed) {
      return { kind: "empty" };
    }

    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const candidate =
            typeof parsed?.token?.refresh_token === "string"
              ? parsed.token.refresh_token
              : typeof parsed?.refresh_token === "string"
                ? parsed.refresh_token
                : "";
          const valid = validateRawToken(candidate);
          if (valid) {
            return { kind: "valid", token: valid, fromJson: true };
          }
        }
      } catch {
        // Fall through to invalid JSON error below.
      }
      return {
        kind: "invalid",
        reason: "未能从 JSON 中提取有效的 refresh_token 字段，请检查粘贴内容。",
      };
    }

    if (/[\r\n]/u.test(trimmed)) {
      return {
        kind: "invalid",
        reason: "请粘贴单个 Refresh Token，或包含 refresh_token 字段的完整 JSON。",
      };
    }

    const valid = validateRawToken(trimmed);
    if (!valid) {
      return {
        kind: "invalid",
        reason: "Refresh Token 不能包含空格、引号或控制字符。",
      };
    }

    return { kind: "valid", token: valid, fromJson: false };
  }

  // Clipboard helper with 3-step fallback: Clipboard API -> execCommand -> selected textarea.
  async function copyOrSelect(text, panel, field, stillCurrent) {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return stillCurrent() ? "copied" : "cancelled";
      } catch {
        // Continue to selection-based fallback.
      }
    }
    if (!stillCurrent()) return "cancelled";
    panel.hidden = false;
    field.value = text;
    field.focus();
    field.select();
    try {
      if (document.execCommand?.("copy")) {
        if (!stillCurrent()) return "cancelled";
        field.value = "";
        panel.hidden = true;
        return "copied";
      }
    } catch {
      // Manual copying still works when both clipboard APIs are blocked.
    }
    return stillCurrent() ? "manual" : "cancelled";
  }

  function formatTimestamp(isoString) {
    if (!isoString) return "";
    const date = new Date(isoString);
    if (Number.isNaN(date.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${date.getFullYear()}/${pad(date.getMonth() + 1)}/${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function flashButtonCopied(button, defaultLabel) {
    const existingTimer = Number(button.dataset.resetTimer || 0);
    if (existingTimer) clearTimeout(existingTimer);
    button.dataset.copied = "true";
    button.textContent = "已复制";
    const timer = window.setTimeout(() => {
      delete button.dataset.copied;
      delete button.dataset.resetTimer;
      if (!button.disabled) {
        button.textContent = defaultLabel;
      }
    }, 1800);
    button.dataset.resetTimer = String(timer);
  }

  // =========================================================================
  // Theme handoff between static Magpie bridge page and local hosted service
  // =========================================================================
  // =========================================================================
  // Left column: Import Refresh Token -> AGY-CLI JSON
  // =========================================================================
  let importRevision = 0;
  let activeValidToken = "";

  function setImportStatus(message, isError = false) {
    if (isError) {
      importStatus.setAttribute("data-error", "");
    } else {
      importStatus.removeAttribute("data-error");
    }
    importStatus.textContent = message;
  }

  function resetImportTransient() {
    importRevision++;
    importResult.value = "";
    importManual.hidden = true;
    setImportStatus("");
  }

  function updateImportValidation(customFeedback = "") {
    const parsed = parseTokenInput(tokenInput.value);
    if (parsed.kind === "empty") {
      activeValidToken = "";
      tokenInput.removeAttribute("aria-invalid");
      tokenFeedback.removeAttribute("data-state");
      tokenFeedback.textContent = "支持直接粘贴裸 RT，或粘贴含 refresh_token 的 JSON 自动提取。";
      importPreview.hidden = true;
      copyJsonBtn.disabled = true;
      downloadJsonBtn.disabled = true;
      return parsed;
    }

    if (parsed.kind === "valid") {
      activeValidToken = parsed.token;
      tokenInput.removeAttribute("aria-invalid");
      tokenFeedback.dataset.state = "ok";
      tokenFeedback.textContent =
        customFeedback
        || (parsed.fromJson
          ? "已从 JSON 自动提取 Refresh Token，可直接复制或下载。"
          : "格式有效，可一键复制或下载导入 JSON。");
      importPreview.hidden = false;
      copyJsonBtn.disabled = false;
      downloadJsonBtn.disabled = false;
      return parsed;
    }

    activeValidToken = "";
    tokenInput.setAttribute("aria-invalid", "true");
    tokenFeedback.dataset.state = "error";
    tokenFeedback.textContent = parsed.reason;
    importPreview.hidden = true;
    copyJsonBtn.disabled = true;
    downloadJsonBtn.disabled = true;
    return parsed;
  }

  function clearImportAll() {
    tokenInput.value = "";
    activeValidToken = "";
    resetImportTransient();
    updateImportValidation();
  }

  toggleVisibilityBtn.addEventListener("click", () => {
    const show = tokenInput.type === "password";
    tokenInput.type = show ? "text" : "password";
    toggleVisibilityBtn.setAttribute("aria-pressed", String(show));
    toggleVisibilityBtn.textContent = show ? "隐藏" : "显示";
    tokenInput.focus();
  });

  tokenInput.addEventListener("paste", (event) => {
    const pasted = event.clipboardData?.getData("text") ?? "";
    const trimmed = pasted.trim();
    // Intercept multi-line content or JSON payloads before password input strips newlines.
    if (!trimmed) return;
    if (/[\r\n]/u.test(trimmed) || trimmed.startsWith("{") || trimmed.startsWith("[")) {
      event.preventDefault();
      resetImportTransient();
      const parsed = parseTokenInput(pasted);
      if (parsed.kind === "valid") {
        tokenInput.value = parsed.token;
        updateImportValidation("已从 JSON 自动提取 Refresh Token，可直接复制或下载。");
        showToast("已自动从 JSON 提取 Refresh Token");
      } else {
        tokenInput.value = "";
        activeValidToken = "";
        tokenInput.setAttribute("aria-invalid", "true");
        tokenFeedback.dataset.state = "error";
        tokenFeedback.textContent = parsed.reason;
        importPreview.hidden = true;
        copyJsonBtn.disabled = true;
        downloadJsonBtn.disabled = true;
      }
    }
  });

  tokenInput.addEventListener("input", () => {
    resetImportTransient();
    const parsed = parseTokenInput(tokenInput.value);
    if (parsed.kind === "valid" && parsed.fromJson) {
      tokenInput.value = parsed.token;
      updateImportValidation("已从 JSON 自动提取 Refresh Token，可直接复制或下载。");
      return;
    }
    updateImportValidation();
  });

  tokenInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing && !copyJsonBtn.disabled) {
      copyJsonBtn.click();
    }
  });

  copyJsonBtn.addEventListener("click", async () => {
    resetImportTransient();
    const parsed = updateImportValidation();
    if (parsed.kind !== "valid") {
      tokenInput.focus();
      return;
    }

    const revision = importRevision;
    const stillCurrent = () => revision === importRevision;
    const json = buildImportJson(parsed.token);

    copyJsonBtn.disabled = true;
    downloadJsonBtn.disabled = true;
    try {
      const state = await copyOrSelect(json, importManual, importResult, stillCurrent);
      if (!stillCurrent()) return;
      if (state === "copied") {
        clearImportAll();
        setImportStatus("已复制导入 JSON，并已清空输入框。");
        showToast("已复制导入 JSON");
        tokenInput.focus();
      } else if (state === "manual") {
        setImportStatus("JSON 已选中，请按 Ctrl+C（macOS 为 Command+C）复制。");
      }
    } finally {
      if (stillCurrent() && activeValidToken) {
        copyJsonBtn.disabled = false;
        downloadJsonBtn.disabled = false;
      }
    }
  });

  downloadJsonBtn.addEventListener("click", () => {
    const parsed = updateImportValidation();
    if (parsed.kind !== "valid") {
      tokenInput.focus();
      return;
    }
    const json = `${buildImportJson(parsed.token)}\n`;
    const blob = new Blob([json], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "agy-account.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setImportStatus("已下载 agy-account.json，可在 AGY-CLI 选择该文件导入。");
    showToast("已下载 agy-account.json");
  });

  clearImportBtn.addEventListener("click", () => {
    clearImportAll();
    tokenInput.focus();
  });

  // =========================================================================
  // Right column: Export Refresh Token (Service accounts + Manual folder)
  // =========================================================================
  let serviceAccounts = [];
  let serviceListRevision = 0;
  let listReady = false;
  let exportRevision = 0;
  const inFlightExports = new Set();
  const manualProfiles = new Map();

  function setExportStatus(message, isError = false) {
    if (isError) {
      exportStatus.setAttribute("data-error", "");
    } else {
      exportStatus.removeAttribute("data-error");
    }
    exportStatus.textContent = message;
  }

  function resetExportOutput() {
    exportRevision++;
    exportResult.value = "";
    exportManual.hidden = true;
    setExportStatus("");
  }

  function showServiceState(message, { isError = false, actionLabel = "", onAction = null } = {}) {
    serviceState.replaceChildren();
    const textEl = document.createElement("span");
    textEl.textContent = message;
    serviceState.appendChild(textEl);

    if (actionLabel && typeof onAction === "function") {
      const actionBtn = document.createElement("button");
      actionBtn.type = "button";
      actionBtn.className = "btn-sm";
      actionBtn.textContent = actionLabel;
      actionBtn.addEventListener("click", onAction);
      serviceState.appendChild(actionBtn);
    }

    if (isError) {
      serviceState.setAttribute("data-error", "");
    } else {
      serviceState.removeAttribute("data-error");
    }
    serviceState.hidden = false;
  }

  function hideServiceState() {
    serviceState.hidden = true;
    serviceState.replaceChildren();
  }

  function createAccountRow(item, onExport) {
    const li = document.createElement("li");
    li.className = "account-item";
    li.dataset.valid = String(item.valid);
    li.dataset.profile = item.profile;

    const info = document.createElement("div");
    info.className = "account-info";

    const title = document.createElement("div");
    title.className = "account-title";
    title.textContent = item.email || item.profile;
    info.appendChild(title);

    const meta = document.createElement("div");
    meta.className = "account-meta";

    if (item.email) {
      const chip = document.createElement("code");
      chip.className = "profile-chip";
      chip.textContent = item.profile;
      meta.appendChild(chip);
    }

    if (typeof item.registered === "boolean") {
      const badge = document.createElement("span");
      badge.className = item.registered ? "badge badge-ok" : "badge badge-neutral";
      badge.textContent = item.registered ? "已登记" : "仅本地目录";
      meta.appendChild(badge);
    }

    if (!item.valid) {
      const invalidBadge = document.createElement("span");
      invalidBadge.className = "badge badge-danger";
      invalidBadge.textContent = "凭据失效";
      meta.appendChild(invalidBadge);
    }

    if (item.updatedAt) {
      const timeText = formatTimestamp(item.updatedAt);
      if (timeText) {
        const timeSpan = document.createElement("span");
        timeSpan.textContent = `更新于 ${timeText}`;
        meta.appendChild(timeSpan);
      }
    }

    info.appendChild(meta);

    if (!item.valid) {
      const invalidNote = document.createElement("div");
      invalidNote.className = "invalid-note";
      invalidNote.textContent = "凭据文件缺失或格式无效，无法导出。";
      info.appendChild(invalidNote);
    }

    const actions = document.createElement("div");
    actions.className = "account-actions";

    const copyRtBtn = document.createElement("button");
    copyRtBtn.type = "button";
    copyRtBtn.className = "btn-sm primary";
    copyRtBtn.textContent = "复制 RT";
    copyRtBtn.disabled = !item.valid;

    const copyJsonActionBtn = document.createElement("button");
    copyJsonActionBtn.type = "button";
    copyJsonActionBtn.className = "btn-sm";
    copyJsonActionBtn.textContent = "复制 JSON";
    copyJsonActionBtn.disabled = !item.valid;

    if (!item.valid) {
      const tip = "该账号凭据文件缺失或格式无效";
      copyRtBtn.title = tip;
      copyJsonActionBtn.title = tip;
    } else {
      copyRtBtn.addEventListener("click", () => onExport(item, "rt", copyRtBtn));
      copyJsonActionBtn.addEventListener("click", () => onExport(item, "json", copyJsonActionBtn));
    }

    actions.append(copyRtBtn, copyJsonActionBtn);
    li.append(info, actions);
    return li;
  }

  async function handleAccountExport({ source, item, format, button, loadRefreshToken }) {
    const key = `${source}:${item.profile}:${format}`;
    if (inFlightExports.has(key)) return;
    inFlightExports.add(key);

    resetExportOutput();
    const revision = exportRevision;
    const stillCurrent = () => revision === exportRevision;
    const defaultLabel = format === "json" ? "复制 JSON" : "复制 RT";
    const displayName = item.email || item.profile;

    button.disabled = true;
    button.textContent = "读取中…";
    try {
      const result = await loadRefreshToken();
      if (!stillCurrent()) return;
      if (!result.ok) {
        const message = EXPORT_ERROR_MESSAGES[result.error] || "导出失败，请稍后重试。";
        setExportStatus(message, true);
        showToast(message, "error");
        return;
      }

      const payload = format === "json" ? buildImportJson(result.refreshToken) : result.refreshToken;
      exportManualLabel.textContent =
        format === "json"
          ? `${displayName} · 导入 JSON（按 Ctrl+C / Command+C 复制）`
          : `${displayName} · Refresh Token（按 Ctrl+C / Command+C 复制）`;

      const copyState = await copyOrSelect(payload, exportManual, exportResult, stillCurrent);
      if (!stillCurrent()) return;

      if (copyState === "copied") {
        const msg = format === "json"
          ? `已复制 ${displayName} 的导入 JSON。`
          : `已复制 ${displayName} 的 Refresh Token。`;
        setExportStatus(msg);
        showToast(format === "json" ? "已复制导入 JSON" : "已复制 Refresh Token");
        flashButtonCopied(button, defaultLabel);
      } else if (copyState === "manual") {
        const msg = format === "json"
          ? "导入 JSON 已选中，请按 Ctrl+C（macOS 为 Command+C）复制。"
          : "Refresh Token 已选中，请按 Ctrl+C（macOS 为 Command+C）复制。";
        setExportStatus(msg);
      }
    } catch {
      if (stillCurrent()) {
        const message = "无法读取账号凭据，请重试或手动选择目录。";
        setExportStatus(message, true);
        showToast(message, "error");
      }
    } finally {
      inFlightExports.delete(key);
      button.disabled = !item.valid;
      if (!button.dataset.copied) {
        button.textContent = defaultLabel;
      }
    }
  }

  function renderServiceAccounts() {
    const query = accountSearch.value.trim().toLowerCase();
    const filtered = query
      ? serviceAccounts.filter(
          (item) =>
            item.profile.toLowerCase().includes(query)
            || (item.email && item.email.toLowerCase().includes(query))
        )
      : serviceAccounts;

    if (serviceAccounts.length === 0) {
      accountCount.textContent = "0 个账号";
      serviceAccountsList.replaceChildren();
      showServiceState("未发现已保存的 Magpie AGY 账号。登录账号后可点击页面右上角刷新。");
      return;
    }

    accountCount.textContent = query
      ? `匹配 ${filtered.length} / ${serviceAccounts.length}`
      : `共 ${serviceAccounts.length} 个账号`;

    if (filtered.length === 0) {
      serviceAccountsList.replaceChildren();
      showServiceState(`没有匹配「${accountSearch.value.trim()}」的账号。`, {
        actionLabel: "清除筛选",
        onAction: () => {
          accountSearch.value = "";
          renderServiceAccounts();
          accountSearch.focus();
        },
      });
      return;
    }

    hideServiceState();
    const fragment = document.createDocumentFragment();
    for (const item of filtered) {
      fragment.appendChild(
        createAccountRow(item, (account, format, button) =>
          handleAccountExport({
            source: "service",
            item: account,
            format,
            button,
            loadRefreshToken: async () => {
              const response = await sessionRequest("/api/export", { profile: account.profile });
              const data = await response.json().catch(() => ({}));
              if (response.status === 403) {
                return { ok: false, error: "forbidden" };
              }
              if (!response.ok || typeof data.refreshToken !== "string") {
                return { ok: false, error: data.error || "read_failed" };
              }
              return { ok: true, refreshToken: data.refreshToken };
            },
          })
        )
      );
    }
    serviceAccountsList.replaceChildren(fragment);
  }

  async function loadServiceAccounts({ notify = false } = {}) {
    listReady = false;
    const revision = ++serviceListRevision;
    const stillCurrent = () => revision === serviceListRevision;

    if (serviceAccounts.length === 0) {
      showServiceState("正在扫描本机 Magpie AGY 账号…");
    }

    try {
      const response = await sessionRequest("/api/accounts");
      if (!stillCurrent()) return;

      if (response.status === 403) {
        setConnectionState("error", "会话已失效");
        serviceAccounts = [];
        serviceAccountsList.replaceChildren();
        accountCount.textContent = "";
        showServiceState("本机服务会话已失效（可能已重启），请重新加载页面。", {
          isError: true,
        });
        manualDrawer.open = true;
        return;
      }

      if (!response.ok) {
        const problem = await response.json().catch(() => ({}));
        throw new Error(problem.error === "read_failed" ? "账号目录读取失败，请检查目录权限。" : "本机服务返回异常，请点击右上角刷新重试。");
      }

      const data = await response.json();
      if (!stillCurrent()) return;

      listReady = true;
      manualDrawer.open = false;
      serviceAccounts = Array.isArray(data?.accounts) ? data.accounts : [];
      setConnectionState("connected", "本机服务已连接");
      renderServiceAccounts();
      if (notify) {
        showToast(`已刷新，共 ${serviceAccounts.length} 个账号`);
      }
    } catch (error) {
      if (!stillCurrent()) return;
      setConnectionState("error", "服务连接异常");
      serviceAccounts = [];
      serviceAccountsList.replaceChildren();
      accountCount.textContent = "";
      showServiceState((error.message.includes("目录权限") ? error.message : "无法连接本机服务，请点击右上角刷新重试，或手动选择目录。"), {
        isError: true,
      });
      manualDrawer.open = true;
    }
  }

  accountSearch.addEventListener("input", () => {
    if (listReady) renderServiceAccounts();
  });

  refreshPageBtn.addEventListener("click", () => {
    localSession = null;
    serviceListRevision++;
    clearImportAll();
    clearManualFolder();
    accountSearch.value = "";
    document.getElementById("session-code").value = "";
    location.reload();
  });

  // Manual folder chooser fallback
  function renderManualAccounts() {
    const ids = Array.from(manualProfiles.keys()).sort();
    if (ids.length === 0) {
      manualAccountsList.replaceChildren();
      manualAccountsList.hidden = true;
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const id of ids) {
      const file = manualProfiles.get(id);
      const item = {
        profile: id,
        email: "",
        valid: true,
        updatedAt: file?.lastModified ? new Date(file.lastModified).toISOString() : null,
      };
      fragment.appendChild(
        createAccountRow(item, (account, format, button) =>
          handleAccountExport({
            source: "manual",
            item: account,
            format,
            button,
            loadRefreshToken: async () => {
              const targetFile = manualProfiles.get(account.profile);
              if (!targetFile) return { ok: false, error: "not_found" };
              try {
                const parsed = JSON.parse(await targetFile.text());
                const rt = validateRawToken(parsed?.token?.refresh_token);
                if (!rt) return { ok: false, error: "invalid_token" };
                return { ok: true, refreshToken: rt };
              } catch {
                return { ok: false, error: "invalid_token" };
              }
            },
          })
        )
      );
    }
    manualAccountsList.replaceChildren(fragment);
    manualAccountsList.hidden = false;
  }

  function clearManualFolder() {
    accountsFolder.value = "";
    manualProfiles.clear();
    renderManualAccounts();
    resetExportOutput();
  }

  accountsFolder.addEventListener("change", () => {
    manualProfiles.clear();
    resetExportOutput();
    const files = accountsFolder.files || [];
    for (const file of files) {
      const match = MANUAL_PROFILE_PATH_RE.exec(file.webkitRelativePath || "");
      if (match && file.size > 0 && file.size <= MAX_CREDENTIAL_BYTES) {
        manualProfiles.set(match[1], file);
      }
    }
    renderManualAccounts();
    if (manualProfiles.size === 0) {
      setExportStatus("所选目录中没有找到 AGY 账号凭据，请选择 Magpie 的 accounts 目录或单个账号目录。", true);
    } else {
      setExportStatus(`已从所选目录载入 ${manualProfiles.size} 个账号。`);
    }
  });

  clearFolderBtn.addEventListener("click", () => {
    clearManualFolder();
    accountsFolder.focus();
  });

  // Clear sensitive credentials when leaving the page
  window.addEventListener("pagehide", () => {
    localSession = null;
    serviceListRevision++;
    clearImportAll();
    clearManualFolder();
    document.getElementById("session-code").value = "";
  });

  // =========================================================================
  // Bootstrap
  // =========================================================================
  async function init() {
    updateImportValidation();

    if (location.hash.startsWith("#theme=")) {
      try {
        applyMagpieTheme(JSON.parse(decodeURIComponent(location.hash.slice(7))));
      } catch {}
    }

    const setup = document.getElementById("local-session");
    const hostedNonce = document.querySelector('meta[name="agy-session"]')?.content;
    if (hostedNonce) {
      window.addEventListener("message", (event) => {
        if (event.source !== parent || !event.data || event.data.magpie !== 1) return;
        const message = event.data;
        if (message.event === "theme") applyMagpieTheme(message.data);
        if (message.id === "agy-theme") applyMagpieTheme(message.result);
      });
      if (parent !== window) parent.postMessage({ magpie: 1, id: "agy-theme", method: "theme" }, "*");
      localSession = { nonce: hostedNonce };
      serviceSection.hidden = false;
      await loadServiceAccounts();
      return;
    }
    if (window.magpie) {
      try {
        const theme = await window.magpie.ready;
        const options = await window.magpie.options.get();
        const port = Number(options?.port) || 34973;
        const target = window.magpie.service || `http://127.0.0.1:${port}/`;
        window.setTimeout(() => {
          setConnectionState("error", "服务连接失败");
          setExportStatus("无法连接本机服务，可点击右上角刷新重试，或手动选择目录。", true);
          manualDrawer.open = true;
        }, 8000);
        location.replace(target + "#theme=" + encodeURIComponent(JSON.stringify(theme)));
      } catch {
        setConnectionState("error", "服务连接失败");
        manualDrawer.open = true;
      }
      return;
    }
    if (location.protocol === "file:" && !window.magpie && globalThis.crypto?.subtle) {
      setup.hidden = false;
      const code = document.getElementById("session-code");
      const connect = document.getElementById("connect-session");
      connect.addEventListener("click", async () => {
        const match = /^([1-9]\d{0,4})\.([a-f0-9]{64})$/u.exec(code.value.trim());
        code.value = "";
        if (!match || Number(match[1]) > 65535) {
          setExportStatus("请粘贴本机终端显示的完整会话码。", true);
          return;
        }
        connect.disabled = true;
        try {
          resetExportOutput();
          serviceAccounts = [];
          serviceAccountsList.replaceChildren();
          localSession = { key: await localSessionCodec.importKey(match[2]),
            origin: "http://127.0.0.1:" + match[1] };
          serviceSection.hidden = false;
          setConnectionState("connecting", "正在验证本机会话…");
          await loadServiceAccounts();
          if (listReady) { setup.open = false; manualDrawer.open = false; }
        } finally {
          connect.disabled = false;
        }
      });
    }
    setConnectionState("offline", "离线手动模式");
    serviceSection.hidden = true;
    manualDrawer.open = true;
  }

  init();
})();
