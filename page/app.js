"use strict";

const token = document.getElementById("token");
const copy = document.getElementById("copy");
const clear = document.getElementById("clear");
const statusLine = document.getElementById("status");
const manual = document.getElementById("manual");
const result = document.getElementById("result");

function resetOutput() {
  token.removeAttribute("aria-invalid");
  statusLine.removeAttribute("data-error");
  statusLine.textContent = "";
  result.value = "";
  manual.hidden = true;
}

function clearToken() {
  token.value = "";
  resetOutput();
}

function invalidToken() {
  token.setAttribute("aria-invalid", "true");
  statusLine.setAttribute("data-error", "");
  statusLine.textContent = "请粘贴一个 Refresh Token。令牌中间不能有空格，请勿粘贴整段 JSON。";
  token.focus();
}

function copied() {
  clearToken();
  token.focus();
  statusLine.textContent = "已复制 JSON，可在 AGY-CLI 的账号导入窗口粘贴。";
}

// A sandbox may deny both clipboard APIs. Leave the selected text for Ctrl+C.
async function copyOrSelect(text, panel, field, stillCurrent) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return stillCurrent() ? "copied" : "cancelled";
    } catch {
      // Continue with the selection-based fallback.
    }
  }
  if (!stillCurrent()) return "cancelled";
  panel.hidden = false;
  field.value = text;
  field.focus();
  field.select();
  try {
    if (document.execCommand?.("copy")) return "copied";
  } catch {
    // Manual copying still works when both clipboard APIs are blocked.
  }
  return "manual";
}

// Magpie's sandbox allows script events, but does not allow form submissions.
copy.addEventListener("click", async () => {
  resetOutput();
  const input = token.value;
  const refresh = input.trim();
  if (!refresh || /[\s\u0000-\u001f\u007f]/u.test(refresh) || "{[\"".includes(refresh[0])) {
    invalidToken();
    return;
  }
  const json = JSON.stringify({ token: { refresh_token: refresh }, auth_method: "consumer" }, null, 2);

  copy.disabled = true;
  try {
    const state = await copyOrSelect(json, manual, result, () => token.value === input);
    if (state === "copied") copied();
    if (state === "manual") {
      statusLine.textContent = "JSON 已选中。请按 Ctrl+C（macOS 为 Command+C）复制。";
    }
  } finally {
    copy.disabled = false;
  }
});

token.addEventListener("input", resetOutput);
token.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.isComposing) copy.click();
});
token.addEventListener("paste", (event) => {
  const pasted = event.clipboardData?.getData("text") ?? "";
  // Password inputs silently remove line breaks before a submit handler sees them.
  if (/[\r\n]/u.test(pasted.trim())) {
    event.preventDefault();
    resetOutput();
    invalidToken();
  }
});
clear.addEventListener("click", () => {
  clearToken();
  token.focus();
});
window.addEventListener("pagehide", clearToken);

const folder = document.getElementById("accounts-folder");
const picker = document.getElementById("profile-picker");
const profile = document.getElementById("profile");
const exportCopy = document.getElementById("export-copy");
const exportClear = document.getElementById("export-clear");
const exportStatus = document.getElementById("export-status");
const exportManual = document.getElementById("export-manual");
const exportResult = document.getElementById("export-result");
const profiles = new Map();
const profilePath = /^(?:accounts\/)?([a-z0-9]{8,32})\/\.gemini\/antigravity-cli\/antigravity-oauth-token$/u;
const maxCredentialBytes = 64 * 1024;
let exportRevision = 0;

function resetExport() {
  exportRevision++;
  exportResult.value = "";
  exportManual.hidden = true;
  exportStatus.removeAttribute("data-error");
  exportStatus.textContent = "";
  exportCopy.disabled = !profiles.has(profile.value);
}

function exportError(message) {
  exportStatus.setAttribute("data-error", "");
  exportStatus.textContent = message;
}

function clearFolder() {
  folder.value = "";
  profiles.clear();
  profile.replaceChildren();
  picker.hidden = true;
  resetExport();
}

folder.addEventListener("change", () => {
  profiles.clear();
  for (const file of folder.files) {
    const id = profilePath.exec(file.webkitRelativePath)?.[1];
    if (id && file.size > 0 && file.size <= maxCredentialBytes) profiles.set(id, file);
  }
  profile.replaceChildren(...Array.from(profiles.keys()).sort().map((id) => new Option(id, id)));
  picker.hidden = profiles.size === 0;
  resetExport();
  if (profiles.size === 0) {
    exportError("这里没有找到 AGY 账号凭据。请选择 Magpie 的 accounts 目录或其中一个账号目录。");
  }
});

profile.addEventListener("change", resetExport);
exportCopy.addEventListener("click", async () => {
  resetExport();
  const file = profiles.get(profile.value);
  if (!file) return;
  const revision = exportRevision;
  const stillCurrent = () => revision === exportRevision;
  exportCopy.disabled = true;
  try {
    let refresh;
    try {
      const saved = JSON.parse(await file.text());
      refresh = typeof saved?.token?.refresh_token === "string" ? saved.token.refresh_token.trim() : "";
      if (!refresh || /[\s\u0000-\u001f\u007f]/u.test(refresh)) throw new Error();
    } catch {
      if (stillCurrent()) exportError("无法从该账号文件读取有效格式的 Refresh Token。");
      return;
    }
    if (!stillCurrent()) return;
    const state = await copyOrSelect(refresh, exportManual, exportResult, stillCurrent);
    if (state === "copied") {
      exportManual.hidden = true;
      exportResult.value = "";
      exportCopy.focus();
      exportStatus.textContent = "已复制选中账号的 Refresh Token。";
    }
    if (state === "manual") {
      exportStatus.textContent = "RT 已选中。请按 Ctrl+C（macOS 为 Command+C）复制。";
    }
  } finally {
    if (stillCurrent()) exportCopy.disabled = false;
  }
});
exportClear.addEventListener("click", () => {
  clearFolder();
  folder.focus();
});
window.addEventListener("pagehide", clearFolder);
