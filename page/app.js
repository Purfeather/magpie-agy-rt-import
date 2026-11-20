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

  if (navigator.clipboard?.writeText) {
    copy.disabled = true;
    try {
      await navigator.clipboard.writeText(json);
      if (token.value === input) copied();
      return;
    } catch {
      // Some Magpie windows restrict clipboard access in the page's iframe.
    } finally {
      copy.disabled = false;
    }
    if (token.value !== input) return;
  }

  manual.hidden = false;
  result.value = json;
  result.focus();
  result.select();
  try {
    if (document.execCommand?.("copy")) {
      copied();
      return;
    }
  } catch {
    // Manual copying still works when both clipboard APIs are blocked.
  }
  statusLine.textContent = "JSON 已选中。请按 Ctrl+C（macOS 为 Command+C）复制。";
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
