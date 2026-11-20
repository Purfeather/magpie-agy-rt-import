"use strict";

const pick = document.getElementById("pick");
const statusLine = document.getElementById("status");
document.getElementById("back").addEventListener("click", () => history.back());

const messages = {
  copied: "已复制选中账号的 RT。",
  cancelled: "已取消。",
  empty: "没有找到 Magpie 保存的独立 AGY 账号。可以返回页面手动选择目录。",
  busy: "本机已有一个账号选择窗口。",
  failed: "无法完成复制。请检查本机窗口，或返回页面手动选择目录。",
};

pick.addEventListener("click", async () => {
  pick.disabled = true;
  statusLine.textContent = "请在本机的 AGY 账号选择窗口继续。";
  try {
    const response = await fetch("pick", { method: "POST", body: pick.dataset.request });
    const { result } = response.ok ? await response.json() : {};
    statusLine.textContent = messages[result] || messages.failed;
  } catch {
    statusLine.textContent = messages.failed;
  } finally {
    pick.disabled = false;
  }
});
