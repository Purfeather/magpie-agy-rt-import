import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const defaultPort = 34973;
const file = (name) => new URL(name, import.meta.url);
const picker = fileURLToPath(file("./picker.ps1"));
const windowsPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
let service;

function openPicker(configDir, accountsDir) {
  return new Promise((resolve) => {
    const powershell = process.env.SystemRoot
      ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
      : windowsPowerShell;
    const child = spawn(powershell, [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-Sta", "-File", picker,
      "-ConfigDir", configDir, "-AccountsDir", accountsDir,
    ], { windowsHide: true, stdio: "ignore" });
    child.once("error", () => resolve("failed"));
    child.once("exit", (code) => resolve(["copied", "failed", "cancelled", "empty"][code] || "failed"));
  });
}

export default {
  id: "magpie-agy-rt-import",
  async server(input, options) {
    if (process.platform !== "win32" || service) return {};
    const port = Number(options?.port) || defaultPort;
    const origin = `http://127.0.0.1:${port}`;
    const nonce = randomBytes(32).toString("hex");
    const configDir = input.directory;
    const accountsDir = path.join(process.env.XDG_STATE_HOME || path.join(homedir(), ".local", "state"),
      "magpie-agy-bridge", "accounts");
    const headers = {
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `default-src 'none'; script-src 'self' ${origin}; style-src 'self' ${origin}; connect-src 'self' ${origin}; base-uri 'none'; form-action 'none'; frame-ancestors 'self' http://127.0.0.1:* http://localhost:* http://magpie.localhost:*`,
    };
    let opening = false;
    try {
      service = Bun.serve({
        hostname: "127.0.0.1",
        port,
        idleTimeout: 0,
        async fetch(request) {
          const url = new URL(request.url);
          if (request.headers.get("Host") !== `127.0.0.1:${port}`) {
            return new Response(null, { status: 403, headers });
          }
          if (request.method === "GET" && url.pathname === "/") {
            const html = await Bun.file(file("./page/locate.html")).text();
            return new Response(html.replace("__LOCATOR_NONCE__", nonce), {
              headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
            });
          }
          if (request.method === "GET" && ["/locate.js", "/style.css"].includes(url.pathname)) {
            const content = Bun.file(file(`./page${url.pathname}`));
            return new Response(content, { headers: { ...headers, "Content-Type": content.type } });
          }
          if (request.method === "POST" && url.pathname === "/pick") {
            const requestOrigin = request.headers.get("Origin");
            if (![origin, "null"].includes(requestOrigin)
              || request.headers.get("Content-Length") !== String(nonce.length)
              || await request.text() !== nonce) {
              return new Response(null, { status: 403, headers });
            }
            const reply = (result) => Response.json({ result }, {
              headers: { ...headers, "Access-Control-Allow-Origin": requestOrigin },
            });
            if (opening) return reply("busy");
            opening = true;
            try {
              return reply(await openPicker(configDir, accountsDir));
            } finally {
              opening = false;
            }
          }
          return new Response(null, { status: 404, headers });
        },
      });
    } catch {
      // The static page and its manual chooser still work if the port is in use.
    }
    return {};
  },
};
