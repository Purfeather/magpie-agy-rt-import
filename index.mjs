import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import { fileURLToPath, pathToFileURL } from "node:url";
import sessionCodec from "./page/session.js";
import {
  getDefaultAccountsDir,
  listAccounts,
  readAccountRefreshToken,
} from "./lib/accounts.mjs";

const DEFAULT_PORT = 34973;
const MAX_API_BODY_BYTES = 4096;
const STATIC_ASSETS = new Map([
  ["/session.js", { path: "./page/session.js", contentType: "text/javascript; charset=utf-8" }],
  ["/app.js", { path: "./page/app.js", contentType: "text/javascript; charset=utf-8" }],
  ["/style.css", { path: "./page/style.css", contentType: "text/css; charset=utf-8" }],
]);
const EXPORT_ERROR_STATUS = {
  invalid_profile: 400,
  not_found: 404,
  invalid_token: 422,
  read_failed: 500,
};

const resolveAssetPath = (relativePath) => fileURLToPath(new URL(relativePath, import.meta.url));


function isValidNonce(candidate, expected) {
  if (typeof candidate !== "string") return false;
  const a = Buffer.from(candidate, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function buildSecurityHeaders(origin) {
  return {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": [
      "default-src 'none'",
      `script-src 'self' ${origin}`,
      `style-src 'self' ${origin}`,
      `connect-src 'self' ${origin}`,
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'self' http://127.0.0.1:* http://localhost:* http://magpie.localhost:* http://wails.localhost",
    ].join("; "),
  };
}

function hostedDocument(html, nonce) {
  return html.replace(/\s*<script\s+src="_magpie\/bridge\.js"><\/script>/u, "")
    .replace("<head>", nonce ? `<head>\n<meta name="agy-session" content="${nonce}">` : "<head>")
    .replace('<body data-hosted="static">', '<body data-hosted="service">');
}

async function readBoundedText(request, maxBytes) {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isFinite(parsedLength) || parsedLength < 0 || parsedLength > maxBytes) {
      return { ok: false, tooLarge: true };
    }
  }

  if (!request.body) {
    const text = await request.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      return { ok: false, tooLarge: true };
    }
    return { ok: true, text };
  }

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return { ok: false, tooLarge: true };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, tooLarge: false };
  }
  return { ok: true, text: Buffer.concat(chunks, total).toString("utf8") };
}

function createServiceHandler({
  port,
  nonce = randomBytes(32).toString("hex"),
  configDir = "",
  accountsDir = getDefaultAccountsDir(),
  hostedSession = false,
}) {
  const expectedHost = `127.0.0.1:${port}`;
  const origin = `http://${expectedHost}`;
  const securityHeaders = buildSecurityHeaders(origin);
  const sessionKey = sessionCodec.importKey(nonce);

  const jsonResponse = (payload, status, extraHeaders = {}) =>
    new Response(JSON.stringify(payload), {
      status,
      headers: {
        ...securityHeaders,
        "Content-Type": "application/json; charset=utf-8",
        ...extraHeaders,
      },
    });

  async function fetchHandler(request) {
    if (request.headers.get("host") !== expectedHost) {
      return new Response(null, { status: 403, headers: securityHeaders });
    }

    const url = new URL(request.url, origin);
    const { pathname } = url;

    if (request.method === "GET") {
      if (pathname === "/" || pathname === "/index.html") {
        const html = await readFile(resolveAssetPath("./page/index.html"), "utf8");
        return new Response(hostedDocument(html, hostedSession ? nonce : ""), {
          status: 200,
          headers: { ...securityHeaders, "Content-Type": "text/html; charset=utf-8" },
        });
      }

      if (pathname === "/manage") {
        return new Response(null, {
          status: 302,
          headers: { ...securityHeaders, Location: "./" },
        });
      }

      const asset = STATIC_ASSETS.get(pathname);
      if (asset) {
        const body = await readFile(resolveAssetPath(asset.path));
        return new Response(body, {
          status: 200,
          headers: { ...securityHeaders, "Content-Type": asset.contentType },
        });
      }

      return new Response(null, { status: 404, headers: securityHeaders });
    }

    if (request.method === "POST" && (pathname === "/api/accounts" || pathname === "/api/export")) {
      const requestOrigin = request.headers.get("origin");
      if (requestOrigin !== null && requestOrigin !== origin && requestOrigin !== "null") {
        return jsonResponse({ error: "forbidden" }, 403);
      }
      const corsHeaders = requestOrigin !== null
        ? { "Access-Control-Allow-Origin": requestOrigin, Vary: "Origin" }
        : {};

      const rawBody = await readBoundedText(request, MAX_API_BODY_BYTES);
      if (!rawBody.ok) {
        return jsonResponse(
          { error: rawBody.tooLarge ? "payload_too_large" : "forbidden" },
          rawBody.tooLarge ? 413 : 403,
          corsHeaders
        );
      }

      let payload;
      try {
        payload = JSON.parse(rawBody.text);
      } catch {
        return jsonResponse({ error: "forbidden" }, 403, corsHeaders);
      }

      const packet = payload?.sealed ? payload : null;
      if (packet) {
        try {
          payload = await sessionCodec.unseal(await sessionKey, "request:" + pathname, packet);
        } catch {
          return jsonResponse({ error: "forbidden" }, 403, corsHeaders);
        }
      }
      const reply = async (data, status) => {
        if (!packet) return jsonResponse(data, status, corsHeaders);
        const message = await sessionCodec.seal(await sessionKey, "response:" + pathname + ":" + packet.iv, { data, status });
        return jsonResponse(message, 200, corsHeaders);
      };

      if (!payload || typeof payload !== "object" || Array.isArray(payload) || (!packet && !isValidNonce(payload.nonce, nonce))) {
        return jsonResponse({ error: "forbidden" }, 403, corsHeaders);
      }

      if (pathname === "/api/accounts") {
        try {
          const result = await listAccounts({ configDir, accountsDir });
          return reply(result, 200);
        } catch {
          return reply({ error: "read_failed" }, 500);
        }
      }

      const exported = await readAccountRefreshToken(accountsDir, payload.profile);
      if (!exported.ok) {
        const status = EXPORT_ERROR_STATUS[exported.error] || 500;
        return reply({ error: exported.error }, status);
      }

      return reply({ profile: exported.profile, refreshToken: exported.refreshToken }, 200);
    }

    return new Response(null, { status: 404, headers: securityHeaders });
  }

  return { fetch: fetchHandler, nonce, origin, port };
}

function readNodeBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    req.on("data", (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        resolve({ ok: false, tooLarge: true });
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!settled) {
        settled = true;
        resolve({ ok: true, buffer: Buffer.concat(chunks, total) });
      }
    });
    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

async function startService({
  port = DEFAULT_PORT,
  configDir = "",
  accountsDir = getDefaultAccountsDir(),
  nonce = randomBytes(32).toString("hex"),
  hostedSession = false,
} = {}) {
  if (typeof globalThis.Bun?.serve === "function") {
    let handler = null;
    const bunServer = globalThis.Bun.serve({
      hostname: "127.0.0.1",
      port,
      idleTimeout: 0,
      fetch(request) {
        return handler.fetch(request);
      },
    });
    handler = createServiceHandler({
      port: bunServer.port,
      nonce,
      configDir,
      accountsDir,
      hostedSession,
    });
    return {
      port: bunServer.port,
      origin: handler.origin,
      nonce,
      stop: async () => {
        bunServer.stop(true);
      },
    };
  }

  let handler = null;
  const nodeServer = http.createServer(async (req, res) => {
    try {
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) headers.append(key, item);
        } else if (typeof value === "string") {
          headers.set(key, value);
        }
      }
      const method = req.method || "GET";
      let body;
      if (method !== "GET" && method !== "HEAD") {
        const read = await readNodeBody(req, MAX_API_BODY_BYTES);
        if (!read.ok) {
          headers.set("content-length", String(MAX_API_BODY_BYTES + 1));
        } else {
          body = read.buffer;
        }
      }
      const requestUrl = new URL(req.url || "/", handler.origin);
      const request = {
        method,
        url: requestUrl.toString(),
        headers,
        body: null,
        text: async () => (body ? body.toString("utf8") : ""),
      };
      const response = await handler.fetch(request);
      res.statusCode = response.status;
      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });
      const buffer = Buffer.from(await response.arrayBuffer());
      res.end(buffer);
    } catch {
      res.statusCode = 500;
      res.end();
    }
  });

  await new Promise((resolve, reject) => {
    nodeServer.once("error", reject);
    nodeServer.listen(port, "127.0.0.1", () => {
      nodeServer.off("error", reject);
      const address = nodeServer.address();
      const boundPort = typeof address === "object" && address ? address.port : port;
      handler = createServiceHandler({
        port: boundPort,
        nonce,
        configDir,
        accountsDir,
        hostedSession,
      });
      resolve();
    });
  });

  return {
    port: handler.port,
    origin: handler.origin,
    nonce,
    stop: () =>
      new Promise((resolve) => {
        nodeServer.close(() => resolve());
      }),
  };
}

let service;
export default {
  id: "magpie-agy-rt-import",
  async server(input, options) {
    if (!service) {
      service = startService({
        port: Number(options?.port) || DEFAULT_PORT,
        configDir: input.directory,
        hostedSession: true,
      }).catch((error) => {
        service = null;
        throw error;
      });
    }
    await service;
    return {};
  },
};

export const _internal = { startService, createServiceHandler };

// A standalone session is started explicitly by its owner, outside Magpie.
// Its key is shown only on an interactive terminal and expires with the process.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url
    && process.argv[2] === "--workbench") {
  if (!process.stdout.isTTY) {
    console.error("Open an interactive terminal to start a private workbench session.");
    process.exitCode = 1;
  } else {
    const session = await startService({ port: 0, configDir: process.argv[3] || "" });
    console.log("Open this local file in your browser:", resolveAssetPath("./page/index.html"));
    console.log("Local session code:", session.port + "." + session.nonce);
    console.log("Press Ctrl+C to end this session.");
  }
}
