import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import sessionCodec from "../page/session.js";
import { _internal } from "../index.mjs";
const { startService } = _internal;

const cleanups = [];

function rawHttpRequest({ port, method = "GET", path: reqPath = "/", headers = {}, body = "" }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        method,
        path: reqPath,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            text: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function setupTestServer(options = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "magpie-agy-srv-"));
  const configDir = path.join(root, "config");
  const accountsDir = path.join(root, "accounts");
  await mkdir(configDir, { recursive: true });
  await mkdir(accountsDir, { recursive: true });

  const goodDir = path.join(accountsDir, "acct1234", ".gemini", "antigravity-cli");
  await mkdir(goodDir, { recursive: true });
  await writeFile(
    path.join(goodDir, "antigravity-oauth-token"),
    JSON.stringify({ token: { refresh_token: "1//0gSECRET_REFRESH_TOKEN" } }),
    "utf8"
  );

  const badDir = path.join(accountsDir, "broken12", ".gemini", "antigravity-cli");
  await mkdir(badDir, { recursive: true });
  await writeFile(path.join(badDir, "antigravity-oauth-token"), "{broken", "utf8");

  await writeFile(
    path.join(configDir, "plugin-auth.json"),
    JSON.stringify({
      "agy-cli#main": { metadata: { agyHome: "acct1234", email: "user@example.com" } },
      "agy-cli#bad": { metadata: { agyHome: "broken12", email: "broken@example.com" } },
    }),
    "utf8"
  );

  const server = await startService({ port: 0, configDir, accountsDir, ...options });
  cleanups.push(async () => {
    await server.stop();
    await rm(root, { recursive: true, force: true });
  });
  return { server, configDir, accountsDir };
}

afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    await fn();
  }
});

describe("index.mjs local plugin service", () => {
  it("serves hosted assets without disclosing the session capability", async () => {
    const { server } = await setupTestServer();

    const res = await fetch(`${server.origin}/`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    const csp = res.headers.get("content-security-policy") || "";
    assert.match(csp, /frame-ancestors 'self'.*http:\/\/wails\.localhost/);
    assert.match(csp, /default-src 'none'/);

    const html = await res.text();
    assert.equal(html.includes("_magpie/bridge.js"), false);
    assert.equal(html.includes('data-hosted="service"'), true);
    assert.equal(html.includes(server.nonce), false);
    for (const entry of ["/index.html", "/manage", "/app.js", "/style.css"]) {
      const response = await fetch(server.origin + entry);
      assert.equal((await response.text()).includes(server.nonce), false);
    }
    for (const route of ["/api/accounts", "/api/export"]) {
      for (const origin of [undefined, "null", server.origin]) {
        const denied = await fetch(server.origin + route, {
          method: "POST", headers: origin ? { Origin: origin } : {},
          body: JSON.stringify({ profile: "acct1234" }),
        });
        assert.equal(denied.status, 403);
        assert.deepEqual(await denied.json(), { error: "forbidden" });
      }
    }

    const redirectRes = await fetch(`${server.origin}/manage`, { redirect: "manual" });
    assert.equal(redirectRes.status, 302);
    assert.equal(redirectRes.headers.get("location"), "./");

    const jsRes = await fetch(`${server.origin}/app.js`);
    assert.equal(jsRes.status, 200);
    assert.match(jsRes.headers.get("content-type") || "", /text\/javascript/);

    const cssRes = await fetch(`${server.origin}/style.css`);
    assert.equal(cssRes.status, 200);
    assert.match(cssRes.headers.get("content-type") || "", /text\/css/);
  });

  it("serves a session to its own hosted document without permitting cross-site reads", async () => {
    const { server } = await setupTestServer({ hostedSession: true });
    const response = await fetch(server.origin);
    const html = await response.text();
    assert.match(html, new RegExp(`name="agy-session" content="${server.nonce}"`));
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    const listed = await fetch(server.origin + "/api/accounts", {
      method: "POST", headers: { Origin: "null" }, body: JSON.stringify({ nonce: server.nonce }),
    });
    assert.equal(listed.status, 200);
    const metadata = await listed.json();
    assert.equal(metadata.accounts.length, 2);
    assert.equal(JSON.stringify(metadata).includes("refresh_token"), false);
    const forbidden = await fetch(server.origin + "/api/accounts", {
      method: "POST", headers: { Origin: "https://example.com" },
      body: JSON.stringify({ nonce: server.nonce }),
    });
    assert.equal(forbidden.status, 403);
    assert.equal(forbidden.headers.get("access-control-allow-origin"), null);
    const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(manifest.magpie.page.service.port, 34973);
  });

  it("authenticates the standalone request and binds its encrypted response to the route and request", async () => {
    const { server } = await setupTestServer();
    const owner = await sessionCodec.importKey(server.nonce);
    const other = await sessionCodec.importKey("aa".repeat(32));
    const route = "/api/export";
    const request = await sessionCodec.seal(owner, "request:" + route, { profile: "acct1234" });
    const post = (endpoint, packet) => fetch(server.origin + endpoint, {
      method: "POST", headers: { Origin: "null", "Content-Type": "text/plain" }, body: JSON.stringify(packet),
    });
    const response = await post(route, request);
    assert.equal(response.status, 200);
    const packet = await response.json();
    assert.equal(JSON.stringify(packet).includes("SECRET_REFRESH_TOKEN"), false);
    const context = "response:" + route + ":" + request.iv;
    const decoded = await sessionCodec.unseal(owner, context, packet);
    assert.equal(decoded.data.refreshToken, "1//0gSECRET_REFRESH_TOKEN");
    await assert.rejects(sessionCodec.unseal(other, context, packet));
    await assert.rejects(sessionCodec.unseal(owner, context + "00", packet));
    assert.equal((await post("/api/accounts", request)).status, 403);
    const wrong = await sessionCodec.seal(other, "request:" + route, { profile: "acct1234" });
    assert.equal((await post(route, wrong)).status, 403);
  });

  it("lists metadata without leaking tokens and exports single account RT on demand", async () => {
    const { server } = await setupTestServer();

    const listRes = await fetch(`${server.origin}/api/accounts`, {
      method: "POST",
      headers: {
        "Content-Type": "text/plain;charset=UTF-8",
        Origin: server.origin,
      },
      body: JSON.stringify({ nonce: server.nonce }),
    });
    assert.equal(listRes.status, 200);
    assert.equal(listRes.headers.get("access-control-allow-origin"), server.origin);
    const listText = await listRes.text();
    assert.equal(listText.includes("1//0gSECRET_REFRESH_TOKEN"), false);

    const listData = JSON.parse(listText);
    assert.equal(listData.accounts.length, 2);
    assert.equal(listData.accounts[0].profile, "broken12");
    assert.equal(listData.accounts[0].valid, false);
    assert.equal(listData.accounts[1].profile, "acct1234");
    assert.equal(listData.accounts[1].email, "user@example.com");
    assert.equal(listData.accounts[1].valid, true);

    // Export valid account
    const exportRes = await fetch(`${server.origin}/api/export`, {
      method: "POST",
      headers: {
        "Content-Type": "text/plain;charset=UTF-8",
        Origin: server.origin,
      },
      body: JSON.stringify({ nonce: server.nonce, profile: "acct1234" }),
    });
    assert.equal(exportRes.status, 200);
    assert.deepEqual(await exportRes.json(), {
      profile: "acct1234",
      refreshToken: "1//0gSECRET_REFRESH_TOKEN",
    });

    // Error codes for invalid / missing / corrupt profiles
    const invalidRes = await fetch(`${server.origin}/api/export`, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify({ nonce: server.nonce, profile: "../etc/passwd" }),
    });
    assert.equal(invalidRes.status, 400);
    assert.deepEqual(await invalidRes.json(), { error: "invalid_profile" });

    const missingRes = await fetch(`${server.origin}/api/export`, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify({ nonce: server.nonce, profile: "notfound1" }),
    });
    assert.equal(missingRes.status, 404);
    assert.deepEqual(await missingRes.json(), { error: "not_found" });

    const brokenRes = await fetch(`${server.origin}/api/export`, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify({ nonce: server.nonce, profile: "broken12" }),
    });
    assert.equal(brokenRes.status, 422);
    assert.deepEqual(await brokenRes.json(), { error: "invalid_token" });
  });

  it("enforces Host, Origin, and Nonce checks and allows Origin: null CORS-simple requests", async () => {
    const { server } = await setupTestServer();

    // Bad Host header -> 403
    const badHost = await rawHttpRequest({
      port: server.port,
      method: "GET",
      path: "/",
      headers: { Host: `evil.example:${server.port}` },
    });
    assert.equal(badHost.status, 403);

    // Bad Origin -> 403
    const badOrigin = await rawHttpRequest({
      port: server.port,
      method: "POST",
      path: "/api/accounts",
      headers: {
        Host: `127.0.0.1:${server.port}`,
        Origin: "https://evil.example",
        "Content-Type": "text/plain;charset=UTF-8",
      },
      body: JSON.stringify({ nonce: server.nonce }),
    });
    assert.equal(badOrigin.status, 403);

    // Missing nonce -> 403
    const missingNonce = await rawHttpRequest({
      port: server.port,
      method: "POST",
      path: "/api/accounts",
      headers: {
        Host: `127.0.0.1:${server.port}`,
        Origin: server.origin,
        "Content-Type": "text/plain;charset=UTF-8",
      },
      body: JSON.stringify({}),
    });
    assert.equal(missingNonce.status, 403);

    // Wrong nonce -> 403
    const wrongNonce = await rawHttpRequest({
      port: server.port,
      method: "POST",
      path: "/api/export",
      headers: {
        Host: `127.0.0.1:${server.port}`,
        Origin: server.origin,
        "Content-Type": "text/plain;charset=UTF-8",
      },
      body: JSON.stringify({ nonce: "0".repeat(64), profile: "acct1234" }),
    });
    assert.equal(wrongNonce.status, 403);

    // Origin: null (sandboxed iframe CORS-simple request) -> 200 with Access-Control-Allow-Origin: null
    const nullOrigin = await rawHttpRequest({
      port: server.port,
      method: "POST",
      path: "/api/accounts",
      headers: {
        Host: `127.0.0.1:${server.port}`,
        Origin: "null",
        "Content-Type": "text/plain;charset=UTF-8",
      },
      body: JSON.stringify({ nonce: server.nonce }),
    });
    assert.equal(nullOrigin.status, 200);
    assert.equal(nullOrigin.headers["access-control-allow-origin"], "null");
    assert.equal(nullOrigin.headers["vary"], "Origin");
  });
});
