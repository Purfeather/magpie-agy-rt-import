import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import fsPromises from "node:fs/promises";
import { afterEach, describe, it } from "node:test";
import {
  getDefaultAccountsDir,
  listAccounts,
  readAccountRefreshToken,
  validateRefreshToken,
} from "../lib/accounts.mjs";

const tempDirs = [];

async function createFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "magpie-agy-test-"));
  tempDirs.push(root);
  const configDir = path.join(root, "config");
  const accountsDir = path.join(root, "accounts");
  await mkdir(configDir, { recursive: true });
  await mkdir(accountsDir, { recursive: true });
  return { root, configDir, accountsDir };
}

async function writeTokenFile(accountsDir, profile, content) {
  const dir = path.join(accountsDir, profile, ".gemini", "antigravity-cli");
  await mkdir(dir, { recursive: true });
  const tokenPath = path.join(dir, "antigravity-oauth-token");
  const body = typeof content === "string" ? content : JSON.stringify(content, null, 2);
  await writeFile(tokenPath, body, "utf8");
  return tokenPath;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    await rm(dir, { recursive: true, force: true });
  }
});

describe("lib/accounts.mjs", () => {
  it("distinguishes an absent account store from an unreadable store", async () => {
    const { root, accountsDir } = await createFixture();
    assert.deepEqual((await listAccounts({ accountsDir: path.join(root, "missing") })).accounts, []);
    const original = fsPromises.readdir;
    fsPromises.readdir = async () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); };
    try {
      await assert.rejects(listAccounts({ accountsDir }), { code: "EACCES" });
    } finally {
      fsPromises.readdir = original;
    }
  });
  it("resolves default accountsDir from XDG_STATE_HOME or homedir", () => {
    const withXdg = getDefaultAccountsDir({ XDG_STATE_HOME: "/custom/state" }, "/home/tester");
    assert.equal(withXdg, path.join("/custom/state", "magpie-agy-bridge", "accounts"));

    const withoutXdg = getDefaultAccountsDir({}, "/home/tester");
    assert.equal(
      withoutXdg,
      path.join("/home/tester", ".local", "state", "magpie-agy-bridge", "accounts")
    );
  });

  it("validates refresh tokens strictly", () => {
    assert.equal(validateRefreshToken("  1//0gVALID-token_123  "), "1//0gVALID-token_123");
    assert.equal(validateRefreshToken("has space"), "");
    assert.equal(validateRefreshToken("line1\nline2"), "");
    assert.equal(validateRefreshToken("ctrl\u0007char"), "");
    assert.equal(validateRefreshToken(""), "");
    assert.equal(validateRefreshToken(null), "");
  });

  it("discovers, deduplicates, and sorts registered and local accounts with fault tolerance", async () => {
    const { configDir, accountsDir } = await createFixture();

    // Registered valid accounts (including duplicate profile with email only on second entry)
    await writeTokenFile(accountsDir, "aaaa1111", { token: { refresh_token: "rt-zeta" } });
    await writeTokenFile(accountsDir, "bbbb2222", { token: { refresh_token: "rt-alpha" } });
    // Registered account with corrupt JSON
    await writeTokenFile(accountsDir, "cccc3333", "{not-json");
    // Registered account whose token file is missing
    // (profile dddd4444 has no directory at all)
    // Unregistered local valid account
    await writeTokenFile(accountsDir, "eeee5555", { token: { refresh_token: "rt-local" } });
    // Unregistered local account with missing refresh_token
    await writeTokenFile(accountsDir, "ffff6666", { token: {} });
    // Unregistered empty dir without token file (should be ignored)
    await mkdir(path.join(accountsDir, "99998888"), { recursive: true });
    // Non-matching directory name (should be ignored)
    await writeTokenFile(accountsDir, "INVALID_ID", { token: { refresh_token: "rt-ignored" } });

    await writeFile(
      path.join(configDir, "plugin-auth.json"),
      JSON.stringify({
        "agy-cli#1": { metadata: { agyHome: "aaaa1111" } },
        "agy-cli-plugin#dup": { metadata: { agyHome: "aaaa1111", email: "zeta@example.com" } },
        "agy-cli#2": { metadata: { agyHome: "bbbb2222", email: "alpha@example.com" } },
        "agy-cli#corrupt": { metadata: { agyHome: "cccc3333", email: "corrupt@example.com" } },
        "agy-cli#missing": { metadata: { agyHome: "dddd4444", email: "missing@example.com" } },
        "other-plugin#1": { metadata: { agyHome: "eeee5555", email: "ignored@example.com" } },
      }),
      "utf8"
    );

    const result = await listAccounts({ configDir, accountsDir });
    assert.equal(result.accountsDir, accountsDir);
    assert.deepEqual(
      result.accounts.map((a) => ({
        profile: a.profile,
        email: a.email,
        registered: a.registered,
        valid: a.valid,
        hasUpdatedAt: Boolean(a.updatedAt),
      })),
      [
        { profile: "bbbb2222", email: "alpha@example.com", registered: true, valid: true, hasUpdatedAt: true },
        { profile: "cccc3333", email: "corrupt@example.com", registered: true, valid: false, hasUpdatedAt: true },
        { profile: "dddd4444", email: "missing@example.com", registered: true, valid: false, hasUpdatedAt: false },
        { profile: "aaaa1111", email: "zeta@example.com", registered: true, valid: true, hasUpdatedAt: true },
        { profile: "eeee5555", email: "", registered: false, valid: true, hasUpdatedAt: true },
        { profile: "ffff6666", email: "", registered: false, valid: false, hasUpdatedAt: true },
      ]
    );

    // Ensure no refresh token string appears anywhere in listAccounts output
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes("rt-zeta"), false);
    assert.equal(serialized.includes("rt-alpha"), false);
    assert.equal(serialized.includes("rt-local"), false);
  });

  it("gracefully ignores malformed plugin-auth.json and still scans accountsDir", async () => {
    const { configDir, accountsDir } = await createFixture();
    await writeFile(path.join(configDir, "plugin-auth.json"), "not valid json", "utf8");
    await writeTokenFile(accountsDir, "abcd1234", { token: { refresh_token: "rt-ok" } });

    const result = await listAccounts({ configDir, accountsDir });
    assert.equal(result.accounts.length, 1);
    assert.equal(result.accounts[0].profile, "abcd1234");
    assert.equal(result.accounts[0].registered, false);
    assert.equal(result.accounts[0].valid, true);
  });

  it("reads valid refresh token and rejects invalid profiles, missing files, and oversized/corrupt files", async () => {
    const { accountsDir } = await createFixture();
    await writeTokenFile(accountsDir, "good1234", { token: { refresh_token: "1//0gTEST_TOKEN" } });
    await writeTokenFile(accountsDir, "badjson1", "{broken");
    await writeTokenFile(accountsDir, "oversize1", "a".repeat(70000));

    const ok = await readAccountRefreshToken(accountsDir, "good1234");
    assert.equal(ok.ok, true);
    assert.equal(ok.profile, "good1234");
    assert.equal(ok.refreshToken, "1//0gTEST_TOKEN");

    assert.deepEqual(await readAccountRefreshToken(accountsDir, "../escape"), {
      ok: false,
      error: "invalid_profile",
    });
    assert.deepEqual(await readAccountRefreshToken(accountsDir, "short"), {
      ok: false,
      error: "invalid_profile",
    });
    assert.deepEqual(await readAccountRefreshToken(accountsDir, "missing12"), {
      ok: false,
      error: "not_found",
    });
    assert.deepEqual(await readAccountRefreshToken(accountsDir, "badjson1"), {
      ok: false,
      error: "invalid_token",
    });
    assert.deepEqual(await readAccountRefreshToken(accountsDir, "oversize1"), {
      ok: false,
      error: "invalid_token",
    });
  });

  it("accepts a leading UTF-8 BOM in the account index and credential", async () => {
    const { accountsDir, configDir } = await createFixture();
    await writeFile(path.join(configDir, "plugin-auth.json"),
      "\uFEFF" + JSON.stringify({ "agy-cli": { metadata: { agyHome: "bomtest1", email: "bom@example.com" } } }));
    await writeTokenFile(accountsDir, "bomtest1", "\uFEFF" + JSON.stringify({ token: { refresh_token: "rt-bom" } }));
    const { accounts } = await listAccounts({ configDir, accountsDir });
    assert.equal(accounts[0].registered, true);
    assert.equal(accounts[0].valid, true);
    assert.equal(accounts[0].email, "bom@example.com");
    assert.equal((await readAccountRefreshToken(accountsDir, "bomtest1")).refreshToken, "rt-bom");
  });

  it("rejects an opened file whose identity differs from the checked entry", async (t) => {
    const { accountsDir } = await createFixture();
    const target = await writeTokenFile(accountsDir, "identity1", { token: { refresh_token: "first" } });
    const other = await writeTokenFile(accountsDir, "identity2", { token: { refresh_token: "second" } });
    const openFile = fsPromises.open;
    const replacement = t.mock.method(fsPromises, "open", (name, ...options) =>
      openFile(name === target ? other : name, ...options));
    try {
      assert.deepEqual(await readAccountRefreshToken(accountsDir, "identity1"), { ok: false, error: "not_found" });
    } finally {
      replacement.mock.restore();
    }
  });

  it("rejects the accounts root itself when it is a junction or symlink", async () => {
    const { root, accountsDir } = await createFixture();
    await writeTokenFile(accountsDir, "rootlink1", { token: { refresh_token: "fixture" } });
    const linked = path.join(root, "linked-accounts");
    await symlink(accountsDir, linked, process.platform === "win32" ? "junction" : "dir");
    assert.deepEqual((await listAccounts({ accountsDir: linked })).accounts, []);
    assert.deepEqual(await readAccountRefreshToken(linked, "rootlink1"), { ok: false, error: "not_found" });
  });

  it("rejects symlink / junction paths in accountsDir", async () => {
    const { root, accountsDir } = await createFixture();
    const externalProfileDir = path.join(root, "external-target");
    await mkdir(path.join(externalProfileDir, ".gemini", "antigravity-cli"), { recursive: true });
    const externalTokenFile = path.join(
      externalProfileDir,
      ".gemini",
      "antigravity-cli",
      "antigravity-oauth-token"
    );
    await writeFile(
      externalTokenFile,
      JSON.stringify({ token: { refresh_token: "1//0gSECRET_EXTERNAL" } }),
      "utf8"
    );

    // Directory junction (works without admin rights on Windows) or symlink on POSIX
    const linkType = process.platform === "win32" ? "junction" : "dir";
    const linkedProfileDir = path.join(accountsDir, "linkdir1");
    await symlink(externalProfileDir, linkedProfileDir, linkType);

    const dirRes = await readAccountRefreshToken(accountsDir, "linkdir1");
    assert.deepEqual(dirRes, { ok: false, error: "not_found" });

    const listRes = await listAccounts({ accountsDir });
    assert.equal(listRes.accounts.some((a) => a.profile === "linkdir1"), false);

    // Also test file-level symlink when permitted by OS
    const normalDir = path.join(accountsDir, "linkfile1", ".gemini", "antigravity-cli");
    await mkdir(normalDir, { recursive: true });
    let fileSymlinkCreated = false;
    try {
      await symlink(externalTokenFile, path.join(normalDir, "antigravity-oauth-token"), "file");
      fileSymlinkCreated = true;
    } catch {
      // Windows without Developer Mode may disallow file symlinks; directory junction above already tested reparse points.
    }
    if (fileSymlinkCreated) {
      const fileRes = await readAccountRefreshToken(accountsDir, "linkfile1");
      assert.deepEqual(fileRes, { ok: false, error: "not_found" });
    }
  });
});
