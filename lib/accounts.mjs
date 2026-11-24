import { constants } from "node:fs";
import { createHash } from "node:crypto";
import fs, { lstat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

export const PROFILE_ID_RE = /^[a-z0-9]{8,32}$/u;
export const AGY_AUTH_KEY_RE = /^agy-cli(?:-plugin)?(?:#.+)?$/u;
export const EMAIL_RE = /^[^\s@]+@[^\s@]+$/u;
export const INVALID_TOKEN_CHARS_RE = /[\s\u0000-\u001f\u007f]/u;
export const MAX_CREDENTIAL_BYTES = 64 * 1024;
const MAX_INDEX_BYTES = 4 * 1024 * 1024;
const TOKEN_SEGMENTS = [".gemini", "antigravity-cli", "antigravity-oauth-token"];

export function getDefaultAccountsDir(env = process.env, home = homedir()) {
  const stateHome = typeof env?.XDG_STATE_HOME === "string" && env.XDG_STATE_HOME.trim()
    ? env.XDG_STATE_HOME.trim()
    : path.join(home, ".local", "state");
  return path.join(stateHome, "magpie-agy-bridge", "accounts");
}

export function getDefaultConfigDir(env = process.env, home = homedir()) {
  return path.join(env.XDG_CONFIG_HOME || path.join(home, ".config"), "magpie");
}

export function validateRefreshToken(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!trimmed || INVALID_TOKEN_CHARS_RE.test(trimmed)) return "";
  return trimmed;
}

export function isValidProfileId(profile) {
  return typeof profile === "string" && PROFILE_ID_RE.test(profile);
}

// Ancestors above root are trusted. Record each identity before opening and
// recheck from leaf to root. Only the verified descriptor supplies bytes.
async function readJsonFile(root, segments, limit) {
  if (typeof root !== "string" || !root) return { ok: false, error: "not_found" };
  const chain = [];
  let file;
  try {
    let current = root;
    for (let i = 0; i <= segments.length; i++) {
      if (i) current = path.join(current, segments[i - 1]);
      const stat = await lstat(current, { bigint: true });
      if (i < segments.length ? !stat.isDirectory() : !stat.isFile()) {
        return { ok: false, error: "not_found" };
      }
      chain.push({ current, stat });
    }
    const last = chain[chain.length - 1];
    file = await fs.open(last.current, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
    const opened = await file.stat({ bigint: true });
    if (!opened.isFile() || opened.ino === 0n || opened.dev !== last.stat.dev || opened.ino !== last.stat.ino) {
      return { ok: false, error: "not_found" };
    }
    for (const { current: component, stat } of chain.reverse()) {
      const now = await lstat(component, { bigint: true });
      if (now.dev !== stat.dev || now.ino !== stat.ino || now.mode !== stat.mode) {
        return { ok: false, error: "not_found" };
      }
    }
    const updatedAt = opened.mtime.toISOString();
    const invalid = { ok: false, error: "invalid_token", updatedAt };
    if (!opened.size || opened.size > BigInt(limit)) return invalid;
    const buffer = Buffer.alloc(Number(opened.size) + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== Number(opened.size)) return invalid;
    try {
      const data = JSON.parse(buffer.toString("utf8", 0, length).replace(/^\uFEFF/u, ""));
      return { ok: true, data, updatedAt };
    } catch {
      return invalid;
    }
  } catch (error) {
    const absent = ["ENOENT", "ENOTDIR", "ELOOP"].includes(error?.code);
    return { ok: false, error: absent ? "not_found" : "read_failed" };
  } finally {
    await file?.close();
  }
}

async function loadToken(accountsDir, profile) {
  if (!isValidProfileId(profile)) return { ok: false, error: "invalid_profile" };
  const result = await readJsonFile(accountsDir, [profile, ...TOKEN_SEGMENTS], MAX_CREDENTIAL_BYTES);
  if (!result.ok) return result;
  const refreshToken = validateRefreshToken(result.data?.token?.refresh_token);
  const tokenEmail = typeof result.data?.id_token_email === "string" ? result.data.id_token_email.trim() : "";
  return refreshToken
    ? {
      ok: true, profile, refreshToken, updatedAt: result.updatedAt,
      ...(EMAIL_RE.test(tokenEmail) ? { email: tokenEmail } : {}),
    }
    : { ok: false, error: "invalid_token", updatedAt: result.updatedAt };
}

export async function readAccountRefreshToken(accountsDir, profile) {
  const result = await loadToken(accountsDir, profile);
  return result.ok ? result : { ok: false, error: result.error };
}

async function readRegisteredProfiles(configDir) {
  const registered = new Map();
  if (typeof configDir !== "string" || !configDir) return registered;

  const result = await readJsonFile(configDir, ["plugin-auth.json"], MAX_INDEX_BYTES);
  if (!result.ok) {
    if (result.error === "not_found") return registered;
    throw new Error("Account index could not be read");
  }
  const parsed = result.data;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid account index");
  }

  for (const [key, value] of Object.entries(parsed)) {
    if (!AGY_AUTH_KEY_RE.test(key)) continue;
    const metadata = value?.metadata;
    const rawEmail = typeof metadata?.email === "string" ? metadata.email.trim() : "";
    const email = EMAIL_RE.test(rawEmail) ? rawEmail : "";
    let profile = metadata?.agyHome;
    const legacy = profile === undefined && value?.key === "agy" && email;
    if (legacy) {
      profile = "own" + createHash("sha256").update(email.toLowerCase()).digest("hex").slice(0, 24);
    }
    if (!isValidProfileId(profile)) continue;
    const existing = registered.get(profile);
    if (!existing) {
      registered.set(profile, { profile, email, registered: true, expectedEmail: legacy ? email : "" });
    } else if (!existing.email && email) {
      existing.email = email;
    }
  }
  return registered;
}

async function inspectTokenMetadata(accountsDir, profile) {
  const token = await loadToken(accountsDir, profile);
  return {
    valid: token.ok,
    email: token.email || "",
    updatedAt: token.updatedAt ?? null,
  };
}

function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

export async function listAccounts({ configDir, accountsDir } = {}) {
  const resolvedAccountsDir = accountsDir || getDefaultAccountsDir();
  const registered = await readRegisteredProfiles(configDir || getDefaultConfigDir());

  const inspected = await Promise.all(
    Array.from(registered.values()).map(async (item) => {
      const tokenInfo = await inspectTokenMetadata(resolvedAccountsDir, item.profile);
      return {
        profile: item.profile,
        email: item.email || tokenInfo.email,
        registered: item.registered,
        updatedAt: tokenInfo.updatedAt,
        valid: tokenInfo.valid && (!item.expectedEmail
          || tokenInfo.email.toLowerCase() === item.expectedEmail.toLowerCase()),
      };
    })
  );

  const accounts = inspected.sort((a, b) => {
    const keyA = (a.email || a.profile).toLowerCase();
    const keyB = (b.email || b.profile).toLowerCase();
    const primary = compareStrings(keyA, keyB);
    if (primary !== 0) return primary;
    return compareStrings(a.profile, b.profile);
  });

  return { accounts, accountsDir: resolvedAccountsDir };
}
