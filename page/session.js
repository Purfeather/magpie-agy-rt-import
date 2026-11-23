"use strict";

// Shared wire encoding for the standalone file client and the local service.
// The route, direction and request IV bind a response to one browser request.
(() => {
  const utf8 = new TextEncoder();
  function hex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  function bytes(value) {
    if (typeof value !== "string" || !/^(?:[a-f0-9]{2})+$/u.test(value)) throw new Error("Invalid encoding");
    return Uint8Array.from(value.match(/../gu), (pair) => Number.parseInt(pair, 16));
  }
  async function importKey(value) {
    if (!/^[a-f0-9]{64}$/u.test(value)) throw new Error("Invalid key");
    return crypto.subtle.importKey("raw", bytes(value), "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  async function seal(key, context, value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const result = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8.encode(context) },
      key, utf8.encode(JSON.stringify(value)));
    return { iv: hex(iv), sealed: hex(new Uint8Array(result)) };
  }
  async function unseal(key, context, packet) {
    if (!/^[a-f0-9]{24}$/u.test(packet?.iv)) throw new Error("Invalid IV");
    const result = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: bytes(packet.iv), additionalData: utf8.encode(context),
    }, key, bytes(packet.sealed));
    return JSON.parse(new TextDecoder().decode(result));
  }
  const codec = { importKey, seal, unseal };
  if (typeof module !== "undefined" && module.exports) module.exports = codec;
  else globalThis.localSessionCodec = codec;
})();
