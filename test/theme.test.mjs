import assert from "node:assert/strict";
import { it } from "node:test";
import applyTheme from "../page/theme.js";

it("maps Magpie's real token names and switches between light and dark", () => {
  const values = new Map();
  const root = { dataset: {}, style: {
    setProperty: (name, value) => values.set(name, value),
    removeProperty: (name) => values.delete(name),
  } };
  applyTheme({ dark: false, lang: "zh", tokens: { bg: "#ffffff", fg: "#18181b", accent: "#5046e5", "fg-2": "#555555" } }, root);
  assert.equal(root.dataset.theme, "light");
  assert.equal(root.lang, "zh");
  assert.equal(values.get("--magpie-bg"), "#ffffff");
  assert.equal(values.get("--magpie-accent"), "#5046e5");
  applyTheme({ dark: true, tokens: { bg: "#18181b", fg: "#eeeeee", card: "#242426", accent: "#a5a0ff" } }, root);
  assert.equal(root.dataset.theme, "dark");
  assert.equal(root.style.colorScheme, "dark");
  assert.equal(values.get("--magpie-bg"), "#18181b");
  assert.equal(values.get("--magpie-card"), "#242426");
  assert.equal(values.get("--magpie-accent"), "#a5a0ff");
  assert.equal(values.has("--magpie-fg-2"), false);
});

it("ignores malformed theme messages and unrelated CSS properties", () => {
  const values = new Map();
  const root = { dataset: {}, style: {
    setProperty: (name, value) => values.set(name, value),
    removeProperty: (name) => values.delete(name),
  } };
  applyTheme(null, root);
  applyTheme({ dark: "true" }, root);
  assert.equal(root.dataset.theme, undefined);
  applyTheme({ dark: true, tokens: { bg: {}, secret: "value", accent: "#a5a0ff" } }, root);
  assert.deepEqual([...values.keys()], ["--magpie-accent"]);
});
