"use strict";

(() => {
  const tokens = ["bg", "card", "fg", "fg-2", "muted", "faint", "line", "accent", "accent-soft", "accent-fg", "green", "red", "amber", "font", "code"];

  function applyTheme(theme, root = document.documentElement) {
    if (!theme || typeof theme.dark !== "boolean") return;
    root.dataset.theme = theme.dark ? "dark" : "light";
    root.style.colorScheme = theme.dark ? "dark" : "light";
    if (typeof theme.lang === "string") root.lang = theme.lang;
    for (const name of tokens) {
      const value = theme.tokens?.[name];
      if (typeof value === "string" && value.trim()) root.style.setProperty("--magpie-" + name, value);
      else root.style.removeProperty("--magpie-" + name);
    }
  }

  if (typeof module !== "undefined" && module.exports) module.exports = applyTheme;
  else globalThis.applyMagpieTheme = applyTheme;
})();
