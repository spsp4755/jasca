export type ThemeMode = "system" | "light" | "dark";
const KEY = "jasca.theme";

// localStorage throws in some locked-down browsers; the theme then just follows the OS.
export function getTheme(): ThemeMode {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

/** Applies the mode to <html data-theme>; "system" removes it so prefers-color-scheme decides. */
export function setTheme(mode: ThemeMode) {
  const root = document.documentElement;
  if (mode === "system") delete root.dataset.theme;
  else root.dataset.theme = mode;
  try { localStorage.setItem(KEY, mode); } catch { /* not persisted */ }
}

export const applySavedTheme = () => setTheme(getTheme());
