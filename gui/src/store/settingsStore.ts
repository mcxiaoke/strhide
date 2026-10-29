import { create } from "zustand";
import type { Lang, SafetyLevel } from "../types/strhide";
import { setUiLanguage } from "../api/commands";

export type ThemeMode = "light" | "dark";

interface SettingsState {
  lang: Lang;
  theme: ThemeMode;
  defaultSafety: SafetyLevel;
  autoBackup: boolean;

  setLang: (lang: Lang) => Promise<void>;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
  setDefaultSafety: (level: SafetyLevel) => void;
  setAutoBackup: (enabled: boolean) => void;
}

const getInitialTheme = (): ThemeMode => {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("strhide_theme") as ThemeMode | null;
    if (saved === "dark" || saved === "light") {
      document.documentElement.setAttribute("data-theme", saved);
      return saved;
    }
    // 默认亮色 (Light Mode)
    document.documentElement.setAttribute("data-theme", "light");
  }
  return "light";
};

const initialTheme = getInitialTheme();

export const useSettingsStore = create<SettingsState>((set, get) => ({
  lang: "zh",
  theme: initialTheme,
  defaultSafety: "high",
  autoBackup: true,

  setLang: async (lang) => {
    try {
      await setUiLanguage(lang);
      set({ lang });
    } catch (err) {
      console.error("Failed to set UI language:", err);
    }
  },

  setTheme: (theme) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("strhide_theme", theme);
      document.documentElement.setAttribute("data-theme", theme);
    }
    set({ theme });
  },

  toggleTheme: () => {
    const nextTheme = get().theme === "light" ? "dark" : "light";
    get().setTheme(nextTheme);
  },

  setDefaultSafety: (defaultSafety) => set({ defaultSafety }),

  setAutoBackup: (autoBackup) => set({ autoBackup }),
}));
