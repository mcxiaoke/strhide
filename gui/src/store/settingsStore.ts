import { create } from "zustand";
import type { Lang, SafetyLevel } from "../types/strhide";
import { setUiLanguage } from "../api/commands";

interface SettingsState {
  lang: Lang;
  defaultSafety: SafetyLevel;
  autoBackup: boolean;

  setLang: (lang: Lang) => Promise<void>;
  setDefaultSafety: (level: SafetyLevel) => void;
  setAutoBackup: (enabled: boolean) => void;
}

export const useSettingsStore = create<SettingsState>((set) => ({
  lang: "zh",
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

  setDefaultSafety: (defaultSafety) => set({ defaultSafety }),

  setAutoBackup: (autoBackup) => set({ autoBackup }),
}));
