import { create } from "zustand";
import type { Capability, DualInspect, ErrorDetail } from "../types/strhide";
import { getCapabilities, inspectCarrier } from "../api/commands";

interface WorkspaceState {
  carrierPath: string | null;
  capabilities: Capability[];
  inspection: DualInspect | null;
  isInspecting: boolean;
  inspectError: ErrorDetail | null;
  activeTab: "inspect" | "hide" | "verify" | "forensics";
  password: string;

  setCarrier: (path: string | null) => void;
  setPassword: (password: string) => void;
  setActiveTab: (tab: "inspect" | "hide" | "verify" | "forensics") => void;
  loadCapabilities: () => Promise<void>;
  inspectCurrentCarrier: (overridePassword?: string) => Promise<void>;
  clearCarrier: () => void;
}

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  carrierPath: null,
  capabilities: [],
  inspection: null,
  isInspecting: false,
  inspectError: null,
  activeTab: "inspect",
  password: "",

  setCarrier: (path) => {
    set({ carrierPath: path, inspection: null, inspectError: null });
    if (path) {
      get().inspectCurrentCarrier();
    }
  },

  setPassword: (password) => set({ password }),

  setActiveTab: (activeTab) => set({ activeTab }),

  loadCapabilities: async () => {
    try {
      const caps = await getCapabilities();
      set({ capabilities: caps });
    } catch (err) {
      console.error("Failed to load capabilities:", err);
    }
  },

  inspectCurrentCarrier: async (overridePassword?: string) => {
    const { carrierPath, password } = get();
    if (!carrierPath) return;

    set({ isInspecting: true, inspectError: null });
    try {
      const pwd = overridePassword !== undefined ? overridePassword : password || undefined;
      const res = await inspectCarrier(carrierPath, pwd);
      set({ inspection: res, isInspecting: false });
    } catch (err) {
      set({
        inspectError: err as ErrorDetail,
        isInspecting: false,
      });
    }
  },

  clearCarrier: () => {
    set({
      carrierPath: null,
      inspection: null,
      inspectError: null,
      password: "",
    });
  },
}));
