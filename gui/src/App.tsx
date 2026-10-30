import React, { useState } from "react";
import { Download, Globe, Layers, Moon, Search, Sparkles, Sun } from "lucide-react";
import { useSettingsStore } from "./store/settingsStore";
import { useT } from "./hooks/useT";
import { ProgressBarOverlay } from "./components/common/ProgressBarOverlay";
import { StegoEmbedView } from "./views/StegoEmbedView";
import { HideStructureView } from "./views/HideStructureView";
import { ExtractView } from "./views/ExtractView";
import { ScanView } from "./views/ScanView";

type TabId = "stego" | "hide" | "extract" | "scan";

export const App: React.FC = () => {
  const c = useT();
  const { lang, setLang, theme, toggleTheme } = useSettingsStore();
  const [activeTab, setActiveTab] = useState<TabId>("stego");

  const tabs = [
    { id: "stego" as const, label: c.tabs.stego, icon: Sparkles },
    { id: "hide" as const, label: c.tabs.hide, icon: Layers },
    { id: "extract" as const, label: c.tabs.extract, icon: Download },
    { id: "scan" as const, label: c.tabs.scan, icon: Search },
  ];

  const themeTarget = theme === "light" ? c.theme.dark : c.theme.light;

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-slate-950 font-sans text-slate-100">
      <header className="flex h-12 shrink-0 items-center gap-5 border-b border-slate-800 bg-slate-900/80 px-4">
        <div className="flex shrink-0 items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-700 text-xs font-bold text-white">
            S
          </div>
          <span className="text-sm font-semibold tracking-tight text-slate-100">StrHide</span>
        </div>

        <nav className="flex flex-1 items-center gap-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                data-testid={`tab-${tab.id}`}
                aria-current={isActive ? "page" : undefined}
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                  isActive
                    ? "bg-slate-800 text-cyan-300"
                    : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </nav>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            data-testid="theme-toggle"
            onClick={toggleTheme}
            title={themeTarget}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700 hover:text-slate-100"
          >
            {theme === "light" ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
            {themeTarget}
          </button>
          <button
            type="button"
            data-testid="lang-toggle"
            onClick={() => setLang(lang === "zh" ? "en" : "zh")}
            title={c.lang.other}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700 hover:text-slate-100"
          >
            <Globe className="h-3.5 w-3.5 text-cyan-400" />
            {c.lang.name}
          </button>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-5xl p-4">
          <div data-panel="stego" className={activeTab === "stego" ? "" : "hidden"}>
            <StegoEmbedView active={activeTab === "stego"} />
          </div>
          <div data-panel="hide" className={activeTab === "hide" ? "" : "hidden"}>
            <HideStructureView active={activeTab === "hide"} />
          </div>
          <div data-panel="extract" className={activeTab === "extract" ? "" : "hidden"}>
            <ExtractView active={activeTab === "extract"} />
          </div>
          <div data-panel="scan" className={activeTab === "scan" ? "" : "hidden"}>
            <ScanView active={activeTab === "scan"} />
          </div>
        </div>
      </main>

      <ProgressBarOverlay />
    </div>
  );
};

export default App;
