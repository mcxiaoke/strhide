import React, { useEffect } from "react";
import {
  Search,
  Shield,
  CheckCircle,
  Microscope,
  Sliders,
  Globe,
  Sun,
  Moon,
} from "lucide-react";
import { useWorkspaceStore } from "./store/workspaceStore";
import { useSettingsStore } from "./store/settingsStore";
import { t } from "./lib/i18n";
import { CarrierDropzone } from "./components/stage/CarrierDropzone";
import { CarrierSummary } from "./components/stage/CarrierSummary";
import { ProgressBarOverlay } from "./components/common/ProgressBarOverlay";
import { InspectExtractView } from "./views/InspectExtractView";
import { HideEmbedView } from "./views/HideEmbedView";
import { VerifyRestoreView } from "./views/VerifyRestoreView";
import { ForensicsBatchView } from "./views/ForensicsBatchView";

export const App: React.FC = () => {
  const { activeTab, setActiveTab, carrierPath, loadCapabilities } = useWorkspaceStore();
  const { lang, setLang, theme, toggleTheme } = useSettingsStore();

  useEffect(() => {
    loadCapabilities();
  }, [loadCapabilities]);

  const i18nText = t(lang);

  const tabs = [
    { id: "inspect" as const, label: i18nText.tabs.inspect, icon: Search },
    { id: "hide" as const, label: i18nText.tabs.hide, icon: Shield },
    { id: "verify" as const, label: i18nText.tabs.verify, icon: CheckCircle },
    { id: "forensics" as const, label: i18nText.tabs.forensics, icon: Microscope },
  ];

  return (
    <div className="flex h-screen w-screen flex-col bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Top Header */}
      <header className="flex h-16 shrink-0 items-center justify-between border-b border-slate-700 bg-slate-900/80 px-6 backdrop-blur-md shadow-sm">
        <div className="flex items-center gap-3.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 font-bold text-white shadow-md shadow-cyan-950/20">
            S
          </div>
          <div>
            <h1 className="text-base font-bold tracking-tight text-slate-100">StrHide Studio</h1>
            <p className="text-[11px] text-slate-400 leading-none mt-0.5">Smart Lossless Data Hiding</p>
          </div>
        </div>

        {/* Global Toolbar: Theme & Language Switch */}
        <div className="flex items-center gap-2.5">
          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            title={i18nText.common[theme === "light" ? "darkTheme" : "lightTheme"]}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-slate-100 transition-colors"
          >
            {theme === "light" ? (
              <>
                <Moon className="h-4 w-4 text-slate-500" />
                <span className="hidden sm:inline">{i18nText.common.darkTheme}</span>
              </>
            ) : (
              <>
                <Sun className="h-4 w-4 text-amber-400" />
                <span className="hidden sm:inline">{i18nText.common.lightTheme}</span>
              </>
            )}
          </button>

          {/* Language Switch */}
          <button
            onClick={() => setLang(lang === "zh" ? "en" : "zh")}
            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700 hover:text-slate-100 transition-colors"
          >
            <Globe className="h-4 w-4 text-cyan-400" />
            <span>{lang === "zh" ? "中文" : "English"}</span>
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Navigation Sidebar */}
        <nav className="flex w-64 shrink-0 flex-col justify-between border-r border-slate-700 bg-slate-900/60 p-4 shadow-sm">
          <div className="space-y-2">
            <div className="px-3 pb-1 text-[11px] font-bold uppercase tracking-wider text-slate-400">
              功能工作台
            </div>
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex w-full items-center gap-3.5 rounded-xl px-4 py-3 text-[13px] font-semibold border transition-colors outline-none focus:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500/50 select-none ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border-cyan-800/60 shadow-sm shadow-cyan-950/10"
                      : "border-transparent text-slate-400 hover:bg-slate-800/70 hover:text-slate-200"
                  }`}
                >
                  <Icon className={`h-4.5 w-4.5 shrink-0 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          <div className="rounded-xl border border-slate-700 bg-slate-900/90 p-3.5 text-xs text-slate-400 space-y-1.5">
            <div className="flex items-center gap-1.5 text-slate-200 font-semibold">
              <Sliders className="h-3.5 w-3.5 text-cyan-400" />
              <span>{i18nText.common.stageReady}</span>
            </div>
            <p className="leading-relaxed text-[11px]">{i18nText.common.features}</p>
          </div>
        </nav>

        {/* Content Workspace Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Global Carrier Stage */}
          {!carrierPath ? <CarrierDropzone /> : <CarrierSummary />}

          {/* Active View Container */}
          {activeTab === "inspect" && <InspectExtractView />}
          {activeTab === "hide" && <HideEmbedView />}
          {activeTab === "verify" && <VerifyRestoreView />}
          {activeTab === "forensics" && <ForensicsBatchView />}
        </main>
      </div>

      {/* Floating Progress Bar Overlay */}
      <ProgressBarOverlay />
    </div>
  );
};
export default App;
