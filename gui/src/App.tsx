import React, { useEffect } from "react";
import {
  Search,
  Shield,
  CheckCircle,
  Microscope,
  Sliders,
  Globe,
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
  const { lang, setLang } = useSettingsStore();

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
      <header className="flex h-14 shrink-0 items-center justify-between border-b border-slate-800/80 bg-slate-900/60 px-6 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 font-bold text-white shadow-md shadow-cyan-950">
            S
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-tight text-slate-100">StrHide Studio</h1>
            <p className="text-[10px] text-slate-500 leading-none">Smart Lossless Data Hiding</p>
          </div>
        </div>

        {/* Global Toolbar / Language Switch */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setLang(lang === "zh" ? "en" : "zh")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white"
          >
            <Globe className="h-3.5 w-3.5 text-cyan-400" />
            <span>{lang === "zh" ? "中文" : "English"}</span>
          </button>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Navigation Sidebar */}
        <nav className="flex w-60 shrink-0 flex-col justify-between border-r border-slate-800/80 bg-slate-900/40 p-4">
          <div className="space-y-1.5">
            <div className="px-2 pb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              功能工作台
            </div>
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex w-full items-center gap-3 rounded-xl px-3.5 py-2.5 text-xs font-semibold transition-all ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-800/50 shadow-sm shadow-cyan-950/20"
                      : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                  }`}
                >
                  <Icon className={`h-4 w-4 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          <div className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-3 text-[11px] text-slate-500 space-y-1">
            <div className="flex items-center gap-1.5 text-slate-400 font-medium">
              <Sliders className="h-3 w-3 text-cyan-400" />
              <span>{i18nText.common.stageReady}</span>
            </div>
            <p>{i18nText.common.features}</p>
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
