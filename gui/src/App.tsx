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
import { CarrierDropzone } from "./components/stage/CarrierDropzone";
import { CarrierSummary } from "./components/stage/CarrierSummary";
import { ProgressBarOverlay } from "./components/common/ProgressBarOverlay";
import { InspectExtractView } from "./views/InspectExtractView";
import { HideEmbedView } from "./views/HideEmbedView";

export const App: React.FC = () => {
  const { activeTab, setActiveTab, carrierPath, loadCapabilities } = useWorkspaceStore();
  const { lang, setLang } = useSettingsStore();

  useEffect(() => {
    loadCapabilities();
  }, [loadCapabilities]);

  const tabs = [
    { id: "inspect" as const, label: "检视与智能提取", icon: Search },
    { id: "hide" as const, label: "隐藏与自适应嵌入", icon: Shield },
    { id: "verify" as const, label: "三级校验与无损还原", icon: CheckCircle },
    { id: "forensics" as const, label: "反隐写取证与批处理", icon: Microscope },
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
              <span>内核就绪 (Stage A–E)</span>
            </div>
            <p>零拷贝原位补丁 · 100% 字节无损还原</p>
          </div>
        </nav>

        {/* Content Workspace Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Global Carrier Stage */}
          {!carrierPath ? <CarrierDropzone /> : <CarrierSummary />}

          {/* Active View Container */}
          {activeTab === "inspect" && <InspectExtractView />}
          {activeTab === "hide" && <HideEmbedView />}
          {activeTab === "verify" && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-8 text-center text-slate-400">
              <CheckCircle className="h-10 w-10 text-emerald-500/50 mx-auto mb-3" />
              <h3 className="text-base font-semibold text-slate-200">工作台 3: 三级校验与无损还原</h3>
              <p className="mt-1 text-xs text-slate-500">
                L1/L2/L3 步进式完整性校验与 100% 原始字节级无损剥离还原
              </p>
            </div>
          )}
          {activeTab === "forensics" && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-8 text-center text-slate-400">
              <Microscope className="h-10 w-10 text-purple-500/50 mx-auto mb-3" />
              <h3 className="text-base font-semibold text-slate-200">工作台 4: 反隐写取证与批处理中心</h3>
              <p className="mt-1 text-xs text-slate-500">
                0..100 黑盒反隐写风险评分盘、检测器指标矩阵与多文件批量处理队列
              </p>
            </div>
          )}
        </main>
      </div>

      {/* Floating Progress Bar Overlay */}
      <ProgressBarOverlay />
    </div>
  );
};
export default App;
