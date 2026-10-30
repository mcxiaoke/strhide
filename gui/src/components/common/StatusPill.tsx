import React from "react";
import { Check, Loader2, MinusCircle, TriangleAlert } from "lucide-react";
import type { ItemStatus } from "../../lib/queue";
import { useT } from "../../hooks/useT";

const STYLES: Record<ItemStatus, string> = {
  idle: "bg-slate-800 text-slate-400",
  running: "bg-cyan-950 text-cyan-300 border border-cyan-800/60",
  ok: "bg-emerald-950 text-emerald-400 border border-emerald-800/60",
  skip: "bg-amber-950 text-amber-300 border border-amber-800/60",
  error: "bg-rose-950 text-rose-300 border border-rose-800/60",
};

export const StatusPill: React.FC<{ status: ItemStatus }> = ({ status }) => {
  const c = useT();
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${STYLES[status]}`}
    >
      {status === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
      {status === "ok" && <Check className="h-3 w-3" />}
      {status === "error" && <TriangleAlert className="h-3 w-3" />}
      {status === "skip" && <MinusCircle className="h-3 w-3" />}
      {c.common.status[status]}
    </span>
  );
};
