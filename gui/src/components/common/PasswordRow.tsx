import React from "react";
import { useT } from "../../hooks/useT";

interface PasswordRowProps {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  placeholder?: string;
  hint?: string | null;
  disabled?: boolean;
  masked?: boolean;
  extra?: React.ReactNode;
}

export const PasswordRow: React.FC<PasswordRowProps> = ({
  value,
  onChange,
  label,
  placeholder,
  hint,
  disabled,
  masked = true,
  extra,
}) => {
  const c = useT();
  return (
    <div className="flex items-center gap-3">
      <span className="w-[5.25rem] shrink-0 text-xs text-slate-400">{label ?? c.common.password}</span>
      <input
        type={masked ? "password" : "text"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
      />
      {hint && (
        <span className="shrink-0 text-[11px] text-amber-300">
          {c.common.hint}：{hint}
        </span>
      )}
      {extra && <span className="shrink-0">{extra}</span>}
    </div>
  );
};
