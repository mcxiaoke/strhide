import { useCallback, useState } from "react";

const KEY = "strhide_output_dir";

/** 记住上次选择的输出目录，下次打开直接沿用 */
export function useOutputDir(): [string, (value: string) => void] {
  const [dir, setDir] = useState<string>(() => {
    try {
      return localStorage.getItem(KEY) ?? "";
    } catch {
      return "";
    }
  });

  const update = useCallback((value: string) => {
    setDir(value);
    try {
      if (value) {
        localStorage.setItem(KEY, value);
      } else {
        localStorage.removeItem(KEY);
      }
    } catch {
      /* localStorage 不可用时只影响记忆功能 */
    }
  }, []);

  return [dir, update];
}
