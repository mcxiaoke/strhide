import { useSettingsStore } from "../store/settingsStore";
import { t, type Dict } from "../lib/i18n";

/** 当前语言的文案表 */
export function useT(): Dict {
  const lang = useSettingsStore((state) => state.lang);
  return t(lang);
}
