import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";

export const openCarrier = async (path: string) => {
  try {
    await openPath(path);
  } catch (err) {
    console.error("Failed to open path:", err);
  }
};

export const revealCarrier = async (path: string) => {
  try {
    await revealItemInDir(path);
  } catch (err) {
    console.error("Failed to reveal item in dir:", err);
  }
};
