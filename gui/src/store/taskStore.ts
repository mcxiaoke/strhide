import { create } from "zustand";
import type { ProgressEvent } from "../types/strhide";
import { cancelTask } from "../api/commands";

interface TaskState {
  currentTaskId: string | null;
  progress: ProgressEvent | null;
  isRunning: boolean;
  statusText: string;

  startTask: (taskId: string, initialStatus?: string) => void;
  updateProgress: (ev: ProgressEvent) => void;
  finishTask: () => void;
  cancelActiveTask: () => Promise<void>;
}

export const useTaskStore = create<TaskState>((set, get) => ({
  currentTaskId: null,
  progress: null,
  isRunning: false,
  statusText: "",

  startTask: (taskId, initialStatus = "") => {
    set({
      currentTaskId: taskId,
      progress: null,
      isRunning: true,
      statusText: initialStatus,
    });
  },

  updateProgress: (ev) => {
    // 只保存进度事件，状态文案由调用方按页签给出（面向普通用户，不暴露内部阶段名）
    set({ progress: ev });
  },

  finishTask: () => {
    set({
      currentTaskId: null,
      progress: null,
      isRunning: false,
      statusText: "",
    });
  },

  cancelActiveTask: async () => {
    const { currentTaskId } = get();
    if (currentTaskId) {
      try {
        await cancelTask(currentTaskId);
      } catch (err) {
        console.error("Cancel task error:", err);
      }
    }
  },
}));
