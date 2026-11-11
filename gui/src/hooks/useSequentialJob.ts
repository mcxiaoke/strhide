import { useState } from "react";

import { useTaskStore } from "../store/taskStore";

/**
 * One item of a sequential batch run.
 *
 * Views provide the item-specific work; the loop (task registration, queue
 * status, error routing, `finishTask`) is shared, so adding cancel/retry/
 * progress merging later means changing one place instead of four.
 */
export interface SequentialJobSpec<T> {
  /** Prefix for the per-item task id (`scan-<ts>-<i>`). */
  taskIdPrefix: string;
  /** Task-store status line shown while item `index` runs. */
  statusText: (index: number, total: number, item: T) => string;
  /** Queue status applied before the item starts (e.g. running + message). */
  markRunning: (item: T) => void;
  /** Do the work for one item; throw to report a failure for that item. */
  runOne: (item: T, taskId: string, index: number) => Promise<void>;
  /** Apply the failure of one item (message mapping differs per view). */
  onError: (item: T, error: unknown) => void;
  /** Optional reset once per run, before the first item. */
  onBegin?: () => void;
}

/**
 * Run `items` one after another, with the shared task/queue bookkeeping.
 *
 * `running` stays true for the whole run (including the gaps between items),
 * matching what the "start" buttons previously tracked by hand.
 */
export function useSequentialJob() {
  const { startTask, finishTask } = useTaskStore();
  const [running, setRunning] = useState(false);

  const run = async <T,>(items: T[], spec: SequentialJobSpec<T>): Promise<void> => {
    spec.onBegin?.();
    setRunning(true);
    try {
      for (let i = 0; i < items.length; i += 1) {
        const item = items[i];
        const taskId = `${spec.taskIdPrefix}-${Date.now()}-${i}`;
        startTask(taskId, spec.statusText(i, items.length, item));
        spec.markRunning(item);
        try {
          await spec.runOne(item, taskId, i);
        } catch (error) {
          spec.onError(item, error);
        }
      }
    } finally {
      finishTask();
      setRunning(false);
    }
  };

  return { running, run };
}
