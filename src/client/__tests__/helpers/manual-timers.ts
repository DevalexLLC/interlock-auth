import type { Timers } from "../../types.js";

export class ManualTimers implements Timers {
  private time = 0;
  private sequence = 0;
  private tasks = new Map<number, { at: number; callback: () => void }>();
  now = () => this.time;
  setTimeout = (callback: () => void, ms: number) => {
    this.sequence += 1;
    this.tasks.set(this.sequence, { at: this.time + ms, callback });
    return this.sequence as unknown as ReturnType<typeof setTimeout>;
  };
  clearTimeout = (id: ReturnType<typeof setTimeout>) => {
    this.tasks.delete(id as unknown as number);
  };
  pending = () => this.tasks.size;
  advance(ms: number) {
    const until = this.time + ms;
    let next = [...this.tasks]
      .filter(([, task]) => task.at <= until)
      .toSorted((a, b) => a[1].at - b[1].at)[0];
    while (next) {
      this.time = next[1].at;
      this.tasks.delete(next[0]);
      next[1].callback();
      next = [...this.tasks]
        .filter(([, task]) => task.at <= until)
        .toSorted((a, b) => a[1].at - b[1].at)[0];
    }
    this.time = until;
  }
}
