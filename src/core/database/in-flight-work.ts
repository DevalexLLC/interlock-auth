import { performance } from "node:perf_hooks";
import { setTimeout as sleep } from "node:timers/promises";

/**
 * Work the pool must outlive. Closing the HTTP server waits for connections,
 * not for the work a request started: a request whose client has left is
 * finished from the server's point of view while its refresh is still at
 * Keycloak, and the rotated tokens it brings back must still be stored. The
 * refresher counts each run in here, and the host's shutdown awaits
 * `drained` before it ends the pool (the README's database host contract).
 * Work the host drains earlier, such as Interlock's WebSocket handshakes, is
 * counted but already settled by then.
 */
export class InFlightWork {
  private readonly pending = new Set<Promise<unknown>>();

  /** How many tracked promises have not settled. */
  get size() {
    return this.pending.size;
  }

  /** Counts `work` until it settles, either way; settles as it does. */
  async track<T>(work: Promise<T>): Promise<T> {
    this.pending.add(work);
    const settled = () => {
      this.pending.delete(work);
    };
    work.then(settled, settled);
    return work;
  }

  /**
   * Resolves once every tracked promise has settled, work tracked meanwhile
   * included, or after `maxMs`. Returns how many are still pending, so the
   * caller can say so before it ends the pool under them.
   */
  async drained(maxMs: number): Promise<number> {
    const deadline = performance.now() + maxMs;
    while (this.pending.size > 0) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) {
        break;
      }
      await Promise.race([Promise.allSettled(this.pending), sleep(remaining)]);
    }
    return this.pending.size;
  }
}
