import { performance } from "node:perf_hooks";

import { describe, expect, it } from "vitest";

import { InFlightWork } from "../../database/in-flight-work.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("InFlightWork", () => {
  it("should count work until it settles, resolved or rejected, and hand it back unchanged", async () => {
    const work = new InFlightWork();
    const ok = deferred<string>();
    const failed = deferred<string>();

    const tracked = work.track(ok.promise);
    work.track(failed.promise).catch(() => undefined);
    expect(work.size).toBe(2);

    ok.resolve("done");
    expect(await tracked).toBe("done");
    failed.reject(new Error("refused"));
    await expect(failed.promise).rejects.toThrow("refused");
    await Promise.resolve();
    expect(work.size).toBe(0);
  });

  it("should resolve drained once everything has settled, work added meanwhile included", async () => {
    const work = new InFlightWork();
    const first = deferred<undefined>();
    const second = deferred<undefined>();
    void work.track(first.promise);

    const drained = work.drained(5000);
    void work.track(second.promise);
    first.resolve(undefined);
    await Promise.resolve();
    expect(work.size).toBe(1);
    second.resolve(undefined);

    expect(await drained).toBe(0);
  });

  it("should give up at maxMs and report what is still pending", async () => {
    const work = new InFlightWork();
    const never = deferred<undefined>();
    void work.track(never.promise);

    const started = performance.now();
    expect(await work.drained(50)).toBe(1);
    expect(performance.now() - started).toBeGreaterThanOrEqual(45);
    expect(performance.now() - started).toBeLessThan(1000);
    never.resolve(undefined);
  });

  it("should resolve drained at once with nothing tracked", async () => {
    expect(await new InFlightWork().drained(5000)).toBe(0);
  });
});
