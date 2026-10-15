/**
 * One holder at a time in a browser, for work that must not interleave with the same work elsewhere in that browser
 * (publishing the account's signed device list: src/lib/unlock/enrol.ts). The Web Locks API's lock is shared by the
 * browser's tabs and its service worker. Where a browser has no Web Locks, or a context can't take them, the work still
 * runs one at a time within this tab (or worker); across tabs, Attest's version check (a 409, then a retry) settles
 * which publish goes first. A wait for another holder is capped at `waitMs`: past it, the work runs anyway (a tab stuck
 * on a request mustn't hold up every other one), and the version check still keeps the list's versions in order.
 * DOM-free. Each call of browserLock is one context's lock: a page module calls it once, at load.
 */
export function browserLock(name: string, waitMs = 30_000): <T>(fn: () => Promise<T>) => Promise<T> {
  const here = contextQueue(waitMs);
  return async <T>(fn: () => Promise<T>): Promise<T> => {
    const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
    if (!locks || typeof locks.request !== "function") return here.run(fn);
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), waitMs);
    let started = false;
    try {
      return (await locks.request(name, { signal: ac.signal }, () => {
        started = true;
        clearTimeout(timer);
        return fn();
      })) as T;
    } catch (e) {
      // The work ran and failed: its error, as it is (it never runs twice).
      if (started) throw e;
    } finally {
      clearTimeout(timer);
    }
    // Not granted: waited past the cap, or this context can't take Web Locks.
    return here.run(fn);
  };
}

/**
 * One holder at a time within this tab or worker, in the order asked: what a browser without Web Locks still has. A wait
 * for the holder before is capped at `waitMs`, after which the work runs anyway. `busy` says whether anything holds the
 * queue or waits in it (a page's periodic unlock check skips then: src/lib/unlock/device.ts).
 */
export function contextQueue(waitMs = 30_000) {
  let last: Promise<void> = Promise.resolve();
  let holders = 0;
  return {
    busy: () => holders > 0,
    async run<T>(fn: () => Promise<T>): Promise<T> {
      const before = last;
      let done!: () => void;
      last = new Promise<void>((r) => (done = r));
      holders++;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([before, new Promise<void>((r) => (timer = setTimeout(r, waitMs)))]);
        clearTimeout(timer);
        return await fn();
      } finally {
        clearTimeout(timer);
        holders--;
        done();
      }
    },
  };
}
