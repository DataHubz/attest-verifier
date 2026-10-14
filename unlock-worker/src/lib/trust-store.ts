/**
 * This device's trust state, in IndexedDB: what the pages and the service worker both read (a service worker can't
 * read localStorage). It holds:
 * - the key directory state (src/lib/key-directory-client.ts): pins, every key accepted for each address, this
 *   owner's own keys, the audit's progress, alarms, and the newest directory root checked;
 * - the device that unlocks documents for new signers (src/lib/unlock/device.ts): its own non-extractable keys (stored
 *   as CryptoKey objects, never exported), the account signing key it pinned and the newest device list it saw.
 *
 * DOM-free: the same code runs in a page and in the service worker. Every read-modify-write runs in one IndexedDB
 * transaction, so two tabs and the worker never lose each other's writes. Where IndexedDB isn't available (a test under
 * Node), the state lives in memory.
 */

const DB_NAME = "attest-trust";
const DB_VERSION = 1;
const STORE = "kv";

export interface TrustBackend {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
  /** Read, change and write one key in a single transaction. `fn` must not await. */
  update<T>(key: string, fn: (current: T | undefined) => T | undefined): Promise<T | undefined>;
  keys(prefix: string): Promise<string[]>;
}

function memoryBackend(): TrustBackend {
  const m = new Map<string, unknown>();
  return {
    async get<T>(key: string) {
      return m.get(key) as T | undefined;
    },
    async set(key, value) {
      m.set(key, value);
    },
    async del(key) {
      m.delete(key);
    },
    async update<T>(key: string, fn: (current: T | undefined) => T | undefined) {
      const next = fn(m.get(key) as T | undefined);
      if (next === undefined) m.delete(key);
      else m.set(key, next);
      return next;
    },
    async keys(prefix) {
      return [...m.keys()].filter((k) => k.startsWith(prefix));
    },
  };
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function idbBackend(idb: IDBFactory): TrustBackend {
  let dbp: Promise<IDBDatabase> | null = null;
  const db = () =>
    (dbp ??= new Promise<IDBDatabase>((resolve, reject) => {
      const open = idb.open(DB_NAME, DB_VERSION);
      open.onupgradeneeded = () => {
        if (!open.result.objectStoreNames.contains(STORE)) open.result.createObjectStore(STORE);
      };
      open.onsuccess = () => {
        const d = open.result;
        // Another context upgrading the database: let it, and reopen next time.
        d.onversionchange = () => {
          d.close();
          dbp = null;
        };
        resolve(d);
      };
      open.onerror = () => {
        dbp = null;
        reject(open.error);
      };
      open.onblocked = () => reject(new Error("The trust store is blocked by another tab."));
    }));
  const tx = async (mode: IDBTransactionMode) => (await db()).transaction(STORE, mode);
  const done = (t: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
      t.oncomplete = () => resolve();
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error ?? new Error("aborted"));
    });
  return {
    async get<T>(key: string) {
      return (await req((await tx("readonly")).objectStore(STORE).get(key))) as T | undefined;
    },
    async set(key, value) {
      const t = await tx("readwrite");
      t.objectStore(STORE).put(value, key);
      await done(t);
    },
    async del(key) {
      const t = await tx("readwrite");
      t.objectStore(STORE).delete(key);
      await done(t);
    },
    async update<T>(key: string, fn: (current: T | undefined) => T | undefined) {
      const t = await tx("readwrite");
      const s = t.objectStore(STORE);
      let next: T | undefined;
      const r = s.get(key);
      r.onsuccess = () => {
        next = fn(r.result as T | undefined);
        if (next === undefined) s.delete(key);
        else s.put(next, key);
      };
      await done(t);
      return next;
    },
    async keys(prefix) {
      const all = (await req((await tx("readonly")).objectStore(STORE).getAllKeys())) as IDBValidKey[];
      return all.map(String).filter((k) => k.startsWith(prefix));
    },
  };
}

let backend: TrustBackend | null = null;
let migrated: Promise<void> | null = null;

/** The trust store of this browser profile (shared by its pages and its service worker). */
export function trustStore(): TrustBackend {
  if (!backend) {
    const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    backend = idb ? idbBackend(idb) : memoryBackend();
  }
  return backend;
}

/** Tests: start from an empty in-memory store (or the one given). */
export function setTrustStoreForTests(b: TrustBackend | null = memoryBackend()) {
  backend = b;
  migrated = null;
}

/** Keys before the trust state moved to IndexedDB (localStorage, pages only). */
const LEGACY_PINS = "attest.keyPins.v1";
const LEGACY_AUDIT = "attest.keyAudit.v1.";
const LEGACY_ALARM = "attest.keyAlarm.v1.";

/**
 * Once per browser profile, in a page: bring the trust state kept in localStorage before this change into the store.
 * What the store already holds wins (a worker or another tab may have written since), pins are merged, and the
 * localStorage entries are left as they were (an older build still running in another tab keeps reading them).
 */
export function migrateLegacyTrustState(): Promise<void> {
  if (migrated) return migrated;
  migrated = (async () => {
    const ls = (globalThis as { localStorage?: Storage }).localStorage;
    if (!ls) return;
    const store = trustStore();
    if (await store.get<boolean>("migrated.v1")) return;
    const read = (k: string) => {
      try {
        return JSON.parse(ls.getItem(k) ?? "null");
      } catch {
        return null;
      }
    };
    const pins = read(LEGACY_PINS) as Record<string, string> | null;
    if (pins && typeof pins === "object") {
      await store.update<Record<string, string>>("pins", (cur) => ({ ...pins, ...(cur ?? {}) }));
      await store.update<Record<string, string[]>>("seen", (cur) => {
        const out = { ...(cur ?? {}) };
        for (const [h, fp] of Object.entries(pins)) if (!out[h]?.includes(fp)) out[h] = [...(out[h] ?? []), fp];
        return out;
      });
    }
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (!k) continue;
      if (k.startsWith(LEGACY_AUDIT)) {
        const v = read(k);
        if (v) await store.update(`audit:${k.slice(LEGACY_AUDIT.length)}`, (cur) => cur ?? v);
      } else if (k.startsWith(LEGACY_ALARM)) {
        const v = read(k);
        if (v) await store.update(`alarm:${k.slice(LEGACY_ALARM.length)}`, (cur) => cur ?? v);
      }
    }
    await store.set("migrated.v1", true);
  })().catch(() => {
    migrated = null;
  });
  return migrated;
}
