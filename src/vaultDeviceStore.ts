/**
 * Petit magasin IndexedDB pour objets `CryptoKey` non extractibles (clone structuré).
 * Si IndexedDB est indisponible (navigation privée stricte, tests jsdom), les valeurs
 * restent en mémoire pour la durée de la page.
 */

const DB_NAME = 'lexpol_studio_vault';
const STORE = 'keys';

const memoryFallback = new Map<string, unknown>();
let dbPromise: Promise<IDBDatabase | null> | null = null;

function openDb(): Promise<IDBDatabase | null> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      if (typeof indexedDB === 'undefined') return resolve(null);
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
      req.onblocked = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return dbPromise;
}

function run<T>(
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest
): Promise<T | undefined> {
  return openDb().then(
    (db) =>
      new Promise<T | undefined>((resolve) => {
        if (!db) return resolve(undefined);
        try {
          const tx = db.transaction(STORE, mode);
          const req = op(tx.objectStore(STORE));
          req.onsuccess = () => resolve(req.result as T);
          req.onerror = () => resolve(undefined);
        } catch {
          resolve(undefined);
        }
      })
  );
}

export async function deviceStoreGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  if (!db) return memoryFallback.get(key) as T | undefined;
  return run<T>('readonly', (s) => s.get(key));
}

export async function deviceStoreSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  if (!db) {
    memoryFallback.set(key, value);
    return;
  }
  await run('readwrite', (s) => s.put(value, key));
}

export async function deviceStoreDelete(key: string): Promise<void> {
  memoryFallback.delete(key);
  const db = await openDb();
  if (db) await run('readwrite', (s) => s.delete(key));
}

/** Supprime toutes les entrées dont la clé commence par `prefix`. */
export async function deviceStoreDeletePrefix(prefix: string): Promise<void> {
  for (const k of Array.from(memoryFallback.keys()))
    if (k.startsWith(prefix)) memoryFallback.delete(k);
  const db = await openDb();
  if (!db) return;
  const keys = (await run<IDBValidKey[]>('readonly', (s) => s.getAllKeys())) || [];
  await Promise.all(
    keys
      .filter((k): k is string => typeof k === 'string' && k.startsWith(prefix))
      .map((k) => run('readwrite', (s) => s.delete(k)))
  );
}
