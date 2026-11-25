/** Picks the storage backend from config: "sqlite" (local/tests) or "firestore" (production). */
export async function createStore(config) {
  if (config.store === 'firestore') {
    const { firestoreStore } = await import('./firestore.js');
    return firestoreStore(config.firebase);
  }
  const { sqliteStore } = await import('./sqlite.js');
  return sqliteStore(config.dbPath);
}
