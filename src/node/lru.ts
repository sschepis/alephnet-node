/**
 * Node Layer — LRU Map
 *
 * A minimal least-recently-used map used to bound the composition root's
 * per-caller caches (wallet views, staking services, tier memo entries).
 *
 * Every unbounded per-identity map in the node layer is a memory-exhaustion
 * vector: an attacker who authenticates with many fingerprints could grow
 * the table without limit. The capacity caps that growth; the oldest entry
 * is evicted once the cap is exceeded.
 */

export class LruMap<K, V> {
  private readonly map = new Map<K, V>();

  constructor(public readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      throw new Error(`LruMap capacity must be a positive integer, received ${String(capacity)}`);
    }
  }

  get(key: K): V | undefined {
    const value = this.map.get(key);
    if (value !== undefined) {
      // Refresh recency: get() moves the entry to the most-recently-used end.
      this.map.delete(key);
      this.map.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    this.map.delete(key);
    this.map.set(key, value);
    this.evict();
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  get size(): number {
    return this.map.size;
  }

  private evict(): void {
    while (this.map.size > this.capacity) {
      const oldest = this.map.keys().next().value as K | undefined;
      if (oldest === undefined) return;
      this.map.delete(oldest);
    }
  }
}
