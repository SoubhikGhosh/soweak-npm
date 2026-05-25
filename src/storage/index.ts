/**
 * Pluggable storage backends for budgets and rate limits.
 *
 * - `CounterStore` — atomic counter for token/cost budgets.
 * - `WindowStore` — sliding-window event store for rate limits.
 *
 * Built-in: in-memory (thread-safe via single-threaded JS), and a Node-only
 * file-backed JSON store that persists across restarts (no native deps).
 */

export abstract class CounterStore {
  abstract add(key: string, delta: number, limit?: number | null): number | null;
  abstract get(key: string): number;
  abstract reset(key?: string | null): void;
  close(): void {
    // default no-op
  }
}

export class InMemoryCounterStore extends CounterStore {
  private values = new Map<string, number>();

  add(key: string, delta: number, limit: number | null = null): number | null {
    const next = (this.values.get(key) ?? 0) + delta;
    if (limit !== null && next > limit) return null;
    this.values.set(key, next);
    return next;
  }

  get(key: string): number {
    return this.values.get(key) ?? 0;
  }

  reset(key: string | null = null): void {
    if (key === null) this.values.clear();
    else this.values.delete(key);
  }
}

export abstract class WindowStore {
  abstract record(key: string, timestamp: number, windowSeconds: number): number;
  abstract count(key: string, now: number, windowSeconds: number): number;
  abstract reset(key?: string | null): void;
  close(): void {
    // default no-op
  }
}

export class InMemoryWindowStore extends WindowStore {
  private buckets = new Map<string, number[]>();

  record(key: string, timestamp: number, windowSeconds: number): number {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = [];
      this.buckets.set(key, bucket);
    }
    const cutoff = timestamp - windowSeconds;
    let i = 0;
    while (i < bucket.length && bucket[i] <= cutoff) i++;
    if (i > 0) bucket.splice(0, i);
    bucket.push(timestamp);
    return bucket.length;
  }

  count(key: string, now: number, windowSeconds: number): number {
    const bucket = this.buckets.get(key);
    if (!bucket) return 0;
    const cutoff = now - windowSeconds;
    let count = 0;
    for (let i = bucket.length - 1; i >= 0; i--) {
      if (bucket[i] > cutoff) count++;
      else break;
    }
    return count;
  }

  reset(key: string | null = null): void {
    if (key === null) this.buckets.clear();
    else this.buckets.delete(key);
  }
}

// File-backed stores live in `soweak/node` — they need `node:fs` and won't
// work in browsers. Subclass CounterStore / WindowStore against your own
// backend (Redis, Postgres, DynamoDB) for multi-replica deployments.
