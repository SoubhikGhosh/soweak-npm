/**
 * Node-only helpers: filesystem-backed audit log, counter / window stores,
 * and `loadPolicy(path)`. Import via `soweak/node`.
 *
 * These use `node:fs` and will throw at module-load time in browsers; keep
 * them out of bundles intended for a browser target.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { AuditEvent, AuditLog, auditEventToJson } from "../core/audit.js";
import { Policy } from "../core/policy.js";
import { CounterStore, WindowStore } from "../storage/index.js";
import { buildPolicy, DetectorFactory, EnforcerFactory } from "../config/index.js";
import { SoweakError } from "../core/errors.js";

// ---------------------------------------------------------------------------
// JsonLinesAuditLog
// ---------------------------------------------------------------------------

/**
 * Append one JSON object per line to a file. Holds the file descriptor open
 * for the log's lifetime. Always call `close()` to release it cleanly.
 */
export class JsonLinesAuditLog extends AuditLog {
  private fd: number | null = null;
  readonly path: string;

  constructor(filePath: string) {
    super();
    this.path = filePath;
    const dir = path.dirname(filePath);
    if (dir && dir !== ".") {
      try {
        fs.mkdirSync(dir, { recursive: true });
      } catch {
        // open() below will surface real errors
      }
    }
    this.fd = fs.openSync(filePath, "a");
  }

  override record(event: AuditEvent): void {
    if (this.fd === null) {
      throw new SoweakError("JsonLinesAuditLog is closed");
    }
    fs.writeSync(this.fd, auditEventToJson(event) + "\n");
  }

  override close(): void {
    if (this.fd !== null) {
      try {
        fs.fsyncSync(this.fd);
      } catch {
        // best-effort
      }
      fs.closeSync(this.fd);
      this.fd = null;
    }
  }
}

// ---------------------------------------------------------------------------
// File-backed CounterStore / WindowStore
//
// Best-effort: rewrites the file synchronously on every change. Single-host
// only — multi-host needs Redis or similar; subclass CounterStore /
// WindowStore.
// ---------------------------------------------------------------------------

function safeReadJson<T>(p: string): T | null {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8")) as T;
  } catch {
    return null;
  }
}

function atomicWriteJson(p: string, data: unknown): void {
  const dir = path.dirname(p);
  if (dir && dir !== ".") {
    fs.mkdirSync(dir, { recursive: true });
  }
  const tmp = `${p}.tmp.${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, p);
}

export class FileCounterStore extends CounterStore {
  readonly path: string;
  private values: Map<string, number>;

  constructor(filePath: string) {
    super();
    this.path = filePath;
    this.values = new Map();
    const parsed = safeReadJson<Record<string, number>>(filePath);
    if (parsed) {
      for (const [k, v] of Object.entries(parsed)) {
        this.values.set(k, Number(v));
      }
    }
  }

  private flush(): void {
    const obj: Record<string, number> = {};
    for (const [k, v] of this.values) obj[k] = v;
    atomicWriteJson(this.path, obj);
  }

  add(key: string, delta: number, limit: number | null = null): number | null {
    const next = (this.values.get(key) ?? 0) + delta;
    if (limit !== null && next > limit) return null;
    this.values.set(key, next);
    this.flush();
    return next;
  }

  get(key: string): number {
    return this.values.get(key) ?? 0;
  }

  reset(key: string | null = null): void {
    if (key === null) this.values.clear();
    else this.values.delete(key);
    this.flush();
  }
}

export class FileWindowStore extends WindowStore {
  readonly path: string;
  private buckets: Map<string, number[]>;

  constructor(filePath: string) {
    super();
    this.path = filePath;
    this.buckets = new Map();
    const parsed = safeReadJson<Record<string, number[]>>(filePath);
    if (parsed) {
      for (const [k, v] of Object.entries(parsed)) {
        if (Array.isArray(v)) this.buckets.set(k, v.map(Number));
      }
    }
  }

  private flush(): void {
    const obj: Record<string, number[]> = {};
    for (const [k, v] of this.buckets) obj[k] = v;
    atomicWriteJson(this.path, obj);
  }

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
    this.flush();
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
    this.flush();
  }
}

// ---------------------------------------------------------------------------
// loadPolicy(filePath) — JSON policy file
// ---------------------------------------------------------------------------

/**
 * Load a Policy from a JSON file. For YAML, parse with `js-yaml`/`yaml`
 * yourself and pass the result to `buildPolicy` from the main package.
 */
export function loadPolicy(
  filePath: string,
  options: {
    detectorRegistry?: Record<string, DetectorFactory>;
    enforcerRegistry?: Record<string, EnforcerFactory>;
  } = {},
): Policy {
  const text = fs.readFileSync(filePath, "utf8");
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new SoweakError(`failed to parse policy JSON at ${filePath}: ${(e as Error).message}`);
  }
  if (!data || typeof data !== "object") {
    throw new SoweakError("policy file root must be an object");
  }
  return buildPolicy(data as Record<string, unknown>, options);
}
