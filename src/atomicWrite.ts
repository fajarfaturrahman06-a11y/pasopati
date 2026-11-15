import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Rename atomik dengan retry terbatas khusus Windows.
 *
 * Windows melempar EPERM/EACCES/EBUSY secara sementara ketika antivirus,
 * indexer, atau handle pembaca lain masih memegang file tujuan/temp walau
 * sepersekian detik. Error lain (ENOENT, EXDEV, ENOSPC, ...) bersifat
 * permanen dan langsung dilempar tanpa retry.
 *
 * File tujuan TIDAK pernah dihapus sebelum rename; tidak ada fallback
 * copy+delete agar atomicity tetap terjaga.
 */
const RETRYABLE_RENAME_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

export interface RenameRetryOptions {
  attempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  deadlineMs?: number;
}

const DEFAULT_OPTIONS: Required<RenameRetryOptions> = {
  attempts: 6,
  baseDelayMs: 25,
  maxDelayMs: 400,
  deadlineMs: 2_000
};

const sleepBuffer = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  if (ms > 0) Atomics.wait(sleepBuffer, 0, 0, ms);
}

function isRetryableRenameError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return Boolean(code && RETRYABLE_RENAME_CODES.has(code));
}

/** Retry rename sementara; melempar error asli setelah batas tercapai. */
export function renameWithRetrySync(source: string, target: string, options: RenameRetryOptions = {}): void {
  const settings = { ...DEFAULT_OPTIONS, ...options };
  const startedAt = Date.now();
  for (let attempt = 1; ; attempt += 1) {
    try {
      fs.renameSync(source, target);
      return;
    } catch (error) {
      const retryable = isRetryableRenameError(error);
      const outOfAttempts = attempt >= settings.attempts;
      const outOfTime = Date.now() - startedAt >= settings.deadlineMs;
      if (!retryable || outOfAttempts || outOfTime) throw error;
      const delay = Math.min(settings.baseDelayMs * 2 ** (attempt - 1), settings.maxDelayMs);
      sleepSync(Math.min(delay, Math.max(0, settings.deadlineMs - (Date.now() - startedAt))));
    }
  }
}

/** fsync direktori bila filesystem mendukung; Windows umumnya melempar, jadi diabaikan. */
export function fsyncDirectorySync(dir: string): void {
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(dir, 'r');
    fs.fsyncSync(descriptor);
  } catch {
    /* metadata direktori tidak selalu bisa di-fsync */
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* abaikan */ }
    }
  }
}

/**
 * Tulis JSON secara atomik: temp unik -> fsync file -> close -> rename retry ->
 * fsync direktori. Temp dibersihkan bila seluruh percobaan gagal; file tujuan
 * lama tidak disentuh sampai rename berhasil.
 */
export function writeJsonAtomicSync(filePath: string, value: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(tempPath, 'wx', 0o600);
    try {
      fs.writeFileSync(descriptor, JSON.stringify(value, null, 2), { encoding: 'utf-8' });
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
      descriptor = undefined;
    }
    renameWithRetrySync(tempPath, filePath);
    fsyncDirectorySync(dir);
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* abaikan */ }
    }
    try { fs.rmSync(tempPath, { force: true }); } catch { /* preserve original error */ }
    throw error;
  }
}
