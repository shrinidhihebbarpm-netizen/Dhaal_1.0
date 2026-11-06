import path from 'path';
import os from 'os';
import crypto from 'crypto';

// Generate deterministic or ephemeral runtime fallback keys for development/test
// when environment variables are not explicitly populated.
const FALLBACK_HEX_32 = crypto
  .createHash('sha256')
  .update(`dhaal-runtime-key-${os.hostname()}`)
  .digest('hex');

export function resolveEncryptionKeyHex(): string {
  const raw = process.env.DATA_ENCRYPTION_KEY?.trim();
  if (raw && raw !== 'your-64-hex-chars-32-bytes-here') {
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes (64 hex chars)');
    }
    return raw;
  }
  return FALLBACK_HEX_32;
}

export function resolveJwtSecret(): string {
  const raw = process.env.JWT_SECRET?.trim();
  if (raw && raw !== 'your-256-bit-hex-secret-here') {
    return raw;
  }
  return crypto
    .createHmac('sha256', FALLBACK_HEX_32)
    .update('dhaal-jwt-secret')
    .digest('hex');
}

export function resolveCsrfSecret(): string {
  const raw = process.env.CSRF_SECRET?.trim();
  if (raw && raw !== 'your-256-bit-hex-secret-here') {
    return raw;
  }
  return crypto
    .createHmac('sha256', FALLBACK_HEX_32)
    .update('dhaal-csrf-secret')
    .digest('hex');
}

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  gemini: {
    model: process.env.GEMINI_MODEL || 'gemini-3.5-flash',
    reasoningModel: process.env.GEMINI_REASONING_MODEL || 'gemini-3.5-flash',
    ocrModel: process.env.GEMINI_OCR_MODEL || 'gemini-3.5-flash-lite',
    timeoutMs: parseInt(process.env.GEMINI_TIMEOUT_MS || '5000', 10),
    mediaTimeoutMs: parseInt(process.env.GEMINI_MEDIA_TIMEOUT_MS || '20000', 10),
  },
  rateLimit: {
    default: { capacity: 20, refillPerMinute: 20 },
    endpoints: {
      '/api/analyze-media': { capacity: 10, refillPerMinute: 10 },
      '/api/export': { capacity: 5, refillPerMinute: 5 },
      '/api/telegram/webhook': { capacity: 30, refillPerMinute: 30 },
      '/api/telegram/sync': { capacity: 20, refillPerMinute: 20 },
      '/api/settings': { capacity: 30, refillPerMinute: 30 },
      '/api/family': { capacity: 30, refillPerMinute: 30 },
      '/api/complaint-draft': { capacity: 30, refillPerMinute: 30 },
      '/api/complaint-drafts': { capacity: 30, refillPerMinute: 30 },
      '/api/unfreeze-cases': { capacity: 30, refillPerMinute: 30 },
      '/api/scam-reports': { capacity: 30, refillPerMinute: 30 },
      '/api/duress/check': { capacity: 10, refillPerMinute: 10 },
    } as Record<string, { capacity: number; refillPerMinute: number }>,
  },
  persistence: {
    dataDir: process.env.DHAAL_DATA_DIR || path.join(os.tmpdir(), 'dhaal-data'),
    get encryptionKey(): string {
      return resolveEncryptionKeyHex();
    },
  },
  telegram: {
    get webhookSecret(): string | undefined {
      return process.env.TELEGRAM_WEBHOOK_SECRET;
    },
    get botToken(): string | undefined {
      return process.env.TELEGRAM_BOT_TOKEN;
    },
    polling: {
      initialIntervalMs: 2500,
      maxBackoffMs: 60000,
      circuitBreakerThreshold: 10,
      circuitResetMs: 300000,
    },
  },
  security: {
    get jwtSecret(): string {
      return resolveJwtSecret();
    },
    get csrfSecret(): string {
      return resolveCsrfSecret();
    },
    get trustedProxy(): boolean {
      return process.env.TRUSTED_PROXY === 'true';
    },
    get exportToken(): string | undefined {
      return process.env.EXPORT_TOKEN;
    },
  },
  upload: {
    maxSizes: {
      image: 5 * 1024 * 1024,
      audio: 10 * 1024 * 1024,
      text: 1 * 1024 * 1024,
    } as Record<string, number>,
    allowedMimes: {
      image: ['image/png', 'image/jpeg', 'image/webp', 'image/gif'],
      audio: ['audio/mp3', 'audio/wav', 'audio/ogg', 'audio/webm', 'audio/mpeg'],
      text: ['text/plain', 'text/csv', 'application/json'],
    } as Record<string, string[]>,
    magicBytes: {
      'image/png': [0x89, 0x50, 0x4e, 0x47],
      'image/jpeg': [0xff, 0xd8, 0xff],
      'image/webp': [0x52, 0x49, 0x46, 0x46],
      'image/gif': [0x47, 0x49, 0x46, 0x38],
      'audio/mp3': [0xff, 0xfb],
      'audio/mpeg': [0xff, 0xfb],
      'audio/wav': [0x52, 0x49, 0x46, 0x46],
      'audio/ogg': [0x4f, 0x67, 0x67, 0x53],
    } as Record<string, number[]>,
  },
} as const;

export type Config = typeof config;
