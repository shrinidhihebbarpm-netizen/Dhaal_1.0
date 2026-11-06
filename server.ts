import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import { config } from './src/config';
import {
  analyzeScamPayloadWithAI,
  sanitizeUntrustedEvidence,
  ScamAnalysisResult,
  checkDuressTrigger,
} from './src/utils/scamEngine';
import {
  initPersistenceStore,
  getDataDir,
  readJsonFile,
  updateJsonFileAtomically,
  getDefaultSettings,
  getDefaultComplaintDrafts,
  getDefaultUnfreezeCases,
  getDefaultScamReports,
  toPublicSettings,
  buildRedactedExportBundle,
  recordAnalysisToScamReports,
  upsertNodesWithConnectionsInMemory,
  createTokenBucketRateLimiter,
  encrypt,
  decryptIfNeeded,
  encryptIfNeeded,
  PersistedSettings,
  PersistedComplaintDrafts,
  PersistedUnfreezeCase,
  PersistedScamReports,
  PersistedTelegramMessage,
} from './src/utils/persistence';
import { FamilyMember } from './src/utils/seedData';

dotenv.config();

const PORT = config.port;

// ============================================================================
// C-01 & C-06 — JWT Authentication & CSRF Protection
// ============================================================================
export interface AuthUser {
  id: string;
  email?: string;
  role: 'user' | 'admin';
}

export interface AuthRequest extends Request {
  user?: AuthUser;
  requestId?: string;
}

export const csrfTokens = new Map<string, string>();

export function issueCsrfToken(userId: string): string {
  const nonce = crypto.randomBytes(16).toString('hex');
  const sig = crypto
    .createHmac('sha256', config.security.csrfSecret)
    .update(`${userId}:${nonce}`)
    .digest('hex')
    .slice(0, 32);
  const token = `${nonce}.${sig}`;
  csrfTokens.set(userId, token);
  const timer = setTimeout(() => {
    if (csrfTokens.get(userId) === token) {
      csrfTokens.delete(userId);
    }
  }, 3600000);
  if (typeof timer.unref === 'function') timer.unref();
  return token;
}

export function verifyCsrfToken(userId: string, token?: string): boolean {
  if (!token || typeof token !== 'string') return false;
  const expected = csrfTokens.get(userId);
  if (expected && expected === token) return true;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, sig] = parts;
  if (!nonce || !sig) return false;
  const expectedSig = crypto
    .createHmac('sha256', config.security.csrfSecret)
    .update(`${userId}:${nonce}`)
    .digest('hex')
    .slice(0, 32);
  return sig === expectedSig;
}

export function issueAuthSession(
  userId = 'dhaal-operator',
  role: 'user' | 'admin' = 'user',
  email = 'operator@dhaal.local'
): { token: string; csrfToken: string; user: AuthUser } {
  const user: AuthUser = { id: userId, email, role };
  const token = jwt.sign(user, config.security.jwtSecret, { expiresIn: '24h' });
  const csrfToken = issueCsrfToken(userId);
  return { token, csrfToken, user };
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ ok: false, error: 'Authentication required' });
    return;
  }
  try {
    const decoded = jwt.verify(
      authHeader.slice(7),
      config.security.jwtSecret
    ) as AuthUser;
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}

export function csrfProtection(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }
  const token = req.headers['x-csrf-token'] as string | undefined;
  const sessionId = req.user?.id || req.ip || 'unknown';
  if (!verifyCsrfToken(sessionId, token)) {
    res.status(403).json({ ok: false, error: 'Invalid CSRF token' });
    return;
  }
  next();
}

// ============================================================================
// H-08 & M-11 — Standardized Error Handler with Request ID Correlation
// ============================================================================
export function handleApiError(
  err: unknown,
  context: string,
  req: AuthRequest,
  res: Response
): void {
  const requestId = req.requestId || 'unknown';
  if (err instanceof Error) {
    console.error(`[${context}] Request ${requestId}: ${err.message}`, {
      stack: err.stack,
      requestId,
    });
  } else {
    console.error(`[${context}] Request ${requestId}:`, err);
  }
  res.status(500).json({
    ok: false,
    error: 'An internal error occurred. Please try again.',
  });
}

// ============================================================================
// C-02, C-03, H-05, L-04 — Secret Accessors & Fail-Closed Webhook Secret
// ============================================================================
function getGeminiApiKey(): string | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (
    !apiKey ||
    apiKey === 'MY_GEMINI_API_KEY' ||
    apiKey === 'your-gemini-api-key' ||
    apiKey.trim() === ''
  ) {
    return null;
  }
  return apiKey.trim();
}

let cachedEncryptedBotToken: string | null = null;

export function getTelegramToken(settings?: PersistedSettings): string | null {
  if (settings?.telegramBotToken && settings.telegramBotToken.trim()) {
    const decrypted = decryptIfNeeded(settings.telegramBotToken.trim());
    if (decrypted) return decrypted;
  }
  const raw = process.env.TELEGRAM_BOT_TOKEN;
  if (
    !raw ||
    raw.trim() === '' ||
    raw === 'YOUR_TELEGRAM_BOT_TOKEN' ||
    raw === 'your-bot-token'
  ) {
    return null;
  }
  if (!cachedEncryptedBotToken) {
    cachedEncryptedBotToken = encryptIfNeeded(raw.trim());
  }
  return decryptIfNeeded(cachedEncryptedBotToken);
}

function getExportToken(): string | null {
  const raw = process.env.EXPORT_TOKEN;
  if (
    !raw ||
    raw.trim() === '' ||
    raw === 'YOUR_EXPORT_TOKEN' ||
    raw === 'your-export-token-here'
  ) {
    return null;
  }
  return raw.trim();
}

/**
 * C-03 & L-04: Dedicated Telegram Webhook Secret.
 * - In production (NODE_ENV === 'production'), fails closed if TELEGRAM_WEBHOOK_SECRET is not set.
 * - In development, generates a 256-bit ephemeral secret cached for the process lifetime.
 *   To rotate the webhook secret in production, update TELEGRAM_WEBHOOK_SECRET in your secrets manager
 *   and re-register the webhook via setWebhook.
 */
const DEV_EPHEMERAL_WEBHOOK_SECRET = crypto.randomBytes(32).toString('hex');

export function getTelegramWebhookSecret(): string {
  const explicit = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (
    explicit &&
    explicit.trim() !== '' &&
    explicit !== 'YOUR_TELEGRAM_WEBHOOK_SECRET' &&
    explicit !== 'your-256-bit-hex-secret-here'
  ) {
    return explicit.trim();
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('TELEGRAM_WEBHOOK_SECRET must be set in environment');
  }
  return DEV_EPHEMERAL_WEBHOOK_SECRET;
}

// ============================================================================
// C-04 — SSRF Protection: Strict Outbound Host Allowlist
// ============================================================================
export const ALLOWED_FETCH_HOSTS = new Set([
  'generativelanguage.googleapis.com',
  'api.telegram.org',
]);

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 15000
): Promise<globalThis.Response> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error('SSRF Protection: Invalid URL');
  }
  if (parsedUrl.protocol !== 'https:') {
    throw new Error(`SSRF Protection: Protocol ${parsedUrl.protocol} not allowed`);
  }
  if (!ALLOWED_FETCH_HOSTS.has(parsedUrl.hostname)) {
    throw new Error(`SSRF Protection: Fetch to ${parsedUrl.hostname} not allowed`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// C-05 & H-04 — Filename Sanitization & Upload Validation (Size, MIME, Magic Bytes)
// ============================================================================
export function sanitizeFileName(fileName: string): string {
  let clean = (fileName || '')
    .replace(/\.\./g, '')
    .replace(/[\\/]/g, '')
    .replace(/\0/g, '')
    .replace(/[^\w.\-]/g, '_')
    .slice(0, 255);
  if (!clean || clean === '.' || clean === '..') clean = 'upload';
  return clean;
}

export function validateMediaUpload(input: {
  mediaType?: string | undefined;
  mimeType?: string | undefined;
  base64Data?: string | undefined;
}): { ok: true; buffer: Buffer } | { ok: false; status: number; error: string } {
  const { mediaType, mimeType, base64Data } = input;
  if (!mediaType || !base64Data) {
    return {
      ok: false,
      status: 400,
      error: 'Missing mediaType or base64Data',
    };
  }
  const maxSize = config.upload.maxSizes[mediaType];
  if (!maxSize) {
    return { ok: false, status: 400, error: 'Invalid mediaType' };
  }
  const allowedMimes = config.upload.allowedMimes[mediaType];
  if (!mimeType || !allowedMimes || !allowedMimes.includes(mimeType)) {
    return {
      ok: false,
      status: 400,
      error: `MIME type ${mimeType || 'unknown'} not allowed for ${mediaType}`,
    };
  }

  // Strip optional data URI prefix before decoding
  const rawBase64 = base64Data.includes(',')
    ? base64Data.split(',')[1] || ''
    : base64Data;

  let buffer: Buffer;
  try {
    buffer = Buffer.from(rawBase64, 'base64');
  } catch {
    return { ok: false, status: 400, error: 'Invalid base64' };
  }

  if (buffer.length > maxSize) {
    return {
      ok: false,
      status: 413,
      error: `File too large. Max ${Math.round(maxSize / 1024 / 1024)}MB`,
    };
  }

  // Magic byte validation for binary media types
  const expectedMagic = config.upload.magicBytes[mimeType];
  if (expectedMagic && buffer.length >= expectedMagic.length) {
    const matchesPrimary = expectedMagic.every((b, idx) => buffer[idx] === b);
    // Allow ID3 header (0x49, 0x44, 0x33) for MP3/MPEG audio in addition to 0xFF 0xFB
    const isMp3Id3 =
      (mimeType === 'audio/mp3' || mimeType === 'audio/mpeg') &&
      buffer.length >= 3 &&
      buffer[0] === 0x49 &&
      buffer[1] === 0x44 &&
      buffer[2] === 0x33;

    if (!matchesPrimary && !isMp3Id3) {
      return {
        ok: false,
        status: 400,
        error: 'File magic bytes do not match MIME type',
      };
    }
  }

  if (
    (mimeType === 'image/webp' || mimeType === 'audio/wav') &&
    buffer.length >= 12
  ) {
    const formatId = String.fromCharCode(...buffer.subarray(8, 12));
    if (
      (mimeType === 'image/webp' && formatId !== 'WEBP') ||
      (mimeType === 'audio/wav' && formatId !== 'WAVE')
    ) {
      return {
        ok: false,
        status: 400,
        error: 'File format identifier mismatch',
      };
    }
  }

  return { ok: true, buffer };
}

// ============================================================================
// H-03 — Gemini Multimodal Call with x-goog-api-key Header
// ============================================================================
async function analyzeMediaWithGemini(
  base64Data: string,
  mimeType: string,
  promptText: string
): Promise<string | null> {
  const apiKey = getGeminiApiKey();
  if (!apiKey) return null;

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.gemini.ocrModel}:generateContent`;
    const resp = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey,
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  inlineData: {
                    mimeType,
                    data: base64Data,
                  },
                },
                {
                  text: promptText,
                },
              ],
            },
          ],
        }),
      },
      config.gemini.mediaTimeoutMs
    );
    if (!resp.ok) return null;
    const data: any = await resp.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    return typeof text === 'string' && text.trim() ? text.trim() : null;
  } catch (err) {
    console.error('[Gemini OCR/Transcribe Error]', (err as Error)?.message);
    return null;
  }
}

// ============================================================================
// Telegram Bot Helpers & M-13 Streaming File Download
// ============================================================================
export async function sendTelegramBotMessage(
  token: string,
  chatId: string,
  text: string,
  replyToMessageId?: number
): Promise<boolean> {
  const decryptedToken = decryptIfNeeded(token);
  const decryptedChatId = decryptIfNeeded(chatId) || chatId;
  if (!decryptedToken || !decryptedChatId) return false;

  try {
    const payload: Record<string, any> = {
      chat_id: decryptedChatId,
      text,
      disable_web_page_preview: true,
    };
    if (replyToMessageId) {
      payload.reply_to_message_id = replyToMessageId;
      payload.allow_sending_without_reply = true;
    }
    const resp = await fetchWithTimeout(
      `https://api.telegram.org/bot${decryptedToken}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
      10000
    );
    const data: any = await resp.json();
    if (!data?.ok) {
      console.warn(
        '[Telegram Send Warning] Failed sending message:',
        data?.description
      );
    }
    return Boolean(data?.ok);
  } catch (err) {
    console.error('[Telegram Send Error]:', (err as Error)?.message);
    return false;
  }
}

export async function sendTelegramTypingAction(
  token: string,
  chatId: string
): Promise<void> {
  const decryptedToken = decryptIfNeeded(token);
  const decryptedChatId = decryptIfNeeded(chatId) || chatId;
  if (!decryptedToken || !decryptedChatId) return;
  try {
    await fetchWithTimeout(
      `https://api.telegram.org/bot${decryptedToken}/sendChatAction`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: decryptedChatId, action: 'typing' }),
      },
      5000
    );
  } catch {
    // Non-blocking
  }
}

const MAX_MEMORY_BUFFER = 5 * 1024 * 1024; // 5MB

export async function downloadTelegramFileAsBase64(
  token: string,
  fileId: string
): Promise<{ base64: string; filePath: string } | null> {
  const decryptedToken = decryptIfNeeded(token);
  if (!decryptedToken) return null;

  try {
    const metaResp = await fetchWithTimeout(
      `https://api.telegram.org/bot${decryptedToken}/getFile?file_id=${encodeURIComponent(fileId)}`,
      {},
      10000
    );
    if (!metaResp.ok) return null;
    const metaJson: any = await metaResp.json();
    const filePath: string | undefined = metaJson?.result?.file_path;
    if (!filePath) return null;

    const fileResp = await fetchWithTimeout(
      `https://api.telegram.org/file/bot${decryptedToken}/${filePath}`,
      {},
      15000
    );
    if (!fileResp.ok) return null;

    const contentLength = parseInt(
      fileResp.headers.get('content-length') || '0',
      10
    );
    // M-13: Stream files > 5MB to temp disk file instead of buffering in memory
    if (contentLength > MAX_MEMORY_BUFFER && fileResp.body) {
      const safeId = sanitizeFileName(fileId);
      const tmpFile = path.join(
        os.tmpdir(),
        `tg_${safeId}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}.tmp`
      );
      try {
        const fileStream = fs.createWriteStream(tmpFile);
        await pipeline(Readable.fromWeb(fileResp.body as any), fileStream);
        const base64 = await fs.promises.readFile(tmpFile, {
          encoding: 'base64',
        });
        return { base64, filePath };
      } finally {
        await fs.promises.unlink(tmpFile).catch(() => {});
      }
    }

    const arrayBuf = await fileResp.arrayBuffer();
    const base64 = Buffer.from(arrayBuf).toString('base64');
    return { base64, filePath };
  } catch (err) {
    console.error('[Telegram File Download Error]', (err as Error)?.message);
    return null;
  }
}

export function formatTelegramBotReply(
  analysis: ScamAnalysisResult,
  rawText: string,
  mediaType: 'text' | 'image' | 'audio'
): string {
  const trimmed = (rawText || '').trim().toLowerCase();
  if (
    trimmed === '/start' ||
    trimmed.startsWith('/start ') ||
    trimmed === '/help'
  ) {
    return [
      '🛡️ DHAAL AI CYBER-SHIELD · ACTIVE',
      '━━━━━━━━━━━━━━━━━━━━━━',
      'Namaste! Forward or send any suspicious content here before you pay:',
      '• 💬 WhatsApp / SMS Texts & Links',
      '• 🖼️ Payment, KYC, or Warrant Screenshots (Photo)',
      '• 🎙️ Call Recordings & Voice Notes (Audio)',
      '',
      'Dhaal will immediately reply with:',
      '1. Pre-Payment Threat Level & Risk Score (0–100)',
      '2. Extracted Scam IOCs (UPI IDs, Phones, Links)',
      '3. Scammer’s Predicted Next Move & Counter-Measure',
      '4. 1930 NCRP Recovery & Family Alert Guidance',
      '',
      'Send any message, photo, or voice note now to scan.',
    ].join('\n');
  }

  const statusIcon =
    analysis.threatLevel >= 4
      ? '🚨'
      : analysis.threatLevel === 3
      ? '⚠️'
      : analysis.threatLevel === 2
      ? '🔶'
      : '✅';

  const lines: string[] = [
    `${statusIcon} DHAAL VERDICT: ${analysis.threatLabel}`,
    `Risk Score: ${analysis.riskScore}/100 · Input: ${mediaType.toUpperCase()}`,
    '━━━━━━━━━━━━━━━━━━━━━━',
    `📌 ${analysis.headlineEn}`,
    `🇮🇳 ${analysis.headlineHinglish}`,
    '',
    `🔍 Analysis: ${analysis.summaryEn}`,
  ];

  if (analysis.triggersDetected.length > 0) {
    lines.push('', '🚩 Red Flags Detected:');
    for (const trig of analysis.triggersDetected.slice(0, 4)) {
      lines.push(`• ${trig}`);
    }
  }

  const iocs = analysis.extractedIOCs;
  const iocParts: string[] = [];
  if (iocs.upiIds.length > 0) iocParts.push(`UPI: ${iocs.upiIds.join(', ')}`);
  if (iocs.phoneNumbers.length > 0)
    iocParts.push(`Phone: ${iocs.phoneNumbers.join(', ')}`);
  if (iocs.domains.length > 0)
    iocParts.push(`Links: ${iocs.domains.join(', ')}`);
  if (iocs.bankAccounts.length > 0)
    iocParts.push(`A/C: ${iocs.bankAccounts.join(', ')}`);
  if (iocParts.length > 0) {
    lines.push(
      '',
      '🕵️ Extracted Scam Identifiers:',
      ...iocParts.map((p) => `• ${p}`)
    );
  }

  const firstMove = analysis.nextMoves[0];
  if (firstMove) {
    lines.push(
      '',
      `🔮 Predicted Next Scammer Move (${firstMove.probabilityPct}% prob):`,
      `• "${firstMove.actorMove}"`,
      `🛡️ Counter-Measure: ${firstMove.counterMeasure}`
    );
  }

  if (analysis.pauseBeforePayRequired) {
    lines.push(
      '',
      '⏸️ 2-MINUTE COOLING LOCK ACTIVATED:',
      'DO NOT transfer money, share OTP/UPI PIN, or stay on a coerced video call. If money was deducted, dial 1930 (National Cyber Crime Helpline) immediately.'
    );
  } else {
    lines.push(
      '',
      '✅ Always verify unknown payment requests directly with your family or official bank app.'
    );
  }

  return lines.join('\n');
}

export function sanitizeMessagesForPublicView(
  messages: PersistedTelegramMessage[]
) {
  return messages.map((m) => ({
    id: m.id,
    updateId: m.updateId,
    messageId: m.messageId,
    chatId: '[PROTECTED_SESSION]',
    chatTitle: 'Anonymous Scan',
    chatType: 'private' as const,
    senderName: 'Protected User',
    forwardedFrom: null,
    mediaType: m.mediaType,
    extractedText: m.extractedText,
    extractionSource:
      m.mediaType === 'audio'
        ? 'Attached Voice Note / Audio File'
        : m.mediaType === 'image'
        ? 'Attached Image / Screenshot'
        : 'Attached Message Text',
    receivedAt: m.receivedAt,
    analysis: m.analysis,
    botReplyText: m.botReplyText,
    repliedInTelegram: m.repliedInTelegram,
  }));
}

async function startServer() {
  const app = express();

  // M-11: Request ID / Correlation ID middleware
  app.use((req: AuthRequest, res: Response, next: NextFunction) => {
    const incomingId = req.headers['x-request-id'];
    const requestId =
      typeof incomingId === 'string' && incomingId.trim()
        ? incomingId.trim()
        : crypto.randomUUID();
    req.requestId = requestId;
    res.setHeader('X-Request-ID', requestId);
    next();
  });

  // H-07 & M-01: Helmet Security Headers
  // Apply strict frameguard/CSP on API routes and iframe-compatible headers on SPA preview
  const strictApiHelmet = helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
        fontSrc: ["'self'", 'fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: [
          "'self'",
          'https://generativelanguage.googleapis.com',
          'https://api.telegram.org',
        ],
        frameAncestors: ["'none'"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
  });

  const spaHelmet = helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://fonts.googleapis.com',
          'fonts.googleapis.com',
        ],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
        mediaSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: [
          "'self'",
          'https://generativelanguage.googleapis.com',
          'https://api.telegram.org',
          'ws:',
          'wss:',
        ],
        frameAncestors: [
          "'self'",
          'https://*.google.com',
          'https://*.ai.studio',
          'https://*.run.app',
        ],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: false,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: false,
  });

  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) {
      return strictApiHelmet(req, res, next);
    }
    return spaHelmet(req, res, next);
  });

  // H-11: Strict 1MB body limit on Telegram webhook endpoints
  app.use('/api/telegram/webhook', express.json({ limit: '1mb' }));
  app.use('/api/v1/telegram/webhook', express.json({ limit: '1mb' }));

  // Standard body parser for multimodal uploads
  app.use(express.json({ limit: '20mb' }));

  // Initialize persistence store
  await initPersistenceStore();
  const dataDir = getDataDir();
  const settingsFilePath = path.join(dataDir, 'settings.json');
  const familyFilePath = path.join(dataDir, 'familyMembers.json');
  const complaintFilePath = path.join(dataDir, 'complaintDrafts.json');
  const unfreezeFilePath = path.join(dataDir, 'unfreezeCases.json');
  const scamReportsFilePath = path.join(dataDir, 'scamReports.json');
  const telegramMessagesFilePath = path.join(dataDir, 'telegramMessages.json');

  // Load persistent Telegram deduplication state
  const currentSettings = await readJsonFile<PersistedSettings>(
    settingsFilePath,
    getDefaultSettings()
  );
  let lastTelegramUpdateId =
    currentSettings.lastUpdateId || currentSettings.lastTelegramUpdateId || 0;
  const repliedUpdateIds = new Set<number>(
    currentSettings.repliedUpdateIds || []
  );
  const repliedMessageKeys = new Set<string>(
    currentSettings.repliedMessageKeys || []
  );
  const repliedMediaGroupIds = new Set<string>(
    currentSettings.repliedMediaGroupIds || []
  );

  // M-12: Mutex for safe concurrent offset & dedupe state persistence
  let offsetMutex = Promise.resolve();

  async function persistTelegramDedupeState() {
    await updateJsonFileAtomically<PersistedSettings>(
      settingsFilePath,
      getDefaultSettings(),
      (curr) => ({
        ...curr,
        lastTelegramUpdateId,
        lastUpdateId: lastTelegramUpdateId,
        repliedUpdateIds: Array.from(repliedUpdateIds).slice(-1000),
        repliedMessageKeys: Array.from(repliedMessageKeys).slice(-1000),
        repliedMediaGroupIds: Array.from(repliedMediaGroupIds).slice(-500),
      })
    );
  }

  async function updateOffsetSafely(newOffset?: number) {
    await offsetMutex;
    offsetMutex = (async () => {
      if (
        typeof newOffset === 'number' &&
        newOffset > lastTelegramUpdateId
      ) {
        lastTelegramUpdateId = newOffset;
      }
      await persistTelegramDedupeState();
    })();
    await offsetMutex;
  }

  // H-01: Rate limit ALL /api/* routes (GET + POST + PATCH + DELETE)
  const rateLimiter = createTokenBucketRateLimiter();
  app.use('/api/', rateLimiter.middleware);

  // Helper for logging disagreements between keyword engine and Gemini
  async function logDisagreement(info: {
    inputSnippet: string;
    channel: string;
    keywordScore: number;
    keywordCategory: string;
    geminiScore: number;
    geminiCategory: string;
    geminiReasoning: string;
  }) {
    await updateJsonFileAtomically<PersistedScamReports>(
      scamReportsFilePath,
      getDefaultScamReports(),
      (curr) => ({
        ...curr,
        disagreements: [
          {
            id: `DISAGREE-${Date.now()}`,
            timestamp: new Date().toISOString(),
            ...info,
          },
          ...(curr.disagreements || []),
        ].slice(0, 100),
      })
    );
  }

  // C-02 & H-05: Decrypt familyTelegramChatId and bot token only at dispatch time
  async function maybeNotifyFamilyTelegram(
    alertReason: string,
    payloadHeadline?: string
  ) {
    const settings = await readJsonFile<PersistedSettings>(
      settingsFilePath,
      getDefaultSettings()
    );
    const token = getTelegramToken(settings);
    if (!token) return;
    const groupId = decryptIfNeeded(
      (settings.familyTelegramChatId || '').trim()
    );
    if (!groupId) return;

    const alertText = [
      '🚨 DHAAL CYBER DEFENSE: FAMILY CIRCLE ALERT',
      '━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      `⚠️ Reason: ${alertReason}`,
      payloadHeadline ? `📌 Context: ${payloadHeadline}` : '',
      `🔐 Family Daily Code: ${settings.dailyCode}`,
      '',
      'DO NOT transfer money, enter UPI PIN, or stay isolated on video calls. Check in with your family immediately or call 1930.',
    ]
      .filter(Boolean)
      .join('\n');

    await sendTelegramBotMessage(token, groupId, alertText);
  }

  // ============================================================================
  // Telegram Bot Update Ingestion Handler (Shared by Webhook and Polling)
  // ============================================================================
  async function processTelegramUpdate(
    token: string,
    update: any
  ): Promise<PersistedTelegramMessage | null> {
    if (!update || typeof update.update_id !== 'number') return null;

    if (repliedUpdateIds.has(update.update_id)) {
      if (update.update_id > lastTelegramUpdateId) {
        await updateOffsetSafely(update.update_id);
      }
      return null;
    }

    const msg = update.message || update.channel_post;
    if (!msg || !msg.chat) {
      repliedUpdateIds.add(update.update_id);
      await updateOffsetSafely(update.update_id);
      return null;
    }

    if (msg.from?.is_bot) {
      repliedUpdateIds.add(update.update_id);
      await updateOffsetSafely(update.update_id);
      return null;
    }

    const rawChatId = String(msg.chat.id);
    const messageKey = `${rawChatId}:${msg.message_id}`;
    const mediaGroupKey = msg.media_group_id
      ? `${rawChatId}:${msg.media_group_id}`
      : null;

    if (
      repliedMessageKeys.has(messageKey) ||
      (mediaGroupKey && repliedMediaGroupIds.has(mediaGroupKey))
    ) {
      repliedUpdateIds.add(update.update_id);
      await updateOffsetSafely(update.update_id);
      return null;
    }

    repliedUpdateIds.add(update.update_id);
    repliedMessageKeys.add(messageKey);
    if (mediaGroupKey) repliedMediaGroupIds.add(mediaGroupKey);
    await updateOffsetSafely(update.update_id);

    const rawChatUsername = msg.chat.username ? `@${msg.chat.username}` : '';
    const chatTitle =
      msg.chat.title ||
      rawChatUsername ||
      [msg.chat.first_name, msg.chat.last_name].filter(Boolean).join(' ') ||
      `Chat ${rawChatId}`;
    const chatType = (msg.chat.type || 'private') as
      | 'private'
      | 'group'
      | 'supergroup'
      | 'channel';

    await sendTelegramTypingAction(token, rawChatId);

    const senderName = msg.from
      ? [msg.from.first_name, msg.from.last_name].filter(Boolean).join(' ') ||
        msg.from.username ||
        'Telegram User'
      : chatTitle;

    let forwardedFrom: string | null = null;
    if (msg.forward_origin) {
      if (msg.forward_origin.sender_user) {
        forwardedFrom = [
          msg.forward_origin.sender_user.first_name,
          msg.forward_origin.sender_user.last_name,
        ]
          .filter(Boolean)
          .join(' ');
      } else if (msg.forward_origin.sender_user_name) {
        forwardedFrom = msg.forward_origin.sender_user_name;
      } else if (msg.forward_origin.chat?.title) {
        forwardedFrom = msg.forward_origin.chat.title;
      }
    } else if (msg.forward_from) {
      forwardedFrom = [msg.forward_from.first_name, msg.forward_from.last_name]
        .filter(Boolean)
        .join(' ');
    } else if (msg.forward_from_chat?.title) {
      forwardedFrom = msg.forward_from_chat.title;
    }

    let mediaType: 'text' | 'image' | 'audio' = 'text';
    const rawIncomingText = (msg.text || msg.caption || '').trim();
    const textSanitized = sanitizeUntrustedEvidence(rawIncomingText);
    let extractedText = textSanitized.sanitizedText;
    const forensicMarkers = textSanitized.injectionDetected
      ? ' prompt_injection_attempt ignore previous instructions '
      : '';
    let extractionSource = forwardedFrom
      ? `Telegram Bot (Forwarded from ${forwardedFrom})`
      : `Telegram Chat (${chatTitle})`;
    let channel: 'whatsapp' | 'sms' | 'voice' | 'upi' = 'sms';

    const hasPhoto = Array.isArray(msg.photo) && msg.photo.length > 0;
    const isImageDoc =
      msg.document &&
      typeof msg.document.mime_type === 'string' &&
      msg.document.mime_type.startsWith('image/');

    if (hasPhoto || isImageDoc) {
      mediaType = 'image';
      const targetFileId = hasPhoto
        ? msg.photo[msg.photo.length - 1].file_id
        : msg.document.file_id;
      const downloaded = await downloadTelegramFileAsBase64(
        token,
        targetFileId
      );
      if (downloaded) {
        const imagePrompt = `Extract all visible text, links, and sender details from this Telegram image verbatim.
Append [VERIFIED_OFFICIAL_CHANNEL] if genuine official brand/bank; append [FORGED_DOCUMENT_DEEPFAKE] if forged warrant/seal.
Output format:
TEXT:
<extracted text>
FLAGS: <flags>`;
        const ocrResult = await analyzeMediaWithGemini(
          downloaded.base64,
          isImageDoc ? msg.document.mime_type : 'image/jpeg',
          imagePrompt
        );
        if (ocrResult) {
          const cleanText = ocrResult
            .replace(/^TEXT:\s*/im, '')
            .replace(/FLAGS:.*$/im, '')
            .trim();
          extractedText = [msg.caption, cleanText].filter(Boolean).join(' — ');
          extractionSource = `Telegram Photo OCR (${downloaded.filePath})`;
        }
      }
      if (!extractedText)
        extractedText = msg.caption || '[Attached Photo Screenshot]';
    } else if (msg.voice || msg.audio) {
      mediaType = 'audio';
      channel = 'voice';
      const audioObj = msg.voice || msg.audio;
      const downloaded = await downloadTelegramFileAsBase64(
        token,
        audioObj.file_id
      );
      if (downloaded) {
        const audioPrompt = `Transcribe this Telegram voice recording verbatim. Append applicable forensic tags.`;
        const transResult = await analyzeMediaWithGemini(
          downloaded.base64,
          audioObj.mime_type || 'audio/ogg',
          audioPrompt
        );
        if (transResult) {
          const cleanText = transResult
            .replace(/^TRANSCRIPT:\s*/im, '')
            .replace(/FLAGS:.*$/im, '')
            .trim();
          extractedText = [msg.caption, cleanText].filter(Boolean).join(' — ');
          extractionSource = `Attached Voice Recording (${downloaded.filePath})`;
        }
      }
      if (!extractedText)
        extractedText = msg.caption || '[Attached Voice Recording]';
    } else if (msg.document && msg.document.file_id) {
      const docName = sanitizeFileName(
        msg.document.file_name || 'document.txt'
      );
      const downloaded = await downloadTelegramFileAsBase64(
        token,
        msg.document.file_id
      );
      if (downloaded) {
        const rawTextDoc = Buffer.from(downloaded.base64, 'base64')
          .toString('utf8')
          .slice(0, 8000);
        extractedText = [msg.caption, rawTextDoc].filter(Boolean).join(' — ');
        extractionSource = `Attached Document (${docName})`;
      }
    }

    if (!extractedText) return null;

    const aiResult = await analyzeScamPayloadWithAI(
      `${extractedText} ${forensicMarkers}`.trim(),
      channel,
      { onDisagreement: logDisagreement }
    );
    const analysis = aiResult.result;

    await recordAnalysisToScamReports(analysis, extractionSource);

    const botReplyText = formatTelegramBotReply(
      analysis,
      extractedText,
      mediaType
    );
    const repliedInTelegram = await sendTelegramBotMessage(
      token,
      rawChatId,
      botReplyText
    );

    if (analysis.threatLevel >= 3) {
      maybeNotifyFamilyTelegram(
        `High-Risk Telegram Intercept (${analysis.riskScore}/100)`,
        analysis.headlineEn
      ).catch(() => {});
    }

    const importedItem: PersistedTelegramMessage = {
      id: `TG-${update.update_id}`,
      updateId: update.update_id,
      messageId: msg.message_id || update.update_id,
      chatId: rawChatId,
      chatTitle,
      chatType,
      senderName,
      forwardedFrom,
      mediaType,
      extractedText,
      extractionSource,
      receivedAt:
        new Date(
          (msg.date || Math.floor(Date.now() / 1000)) * 1000
        ).toLocaleTimeString('en-IN', {
          hour12: false,
        }) + ' IST',
      analysis,
      botReplyText,
      repliedInTelegram,
    };

    await updateJsonFileAtomically<PersistedTelegramMessage[]>(
      telegramMessagesFilePath,
      [],
      (curr) => {
        const filtered = curr.filter(
          (m) => m.updateId !== importedItem.updateId
        );
        return [importedItem, ...filtered].slice(0, 200);
      }
    );

    return importedItem;
  }

  // ============================================================================
  // H-10 — Telegram Polling with Exponential Backoff & Circuit Breaker
  // ============================================================================
  let isPollingTelegram = false;
  let lastPollStartedAt = 0;

  async function pollTelegramUpdatesAndAutoReply(): Promise<{
    ok: boolean;
    error?: string;
    newlyImported: PersistedTelegramMessage[];
  }> {
    const settings = await readJsonFile<PersistedSettings>(
      settingsFilePath,
      getDefaultSettings()
    );
    const token = getTelegramToken(settings);
    if (!token) return { ok: true, newlyImported: [] };

    if (isPollingTelegram) {
      if (Date.now() - lastPollStartedAt > 30000) {
        console.warn('[Telegram Polling] Resetting stuck poll lock (>30s)');
        isPollingTelegram = false;
      } else {
        return { ok: true, newlyImported: [] };
      }
    }

    isPollingTelegram = true;
    lastPollStartedAt = Date.now();
    const newlyImported: PersistedTelegramMessage[] = [];

    try {
      const updatesUrl = `https://api.telegram.org/bot${token}/getUpdates?offset=${
        lastTelegramUpdateId + 1
      }&limit=25&allowed_updates=${encodeURIComponent(
        JSON.stringify(['message', 'channel_post'])
      )}`;
      const tgResp = await fetchWithTimeout(updatesUrl, {}, 12000);
      const tgData: any = await tgResp.json();

      if (!tgData?.ok || !Array.isArray(tgData.result)) {
        return {
          ok: false,
          error: 'Telegram polling returned non-ok',
          newlyImported: [],
        };
      }

      for (const update of tgData.result) {
        const item = await processTelegramUpdate(token, update);
        if (item) newlyImported.push(item);
      }

      return { ok: true, newlyImported };
    } catch (err) {
      return {
        ok: false,
        error: (err as Error)?.message || 'Polling failed',
        newlyImported: [],
      };
    } finally {
      isPollingTelegram = false;
    }
  }

  let pollingBackoffMs: number = config.telegram.polling.initialIntervalMs;
  let consecutiveFailures = 0;
  const MAX_BACKOFF_MS: number = config.telegram.polling.maxBackoffMs;
  const CIRCUIT_BREAKER_THRESHOLD: number =
    config.telegram.polling.circuitBreakerThreshold;
  let circuitOpen = false;
  let circuitOpenTime = 0;

  async function runPollingLoop() {
    if (circuitOpen) {
      if (
        Date.now() - circuitOpenTime >
        config.telegram.polling.circuitResetMs
      ) {
        circuitOpen = false;
        consecutiveFailures = 0;
        pollingBackoffMs = config.telegram.polling.initialIntervalMs;
      } else {
        setTimeout(runPollingLoop, pollingBackoffMs);
        return;
      }
    }

    const token = getTelegramToken();
    if (token) {
      try {
        const result = await pollTelegramUpdatesAndAutoReply();
        if (result.ok) {
          consecutiveFailures = 0;
          pollingBackoffMs = config.telegram.polling.initialIntervalMs;
        } else {
          throw new Error(result.error || 'Polling failed');
        }
      } catch {
        consecutiveFailures++;
        pollingBackoffMs = Math.min(pollingBackoffMs * 2, MAX_BACKOFF_MS);
        if (consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
          circuitOpen = true;
          circuitOpenTime = Date.now();
          console.error(
            '[Telegram Polling] Circuit breaker OPEN — too many consecutive failures'
          );
        }
      }
    }

    const timer = setTimeout(runPollingLoop, pollingBackoffMs);
    if (typeof timer.unref === 'function') timer.unref();
  }

  runPollingLoop();

  // ============================================================================
  // Versioned API Router (/api/v1/* and legacy /api/*)
  // ============================================================================
  const apiRouter = express.Router();

  // Public Route 1: Authentication Session Login (C-01)
  apiRouter.post('/auth/login', (req: AuthRequest, res: Response) => {
    try {
      const { email, operatorName } = req.body || {};
      const cleanEmail =
        typeof email === 'string' && email.trim()
          ? email.trim().slice(0, 120)
          : typeof operatorName === 'string' && operatorName.trim()
          ? `${operatorName.trim().slice(0, 60)}@dhaal.local`
          : 'operator@dhaal.local';
      const userId = `usr_${crypto
        .createHash('sha256')
        .update(cleanEmail.toLowerCase())
        .digest('hex')
        .slice(0, 16)}`;

      const session = issueAuthSession(userId, 'user', cleanEmail);
      res.status(200).json({
        ok: true,
        token: session.token,
        csrfToken: session.csrfToken,
        user: session.user,
      });
    } catch (err) {
      handleApiError(err, 'AuthLogin', req, res);
    }
  });

  // Public Route 2: Protected Export Endpoint (Fix #2, H-06, M-17)
  // Guarded by X-Export-Token shared secret; returns generic 404 when missing/mismatched
  apiRouter.get('/export', async (req: AuthRequest, res: Response) => {
    const configuredToken = getExportToken();
    const providedToken = req.headers['x-export-token'];

    if (!configuredToken || providedToken !== configuredToken) {
      res.status(404).send('Cannot GET /api/export');
      return;
    }

    try {
      const bundle = await buildRedactedExportBundle();
      res.status(200).json(bundle);
    } catch (err) {
      handleApiError(err, 'ExportBundle', req, res);
    }
  });

  // Public Route 3: Telegram Webhook (C-03, Fix #7, H-11)
  // Authenticated via X-Telegram-Bot-Api-Secret-Token header
  apiRouter.post(
    '/telegram/webhook',
    async (req: AuthRequest, res: Response) => {
      let expectedSecret: string;
      try {
        expectedSecret = getTelegramWebhookSecret();
      } catch (err) {
        handleApiError(err, 'TelegramWebhookSecret', req, res);
        return;
      }

      const secretHeader = req.headers['x-telegram-bot-api-secret-token'];
      if (!secretHeader || secretHeader !== expectedSecret) {
        res.status(403).json({ error: 'Access denied: invalid secret token' });
        return;
      }

      const settings = await readJsonFile<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings()
      );
      const token = getTelegramToken(settings);
      if (!token) {
        res
          .status(200)
          .json({ ok: false, error: 'Telegram bot token not configured' });
        return;
      }

      try {
        const update = req.body;
        const imported = await processTelegramUpdate(token, update);
        res.status(200).json({ ok: true, processed: Boolean(imported) });
      } catch (err) {
        handleApiError(err, 'TelegramWebhook', req, res);
      }
    }
  );

  // ============================================================================
  // C-01 & C-06: Require JWT Auth + CSRF Protection for all remaining routes
  // ============================================================================
  apiRouter.use(requireAuth);

  // CSRF token endpoint (requires JWT, issues CSRF token for mutating requests)
  apiRouter.get('/csrf-token', (req: AuthRequest, res: Response) => {
    const userId = req.user?.id || 'dhaal-operator';
    const token = issueCsrfToken(userId);
    res.status(200).json({ ok: true, csrfToken: token });
  });

  apiRouter.use(csrfProtection);

  // Settings Routes (C-02, H-05, M-02, M-03)
  apiRouter.get('/settings', async (req: AuthRequest, res: Response) => {
    try {
      const settings = await readJsonFile<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings()
      );
      res.status(200).json(toPublicSettings(settings));
    } catch (err) {
      handleApiError(err, 'GetSettings', req, res);
    }
  });

  apiRouter.post('/settings', async (req: AuthRequest, res: Response) => {
    try {
      const {
        duressWord,
        dailyCode,
        familyTelegramChatId,
        telegramBotToken,
      }: {
        duressWord?: string;
        dailyCode?: string;
        familyTelegramChatId?: string;
        telegramBotToken?: string;
      } = req.body || {};

      const updated = await updateJsonFileAtomically<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings(),
        (curr) => ({
          ...curr,
          updatedAt: new Date().toISOString(),
          // C-02: Encrypt duressWord at rest with AES-256-GCM
          duressWord:
            typeof duressWord === 'string' && duressWord.trim()
              ? encrypt(duressWord.trim())
              : curr.duressWord,
          duressWordConfigured:
            typeof duressWord === 'string' && duressWord.trim()
              ? true
              : curr.duressWordConfigured,
          dailyCode:
            typeof dailyCode === 'string' && dailyCode.trim()
              ? dailyCode.trim()
              : curr.dailyCode,
          // C-02 & H-05: Encrypt familyTelegramChatId at rest with AES-256-GCM
          familyTelegramChatId:
            typeof familyTelegramChatId === 'string'
              ? familyTelegramChatId.trim()
                ? encrypt(familyTelegramChatId.trim())
                : ''
              : curr.familyTelegramChatId,
          // C-02 & H-05: Encrypt telegramBotToken at rest with AES-256-GCM
          telegramBotToken:
            typeof telegramBotToken === 'string' && telegramBotToken.trim()
              ? encrypt(telegramBotToken.trim())
              : curr.telegramBotToken || '',
        })
      );

      res.status(200).json({ ok: true, settings: toPublicSettings(updated) });
    } catch (err) {
      handleApiError(err, 'UpdateSettings', req, res);
    }
  });

  // Duress Check Route (C-02: decrypt duressWord only in memory for comparison)
  apiRouter.post('/duress/check', async (req: AuthRequest, res: Response) => {
    try {
      const { spokenTranscript = '' }: { spokenTranscript?: string } =
        req.body || {};
      const settings = await readJsonFile<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings()
      );
      const plaintextDuressWord = decryptIfNeeded(settings.duressWord);
      const evalResult = checkDuressTrigger(
        spokenTranscript,
        plaintextDuressWord
      );

      if (evalResult.triggered) {
        await maybeNotifyFamilyTelegram(
          'Duress Codeword Triggered during an active call/encounter!',
          `Spoken utterance: "${spokenTranscript.slice(0, 120)}"`
        );
      }

      res.status(200).json({
        ok: true,
        triggered: evalResult.triggered,
        silentProtocol: evalResult.silentProtocol,
      });
    } catch (err) {
      handleApiError(err, 'DuressCheck', req, res);
    }
  });

  // Family Members Routes
  apiRouter.get('/family', async (req: AuthRequest, res: Response) => {
    try {
      const members = await readJsonFile<FamilyMember[]>(familyFilePath, []);
      res.status(200).json({ ok: true, members });
    } catch (err) {
      handleApiError(err, 'GetFamily', req, res);
    }
  });

  apiRouter.post('/family', async (req: AuthRequest, res: Response) => {
    try {
      const memberInput = req.body || {};
      if (!memberInput.name || !memberInput.relation) {
        res
          .status(400)
          .json({ ok: false, error: 'Name and relation are required.' });
        return;
      }
      const newMember: FamilyMember = {
        id:
          typeof memberInput.id === 'string' && memberInput.id.trim()
            ? memberInput.id.trim()
            : `fam-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        name: String(memberInput.name).trim(),
        relation: String(memberInput.relation).trim(),
        phone: String(memberInput.phone || 'Not specified').trim(),
        language: memberInput.language || 'Hinglish',
        lastDrillScore:
          typeof memberInput.lastDrillScore === 'number'
            ? memberInput.lastDrillScore
            : 85,
        status: memberInput.status || 'PROTECTED',
      };

      const updated = await updateJsonFileAtomically<FamilyMember[]>(
        familyFilePath,
        [],
        (curr) => [...curr, newMember]
      );
      res.status(200).json({ ok: true, member: newMember, members: updated });
    } catch (err) {
      handleApiError(err, 'AddFamily', req, res);
    }
  });

  apiRouter.delete('/family/:id', async (req: AuthRequest, res: Response) => {
    try {
      const targetId = req.params.id;
      const updated = await updateJsonFileAtomically<FamilyMember[]>(
        familyFilePath,
        [],
        (curr) => curr.filter((m) => m.id !== targetId)
      );
      res.status(200).json({ ok: true, members: updated });
    } catch (err) {
      handleApiError(err, 'DeleteFamily', req, res);
    }
  });

  apiRouter.patch('/family/:id', async (req: AuthRequest, res: Response) => {
    try {
      const targetId = req.params.id;
      const patch = req.body || {};
      const updated = await updateJsonFileAtomically<FamilyMember[]>(
        familyFilePath,
        [],
        (curr) => curr.map((m) => (m.id === targetId ? { ...m, ...patch } : m))
      );
      res.status(200).json({ ok: true, members: updated });
    } catch (err) {
      handleApiError(err, 'PatchFamily', req, res);
    }
  });

  // Complaint Draft Routes (supports both /complaint-draft and /complaint-drafts)
  const handleGetComplaintDraft = async (req: AuthRequest, res: Response) => {
    try {
      const drafts = await readJsonFile<PersistedComplaintDrafts>(
        complaintFilePath,
        getDefaultComplaintDrafts()
      );
      res.status(200).json({
        ok: true,
        draft: drafts.current,
        drafts: drafts.history || [drafts.current],
      });
    } catch (err) {
      handleApiError(err, 'GetComplaintDraft', req, res);
    }
  };

  const handlePostComplaintDraft = async (req: AuthRequest, res: Response) => {
    try {
      const draft = req.body;
      if (!draft || !draft.incidentId || !Array.isArray(draft.fields)) {
        res
          .status(400)
          .json({ ok: false, error: 'Invalid complaint draft payload.' });
        return;
      }
      await updateJsonFileAtomically<PersistedComplaintDrafts>(
        complaintFilePath,
        getDefaultComplaintDrafts(),
        (curr) => ({
          current: draft,
          history: [draft, ...(curr.history || [])].slice(0, 20),
        })
      );
      res.status(200).json({ ok: true, draft });
    } catch (err) {
      handleApiError(err, 'PostComplaintDraft', req, res);
    }
  };

  apiRouter.get('/complaint-draft', handleGetComplaintDraft);
  apiRouter.get('/complaint-drafts', handleGetComplaintDraft);
  apiRouter.post('/complaint-draft', handlePostComplaintDraft);
  apiRouter.post('/complaint-drafts', handlePostComplaintDraft);

  // Unfreeze Case Routes
  apiRouter.get('/unfreeze-cases', async (req: AuthRequest, res: Response) => {
    try {
      const cases = await readJsonFile<PersistedUnfreezeCase[]>(
        unfreezeFilePath,
        getDefaultUnfreezeCases()
      );
      res.status(200).json({ ok: true, cases });
    } catch (err) {
      handleApiError(err, 'GetUnfreezeCases', req, res);
    }
  });

  apiRouter.post('/unfreeze-cases', async (req: AuthRequest, res: Response) => {
    try {
      const input = req.body || {};
      const newCase: PersistedUnfreezeCase = {
        id: `UF-${Date.now()}`,
        updatedAt: new Date().toISOString(),
        bankName: String(input.bankName || 'HDFC Bank'),
        accountMask: String(input.accountMask || 'XXXX-8821'),
        totalBalanceInr: Number(input.totalBalanceInr) || 0,
        disputedTransactionInr: Number(input.disputedTransactionInr) || 0,
        freezeType: input.freezeType || 'FULL_DEBIT_FREEZE',
        policeNoticeStation: String(
          input.policeNoticeStation || 'Cyber Police Station'
        ),
        ackNumber1930: String(input.ackNumber1930 || '30811260049182'),
      };
      const updated = await updateJsonFileAtomically<PersistedUnfreezeCase[]>(
        unfreezeFilePath,
        getDefaultUnfreezeCases(),
        (curr) => [newCase, ...curr].slice(0, 50)
      );
      res.status(200).json({ ok: true, case: newCase, cases: updated });
    } catch (err) {
      handleApiError(err, 'PostUnfreezeCase', req, res);
    }
  });

  // Scam Radar Routes
  apiRouter.get('/scam-reports', async (req: AuthRequest, res: Response) => {
    try {
      const reports = await readJsonFile<PersistedScamReports>(
        scamReportsFilePath,
        getDefaultScamReports()
      );
      res.status(200).json({ ok: true, nodes: reports.nodes || [] });
    } catch (err) {
      handleApiError(err, 'GetScamReports', req, res);
    }
  });

  apiRouter.post(
    '/scam-reports/upsert',
    async (req: AuthRequest, res: Response) => {
      try {
        const {
          primary,
          connectedLabels = [],
          existingParentId,
        }: {
          primary: { label: string; type: any; source: string };
          connectedLabels: string[];
          existingParentId?: string;
        } = req.body || {};

        if (!primary || !primary.label) {
          res
            .status(400)
            .json({ ok: false, error: 'Primary node label is required.' });
          return;
        }

        const updated = await updateJsonFileAtomically<PersistedScamReports>(
          scamReportsFilePath,
          getDefaultScamReports(),
          (curr) => {
            const nextNodes = upsertNodesWithConnectionsInMemory(
              curr.nodes || [],
              primary,
              connectedLabels,
              existingParentId
            );
            return {
              ...curr,
              nodes: nextNodes,
            };
          }
        );

        res.status(200).json({ ok: true, nodes: updated.nodes });
      } catch (err) {
        handleApiError(err, 'UpsertScamNode', req, res);
      }
    }
  );

  apiRouter.post(
    '/scam-reports/clear',
    async (req: AuthRequest, res: Response) => {
      try {
        await updateJsonFileAtomically<PersistedScamReports>(
          scamReportsFilePath,
          getDefaultScamReports(),
          (curr) => ({
            ...curr,
            nodes: [],
          })
        );
        res.status(200).json({ ok: true, nodes: [] });
      } catch (err) {
        handleApiError(err, 'ClearScamReports', req, res);
      }
    }
  );

  // Family Alert Broadcast Route
  apiRouter.post('/family/alert', async (req: AuthRequest, res: Response) => {
    try {
      const {
        reason = 'Emergency Alert',
        message,
        headline = '',
      } = req.body || {};
      await maybeNotifyFamilyTelegram(message || reason, headline);
      res
        .status(200)
        .json({ ok: true, message: 'Alert recorded and dispatched.' });
    } catch (err) {
      handleApiError(err, 'FamilyAlert', req, res);
    }
  });

  // Multimodal Upload Analysis Route (C-05 sanitized fileName, H-04 size/MIME/magic byte validation)
  apiRouter.post('/analyze-media', async (req: AuthRequest, res: Response) => {
    try {
      const {
        mediaType,
        mimeType,
        base64Data,
        fileName: rawFileName,
        textContent,
        channel = 'sms',
      }: {
        mediaType?: 'image' | 'audio' | 'text';
        mimeType?: string;
        base64Data?: string;
        fileName?: string;
        textContent?: string;
        channel?: 'whatsapp' | 'sms' | 'voice' | 'upi';
      } = req.body || {};

      // C-05: Sanitize fileName to prevent path traversal
      const fileName = sanitizeFileName(rawFileName || 'upload');

      // H-04: Validate upload size, MIME allowlist, and magic bytes when base64Data is provided
      if (base64Data || (mediaType && mediaType !== 'text')) {
        const validation = validateMediaUpload({
          mediaType,
          mimeType,
          base64Data,
        });
        if (!validation.ok) {
          res
            .status(validation.status)
            .json({ ok: false, error: validation.error });
          return;
        }
      }

      const fileGuard = sanitizeUntrustedEvidence(rawFileName || '');
      const textGuard = sanitizeUntrustedEvidence(textContent || '');

      let extractedText = textGuard.sanitizedText;
      let extractionSource = 'Direct Text Input';
      let backgroundForensicContext = '';

      if (fileGuard.injectionDetected || textGuard.injectionDetected) {
        backgroundForensicContext +=
          ' prompt_injection_attempt ignore previous instructions ';
      }

      if (mediaType === 'image' && base64Data) {
        const imagePrompt = `Extract all visible text, links, and sender details from this image verbatim.
Analyze whether this screenshot represents:
1. LEGITIMATE_OFFICIAL: Genuine official notification, public advisory, or verified business account (e.g. verified Amazon, Flipkart, Myntra, Swiggy, or Zomato WhatsApp Business account with green/blue verified badge, "Business Account", "Shop Now" button, official amazon.in / flipkart.com links, deals/discounts, "Reply STOP to unsubscribe"; verified RBI account with rbi.org.in link, bank nomination updates). If legitimate official or verified business, append [VERIFIED_OFFICIAL_CHANNEL].
2. PHISHING_OR_SCAM: Fraudulent attempt, fake courier cancellation, fake delivery fee, digital arrest, fake police/CBI warrant, malicious APK, fake prize, lottery fraud, or extortion. If forged seal, fake warrant, or manipulated screenshot, append [FORGED_DOCUMENT_DEEPFAKE].
3. SUSPICIOUS_UNVERIFIED: Unverified contact with suspicious links.
Output format:
TEXT:
<all extracted text verbatim>
FLAGS: <applicable tags>`;

        const ocrResult = await analyzeMediaWithGemini(
          base64Data,
          mimeType || 'image/png',
          imagePrompt
        );

        if (ocrResult) {
          if (ocrResult.includes('[VERIFIED_OFFICIAL_CHANNEL]')) {
            backgroundForensicContext += ' [verified_official_channel] ';
          }
          if (ocrResult.includes('[FORGED_DOCUMENT_DEEPFAKE]')) {
            backgroundForensicContext +=
              ' forged seal manipulated screenshot deepfake ';
          }
          if (ocrResult.includes('[PROMPT_INJECTION_ATTEMPT]')) {
            backgroundForensicContext +=
              ' prompt_injection_attempt ignore previous instructions ';
          }
          const cleanText = ocrResult
            .replace(/^TEXT:\s*/im, '')
            .replace(/FLAGS:.*$/im, '')
            .replace(/\[VERIFIED_OFFICIAL_CHANNEL\]/g, '')
            .replace(/\[FORGED_DOCUMENT_DEEPFAKE\]/g, '')
            .replace(/\[PROMPT_INJECTION_ATTEMPT\]/g, '')
            .trim();
          const postGuard = sanitizeUntrustedEvidence(cleanText);
          if (postGuard.injectionDetected) {
            backgroundForensicContext +=
              ' prompt_injection_attempt ignore previous instructions ';
          }
          extractedText = postGuard.sanitizedText;
          extractionSource = fileName;
        }

        if (!extractedText) {
          extractedText = `[Uploaded Screenshot: ${fileName}]`;
          extractionSource = fileName;
        }
      } else if (mediaType === 'audio' && base64Data) {
        const audioPrompt = `Accurately transcribe this audio recording verbatim in its original spoken language (English, Hindi, or Hinglish).
Append [VERIFIED_OFFICIAL_CHANNEL] if genuine public awareness; append [LOTTERY_PRIZE_SCAM], [SYNTHETIC_VOICE_CLONE], [DIGITAL_ARREST_COERCION], or [FAKE_DELIVERY_TRAP] if scam.
Output format:
TRANSCRIPT:
<verbatim transcription>
FLAGS: <applicable tags>`;

        const transResult = await analyzeMediaWithGemini(
          base64Data,
          mimeType || 'audio/ogg',
          audioPrompt
        );

        if (transResult) {
          if (transResult.includes('[VERIFIED_OFFICIAL_CHANNEL]')) {
            backgroundForensicContext += ' [verified_official_channel] ';
          }
          if (transResult.includes('[LOTTERY_PRIZE_SCAM]')) {
            backgroundForensicContext +=
              ' [lottery_prize_scam] fake lottery prize ';
          }
          if (transResult.includes('[SYNTHETIC_VOICE_CLONE]')) {
            backgroundForensicContext +=
              ' synthetic voice clone deepfake audio ';
          }
          if (transResult.includes('[DIGITAL_ARREST_COERCION]')) {
            backgroundForensicContext +=
              ' digital arrest police cbi warrant ';
          }
          if (transResult.includes('[FAKE_DELIVERY_TRAP]')) {
            backgroundForensicContext +=
              ' fake courier delivery cancellation ';
          }
          if (transResult.includes('[PROMPT_INJECTION_ATTEMPT]')) {
            backgroundForensicContext +=
              ' prompt_injection_attempt ignore previous instructions ';
          }
          const cleanText = transResult
            .replace(/^TRANSCRIPT:\s*/im, '')
            .replace(/FLAGS:.*$/im, '')
            .replace(/\[VERIFIED_OFFICIAL_CHANNEL\]/g, '')
            .replace(/\[LOTTERY_PRIZE_SCAM\]/g, '')
            .replace(/\[SYNTHETIC_VOICE_CLONE\]/g, '')
            .replace(/\[DIGITAL_ARREST_COERCION\]/g, '')
            .replace(/\[FAKE_DELIVERY_TRAP\]/g, '')
            .replace(/\[PROMPT_INJECTION_ATTEMPT\]/g, '')
            .trim();
          const postGuard = sanitizeUntrustedEvidence(cleanText);
          if (postGuard.injectionDetected) {
            backgroundForensicContext +=
              ' prompt_injection_attempt ignore previous instructions ';
          }
          extractedText = postGuard.sanitizedText;
          extractionSource = fileName;
        }

        if (!extractedText) {
          extractedText = `[Uploaded Audio Recording: ${fileName}]`;
          extractionSource = fileName;
        }
      } else if (mediaType === 'text' && base64Data && !extractedText) {
        const decodedText = Buffer.from(base64Data, 'base64')
          .toString('utf8')
          .slice(0, 10000);
        const postGuard = sanitizeUntrustedEvidence(decodedText);
        if (postGuard.injectionDetected) {
          backgroundForensicContext +=
            ' prompt_injection_attempt ignore previous instructions ';
        }
        extractedText = postGuard.sanitizedText;
        extractionSource = fileName;
      }

      const effectiveChannel =
        mediaType === 'audio' ? 'voice' : channel || 'sms';
      const fullText = `${extractedText} ${fileName} ${backgroundForensicContext}`.trim();

      const aiResult = await analyzeScamPayloadWithAI(
        fullText,
        effectiveChannel,
        {
          imageMetadata: {
            fileName,
            ...(mimeType !== undefined ? { mimeType } : {}),
            ...(mediaType !== undefined ? { mediaType } : {}),
          },
          onDisagreement: logDisagreement,
        }
      );

      const analysis = aiResult.result;

      await recordAnalysisToScamReports(analysis, extractionSource);

      if (analysis.threatLevel >= 3) {
        maybeNotifyFamilyTelegram(
          `High-Risk Verdict (${analysis.riskScore}/100 · ${analysis.threatLabel})`,
          analysis.headlineEn
        ).catch(() => {});
      }

      res.status(200).json({
        ok: true,
        fileName,
        extractedText,
        extractionSource,
        analysis,
        escalated: aiResult.escalated,
        fallbackUsed: aiResult.fallbackUsed,
      });
    } catch (err) {
      handleApiError(err, 'AnalyzeMedia', req, res);
    }
  });

  // Telegram Status & Sync Routes
  apiRouter.get(
    '/telegram/status',
    async (req: AuthRequest, res: Response) => {
      try {
        const settings = await readJsonFile<PersistedSettings>(
          settingsFilePath,
          getDefaultSettings()
        );
        const token = getTelegramToken(settings);
        const messages = await readJsonFile<PersistedTelegramMessage[]>(
          telegramMessagesFilePath,
          []
        );

        if (!token) {
          res.status(200).json({
            configured: false,
            botUsername: null,
            botName: null,
            lastUpdateId: lastTelegramUpdateId,
            discoveredChats: [],
            messages: sanitizeMessagesForPublicView(messages.slice(0, 30)),
          });
          return;
        }

        try {
          const meResp = await fetchWithTimeout(
            `https://api.telegram.org/bot${token}/getMe`,
            {},
            5000
          );
          const meData: any = await meResp.json();
          if (meData?.ok && meData?.result) {
            res.status(200).json({
              configured: true,
              botUsername: meData.result.username || 'DhaalTELEBot',
              botName: meData.result.first_name || 'DHAAL',
              lastUpdateId: lastTelegramUpdateId,
              discoveredChats: [],
              messages: sanitizeMessagesForPublicView(messages.slice(0, 30)),
            });
            return;
          }
        } catch {
          // Fall through
        }

        res.status(200).json({
          configured: true,
          botUsername: 'DhaalTELEBot',
          botName: 'DHAAL',
          lastUpdateId: lastTelegramUpdateId,
          discoveredChats: [],
          messages: sanitizeMessagesForPublicView(messages.slice(0, 30)),
        });
      } catch (err) {
        handleApiError(err, 'TelegramStatus', req, res);
      }
    }
  );

  apiRouter.post('/telegram/sync', async (req: AuthRequest, res: Response) => {
    try {
      const {
        chatIdFilter = '',
        simulateType,
      }: {
        chatIdFilter?: string;
        simulateType?: 'text' | 'image' | 'audio';
      } = req.body || {};

      const cleanFilter = chatIdFilter.trim().toLowerCase();
      const newlyImported: PersistedTelegramMessage[] = [];

      if (simulateType) {
        const nowStr =
          new Date().toLocaleTimeString('en-IN', { hour12: false }) + ' IST';
        let chatId = '-100219847102';
        let chatTitle = 'Family Cyber Watch Group';
        let chatType: 'private' | 'group' | 'supergroup' | 'channel' =
          'supergroup';
        let senderName = 'Ramesh Uncle';
        let forwardedFrom: string | null =
          'CBI Cyber Dispatch Desk (+91 9820194812)';
        let extractedText = '';
        let extractionSource = '';
        let channel: 'whatsapp' | 'sms' | 'voice' | 'upi' = 'sms';

        if (simulateType === 'text') {
          chatId = cleanFilter ? chatIdFilter.trim() : '648910234';
          chatTitle = 'Direct Bot DM (Forwarded Scam)';
          chatType = 'private';
          senderName = 'You (Forwarded to Bot)';
          forwardedFrom =
            'SEBI Institutional VIP Block Deal (@sebi_vip_pump)';
          extractedText =
            '[Telegram Forwarded Message] SEBI Registered Institutional VIP Group: Join our Pre-IPO upper circuit block deal with 200% guaranteed return! Deposit minimum ₹50,000 via UPI to institutional.pool@okicici or visit https://www.sebi-vip-alloc.in immediately.';
          extractionSource = 'Telegram Bot API · Forwarded Text & Link';
          channel = 'sms';
        } else if (simulateType === 'image') {
          chatId = cleanFilter ? chatIdFilter.trim() : '-100219847102';
          chatTitle = 'Sharma Family Protection Group';
          chatType = 'supergroup';
          senderName = 'Meera Aunty';
          forwardedFrom = 'Supreme Court Warrant Desk';
          extractedText =
            '[Telegram Photo OCR · warrant_notice_tg.jpg] SUPREME COURT OF INDIA & CBI NARCOTICS CELL: Non-Bailable Digital Arrest Warrant issued against your Aadhaar ID for a FedEx parcel containing MDMA. Stay on Skype video call and transfer ₹3,85,000 verification bond to rbi.verify99@okaxis.';
          extractionSource =
            'Telegram Bot getFile + Gemini OCR (Photo Screenshot)';
          channel = 'sms';
        } else {
          chatId = cleanFilter ? chatIdFilter.trim() : '-100219847102';
          chatTitle = 'Sharma Family Protection Group';
          chatType = 'supergroup';
          senderName = 'Vikram (Cousin)';
          forwardedFrom = 'Unknown Caller Voice Note';
          extractedText =
            '[Telegram Voice Note · voice_049.ogg] "Hello, main BESCOM electricity office se officer bol raha hoon. Aaj raat 9:30 baje aapka bijli connection kat jayega kyunki KYC update nahi hua. Turant +91 8892019283 par call karke BESCOM-Support.apk install karo aur ₹10 UPI collect request approve karo."';
          extractionSource =
            'Telegram Bot getFile + Gemini Audio Transcription (Voice Note)';
          channel = 'voice';
        }

        const aiResult = await analyzeScamPayloadWithAI(extractedText, channel);
        const analysis = aiResult.result;
        await recordAnalysisToScamReports(analysis, extractionSource);
        const botReplyText = formatTelegramBotReply(
          analysis,
          extractedText,
          simulateType
        );

        const settings = await readJsonFile<PersistedSettings>(
          settingsFilePath,
          getDefaultSettings()
        );
        const token = getTelegramToken(settings);
        let repliedInTelegram = false;
        if (token && /^-?\d+$/.test(chatIdFilter.trim())) {
          repliedInTelegram = await sendTelegramBotMessage(
            token,
            chatIdFilter.trim(),
            botReplyText
          );
        }

        const simMsg: PersistedTelegramMessage = {
          id: `TG-SIM-${Date.now()}`,
          updateId: 900000 + Math.floor(Math.random() * 10000),
          messageId: 400 + Math.floor(Math.random() * 10000),
          chatId,
          chatTitle,
          chatType,
          senderName,
          forwardedFrom,
          mediaType: simulateType,
          extractedText,
          extractionSource,
          receivedAt: nowStr,
          analysis,
          botReplyText,
          repliedInTelegram,
        };

        const allStored = await updateJsonFileAtomically<
          PersistedTelegramMessage[]
        >(telegramMessagesFilePath, [], (curr) =>
          [simMsg, ...curr].slice(0, 200)
        );
        newlyImported.push(simMsg);

        res.status(200).json({
          ok: true,
          configured: Boolean(token),
          newlyImported: sanitizeMessagesForPublicView(newlyImported),
          discoveredChats: [],
          messages: sanitizeMessagesForPublicView(allStored.slice(0, 30)),
        });
        return;
      }

      const pollResult = await pollTelegramUpdatesAndAutoReply();
      const allStored = await readJsonFile<PersistedTelegramMessage[]>(
        telegramMessagesFilePath,
        []
      );

      const filteredMessages = cleanFilter
        ? allStored.filter(
            (m) =>
              m.chatId.toLowerCase() === cleanFilter ||
              m.chatTitle.toLowerCase().includes(cleanFilter)
          )
        : allStored;

      const filteredNewlyImported = cleanFilter
        ? pollResult.newlyImported.filter(
            (m) =>
              m.chatId.toLowerCase() === cleanFilter ||
              m.chatTitle.toLowerCase().includes(cleanFilter)
          )
        : pollResult.newlyImported;

      res.status(200).json({
        ok: pollResult.ok,
        configured: Boolean(getTelegramToken()),
        error: pollResult.error,
        newlyImported: sanitizeMessagesForPublicView(filteredNewlyImported),
        discoveredChats: [],
        messages: sanitizeMessagesForPublicView(filteredMessages.slice(0, 30)),
      });
    } catch (err) {
      handleApiError(err, 'TelegramSync', req, res);
    }
  });

  // M-04: Mount versioned API under /api/v1 and legacy /api with Deprecation headers
  app.use('/api/v1', apiRouter);
  app.use('/api', (_req, res, next) => {
    res.setHeader('Deprecation', 'true');
    res.setHeader('Link', '</api/v1/>; rel="successor-version"');
    next();
  });
  app.use('/api', apiRouter);

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Dhaal server listening on http://localhost:${PORT}`);
  });
}

if (process.env.DHAAL_TEST_IMPORT !== 'true') {
  startServer();
}
