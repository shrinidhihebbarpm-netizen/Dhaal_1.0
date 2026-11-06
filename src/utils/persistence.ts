import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { config, resolveEncryptionKeyHex } from '../config';
import {
  ComplaintDraft,
  ScamAnalysisResult,
  UnfreezeCaseInput,
} from './scamEngine';
import {
  FamilyMember,
  ScamGraphNode,
  INITIAL_COMPLAINT_DRAFT,
  INITIAL_SCAM_GRAPH,
  inferGraphNodeType,
} from './seedData';

// ============================================================================
// C-02 & H-05 — AES-256-GCM Encryption at Rest
// ============================================================================
function getEncryptionKeyBuffer(): Buffer {
  const keyHex = resolveEncryptionKeyHex();
  const buf = Buffer.from(keyHex, 'hex');
  if (buf.length !== 32) {
    throw new Error('DATA_ENCRYPTION_KEY must be 32 bytes (64 hex chars)');
  }
  return buf;
}

export function encrypt(plaintext: string): string {
  const key = getEncryptionKeyBuffer();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${ciphertext.toString('hex')}:${authTag.toString('hex')}`;
}

export function decrypt(ciphertext: string): string {
  const parts = ciphertext.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid ciphertext format');
  }
  const [ivHex, ctHex, tagHex] = parts;
  if (!ivHex || !tagHex || ivHex.length !== 24 || tagHex.length !== 32) {
    throw new Error('Invalid ciphertext format');
  }
  const key = getEncryptionKeyBuffer();
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(ctHex || '', 'hex')),
    decipher.final(),
  ]).toString('utf8');
}

export function isEncryptedValue(value: string): boolean {
  return /^[0-9a-fA-F]{24}:[0-9a-fA-F]*:[0-9a-fA-F]{32}$/.test(value);
}

export function encryptIfNeeded(value: string): string {
  if (!value || !value.trim()) return '';
  if (isEncryptedValue(value)) return value;
  return encrypt(value);
}

export function decryptIfNeeded(value: string): string {
  if (!value || !value.trim()) return '';
  if (!isEncryptedValue(value)) return value;
  try {
    return decrypt(value);
  } catch {
    return '';
  }
}

export interface PersistedSettings {
  duressWord: string;
  duressWordConfigured: boolean;
  dailyCode: string;
  familyTelegramChatId: string;
  telegramBotToken?: string;
  updatedAt?: string;
  lastTelegramUpdateId: number;
  lastUpdateId?: number;
  repliedUpdateIds: number[];
  repliedMessageKeys: string[];
  repliedMediaGroupIds: string[];
}

export interface PublicSettingsView {
  duressWordSet: boolean;
  duressWordConfigured: boolean;
  dailyCodeConfigured: boolean;
  familyTelegramConfigured: boolean;
}

export interface PersistedComplaintDrafts {
  current: ComplaintDraft;
  history: ComplaintDraft[];
}

export interface PersistedUnfreezeCase extends UnfreezeCaseInput {
  id: string;
  updatedAt: string;
}

export interface ModelDisagreementRecord {
  id: string;
  timestamp: string;
  inputSnippet: string;
  channel: string;
  keywordScore: number;
  keywordCategory: string;
  geminiScore: number;
  geminiCategory: string;
  geminiReasoning: string;
}

export interface PersistedScamReports {
  nodes: ScamGraphNode[];
  disagreements: ModelDisagreementRecord[];
}

export interface PersistedTelegramMessage {
  id: string;
  updateId: number;
  messageId: number;
  chatId: string;
  chatTitle: string;
  chatType: 'private' | 'group' | 'supergroup' | 'channel';
  senderName: string;
  forwardedFrom: string | null;
  mediaType: 'text' | 'image' | 'audio';
  extractedText: string;
  extractionSource: string;
  receivedAt: string;
  analysis: ScamAnalysisResult;
  botReplyText: string;
  repliedInTelegram: boolean;
}

// Per-file in-process write lock queue to prevent concurrent write clobbering
const fileWriteLocks = new Map<string, Promise<void>>();

export function getDataDir(customDir?: string): string {
  return (
    customDir ||
    process.env.DHAAL_DATA_DIR ||
    config.persistence.dataDir ||
    path.join(os.tmpdir(), 'dhaal-data')
  );
}

export const DATA_DIR = getDataDir();
export const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
export const SCAM_REPORTS_FILE = path.join(DATA_DIR, 'scamReports.json');
export const FAMILY_MEMBERS_FILE = path.join(DATA_DIR, 'familyMembers.json');
export const COMPLAINT_DRAFTS_FILE = path.join(DATA_DIR, 'complaintDrafts.json');
export const UNFREEZE_CASES_FILE = path.join(DATA_DIR, 'unfreezeCases.json');
export const TELEGRAM_MESSAGES_FILE = path.join(DATA_DIR, 'telegramMessages.json');

export async function withFileLock<T>(
  filePath: string,
  fn: () => Promise<T>
): Promise<T> {
  const prevLock = fileWriteLocks.get(filePath) || Promise.resolve();
  let releaseLock!: () => void;
  const nextLock = new Promise<void>((resolve) => {
    releaseLock = resolve;
  });
  fileWriteLocks.set(
    filePath,
    prevLock.then(
      () => nextLock,
      () => nextLock
    )
  );

  await prevLock;
  try {
    return await fn();
  } finally {
    releaseLock();
  }
}

// L-05: 64-bit random entropy (8 bytes) on temp filenames
export async function atomicWriteJson<T>(
  filePath: string,
  data: T
): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.promises.mkdir(dir, { recursive: true });
  const tmpFile = `${filePath}.${process.pid}.${Date.now()}.${crypto
    .randomBytes(8)
    .toString('hex')}.tmp`;
  const serialized = JSON.stringify(data, null, 2);
  await fs.promises.writeFile(tmpFile, serialized, 'utf8');
  await fs.promises.rename(tmpFile, filePath);
}

export async function readJsonFile<T>(
  filePath: string,
  defaultValue: T
): Promise<T> {
  try {
    const raw = await fs.promises.readFile(filePath, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    return defaultValue;
  }
}

export async function updateJsonFileAtomically<T>(
  filePath: string,
  defaultValue: T,
  updater: (current: T) => T | Promise<T>
): Promise<T> {
  return withFileLock(filePath, async () => {
    const current = await readJsonFile<T>(filePath, defaultValue);
    const updated = await updater(current);
    await atomicWriteJson(filePath, updated);
    return updated;
  });
}

// H-09: 256-bit cryptographic entropy (43 chars base64url)
export function generateRandomServerDuressWord(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function getDefaultSettings(): PersistedSettings {
  return {
    duressWord: encryptIfNeeded(generateRandomServerDuressWord()),
    duressWordConfigured: false,
    dailyCode: 'KAVACH-749',
    familyTelegramChatId: '',
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN
      ? encryptIfNeeded(process.env.TELEGRAM_BOT_TOKEN.trim())
      : '',
    lastTelegramUpdateId: 0,
    repliedUpdateIds: [],
    repliedMessageKeys: [],
    repliedMediaGroupIds: [],
  };
}

export function getDefaultUnfreezeCases(): PersistedUnfreezeCase[] {
  return [
    {
      id: 'UF-DEFAULT',
      updatedAt: new Date().toISOString(),
      bankName: 'HDFC Bank',
      accountMask: 'XXXX-8821',
      totalBalanceInr: 245000,
      disputedTransactionInr: 4500,
      freezeType: 'FULL_DEBIT_FREEZE',
      policeNoticeStation:
        'Cyber Crime Police Station Ahmedabad (Layer-3 Notice)',
      ackNumber1930: '30811260049182',
    },
  ];
}

export function getDefaultComplaintDrafts(): PersistedComplaintDrafts {
  return {
    current: INITIAL_COMPLAINT_DRAFT,
    history: [INITIAL_COMPLAINT_DRAFT],
  };
}

export function getDefaultScamReports(): PersistedScamReports {
  return {
    nodes: INITIAL_SCAM_GRAPH.map((n) => ({
      ...n,
      connections: [...n.connections],
    })),
    disagreements: [],
  };
}

export async function initPersistenceStore(customDir?: string): Promise<{
  backend: 'local-atomic';
  dataDir: string;
}> {
  const dataDir = getDataDir(customDir);
  await fs.promises.mkdir(dataDir, { recursive: true });

  const filesToEnsure: Array<{ name: string; defaultVal: unknown }> = [
    { name: 'familyMembers.json', defaultVal: [] as FamilyMember[] },
    { name: 'settings.json', defaultVal: getDefaultSettings() },
    { name: 'complaintDrafts.json', defaultVal: getDefaultComplaintDrafts() },
    { name: 'unfreezeCases.json', defaultVal: getDefaultUnfreezeCases() },
    { name: 'scamReports.json', defaultVal: getDefaultScamReports() },
    {
      name: 'telegramMessages.json',
      defaultVal: [] as PersistedTelegramMessage[],
    },
  ];

  for (const item of filesToEnsure) {
    const filePath = path.join(dataDir, item.name);
    if (!fs.existsSync(filePath)) {
      await withFileLock(filePath, async () => {
        if (!fs.existsSync(filePath)) {
          await atomicWriteJson(filePath, item.defaultVal);
        }
      });
    }
  }

  return { backend: 'local-atomic', dataDir };
}

// C-02, M-02, M-03: Never expose plaintext secrets in public settings
export function toPublicSettings(
  settings: PersistedSettings
): PublicSettingsView {
  return {
    duressWordSet: Boolean(settings.duressWord && settings.duressWord.trim()),
    duressWordConfigured: Boolean(settings.duressWordConfigured),
    dailyCodeConfigured: Boolean(
      settings.dailyCode && settings.dailyCode.trim()
    ),
    familyTelegramConfigured: Boolean(
      settings.familyTelegramChatId && settings.familyTelegramChatId.trim()
    ),
  };
}

// H-06, M-02, M-03, M-17: Redact secrets, PII, and unverified AI fields in export
export async function buildRedactedExportBundle(customDir?: string) {
  const dataDir = getDataDir(customDir);
  const [
    familyMembers,
    rawSettings,
    complaintDrafts,
    unfreezeCases,
    scamReports,
    telegramMessages,
  ] = await Promise.all([
    readJsonFile<FamilyMember[]>(path.join(dataDir, 'familyMembers.json'), []),
    readJsonFile<PersistedSettings>(
      path.join(dataDir, 'settings.json'),
      getDefaultSettings()
    ),
    readJsonFile<PersistedComplaintDrafts>(
      path.join(dataDir, 'complaintDrafts.json'),
      getDefaultComplaintDrafts()
    ),
    readJsonFile<PersistedUnfreezeCase[]>(
      path.join(dataDir, 'unfreezeCases.json'),
      getDefaultUnfreezeCases()
    ),
    readJsonFile<PersistedScamReports>(
      path.join(dataDir, 'scamReports.json'),
      getDefaultScamReports()
    ),
    readJsonFile<PersistedTelegramMessage[]>(
      path.join(dataDir, 'telegramMessages.json'),
      []
    ),
  ]);

  const {
    duressWord: _redactedDuress,
    dailyCode: _redactedDailyCode,
    familyTelegramChatId: _redactedChatId,
    telegramBotToken: _redactedBotToken,
    ...safeSettingsRest
  } = rawSettings;
  void _redactedDuress;
  void _redactedDailyCode;
  void _redactedChatId;
  void _redactedBotToken;

  const currentDraft = complaintDrafts?.current || INITIAL_COMPLAINT_DRAFT;
  const historyDrafts = Array.isArray(complaintDrafts?.history)
    ? complaintDrafts.history
    : [INITIAL_COMPLAINT_DRAFT];

  return {
    exportedAt: new Date().toISOString(),
    persistenceBackend: 'local-atomic',
    familyMembers,
    settings: {
      ...safeSettingsRest,
      duressWordSet: Boolean(
        rawSettings.duressWord && rawSettings.duressWord.trim()
      ),
      dailyCodeConfigured: Boolean(
        rawSettings.dailyCode && rawSettings.dailyCode.trim()
      ),
      familyTelegramConfigured: Boolean(
        rawSettings.familyTelegramChatId &&
          rawSettings.familyTelegramChatId.trim()
      ),
    },
    complaintDrafts: {
      ...complaintDrafts,
      current: {
        ...currentDraft,
        fields: (currentDraft.fields || []).map((f) => ({
          ...f,
          value: f.verifiedByUser
            ? f.value
            : '[UNVERIFIED AI DRAFT — REDACTED]',
        })),
      },
      history: historyDrafts.map((d) => ({
        ...d,
        fields: (d.fields || []).map((f) => ({
          ...f,
          value: f.verifiedByUser
            ? f.value
            : '[UNVERIFIED AI DRAFT — REDACTED]',
        })),
      })),
    },
    unfreezeCases,
    scamReports,
    telegramMessages: telegramMessages.slice(0, 200).map((m) => ({
      id: m.id,
      updateId: m.updateId,
      messageId: m.messageId,
      chatId: '[REDACTED]',
      chatTitle: '[REDACTED]',
      chatType: m.chatType,
      senderName: '[REDACTED]',
      forwardedFrom: '[REDACTED]',
      mediaType: m.mediaType,
      extractedText: m.extractedText,
      extractionSource: m.extractionSource,
      receivedAt: m.receivedAt,
      analysis: m.analysis,
      botReplyText: m.botReplyText,
      repliedInTelegram: m.repliedInTelegram,
    })),
  };
}

// ============================================================================
// Fix #5 & L-06 — DRY Idempotent Scam Graph Clustering Logic
// ============================================================================
export { inferGraphNodeType };

export function upsertNodesWithConnectionsInMemory(
  existingNodes: ScamGraphNode[],
  primary: { label: string; type: ScamGraphNode['type']; source: string },
  connectedLabels: string[],
  existingParentId?: string
): ScamGraphNode[] {
  const baseMap = new Map<string, ScamGraphNode>();
  for (const seedNode of INITIAL_SCAM_GRAPH) {
    baseMap.set(seedNode.label.toLowerCase(), {
      ...seedNode,
      connections: [...seedNode.connections],
    });
  }
  for (const node of existingNodes) {
    baseMap.set(node.label.toLowerCase(), {
      ...node,
      connections: [...(node.connections || [])],
    });
  }

  const next = Array.from(baseMap.values());

  const computeCoords = (idx: number) => {
    if (idx === 0) return { x: 460, y: 180 };
    const presetSlots = [
      { x: 210, y: 95 },
      { x: 710, y: 95 },
      { x: 210, y: 265 },
      { x: 710, y: 265 },
      { x: 460, y: 60 },
      { x: 460, y: 300 },
      { x: 115, y: 180 },
      { x: 805, y: 180 },
    ];
    return presetSlots[(idx - 1) % presetSlots.length]!;
  };

  const upsertNode = (
    label: string,
    type: ScamGraphNode['type'],
    source: string
  ): ScamGraphNode => {
    const clean = label.trim();
    const existing = next.find(
      (n) => n.label.toLowerCase() === clean.toLowerCase()
    );
    if (existing) {
      existing.reportsCount += 1;
      existing.confidencePct = Math.min(99, existing.confidencePct + 2);
      return existing;
    }
    const coords = computeCoords(next.length);
    const created: ScamGraphNode = {
      id: `NODE-${next.length + 101}`,
      label: clean,
      type,
      confidencePct: 95,
      reportsCount: 1,
      source,
      status: 'ACTIVE_THREAT',
      region: 'User Input Telemetry',
      x: coords.x,
      y: coords.y,
      connections: [],
    };
    next.push(created);
    return created;
  };

  const primaryNode = upsertNode(primary.label, primary.type, primary.source);

  const linkNodes = (a: ScamGraphNode, b: ScamGraphNode) => {
    if (a.id === b.id) return;
    if (!a.connections.includes(b.id)) a.connections.push(b.id);
    if (!b.connections.includes(a.id)) b.connections.push(a.id);
  };

  if (existingParentId) {
    const parentNode = next.find((n) => n.id === existingParentId);
    if (parentNode) {
      linkNodes(primaryNode, parentNode);
    }
  }

  connectedLabels
    .map((c) => c.trim())
    .filter(Boolean)
    .forEach((connLabel) => {
      const connNode = upsertNode(
        connLabel,
        inferGraphNodeType(connLabel),
        primary.source
      );
      linkNodes(primaryNode, connNode);
    });

  return next;
}

export async function recordAnalysisToScamReports(
  analysis: ScamAnalysisResult,
  sourceLabel: string,
  customDir?: string
): Promise<PersistedScamReports> {
  const dataDir = getDataDir(customDir);
  const filePath = path.join(dataDir, 'scamReports.json');

  const connectedEntities: string[] = [
    ...analysis.extractedIOCs.upiIds,
    ...analysis.extractedIOCs.phoneNumbers,
    ...analysis.extractedIOCs.bankAccounts,
    ...analysis.extractedIOCs.domains,
  ];

  if (
    analysis.categoryCode === 'VERIFIED_CLEAN' &&
    analysis.threatLevel === 0 &&
    connectedEntities.length === 0
  ) {
    return readJsonFile<PersistedScamReports>(
      filePath,
      getDefaultScamReports()
    );
  }

  const primaryLabel =
    analysis.extractedIOCs.impersonatedEntity &&
    analysis.extractedIOCs.impersonatedEntity !== 'None Detected' &&
    analysis.extractedIOCs.impersonatedEntity !== 'Unverified Sender'
      ? `${analysis.extractedIOCs.impersonatedEntity} (${analysis.categoryCode})`
      : `User Scan: ${analysis.categoryCode}`;

  if (connectedEntities.length === 0 && analysis.triggersDetected.length > 0) {
    const firstTrigger = analysis.triggersDetected[0];
    if (firstTrigger) connectedEntities.push(firstTrigger);
  }

  return updateJsonFileAtomically<PersistedScamReports>(
    filePath,
    getDefaultScamReports(),
    (current) => {
      const updatedNodes = upsertNodesWithConnectionsInMemory(
        current.nodes || INITIAL_SCAM_GRAPH,
        {
          label: primaryLabel,
          type: 'CAMPAIGN_CLUSTER',
          source: sourceLabel,
        },
        connectedEntities
      );
      return {
        ...current,
        nodes: updatedNodes,
      };
    }
  );
}

// ============================================================================
// H-01 & H-02 — Proxy-Aware Per-Endpoint Token-Bucket Rate Limiter
// ============================================================================
export function extractClientIp(req: {
  headers?: Record<string, string | string[] | undefined>;
  ip?: string;
  socket?: { remoteAddress?: string | undefined };
}): string {
  const trustedProxy = process.env.TRUSTED_PROXY === 'true';
  if (trustedProxy) {
    const xff = req.headers?.['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim().length > 0) {
      return xff.split(',')[0]?.trim() || 'unknown-client';
    }
    if (Array.isArray(xff) && xff.length > 0 && xff[0]) {
      return xff[0].split(',')[0]?.trim() || 'unknown-client';
    }
  }
  return req.ip || req.socket?.remoteAddress || 'unknown-client';
}

function normalizeEndpointPath(rawPath?: string): string {
  if (!rawPath) return '/api/default';
  // Normalize /api/v1/xyz or /v1/xyz or /xyz to /api/xyz for endpoint limit lookup
  let p = rawPath.split('?')[0] || '/';
  if (p.startsWith('/api/v1/')) {
    p = '/api/' + p.slice('/api/v1/'.length);
  } else if (p.startsWith('/v1/')) {
    p = '/api/' + p.slice('/v1/'.length);
  } else if (!p.startsWith('/api/')) {
    p = '/api' + (p.startsWith('/') ? p : '/' + p);
  }
  // Match base resource prefix (e.g. /api/family/:id -> /api/family)
  for (const key of Object.keys(config.rateLimit.endpoints)) {
    if (p === key || p.startsWith(key + '/')) {
      return key;
    }
  }
  return p;
}

export function createTokenBucketRateLimiter(options?: {
  capacity?: number;
  refillPerMinute?: number;
}) {
  const customCapacity = options?.capacity;
  const customRefill = options?.refillPerMinute;
  const defaultCapacity = customCapacity ?? config.rateLimit.default.capacity;
  const defaultRefillPerMinute =
    customRefill ?? config.rateLimit.default.refillPerMinute;

  const buckets = new Map<string, { tokens: number; lastRefillMs: number }>();

  const check = (clientIp: string, routePath = '/api/default'): boolean => {
    const now = Date.now();
    const normalizedPath = normalizeEndpointPath(routePath);
    const endpointSpecific =
      customCapacity !== undefined
        ? undefined
        : config.rateLimit.endpoints[normalizedPath];

    const capacity = endpointSpecific?.capacity ?? defaultCapacity;
    const refillPerMinute =
      endpointSpecific?.refillPerMinute ?? defaultRefillPerMinute;
    const refillRatePerMs = refillPerMinute / 60000;

    const key = `${clientIp}:${normalizedPath}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { tokens: capacity, lastRefillMs: now };
      buckets.set(key, bucket);
    } else {
      const elapsed = Math.max(0, now - bucket.lastRefillMs);
      bucket.tokens = Math.min(
        capacity,
        bucket.tokens + elapsed * refillRatePerMs
      );
      bucket.lastRefillMs = now;
    }

    if (bucket.tokens < 1) {
      return false;
    }
    bucket.tokens -= 1;
    return true;
  };

  const middleware = (req: Request, res: Response, next: NextFunction) => {
    const clientIp = extractClientIp(req);
    const fullPath = req.baseUrl ? `${req.baseUrl}${req.path}` : req.path;
    if (!check(clientIp, fullPath)) {
      res.setHeader('Retry-After', '3');
      res.status(429).json({
        ok: false,
        error:
          'Rate limit exceeded. Please wait before sending more requests.',
      });
      return;
    }
    next();
  };

  return {
    middleware,
    check,
    buckets,
    reset: () => buckets.clear(),
  };
}
