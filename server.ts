import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import {
  analyzeScamPayload,
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
  PersistedSettings,
  PersistedComplaintDrafts,
  PersistedUnfreezeCase,
  PersistedScamReports,
  PersistedTelegramMessage,
} from './src/utils/persistence';
import { FamilyMember } from './src/utils/seedData';

dotenv.config();

const PORT = 3000;

function getGeminiApiKey(): string | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || apiKey.trim() === '') {
    return null;
  }
  return apiKey.trim();
}

function getTelegramToken(): string | null {
  const raw = process.env.TELEGRAM_BOT_TOKEN;
  if (!raw || raw.trim() === '' || raw === 'YOUR_TELEGRAM_BOT_TOKEN') {
    return null;
  }
  return raw.trim();
}

function getExportToken(): string | null {
  const raw = process.env.EXPORT_TOKEN;
  if (!raw || raw.trim() === '' || raw === 'YOUR_EXPORT_TOKEN') {
    return null;
  }
  return raw.trim();
}

const EPHEMERAL_WEBHOOK_SECRET = crypto.randomBytes(24).toString('hex');

function getTelegramWebhookSecret(): string {
  const explicit = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (explicit && explicit.trim() !== '' && explicit !== 'YOUR_TELEGRAM_WEBHOOK_SECRET') {
    return explicit.trim();
  }
  const botToken = getTelegramToken();
  if (botToken) {
    return crypto
      .createHmac('sha256', botToken)
      .update('dhaal-telegram-webhook-secret')
      .digest('hex')
      .slice(0, 48);
  }
  return EPHEMERAL_WEBHOOK_SECRET;
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 15000
): Promise<Response> {
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

async function analyzeMediaWithGemini(
  base64Data: string,
  mimeType: string,
  promptText: string
): Promise<string | null> {
  const apiKey = getGeminiApiKey();
  if (!apiKey) return null;

  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key=${apiKey}`;
    const resp = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      20000
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

// Reusable Telegram send function used for user bot chats AND Family Group Alerts (Fix #3)
export async function sendTelegramBotMessage(
  token: string,
  chatId: string,
  text: string,
  replyToMessageId?: number
): Promise<boolean> {
  try {
    const payload: Record<string, any> = {
      chat_id: chatId,
      text,
      disable_web_page_preview: true,
    };
    if (replyToMessageId) {
      payload.reply_to_message_id = replyToMessageId;
      payload.allow_sending_without_reply = true;
    }
    const resp = await fetchWithTimeout(
      `https://api.telegram.org/bot${token}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
      10000
    );
    const data: any = await resp.json();
    if (!data?.ok) {
      console.warn(`[Telegram Send Warning] Failed sending to ${chatId}:`, data?.description);
    }
    return Boolean(data?.ok);
  } catch (err) {
    console.error(`[Telegram Send Error] Failed sending to ${chatId}:`, (err as Error)?.message);
    return false;
  }
}

export async function sendTelegramTypingAction(token: string, chatId: string): Promise<void> {
  try {
    await fetchWithTimeout(
      `https://api.telegram.org/bot${token}/sendChatAction`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, action: 'typing' }),
      },
      5000
    );
  } catch {
    // Non-blocking
  }
}

export async function downloadTelegramFileAsBase64(
  token: string,
  fileId: string
): Promise<{ base64: string; filePath: string } | null> {
  try {
    const metaResp = await fetchWithTimeout(
      `https://api.telegram.org/bot${token}/getFile?file_id=${encodeURIComponent(fileId)}`,
      {},
      10000
    );
    if (!metaResp.ok) return null;
    const metaJson: any = await metaResp.json();
    const filePath: string | undefined = metaJson?.result?.file_path;
    if (!filePath) return null;

    const fileResp = await fetchWithTimeout(
      `https://api.telegram.org/file/bot${token}/${filePath}`,
      {},
      15000
    );
    if (!fileResp.ok) return null;
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
  if (trimmed === '/start' || trimmed.startsWith('/start ') || trimmed === '/help') {
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
  if (iocs.phoneNumbers.length > 0) iocParts.push(`Phone: ${iocs.phoneNumbers.join(', ')}`);
  if (iocs.domains.length > 0) iocParts.push(`Links: ${iocs.domains.join(', ')}`);
  if (iocs.bankAccounts.length > 0) iocParts.push(`A/C: ${iocs.bankAccounts.join(', ')}`);
  if (iocParts.length > 0) {
    lines.push('', '🕵️ Extracted Scam Identifiers:', ...iocParts.map((p) => `• ${p}`));
  }

  if (analysis.nextMoves.length > 0) {
    const next = analysis.nextMoves[0];
    lines.push(
      '',
      `🔮 Predicted Next Scammer Move (${next.probabilityPct}% prob):`,
      `• "${next.actorMove}"`,
      `🛡️ Counter-Measure: ${next.counterMeasure}`
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

export function sanitizeMessagesForPublicView(messages: PersistedTelegramMessage[]) {
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
  app.use(express.json({ limit: '20mb' }));

  // Initialize Fix #1 storage (Path B: atomic local-disk with write locks)
  await initPersistenceStore();
  const dataDir = getDataDir();
  const settingsFilePath = path.join(dataDir, 'settings.json');
  const familyFilePath = path.join(dataDir, 'familyMembers.json');
  const complaintFilePath = path.join(dataDir, 'complaintDrafts.json');
  const unfreezeFilePath = path.join(dataDir, 'unfreezeCases.json');
  const scamReportsFilePath = path.join(dataDir, 'scamReports.json');
  const telegramMessagesFilePath = path.join(dataDir, 'telegramMessages.json');

  // In-memory Telegram de-duplication cache loaded from persistent settings
  const currentSettings = await readJsonFile<PersistedSettings>(
    settingsFilePath,
    getDefaultSettings()
  );
  let lastTelegramUpdateId = currentSettings.lastUpdateId || 0;
  const repliedUpdateIds = new Set<number>(currentSettings.repliedUpdateIds || []);
  const repliedMessageKeys = new Set<string>(currentSettings.repliedMessageKeys || []);
  const repliedMediaGroupIds = new Set<string>(currentSettings.repliedMediaGroupIds || []);

  async function persistTelegramDedupeState() {
    await updateJsonFileAtomically<PersistedSettings>(
      settingsFilePath,
      getDefaultSettings(),
      (curr) => ({
        ...curr,
        lastUpdateId: lastTelegramUpdateId,
        repliedUpdateIds: Array.from(repliedUpdateIds).slice(-1000),
        repliedMessageKeys: Array.from(repliedMessageKeys).slice(-1000),
        repliedMediaGroupIds: Array.from(repliedMediaGroupIds).slice(-500),
      })
    );
  }

  // Fix #8: Token-Bucket Rate Limiter per client IP via X-Forwarded-For
  const rateLimiter = createTokenBucketRateLimiter({ capacity: 20, refillPerMinute: 20 });
  app.use((req, res, next) => {
    // Apply rate limiter to all API POST routes
    if (req.method === 'POST' && req.path.startsWith('/api/')) {
      return rateLimiter.middleware(req, res, next);
    }
    next();
  });

  // Helper for logging disagreements between keyword engine and Gemini (Fix #6)
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

  // Fix #3 helper: Notify Family Group on Telegram if configured
  async function maybeNotifyFamilyTelegram(alertReason: string, payloadHeadline?: string) {
    const token = getTelegramToken();
    if (!token) return;
    const settings = await readJsonFile<PersistedSettings>(
      settingsFilePath,
      getDefaultSettings()
    );
    const groupId = (settings.familyTelegramChatId || '').trim();
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
  // API Routes
  // ============================================================================

  // Fix #2: Protected Export Endpoint (safety net, generic 404 without secret header, duress word redacted)
  app.get('/api/export', async (req, res) => {
    const configuredToken = getExportToken();
    const providedToken = req.headers['x-export-token'];

    if (!configuredToken || providedToken !== configuredToken) {
      // Return generic 404 so endpoint existence is not revealed
      res.status(404).send('Cannot GET /api/export');
      return;
    }

    try {
      const bundle = await buildRedactedExportBundle();
      res.status(200).json(bundle);
    } catch (err) {
      console.error('[Export Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to process export.' });
    }
  });

  // Settings Routes (Fix #1, Fix #3, Fix #4)
  app.get('/api/settings', async (_req, res) => {
    try {
      const settings = await readJsonFile<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings()
      );
      res.status(200).json(toPublicSettings(settings));
    } catch (err) {
      console.error('[Get Settings Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to retrieve settings.' });
    }
  });

  app.post('/api/settings', async (req, res) => {
    try {
      const {
        duressWord,
        dailyCode,
        familyTelegramChatId,
      }: {
        duressWord?: string;
        dailyCode?: string;
        familyTelegramChatId?: string;
      } = req.body || {};

      const updated = await updateJsonFileAtomically<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings(),
        (curr) => ({
          ...curr,
          duressWord:
            typeof duressWord === 'string' && duressWord.trim()
              ? duressWord.trim()
              : curr.duressWord,
          duressWordConfigured:
            typeof duressWord === 'string' && duressWord.trim()
              ? true
              : curr.duressWordConfigured,
          dailyCode:
            typeof dailyCode === 'string' && dailyCode.trim()
              ? dailyCode.trim()
              : curr.dailyCode,
          familyTelegramChatId:
            typeof familyTelegramChatId === 'string'
              ? familyTelegramChatId.trim()
              : curr.familyTelegramChatId,
        })
      );

      res.status(200).json({ ok: true, settings: toPublicSettings(updated) });
    } catch (err) {
      console.error('[Update Settings Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to save settings.' });
    }
  });

  // Duress Check Route (Fix #4: duress word evaluated server-side, never sent to client)
  app.post('/api/duress/check', async (req, res) => {
    try {
      const { spokenTranscript = '' }: { spokenTranscript?: string } = req.body || {};
      const settings = await readJsonFile<PersistedSettings>(
        settingsFilePath,
        getDefaultSettings()
      );
      const evalResult = checkDuressTrigger(spokenTranscript, settings.duressWord);

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
      console.error('[Duress Check Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to check duress trigger.' });
    }
  });

  // Family Members Routes (Fix #1: persistent GET, POST, DELETE)
  app.get('/api/family', async (_req, res) => {
    try {
      const members = await readJsonFile<FamilyMember[]>(familyFilePath, []);
      res.status(200).json({ ok: true, members });
    } catch (err) {
      console.error('[Get Family Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to load family members.' });
    }
  });

  app.post('/api/family', async (req, res) => {
    try {
      const memberInput = req.body || {};
      if (!memberInput.name || !memberInput.relation) {
        res.status(400).json({ error: 'Name and relation are required.' });
        return;
      }
      const newMember: FamilyMember = {
        id: `fam-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        name: String(memberInput.name).trim(),
        relation: String(memberInput.relation).trim(),
        phone: String(memberInput.phone || 'Not specified').trim(),
        language: memberInput.language || 'Hinglish',
        lastDrillScore: 85,
        status: 'PROTECTED',
      };

      const updated = await updateJsonFileAtomically<FamilyMember[]>(
        familyFilePath,
        [],
        (curr) => [...curr, newMember]
      );
      res.status(200).json({ ok: true, member: newMember, members: updated });
    } catch (err) {
      console.error('[Add Family Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to add family member.' });
    }
  });

  app.delete('/api/family/:id', async (req, res) => {
    try {
      const targetId = req.params.id;
      const updated = await updateJsonFileAtomically<FamilyMember[]>(
        familyFilePath,
        [],
        (curr) => curr.filter((m) => m.id !== targetId)
      );
      res.status(200).json({ ok: true, members: updated });
    } catch (err) {
      console.error('[Delete Family Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to remove family member.' });
    }
  });

  app.patch('/api/family/:id', async (req, res) => {
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
      console.error('[Patch Family Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to update family member.' });
    }
  });

  // Complaint Draft Routes (Fix #1)
  app.get('/api/complaint-draft', async (_req, res) => {
    try {
      const drafts = await readJsonFile<PersistedComplaintDrafts>(
        complaintFilePath,
        getDefaultComplaintDrafts()
      );
      res.status(200).json({ ok: true, draft: drafts.current });
    } catch (err) {
      console.error('[Get Complaint Draft Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to retrieve complaint draft.' });
    }
  });

  app.post('/api/complaint-draft', async (req, res) => {
    try {
      const draft = req.body;
      if (!draft || !draft.incidentId || !Array.isArray(draft.fields)) {
        res.status(400).json({ error: 'Invalid complaint draft payload.' });
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
      console.error('[Update Complaint Draft Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to update complaint draft.' });
    }
  });

  // Unfreeze Case Routes (Fix #1)
  app.get('/api/unfreeze-cases', async (_req, res) => {
    try {
      const cases = await readJsonFile<PersistedUnfreezeCase[]>(
        unfreezeFilePath,
        getDefaultUnfreezeCases()
      );
      res.status(200).json({ ok: true, cases });
    } catch (err) {
      console.error('[Get Unfreeze Cases Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to load unfreeze cases.' });
    }
  });

  app.post('/api/unfreeze-cases', async (req, res) => {
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
        policeNoticeStation: String(input.policeNoticeStation || 'Cyber Police Station'),
        ackNumber1930: String(input.ackNumber1930 || '30811260049182'),
      };
      const updated = await updateJsonFileAtomically<PersistedUnfreezeCase[]>(
        unfreezeFilePath,
        getDefaultUnfreezeCases(),
        (curr) => [newCase, ...curr].slice(0, 50)
      );
      res.status(200).json({ ok: true, case: newCase, cases: updated });
    } catch (err) {
      console.error('[Add Unfreeze Case Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to save unfreeze case.' });
    }
  });

  // Scam Radar Routes (Fix #1, Fix #5: persistent and idempotent)
  app.get('/api/scam-reports', async (_req, res) => {
    try {
      const reports = await readJsonFile<PersistedScamReports>(
        scamReportsFilePath,
        getDefaultScamReports()
      );
      res.status(200).json({ ok: true, nodes: reports.nodes || [] });
    } catch (err) {
      console.error('[Get Scam Reports Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to load scam reports.' });
    }
  });

  app.post('/api/scam-reports/upsert', async (req, res) => {
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
        res.status(400).json({ error: 'Primary node label is required.' });
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
      console.error('[Upsert Scam Node Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to update scam radar.' });
    }
  });

  app.post('/api/scam-reports/clear', async (_req, res) => {
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
      console.error('[Clear Scam Reports Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to clear scam reports.' });
    }
  });

  // Family Alert Broadcast Route (Fix #3: dispatches in-app and to configured Telegram group)
  app.post('/api/family/alert', async (req, res) => {
    try {
      const { reason = 'Emergency Alert', headline = '' } = req.body || {};
      await maybeNotifyFamilyTelegram(reason, headline);
      res.status(200).json({ ok: true, message: 'Alert recorded and dispatched.' });
    } catch (err) {
      console.error('[Family Alert Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to dispatch family alert.' });
    }
  });

  // Multimodal Upload Analysis Route (Hardened with Fix #5 Radar wire-up, Fix #6 Gemini escalation, Fix #10 safe error response)
  app.post('/api/analyze-media', async (req, res) => {
    try {
      const {
        mediaType,
        mimeType,
        base64Data,
        fileName,
        textContent,
        channel = 'sms',
      }: {
        mediaType: 'image' | 'audio' | 'text';
        mimeType?: string;
        base64Data?: string;
        fileName?: string;
        textContent?: string;
        channel?: 'whatsapp' | 'sms' | 'voice' | 'upi';
      } = req.body || {};

      const fileGuard = sanitizeUntrustedEvidence(fileName || '');
      const textGuard = sanitizeUntrustedEvidence(textContent || '');

      let extractedText = textGuard.sanitizedText;
      let extractionSource = 'Direct Text Input';
      let backgroundForensicContext = '';

      if (fileGuard.injectionDetected || textGuard.injectionDetected) {
        backgroundForensicContext += ' prompt_injection_attempt ignore previous instructions ';
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
            backgroundForensicContext += ' forged seal manipulated screenshot deepfake ';
          }
          if (ocrResult.includes('[PROMPT_INJECTION_ATTEMPT]')) {
            backgroundForensicContext += ' prompt_injection_attempt ignore previous instructions ';
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
            backgroundForensicContext += ' prompt_injection_attempt ignore previous instructions ';
          }
          extractedText = postGuard.sanitizedText;
          extractionSource = fileName || 'Uploaded Image';
        }

        if (!extractedText) {
          extractedText = `[Uploaded Screenshot: ${fileName || 'image_upload.png'}]`;
          extractionSource = fileName || 'Uploaded Image';
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
            backgroundForensicContext += ' [lottery_prize_scam] fake lottery prize ';
          }
          if (transResult.includes('[SYNTHETIC_VOICE_CLONE]')) {
            backgroundForensicContext += ' synthetic voice clone deepfake audio ';
          }
          if (transResult.includes('[DIGITAL_ARREST_COERCION]')) {
            backgroundForensicContext += ' digital arrest police cbi warrant ';
          }
          if (transResult.includes('[FAKE_DELIVERY_TRAP]')) {
            backgroundForensicContext += ' fake courier delivery cancellation ';
          }
          if (transResult.includes('[PROMPT_INJECTION_ATTEMPT]')) {
            backgroundForensicContext += ' prompt_injection_attempt ignore previous instructions ';
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
            backgroundForensicContext += ' prompt_injection_attempt ignore previous instructions ';
          }
          extractedText = postGuard.sanitizedText;
          extractionSource = fileName || 'Uploaded Audio';
        }

        if (!extractedText) {
          extractedText = `[Uploaded Audio Recording: ${fileName || 'voice_recording.mp3'}]`;
          extractionSource = fileName || 'Uploaded Audio';
        }
      }

      const effectiveChannel = mediaType === 'audio' ? 'voice' : channel || 'sms';
      const fullText = `${extractedText} ${fileName || ''} ${backgroundForensicContext}`.trim();

      // Fix #6: Two-pass analysis (keyword engine + calibrated Gemini escalation for ambiguous cases with 5s fallback)
      const aiResult = await analyzeScamPayloadWithAI(fullText, effectiveChannel, {
        imageMetadata: { fileName, mimeType, mediaType },
        onDisagreement: logDisagreement,
      });

      const analysis = aiResult.result;

      // Fix #5: Automatically write node/edge into scamReports.json idempotently
      await recordAnalysisToScamReports(analysis, extractionSource);

      // Fix #3: If high-risk threat (Level 3 or 4), alert family Telegram group
      if (analysis.threatLevel >= 3) {
        maybeNotifyFamilyTelegram(
          `High-Risk Verdict (${analysis.riskScore}/100 · ${analysis.threatLabel})`,
          analysis.headlineEn
        ).catch(() => {});
      }

      res.status(200).json({
        ok: true,
        extractedText,
        extractionSource,
        analysis,
        escalated: aiResult.escalated,
        fallbackUsed: aiResult.fallbackUsed,
      });
    } catch (err: any) {
      console.error('[Analyze Media Error]', err);
      // Fix #10: Return generic message to client without leaking raw error internals
      res.status(500).json({
        ok: false,
        error: 'Failed to analyze uploaded media. Please try again.',
      });
    }
  });

  // ============================================================================
  // Telegram Bot Update Ingestion Handler (Shared by Webhook and Polling)
  // ============================================================================
  async function processTelegramUpdate(
    token: string,
    update: any
  ): Promise<PersistedTelegramMessage | null> {
    if (!update || typeof update.update_id !== 'number') return null;

    if (update.update_id > lastTelegramUpdateId) {
      lastTelegramUpdateId = update.update_id;
    }

    if (repliedUpdateIds.has(update.update_id)) {
      return null;
    }

    const msg = update.message || update.channel_post;
    if (!msg || !msg.chat) {
      repliedUpdateIds.add(update.update_id);
      await persistTelegramDedupeState();
      return null;
    }

    if (msg.from?.is_bot) {
      repliedUpdateIds.add(update.update_id);
      await persistTelegramDedupeState();
      return null;
    }

    const rawChatId = String(msg.chat.id);
    const messageKey = `${rawChatId}:${msg.message_id}`;
    const mediaGroupKey = msg.media_group_id ? `${rawChatId}:${msg.media_group_id}` : null;

    if (
      repliedMessageKeys.has(messageKey) ||
      (mediaGroupKey && repliedMediaGroupIds.has(mediaGroupKey))
    ) {
      repliedUpdateIds.add(update.update_id);
      await persistTelegramDedupeState();
      return null;
    }

    // Synchronously lock out duplicate execution immediately
    repliedUpdateIds.add(update.update_id);
    repliedMessageKeys.add(messageKey);
    if (mediaGroupKey) repliedMediaGroupIds.add(mediaGroupKey);
    await persistTelegramDedupeState();

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
    let forensicMarkers = textSanitized.injectionDetected
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
      const downloaded = await downloadTelegramFileAsBase64(token, targetFileId);
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
      if (!extractedText) extractedText = msg.caption || '[Attached Photo Screenshot]';
    } else if (msg.voice || msg.audio) {
      mediaType = 'audio';
      channel = 'voice';
      const audioObj = msg.voice || msg.audio;
      const downloaded = await downloadTelegramFileAsBase64(token, audioObj.file_id);
      if (downloaded) {
        const audioPrompt = `Transcribe this Telegram voice recording verbatim. Append applicable forensic tags.`;
        const transResult = await analyzeMediaWithGemini(
          downloaded.base64,
          audioObj.mime_type || 'audio/ogg',
          audioPrompt
        );
        if (transResult) {
          const cleanText = transResult.replace(/^TRANSCRIPT:\s*/im, '').replace(/FLAGS:.*$/im, '').trim();
          extractedText = [msg.caption, cleanText].filter(Boolean).join(' — ');
          extractionSource = `Attached Voice Recording (${downloaded.filePath})`;
        }
      }
      if (!extractedText) extractedText = msg.caption || '[Attached Voice Recording]';
    } else if (msg.document && msg.document.file_id) {
      const docName = msg.document.file_name || 'document.txt';
      const downloaded = await downloadTelegramFileAsBase64(token, msg.document.file_id);
      if (downloaded) {
        const rawTextDoc = Buffer.from(downloaded.base64, 'base64').toString('utf8').slice(0, 8000);
        extractedText = [msg.caption, rawTextDoc].filter(Boolean).join(' — ');
        extractionSource = `Attached Document (${docName})`;
      }
    }

    if (!extractedText) return null;

    // Run two-pass forensic analysis
    const aiResult = await analyzeScamPayloadWithAI(
      `${extractedText} ${forensicMarkers}`.trim(),
      channel,
      { onDisagreement: logDisagreement }
    );
    const analysis = aiResult.result;

    // Fix #5: Update Scam Radar idempotently
    await recordAnalysisToScamReports(analysis, extractionSource);

    // Format single reply and send
    const botReplyText = formatTelegramBotReply(analysis, extractedText, mediaType);
    const repliedInTelegram = await sendTelegramBotMessage(token, rawChatId, botReplyText);

    // If severe scam, alert family group
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
        new Date((msg.date || Math.floor(Date.now() / 1000)) * 1000).toLocaleTimeString('en-IN', {
          hour12: false,
        }) + ' IST',
      analysis,
      botReplyText,
      repliedInTelegram,
    };

    // Store in telegramMessages.json (capped at 200 entries, Fix #1)
    await updateJsonFileAtomically<PersistedTelegramMessage[]>(
      telegramMessagesFilePath,
      [],
      (curr) => {
        const filtered = curr.filter((m) => m.updateId !== importedItem.updateId);
        return [importedItem, ...filtered].slice(0, 200);
      }
    );

    return importedItem;
  }

  // Fix #7: Primary Webhook Route with Secret Header Validation and Rate Limiting
  app.post('/api/telegram/webhook', async (req, res) => {
    const secretHeader = req.headers['x-telegram-bot-api-secret-token'];
    if (secretHeader !== getTelegramWebhookSecret()) {
      // Cheap rejection for flood/secret-mismatched requests
      res.status(403).json({ error: 'Access denied: invalid secret token' });
      return;
    }

    const token = getTelegramToken();
    if (!token) {
      res.status(200).json({ ok: false, error: 'Telegram bot token not configured' });
      return;
    }

    try {
      const update = req.body;
      const imported = await processTelegramUpdate(token, update);
      res.status(200).json({ ok: true, processed: Boolean(imported) });
    } catch (err) {
      console.error('[Telegram Webhook Error]', (err as Error)?.message);
      res.status(500).json({ error: 'Failed to process Telegram webhook update.' });
    }
  });

  // Polling Fallback Loop (Kept verified as fallback, Fix #7)
  let isPollingTelegram = false;
  let lastPollStartedAt = 0;

  async function pollTelegramUpdatesAndAutoReply(): Promise<{
    ok: boolean;
    error?: string;
    newlyImported: PersistedTelegramMessage[];
  }> {
    const token = getTelegramToken();
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
        return { ok: false, error: 'Telegram polling returned non-ok', newlyImported: [] };
      }

      for (const update of tgData.result) {
        const item = await processTelegramUpdate(token, update);
        if (item) newlyImported.push(item);
      }

      return { ok: true, newlyImported };
    } catch (err) {
      return { ok: false, error: (err as Error)?.message, newlyImported: [] };
    } finally {
      isPollingTelegram = false;
    }
  }

  // Continuous background polling loop (runs independently of browser state)
  setInterval(() => {
    if (getTelegramToken()) {
      pollTelegramUpdatesAndAutoReply().catch(() => {});
    }
  }, 2500);

  app.get('/api/telegram/status', async (_req, res) => {
    const token = getTelegramToken();
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
  });

  app.post('/api/telegram/sync', async (req, res) => {
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
        const nowStr = new Date().toLocaleTimeString('en-IN', { hour12: false }) + ' IST';
        let chatId = '-100219847102';
        let chatTitle = 'Family Cyber Watch Group';
        let chatType: 'private' | 'group' | 'supergroup' | 'channel' = 'supergroup';
        let senderName = 'Ramesh Uncle';
        let forwardedFrom: string | null = 'CBI Cyber Dispatch Desk (+91 9820194812)';
        let extractedText = '';
        let extractionSource = '';
        let channel: 'whatsapp' | 'sms' | 'voice' | 'upi' = 'sms';

        if (simulateType === 'text') {
          chatId = cleanFilter ? chatIdFilter.trim() : '648910234';
          chatTitle = 'Direct Bot DM (Forwarded Scam)';
          chatType = 'private';
          senderName = 'You (Forwarded to Bot)';
          forwardedFrom = 'SEBI Institutional VIP Block Deal (@sebi_vip_pump)';
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
          extractionSource = 'Telegram Bot getFile + Gemini OCR (Photo Screenshot)';
          channel = 'sms';
        } else {
          chatId = cleanFilter ? chatIdFilter.trim() : '-100219847102';
          chatTitle = 'Sharma Family Protection Group';
          chatType = 'supergroup';
          senderName = 'Vikram (Cousin)';
          forwardedFrom = 'Unknown Caller Voice Note';
          extractedText =
            '[Telegram Voice Note · voice_049.ogg] "Hello, main BESCOM electricity office se officer bol raha hoon. Aaj raat 9:30 baje aapka bijli connection kat jayega kyunki KYC update nahi hua. Turant +91 8892019283 par call karke BESCOM-Support.apk install karo aur ₹10 UPI collect request approve karo."';
          extractionSource = 'Telegram Bot getFile + Gemini Audio Transcription (Voice Note)';
          channel = 'voice';
        }

        const aiResult = await analyzeScamPayloadWithAI(extractedText, channel);
        const analysis = aiResult.result;
        await recordAnalysisToScamReports(analysis, extractionSource);
        const botReplyText = formatTelegramBotReply(analysis, extractedText, simulateType);

        const token = getTelegramToken();
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

        const allStored = await updateJsonFileAtomically<PersistedTelegramMessage[]>(
          telegramMessagesFilePath,
          [],
          (curr) => [simMsg, ...curr].slice(0, 200)
        );
        newlyImported.push(simMsg);

        res.status(200).json({
          ok: true,
          configured: Boolean(getTelegramToken()),
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
    } catch (err: any) {
      console.error('[Telegram Sync Error]', err);
      res.status(500).json({
        ok: false,
        error: 'Failed to sync with Telegram Bot API.',
      });
    }
  });

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

startServer();
