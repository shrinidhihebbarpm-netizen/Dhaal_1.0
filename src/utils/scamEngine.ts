export type LanguageMode = 'en' | 'hinglish' | 'hi';

export type ThreatLevel = 0 | 1 | 2 | 3 | 4;

export interface NextMoveStep {
  stepNumber: number;
  actorMove: string;
  actorMoveHinglish: string;
  actorMoveHi: string;
  probabilityPct: number;
  timeWindow: string;
  counterMeasure: string;
}

export interface ExtractedIOCs {
  upiIds: string[];
  phoneNumbers: string[];
  bankAccounts: string[];
  domains: string[];
  impersonatedEntity: string;
}

export interface ScamAnalysisResult {
  id: string;
  timestamp: string;
  channel: 'whatsapp' | 'sms' | 'voice' | 'upi';
  riskScore: number; // 0 - 100
  threatLevel: ThreatLevel; // 0: Safe, 1: Caution, 2: Warning, 3: Severe, 4: Critical
  meterBlocks: number; // 1 - 10 discrete blocks
  threatColor: string;
  threatLabel: string;
  categoryCode:
    | 'DIGITAL_ARREST_COERCION'
    | 'UPI_COLLECT_TRAP'
    | 'STOCK_VIP_PUMP'
    | 'FAKE_KYC_UTILITY'
    | 'FAKE_DELIVERY_TRAP'
    | 'LOTTERY_PRIZE_SCAM'
    | 'VOICE_CLONE_SOS'
    | 'VERIFIED_CLEAN';
  headlineEn: string;
  headlineHinglish: string;
  headlineHi: string;
  summaryEn: string;
  summaryHinglish: string;
  summaryHi: string;
  pauseBeforePayRequired: boolean;
  pauseDurationSeconds: number;
  triggersDetected: string[];
  extractedIOCs: ExtractedIOCs;
  nextMoves: NextMoveStep[];
}

export interface OutbreakPoint {
  hour: number;
  unmitigatedVictims: number;
  mitigatedVictims: number;
  preWarningsSent: number;
}

export interface OutbreakSimulationResult {
  effectiveR: number;
  unmitigatedTotal: number;
  mitigatedTotal: number;
  victimsSaved: number;
  paisaSavedLakhs: number;
  points: OutbreakPoint[];
}

export interface AiGuardEvaluation {
  quarantined: boolean;
  tripwireCode: string | null;
  confidencePct: number;
  action: 'CONTINUE_STING' | 'QUARANTINE_SESSION';
  reason: string;
}

export interface ComplaintField {
  key: string;
  label: string;
  value: string;
  aiDrafted: boolean;
  verifiedByUser: boolean;
}

export interface ComplaintDraft {
  incidentId: string;
  ncrpCategory: string;
  fields: ComplaintField[];
}

export interface UnfreezeCaseInput {
  bankName: string;
  accountMask: string;
  totalBalanceInr: number;
  disputedTransactionInr: number;
  freezeType: 'FULL_DEBIT_FREEZE' | 'LIEN_MARKED';
  policeNoticeStation: string;
  ackNumber1930: string;
}

export interface UnfreezeAssessment {
  isDisproportionateFreeze: boolean;
  excessFrozenInr: number;
  legalGrounds: string[];
  petitionText: string;
}

const THREAT_COLORS: Record<ThreatLevel, string> = {
  0: '#43AA8B', // Level 0 Safe - Hardened Green
  1: '#F9C74F', // Level 1 Caution - Sunflower Gold
  2: '#F8961E', // Level 2 Warning - Tangerine
  3: '#F3722C', // Level 3 Severe - Deep Orange
  4: '#F94144', // Level 4 Critical - Intercept Red
};

const THREAT_LABELS: Record<ThreatLevel, string> = {
  0: 'LEVEL 0 · VERIFIED SAFE',
  1: 'LEVEL 1 · CAUTION DRIFT',
  2: 'LEVEL 2 · SUSPICIOUS VECTOR',
  3: 'LEVEL 3 · HIGH RISK FRAUD',
  4: 'LEVEL 4 · CRITICAL INTERCEPT',
};

function decodeBase64Snippets(input: string): string {
  const matches = input.match(/\b[A-Za-z0-9+/]{16,}={0,2}\b/g);
  if (!matches) return '';
  const decodedParts: string[] = [];
  for (const token of matches.slice(0, 8)) {
    try {
      const decoded =
        typeof Buffer !== 'undefined'
          ? Buffer.from(token, 'base64').toString('utf8')
          : typeof atob === 'function'
          ? atob(token)
          : '';
      if (decoded && /^[\x20-\x7E\s]{6,}$/.test(decoded)) {
        decodedParts.push(decoded);
      }
    } catch {
      // Ignore invalid base64 tokens
    }
  }
  return decodedParts.join(' ');
}

function normalizeAndDeobfuscateText(raw: string): string {
  if (!raw) return '';

  // 1. Decode invisible Unicode Tag characters (U+E0020..U+E007E) used by crackers for hidden prompt injection
  let unicodeDecoded = '';
  for (const ch of raw) {
    const cp = ch.codePointAt(0) || 0;
    if (cp >= 0xe0020 && cp <= 0xe007e) {
      unicodeDecoded += String.fromCodePoint(cp - 0xe0000);
    } else {
      unicodeDecoded += ch;
    }
  }

  let cleaned = unicodeDecoded
    // Strip zero-width & invisible unicode characters
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, '')
    // Normalize common leetspeak substitutions inside alphabetic words
    .replace(/(?<=[a-zA-Z])0(?=[a-zA-Z])/g, 'o')
    .replace(/(?<=[a-zA-Z])1(?=[a-zA-Z])/g, 'i')
    .replace(/(?<=[a-zA-Z])3(?=[a-zA-Z])/g, 'e')
    .replace(/(?<=[a-zA-Z])4(?=[a-zA-Z])/g, 'a')
    .replace(/(?<=[a-zA-Z])\$(?=[a-zA-Z])/g, 's');

  // Collapse spaced-out UPI handles like "rbi . verify99 @ okaxis" -> "rbi.verify99@okaxis"
  cleaned = cleaned.replace(
    /([a-zA-Z0-9_-]{2,25})\s*\.\s*([a-zA-Z0-9_-]{2,25})\s*@\s*([a-zA-Z]{2,20})/g,
    '$1.$2@$3'
  );
  cleaned = cleaned.replace(
    /([a-zA-Z0-9._-]{2,40})\s*@\s*(okaxis|okhdfcbank|okicici|oksbi|ybl|paytm|ibl|axl|apl|upi|icici|sbi|hdfcbank|kotak|axisbank|yesbank|barodampay)\b/gi,
    '$1@$2'
  );

  // Collapse any spaced, dotted, or dashed 10-digit Indian mobile number (e.g. "+91 982 019 4812", "98 20 19 48 12", "98201-94812")
  cleaned = cleaned.replace(
    /(?:\+91[\s.-]*)?([6-9](?:[\s.-]*\d){9})\b/g,
    (_m, digits: string) => digits.replace(/\D/g, '')
  );

  // Collapse single-character spaced or dotted obfuscation (e.g. "d i g i t a l" or "d.i.g.i.t.a.l")
  cleaned = cleaned.replace(/\b(?:[a-zA-Z]\.){3,}[a-zA-Z]\b/g, (m) =>
    m.replace(/\./g, '')
  );
  cleaned = cleaned.replace(
    /\b([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])\s+([a-zA-Z])(?:\s+([a-zA-Z]))?(?:\s+([a-zA-Z]))?(?:\s+([a-zA-Z]))?\b/g,
    (_m, c1, c2, c3, c4, c5, c6, c7) =>
      [c1, c2, c3, c4, c5, c6, c7].filter(Boolean).join('')
  );

  // Append any decoded Base64 payload so hidden base64 prompt-injections are exposed to the scanner
  const decodedB64 = decodeBase64Snippets(raw);
  if (decodedB64) {
    cleaned = `${cleaned}\n${decodedB64}`;
  }

  return cleaned;
}

export function sanitizeUntrustedEvidence(rawInput: string): {
  sanitizedText: string;
  injectionDetected: boolean;
  tripwireCode: string | null;
  reason: string | null;
} {
  const raw = (rawInput || '').trim();
  const guard = evaluateAiGuardSession(raw);
  // Strip LLM control tokens and role delimiters so untrusted text can never break prompt boundaries
  const sanitizedText = raw
    .replace(/<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>/gi, '[STRIPPED_TOKEN]')
    .replace(/\[\/?INST\]|<<\/?SYS>>|<\/?system>/gi, '[STRIPPED_DELIMITER]')
    .replace(/###\s*(system|instruction|assistant|developer)\s*:/gi, '[STRIPPED_ROLE]:');

  return {
    sanitizedText,
    injectionDetected: guard.quarantined,
    tripwireCode: guard.tripwireCode,
    reason: guard.quarantined ? guard.reason : null,
  };
}

function matchesAny(text: string, patterns: Array<string | RegExp>): boolean {
  for (const p of patterns) {
    if (typeof p === 'string') {
      if (text.includes(p)) return true;
    } else if (p.test(text)) {
      return true;
    }
  }
  return false;
}

export function extractIOCsFromText(text: string): ExtractedIOCs {
  const deobfuscated = normalizeAndDeobfuscateText(text);
  const combined = `${text}\n${deobfuscated}`;

  const upiRegex = /[a-zA-Z0-9.\-_]{2,40}@[a-zA-Z]{2,20}/g;
  const phoneRegex = /(?:\+91[\s-]?)?[6-9]\d{9}\b/g;
  const acctRegex = /\b\d{11,16}\b/g;
  const urlRegex =
    /(?:https?:\/\/|www\.|[a-zA-Z0-9-]+\.(?:apk|in|com|org|net|xyz|top|click|link|online|site|info|me|ly)\/?)[^\s,)"']*/gi;

  const rawUpi = Array.from(new Set(combined.match(upiRegex) || [])).filter(
    (u) => !u.endsWith('.com') && !u.endsWith('.in') && !u.endsWith('.org')
  );
  const rawPhones = Array.from(new Set(combined.match(phoneRegex) || [])).map((p) =>
    p.replace(/\D/g, '').slice(-10)
  );
  const phoneNumbers = Array.from(new Set(rawPhones));
  const bankAccounts = Array.from(
    new Set((combined.match(acctRegex) || []).filter((a) => !phoneNumbers.includes(a.slice(-10))))
  );
  const rawDomains = Array.from(
    new Set(
      (combined.match(urlRegex) || []).filter(
        (d) => !rawUpi.some((u) => d.includes(u))
      )
    )
  );

  const LEGIT_OFFICIAL_ROOTS = [
    'rbi.org.in',
    'gov.in',
    'nic.in',
    'incometax.gov.in',
    'cybercrime.gov.in',
    'sbi.co.in',
    'hdfcbank.com',
    'icicibank.com',
    'axisbank.com',
    'punjabnationalbank.in',
    'bankofbaroda.in',
    'canarabank.com',
    'indiapost.gov.in',
    'ceir.gov.in',
    'sancharsaathi.gov.in',
  ];

  const isLegitDomain = (url: string) => {
    try {
      const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
      const host = parsed.hostname.toLowerCase();
      return LEGIT_OFFICIAL_ROOTS.some((root) => host === root || host.endsWith(`.${root}`));
    } catch {
      return false;
    }
  };

  // Only treat external domains as untrusted IOCs if they are NOT verified official government/bank domains
  const domains = rawDomains.filter((d) => !isLegitDomain(d));

  const lower = combined.toLowerCase();
  let impersonatedEntity = 'None Detected';
  if (
    matchesAny(lower, [
      'cbi',
      'narcotics',
      'ncb',
      'customs',
      'fedex',
      'dhl',
      'trai',
      'cyber crime',
      'cyber cell',
      'enforcement directorate',
      'mumbai police',
      'delhi police',
      'सीबीआई',
      'पुलिस',
      'कस्टम्स',
      'नारकोटिक्स',
    ])
  ) {
    impersonatedEntity = 'CBI / Narcotics Control Bureau / Customs';
  } else if (
    matchesAny(lower, [
      'rbi',
      'reserve bank',
      'supreme court',
      'high court',
      'magistrate',
      'chief justice',
      'income tax',
      'सुप्रीम कोर्ट',
      'रिजर्व बैंक',
    ])
  ) {
    impersonatedEntity = 'Reserve Bank of India / Judiciary';
  } else if (
    matchesAny(lower, [
      'sebi',
      'ipo',
      'institutional',
      'upper circuit',
      'block deal',
      'foreign institutional',
      'stock',
      'trading group',
    ])
  ) {
    impersonatedEntity = 'SEBI Registered Broker (Spoofed)';
  } else if (
    matchesAny(lower, [
      'bescom',
      'electricity',
      'mseb',
      'msedcl',
      'tneb',
      'pan card',
      'sbi',
      'hdfc',
      'icici',
      'axis bank',
      'kyc',
      'fastag',
      'bijli',
      'बिजली',
      'केवाईसी',
    ])
  ) {
    impersonatedEntity = 'Banking / Utility KYC Desk';
  } else if (
    matchesAny(lower, [
      'voice clone',
      'deepfake',
      'ai generated',
      'synthetic',
      'hospital',
      'accident',
      'kidnap',
      'papa',
      'mummy',
      'beta',
      'my phone broke',
      'friend number',
      'अस्पताल',
      'एक्सीडेंट',
    ])
  ) {
    impersonatedEntity = 'Distressed Family Member / AI Voice Clone';
  }

  return {
    upiIds: rawUpi,
    phoneNumbers,
    bankAccounts,
    domains,
    impersonatedEntity,
  };
}

export function analyzeScamPayload(
  rawText: string,
  channel: 'whatsapp' | 'sms' | 'voice' | 'upi' = 'whatsapp'
): ScamAnalysisResult {
  const text = (rawText || '').trim();
  const normalized = normalizeAndDeobfuscateText(text);
  const lower = `${text.toLowerCase()}\n${normalized.toLowerCase()}`;
  const iocs = extractIOCsFromText(text);

  if (!text) {
    return {
      id: 'SCAN-EMPTY',
      timestamp: new Date().toISOString(),
      channel,
      riskScore: 0,
      threatLevel: 0,
      meterBlocks: 1,
      threatColor: THREAT_COLORS[0],
      threatLabel: THREAT_LABELS[0],
      categoryCode: 'VERIFIED_CLEAN',
      headlineEn: 'Awaiting payload input for analysis',
      headlineHinglish: 'Scan ke liye message ya voice transcript daalein',
      headlineHi: 'विश्लेषण के लिए संदेश या ऑडियो ट्रांसक्रिप्ट दर्ज करें',
      summaryEn: 'Paste any WhatsApp message, SMS link, UPI collect request, or call transcript.',
      summaryHinglish: 'Koi bhi shakiya WhatsApp message, UPI ID ya call transcript yahan check karein.',
      summaryHi: 'कोई भी संदिग्ध व्हाट्सएप संदेश, यूपीआई आईडी या कॉल ट्रांसक्रिप्ट यहाँ जांचें।',
      pauseBeforePayRequired: false,
      pauseDurationSeconds: 0,
      triggersDetected: [],
      extractedIOCs: iocs,
      nextMoves: [],
    };
  }

  const triggers: string[] = [];
  let score = 8;

  // 0a. Silent Background AI Guard Tripwire (Quarantines Adversarial Prompt-Injection / Scanner Bypass Attempts)
  const aiGuardCheck = evaluateAiGuardSession(lower);
  const isAiGuardQuarantined = aiGuardCheck.quarantined;

  // 0b. Silent Background Detection of AI-Generated / Deepfake / Synthetic Forgery Markers
  const hasAiSyntheticMarker = matchesAny(lower, [
    'deepfake',
    'ai-generated',
    'ai generated',
    'synthetic voice',
    'cloned voice',
    'voice clone',
    'forged seal',
    'manipulated screenshot',
    'synthetic media',
    'forged document',
    'fake warrant',
    'spoofed caller',
  ]);

  // 1. Digital Arrest / Fake Law Enforcement / Courier Parcel Coercion (EN + Hinglish + Hindi)
  const isDigitalArrest = matchesAny(lower, [
    'digital arrest',
    'fedex',
    'dhl',
    'mdma',
    'narcotics',
    'ncb',
    'cbi',
    'enforcement directorate',
    'skype',
    'money laundering',
    'arrest warrant',
    'non-bailable',
    'non bailable',
    'supreme court',
    'verification bond',
    'supervision account',
    'escrow account',
    'secret supervision',
    'parcel pakda',
    'parcel seized',
    'aadhaar linked to crime',
    'video call arrest',
    'stay on video',
    'do not disconnect',
    'national security',
    'डिजिटल अरेस्ट',
    'सीबीआई',
    'अरेस्ट वारंट',
    'सुप्रीम कोर्ट',
    'मनी लॉन्ड्रिंग',
    'नारकोटिक्स',
    'पार्सल',
  ]);

  // 2. AI Voice Clone / Relative-in-Distress Emergency SOS Scam
  const isVoiceCloneSos = matchesAny(lower, [
    'voice clone',
    'cloned voice',
    'synthetic voice',
    'deepfake audio',
    'in an accident',
    'met with an accident',
    'admitted in hospital',
    'icu emergency',
    'police lockup',
    'hit someone with car',
    'my phone broke',
    'phone is broken',
    'calling from friend',
    'new number papa',
    'new number mummy',
    'send money to my friend',
    'doctor won’t start surgery',
    'bail money',
    'papa main',
    'mummy main',
    'अस्पताल में भर्ती',
    'एक्सीडेंट हो गया',
    'फोन टूट गया',
  ]);

  // 3. UPI Collect / Wrong Transfer Refund Trap / QR Scan Debit Trap
  const isUpiTrap = matchesAny(lower, [
    'sent by mistake',
    'transferred by mistake',
    'enter upi pin',
    'enter your pin',
    'input upi pin',
    'scan qr to receive',
    'scan qr code to get',
    'receive money',
    'collect request',
    'approve collect',
    'galti se',
    'wapas bhej',
    'wapas kar',
    'refund link',
    'approve refund',
    'army officer olx',
    'cisf officer payment',
    'गलती से पैसे',
    'यूपीआई पिन डालें',
    'कलेक्ट रिक्वेस्ट',
  ]);

  // 4. Fake KYC / APK Malware / Electricity Cutoff / Remote Screen Share
  const isKycUtility = matchesAny(lower, [
    '.apk',
    'electricity',
    'bijli',
    'power will be disconnected',
    'connection kat jayega',
    'tonight at 9:30',
    'tonight at 10',
    'pan card blocked',
    'account suspended',
    'sim card block',
    'kyc update',
    'kyc expired',
    'update pan',
    'anydesk',
    'rustdesk',
    'teamviewer',
    'quicksupport',
    'screen share',
    'bescom',
    'msedcl',
    'fastag blocked',
    'बिजली कनेक्शन कट',
    'केवाईसी अपडेट',
    'पैन कार्ड बंद',
  ]);

  // 5. Stock / Task / VIP Investment / Pig-Butchering / Prepaid Review Trap
  const isStockPump = matchesAny(lower, [
    'guaranteed return',
    'upper circuit',
    'institutional account',
    'block deal',
    'vip group',
    'telegram task',
    'youtube like task',
    'google maps review',
    'prepaid task',
    'double your',
    'pre-ipo',
    'sebi release tax',
    'withdrawal fee',
    'unfreeze fee',
    'daily profit',
    '200% return',
    '300% profit',
    'गारंटीड रिटर्न',
    'डबल मुनाफा',
    'टेलीग्राम टास्क',
  ]);

  // 5b. Fake Courier / Delivery Cancellation Trap / E-Commerce Phishing
  const isFakeDeliveryTrap = matchesAny(lower, [
    'cancellation request',
    'cancel delivery',
    'i want delivery',
    'delivery cancellation',
    'order cancellation',
    'jio home delivery',
    'jio order',
    'parcel on hold',
    'delivery failed',
    'address incomplete',
    'package pending',
    'update delivery address',
    'reschedule delivery',
    'pay re-delivery',
    'redelivery fee',
    'delivery boy number',
    'courier boy',
    'indiapost parcel',
    'india post speed post',
    'speedpost hold',
    'पार्सल डिलीवरी',
    'ऑर्डर कैंसिल',
  ]);

  // 5c. Fake Lottery / Lucky Draw / Prize Reward Phishing & Bank Detail Harvesting
  const hasLotteryOrPrizeSignal = matchesAny(lower, [
    'lottery',
    'international lottery',
    'lucky winner',
    'lucky draw',
    'you have won',
    'you\'ve won',
    'have won',
    'won $',
    'won £',
    'won €',
    'won inr',
    'won rs',
    'won ₹',
    'won five hundred',
    'won 500',
    'claim your prize',
    'claim the prize',
    'claim your reward',
    'claim prize',
    'claim reward',
    'cash prize',
    'prize money',
    'selected as the lucky',
    'congratulations you have won',
    'congratulations, you have won',
    'mega jackpot',
    'kbc lottery',
    'kaun banega crorepati',
    'जीता है',
    'जीत पाने के लिए',
    'रुपए जीता',
    'रुपये जीता',
    'रुपया जीता',
    'लॉटरी',
    'लकी ड्रा',
    'लकी ड्रॉ',
    'इनाम जीता',
    'इनाम मिला',
    'इनाम पाने के लिए',
    'पुरस्कार जीता',
    'जैकपॉट',
    'केबीसी लॉटरी',
    'लकी विनर',
    'jeeta hai',
    'jeetne par',
    'inaam mila',
    'inaam jeeta',
    'lottery lagi',
    'lucky draw winner',
    'prize claim',
    '[lottery_prize_scam]',
  ]);

  const hasDetailOrAdvanceDemandSignal = matchesAny(lower, [
    'send your bank details',
    'send bank details',
    'bank details',
    'account details',
    'reply with your details',
    'send your details',
    'send details',
    'share details',
    'account number',
    'bank account',
    'contact us and send',
    'claim before it expires',
    'before it expires',
    'processing fee',
    'conversion fee',
    'clearance fee',
    'अकाउंट डिटेल्स सेंड करें',
    'अकाउंट डिटेल्स भेजें',
    'बैंक डिटेल्स भेजें',
    'बैंक डिटेल्स',
    'खाता विवरण',
    'अकाउंट डिटेल्स',
    'बैंक खाता',
    'डिटेल्स सेंड करें',
    'details send karein',
    'account details bhejo',
    'bank details bhejo',
  ]);

  const isLotteryPrizeTrap =
    hasLotteryOrPrizeSignal &&
    (hasDetailOrAdvanceDemandSignal ||
      lower.includes('reply with') ||
      lower.includes('contact us') ||
      lower.includes('expires') ||
      lower.includes('सेंड करें') ||
      lower.includes('भेजें') ||
      lower.includes('send') ||
      lower.includes('[lottery_prize_scam]'));


  // 6. Multi-Signal Behavioral & Semantic Matrix (Catches Novel, Paraphrased & AI-Generated Scams)
  const hasAuthorityOrImpersonationSignal = matchesAny(lower, [
    'officer',
    'inspector',
    'commissioner',
    'magistrate',
    'judge',
    'ministry',
    'department',
    'cyber',
    'police',
    'customs',
    'bureau',
    'nodal',
    'bank manager',
    'rbi',
    'sebi',
    'trai',
    'income tax',
    'vigilance',
    'embassy',
    'warrant',
    'summons',
    'fir ',
    'subpoena',
    'अधिकारी',
    'इंस्पेक्टर',
    'नोडल',
  ]);

  const hasUrgencyOrCoercionSignal = matchesAny(lower, [
    'urgent',
    'immediately',
    'immediate',
    'right now',
    'within 15',
    'within 30',
    'within 10',
    'within 2 hours',
    'tonight',
    'freeze',
    'frozen',
    'blocked',
    'suspended',
    'terminated',
    'cancelled',
    'cancellation',
    'failed',
    'on hold',
    'pending delivery',
    'arrest',
    'jail',
    'prison',
    'custody',
    'penalty',
    'fine of',
    'legal action',
    'do not tell',
    'dont tell',
    'keep secret',
    'confidential',
    'kisi ko mat',
    'turant',
    'abhi ke abhi',
    'warna',
    'तुरंत',
    'अभी',
    'गिरफ्तार',
    'खाता फ्रीज',
    'बंद हो जाएगा',
  ]);

  const hasFinancialOrCredentialExtractionSignal = matchesAny(lower, [
    'transfer',
    'deposit',
    'send money',
    'pay ₹',
    'pay rs',
    'pay inr',
    '₹',
    'rs.',
    'inr ',
    'lakh',
    'thousand',
    'rtgs',
    'imps',
    'neft',
    'upi',
    'pin',
    'otp',
    'cvv',
    'password',
    'passcode',
    'click here',
    'click link',
    'install',
    'download',
    'verify account',
    'refundable',
    'security deposit',
    'bail',
    'clearance fee',
    'processing fee',
    'पैसे',
    'ट्रांसफर',
    'ओटीपी',
    'यूपीआई',
    'जमा करें',
  ]);

  const hasAnyExtractedIoc =
    iocs.upiIds.length > 0 ||
    iocs.phoneNumbers.length > 0 ||
    iocs.bankAccounts.length > 0 ||
    iocs.domains.length > 0;

  const behavioralSignalCount =
    (hasAuthorityOrImpersonationSignal ? 1 : 0) +
    (hasUrgencyOrCoercionSignal ? 1 : 0) +
    (hasFinancialOrCredentialExtractionSignal ? 1 : 0) +
    (hasAnyExtractedIoc ? 1 : 0) +
    (hasAiSyntheticMarker ? 2 : 0);

  // Check for verified official institutional advisory signals (e.g. RBI nomination advice with official rbi.org.in link)
  const isVerifiedOfficialAdvisory =
    matchesAny(lower, [
      'rbikehtahai',
      'rbi.org.in',
      'cybercrime.gov.in',
      'sancharsaathi.gov.in',
      'nomination',
      'नॉमिनी',
      'नामांकन',
      'rbi awareness',
      'public awareness',
      '[verified_official_channel]',
    ]) &&
    !hasUrgencyOrCoercionSignal &&
    !hasFinancialOrCredentialExtractionSignal &&
    iocs.upiIds.length === 0 &&
    iocs.bankAccounts.length === 0;

  // Determine if a novel/paraphrased scam is detected via multi-signal convergence
  const isNovelBehavioralCoercion =
    !isVerifiedOfficialAdvisory &&
    !isDigitalArrest &&
    !isVoiceCloneSos &&
    !isUpiTrap &&
    !isKycUtility &&
    !isStockPump &&
    !isFakeDeliveryTrap &&
    !isLotteryPrizeTrap &&
    (behavioralSignalCount >= 3 ||
      (hasUrgencyOrCoercionSignal && hasFinancialOrCredentialExtractionSignal) ||
      (hasAuthorityOrImpersonationSignal && (hasFinancialOrCredentialExtractionSignal || hasAnyExtractedIoc)) ||
      hasAiSyntheticMarker);

  if (isVerifiedOfficialAdvisory) {
    score = 4;
    triggers.push('Verified Official Government/RBI Public Awareness Channel');
  } else if (isDigitalArrest || (isNovelBehavioralCoercion && hasAuthorityOrImpersonationSignal)) {
    score = hasAiSyntheticMarker ? 98 : 96;
    triggers.push(
      'Authority Impersonation (Police/CBI/Customs/Judiciary)',
      'Video Call / Secrecy Isolation Demand ("Do not disconnect")',
      'Fake Asset Verification / Escrow Transfer Demand'
    );
    if (hasAiSyntheticMarker) {
      triggers.push('AI-Generated / Forged Warrant or Synthetic Media Signature');
    }
  } else if (isVoiceCloneSos) {
    score = 94;
    triggers.push(
      'AI Voice Clone / Relative-in-Distress Emergency Script',
      'Sudden Phone/Number Change Claim ("Calling from friend/police phone")',
      'Urgent Third-Party UPI / Bail / Hospital Deposit Demand'
    );
  } else if (isLotteryPrizeTrap) {
    score = 92;
    triggers.push(
      'Fake International Lottery / Cash Prize Winner Bait',
      'Bank Account / Personal Credential Extraction Demand',
      'Urgency Expiry Pressure ("Claim before it expires")'
    );
  } else if (isFakeDeliveryTrap) {
    score = 87;
    triggers.push(
      'Fake Courier / Delivery Cancellation Phishing Trap',
      'Urgency Button/Link Prompt ("Cancel Delivery" / "I Want Delivery")',
      'Spoofed Brand Name / WhatsApp Business Account Impersonation'
    );
  } else if (isUpiTrap) {
    score = 89;
    triggers.push(
      'Fake Credit SMS Social Engineering',
      'UPI Collect Request / QR Scan Disguised as Refund',
      'PIN Entry Prompt for Outbound Debit'
    );
  } else if (isKycUtility) {
    score = 86;
    triggers.push(
      'Urgent Utility / Bank Account / SIM Cutoff Threat',
      'Malicious Remote Access / APK Side-load Vector',
      'Unverified Personal Mobile Number as Officer Helpline'
    );
  } else if (isStockPump) {
    score = 82;
    triggers.push(
      'Unrealistic Guaranteed Return / Prepaid Task Promise',
      'Fake Institutional Trading App / Mule Pool',
      'Withdrawal Tax / Margin Lockup Trap'
    );
  } else if (isNovelBehavioralCoercion) {
    score = 88;
    triggers.push(
      'High-Risk Multi-Signal Social Engineering (Urgency + Financial Extraction)',
      'Coercive Payment or Credential Harvest Pattern',
      hasAnyExtractedIoc
        ? 'Unverified Payment Handle / Phone / Link in Coercive Context'
        : 'Suspicious Off-Record Financial Demand'
    );
  } else if (
    (hasUrgencyOrCoercionSignal || hasFinancialOrCredentialExtractionSignal) &&
    hasAnyExtractedIoc
  ) {
    score = 76;
    triggers.push(
      'Financial or Urgency Request Combined with External IOC',
      'Unverified Payment Handle, Phone Number, or Link Detected'
    );
  } else if (hasAnyExtractedIoc) {
    score = 54;
    triggers.push('Unverified Payment Handle or External Link Detected');
  } else {
    score = 12;
  }

  if (isAiGuardQuarantined) {
    score = 99;
    triggers.unshift(
      'AI Guard Tripwire: Adversarial Prompt-Injection Quarantined',
      aiGuardCheck.reason
    );
  }

  let threatLevel: ThreatLevel = 0;
  if (score >= 85) threatLevel = 4;
  else if (score >= 70) threatLevel = 3;
  else if (score >= 45) threatLevel = 2;
  else if (score >= 25) threatLevel = 1;
  else threatLevel = 0;

  const meterBlocks = Math.max(1, Math.min(10, Math.round(score / 10)));
  const pauseBeforePayRequired = score >= 65;

  if (isAiGuardQuarantined && !isVoiceCloneSos && !isDigitalArrest && !isUpiTrap && !isKycUtility && !isStockPump) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: 99,
      threatLevel: 4,
      meterBlocks: 10,
      threatColor: THREAT_COLORS[4],
      threatLabel: THREAT_LABELS[4],
      categoryCode: 'DIGITAL_ARREST_COERCION',
      headlineEn: 'CRITICAL: Adversarial AI Prompt-Injection & Scanner Bypass Quarantined',
      headlineHinglish: 'KHATRA: AI Scanner Bypass / Prompt-Injection Scam Quarantined!',
      headlineHi: 'गंभीर चेतावनी: एआई स्कैनर बायपास / प्रॉम्प्ट-इंजेक्शन प्रयास क्वारंटाइन किया गया!',
      summaryEn:
        'This message contains hidden or adversarial instructions attempting to hijack AI safety filters and force a false "Safe" rating. Session quarantined automatically.',
      summaryHinglish:
        'Is message mein AI security filter ko dhokha dene aur nakli "Safe" status dikhane ki chalaki pakdi gayi hai. Kisi bhi link ya UPI par bharosa na karein.',
      summaryHi:
        'इस संदेश में एआई सुरक्षा फ़िल्टर को धोखा देने और फर्जी "सुरक्षित" स्थिति दिखाने का प्रयास पकड़ा गया है। किसी भी भुगतान या लिंक पर भरोसा न करें।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Embed invisible or adversarial text in screenshots/messages to trick automated scam scanners into marking a fraudulent payment request as safe.',
          actorMoveHinglish: 'Message ya photo ke andar chhupa hua text daal kar AI scanner ko bypass karne ki koshish karenge.',
          actorMoveHi: 'संदेश या फोटो के भीतर छिपे निर्देश डालकर सुरक्षा जांच को बायपास करने की कोशिश करेंगे।',
          probabilityPct: 98,
          timeWindow: 'Immediate',
          counterMeasure: 'Enforce 2-Minute Cooling Pause and block sender immediately.',
        },
      ],
    };
  }

  if (isVoiceCloneSos) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: 'VOICE_CLONE_SOS',
      headlineEn: 'CRITICAL: AI Voice-Clone / Emergency Family Impersonation Scam Detected',
      headlineHinglish: 'KHATRA: AI Voice-Clone ya Relative Emergency Scam Pakda Gaya!',
      headlineHi: 'गंभीर चेतावनी: एआई वॉयस-क्लोन / पारिवारिक इमरजेंसी स्कैम की पहचान हुई!',
      summaryEn:
        'Scammers use 3-second AI voice clones to imitate a relative in a sudden accident, hospital, or police custody while claiming their phone broke. Call the family member back on their real number and ask for your Family Circle Daily Safe-Word.',
      summaryHinglish:
        'Scammers AI se aapke parivar ki aawaz nakal karke accident ya police thane ka dar dikhate hain. Paisa bhejne se pehle unke asli number par call karein aur Daily Safe-Word puchein!',
      summaryHi:
        'स्कैमर्स एआई से आपके परिवार की आवाज की नकल करके एक्सीडेंट या पुलिस थाने का डर दिखाते हैं। पैसे भेजने से पहले उनके असली नंबर पर कॉल करें और अपना डेली सेफ-वर्ड पूछें।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Use background sirens or crying sounds while claiming their phone/SIM is damaged so you cannot call their regular number.',
          actorMoveHinglish: 'Peeche rone ya siren ki aawaz bajakar bolenge ki mera phone toot gaya hai, isliye dost ya police ke number se call kiya hai.',
          actorMoveHi: 'पीछे रोने या सायरन की आवाज बजाकर बोलेंगे कि मेरा फोन टूट गया है।',
          probabilityPct: 96,
          timeWindow: 'Immediate',
          counterMeasure: 'Ask the caller for your Family Circle Daily Safe-Word before saying anything else.',
        },
        {
          stepNumber: 2,
          actorMove: 'Hand the phone to a fake "doctor" or "police officer" demanding an instant ₹50,000–₹2,00,000 UPI/IMPS transfer to settle the case or start surgery.',
          actorMoveHinglish: 'Nakli doctor ya police officer ko phone dekar turant UPI/IMPS se paisa bhejne ka दबाव banayenge.',
          actorMoveHi: 'नकली डॉक्टर या पुलिस अधिकारी को फोन देकर तुरंत पैसे भेजने का दबाव बनाएंगे।',
          probabilityPct: 94,
          timeWindow: 'Next 2–5 mins',
          counterMeasure: 'Enforce 2-Minute Cooling Pause and dial your family member’s saved phone number directly.',
        },
      ],
    };
  }

  if (isDigitalArrest || (isNovelBehavioralCoercion && hasAuthorityOrImpersonationSignal)) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: 'DIGITAL_ARREST_COERCION',
      headlineEn: 'CRITICAL: "Digital Arrest" Fake Law Enforcement Extortion Detected',
      headlineHinglish: 'KHATRA: Fake "Digital Arrest" Police/CBI Scam Pakda Gaya!',
      headlineHi: 'गंभीर चेतावनी: फर्जी "डिजिटल अरेस्ट" पुलिस/सीबीआई स्कैम की पहचान हुई!',
      summaryEn:
        'Indian police, CBI, Customs, or RBI NEVER conduct interrogations on WhatsApp/Skype video calls or ask you to transfer funds to a "verification account". Hang up immediately.',
      summaryHinglish:
        'Asli Police, CBI ya Judge kabhi WhatsApp/Skype video call par "Digital Arrest" nahi karte aur na hi verification ke naam par paisa mangte hain. Turant call kaatein!',
      summaryHi:
        'असली पुलिस, सीबीआई या जज कभी भी व्हाट्सएप या स्काइप वीडियो कॉल पर पूछताछ नहीं करते और न ही वेरिफिकेशन के लिए पैसे मांगते हैं। तुरंत कॉल काटें।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Demand you stay on video call in a locked room & forbid telling family ("National Security NDA").',
          actorMoveHinglish: 'Aapko kamra band karke video call chalu rakhne aur family ko na batane ki dhamki denge.',
          actorMoveHi: 'आपको कमरा बंद करके वीडियो कॉल पर रहने और परिवार को न बताने की धमकी देंगे।',
          probabilityPct: 97,
          timeWindow: 'Next 2–5 mins',
          counterMeasure: 'Trigger Family Circle Duress Word or disconnect call immediately.',
        },
        {
          stepNumber: 2,
          actorMove: 'Send a forged Supreme Court / RBI arrest order on WhatsApp with a fake seal.',
          actorMoveHinglish: 'WhatsApp par nakli Supreme Court ya CBI ka arrest warrant PDF bhejenge.',
          actorMoveHi: 'व्हाट्सएप पर नकली सुप्रीम कोर्ट या सीबीआई का अरेस्ट वारंट भेजेंगे।',
          probabilityPct: 94,
          timeWindow: 'Next 5–12 mins',
          counterMeasure: 'Lock screenshot in Dhaal Evidence Vault with SHA-256 timestamp.',
        },
        {
          stepNumber: 3,
          actorMove: 'Instruct RTGS/IMPS transfer of 80-90% savings to a "Secret Supervision Account" promised back in 30 mins.',
          actorMoveHinglish: 'Verification ke naam par RTGS/UPI se saari jama-punji mule account mein transfer karwayenge.',
          actorMoveHi: 'वेरिफिकेशन के नाम पर आरटीजीएस/यूपीआई से आपकी जमा-पूंजी म्यूल खाते में ट्रांसफर करवाएंगे।',
          probabilityPct: 99,
          timeWindow: 'Next 15–30 mins',
          counterMeasure: 'Enforce 2-Minute Cooling Pause; NEVER transfer money for verification.',
        },
      ],
    };
  }

  if (isUpiTrap || (isNovelBehavioralCoercion && !hasAuthorityOrImpersonationSignal)) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: 'UPI_COLLECT_TRAP',
      headlineEn: 'CRITICAL: Fake UPI Credit & Coercive Payment Trap Detected',
      headlineHinglish: 'SAVDHAAN: Nakli UPI Credit SMS aur Coercive Payment Trap!',
      headlineHi: 'सावधान: नकली यूपीआई क्रेडिट एसएमएस और भुगतान जाल!',
      summaryEn:
        'Scammer is using urgency or a fake credit claim to trick you into approving a transfer or entering your UPI PIN. Entering your UPI PIN always deducts money from your account.',
      summaryHinglish:
        'Scammer jaldbazi ya nakli bank credit SMS dikha kar aapse paisa nikalwana chahta hai. Yaad rakhein: Paisa aane ke liye kabhi UPI PIN nahi lagta!',
      summaryHi:
        'स्कैमर जल्दबाजी या नकली बैंक क्रेडिट एसएमएस दिखाकर आपसे पैसे निकलवाना चाहता है। याद रखें: पैसे प्राप्त करने के लिए कभी भी यूपीआई पिन नहीं डालना पड़ता।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Emotional call claiming medical emergency ("Sent ₹15,000 by mistake for hospital bill, please return").',
          actorMoveHinglish: 'Call karke royeinge ki hospital ke liye galti se paisa chala gaya, turant wapas kar do.',
          actorMoveHi: 'कॉल करके इमोशनल दबाव बनाएंगे कि अस्पताल के लिए गलती से पैसा चला गया है।',
          probabilityPct: 95,
          timeWindow: 'Immediate',
          counterMeasure: 'Check actual bank balance inside your official bank app, not SMS.',
        },
        {
          stepNumber: 2,
          actorMove: 'Push a UPI Collect Request or QR code labeled "Refund Approval" requiring your 4/6-digit UPI PIN.',
          actorMoveHinglish: 'UPI app par "Approve Refund" collect notification bhejenge jisme PIN maanga jayega.',
          actorMoveHi: 'यूपीआई ऐप पर कलेक्ट रिक्वेस्ट भेजेंगे जिसमें पिन मांगा जाएगा।',
          probabilityPct: 92,
          timeWindow: 'Next 1–3 mins',
          counterMeasure: 'Decline Collect Request and report VPA handle to Scam Radar.',
        },
      ],
    };
  }

  if (isLotteryPrizeTrap) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: 'LOTTERY_PRIZE_SCAM',
      headlineEn: 'CRITICAL: Fake Lottery / Prize Winner Phishing Scam Detected',
      headlineHinglish: 'KHATRA: Fake Lottery / Lucky Draw Inaam Scam Pakda Gaya!',
      headlineHi: 'गंभीर चेतावनी: फर्जी लॉटरी / लकी ड्रॉ इनाम धोखाधड़ी की पहचान हुई!',
      summaryEn:
        'Scammers use fabricated lottery wins or lucky draw prizes to harvest your bank account details or demand an advance "clearance/processing fee" before disappearing. Real lotteries never ask for upfront payments or unverified bank details.',
      summaryHinglish:
        'Scammers nakli lottery ya lucky draw ka lalach dekar aapke bank account ki details churaate hain ya "clearance fee" maangte hain. Kisi ko bhi account details na bhejein!',
      summaryHi:
        'स्कैमर्स फर्जी लॉटरी या लकी ड्रॉ का लालच देकर आपके बैंक खाते का विवरण चुराते हैं या प्रोसेसिंग फीस मांगते हैं। किसी को भी बैंक विवरण न भेजें।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Demand your bank account number, IFSC code, and Aadhaar card under the pretext of depositing prize winnings.',
          actorMoveHinglish: 'Inaam transfer karne ke bahane aapka bank account number, IFSC code aur Aadhaar card maangenge.',
          actorMoveHi: 'इनाम ट्रांसफर करने के बहाने आपका बैंक खाता नंबर, आईएफएससी कोड और आधार कार्ड मांगेंगे।',
          probabilityPct: 97,
          timeWindow: 'Immediate',
          counterMeasure: 'NEVER share bank account details, card numbers, or OTP for unsolicited lottery or prize notifications.',
        },
        {
          stepNumber: 2,
          actorMove: 'Demand an upfront "TDS Tax", "RBI Currency Conversion Fee", or "Processing Charge" of ₹2,500–₹25,000 before releasing funds.',
          actorMoveHinglish: 'Lottery release karne ke liye pehle "Processing Fee" ya "RBI Tax" ke naam par paise maangenge.',
          actorMoveHi: 'लॉटरी जारी करने के लिए पहले प्रोसेसिंग फीस या टैक्स के नाम पर पैसे मांगेंगे।',
          probabilityPct: 94,
          timeWindow: 'Next 5–15 mins',
          counterMeasure: 'Block caller immediately and file a complaint on 1930 / cybercrime.gov.in.',
        },
      ],
    };
  }

  if (isFakeDeliveryTrap) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: 'FAKE_DELIVERY_TRAP',
      headlineEn: 'CRITICAL: Fake Courier / Order Cancellation Phishing Trap Detected',
      headlineHinglish: 'KHATRA: Fake Jio/Courier Delivery Cancellation Scam Pakda Gaya!',
      headlineHi: 'गंभीर चेतावनी: फर्जी कूरियर / डिलीवरी कैंसलेशन फिशिंग ट्रैप की पहचान हुई!',
      summaryEn:
        'Scammers use fake delivery cancellation alerts ("Jio Home Delivery", "IndiaPost", "FedEx") with urgent action buttons to bait victims into paying a ₹5–₹25 "reschedule fee" or installing an APK that drains their bank account.',
      summaryHinglish:
        'Scammers nakli delivery cancellation message bhej kar aapko link par click karne ya ₹10-₹25 fee bharne ko bolte hain, jisse bank account khali ho jata hai. Kisi bhi button par click na karein!',
      summaryHi:
        'स्कैमर्स फर्जी डिलीवरी कैंसलेशन संदेश भेजकर लिंक पर क्लिक करने या टोकन फीस भरने का दबाव बनाते हैं। किसी भी बटन या लिंक पर क्लिक न करें।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: 'Offer "I Want Delivery" or "Cancel Delivery" interactive options to capture your mobile response.',
          actorMoveHinglish: 'Aapko "I Want Delivery" ya "Cancel" option dikha kar response lenge.',
          actorMoveHi: 'आपको डिलीवरी जारी रखने या रद्द करने का विकल्प दिखाकर प्रतिक्रिया लेंगे।',
          probabilityPct: 96,
          timeWindow: 'Immediate',
          counterMeasure: 'Do not click buttons. Verify order directly inside official MyJio or e-commerce app.',
        },
        {
          stepNumber: 2,
          actorMove: 'Send a malicious payment link or APK download claiming a ₹5–₹25 redelivery charge or ask you to call a fake delivery executive number.',
          actorMoveHinglish: '₹5-₹25 re-delivery charge ke naam par phishing link bhejenge ya fake delivery boy number denge.',
          actorMoveHi: 'पुनः डिलीवरी के नाम पर छोटा भुगतान मांगने वाला लिंक या फर्जी नंबर भेजेंगे।',
          probabilityPct: 93,
          timeWindow: 'Next 2–5 mins',
          counterMeasure: 'Never enter UPI PIN or card CVV for delivery redelivery charges.',
        },
      ],
    };
  }

  if (isKycUtility || isStockPump || score >= 70) {
    return {
      id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      channel,
      riskScore: score,
      threatLevel,
      meterBlocks,
      threatColor: THREAT_COLORS[threatLevel],
      threatLabel: THREAT_LABELS[threatLevel],
      categoryCode: isStockPump ? 'STOCK_VIP_PUMP' : 'FAKE_KYC_UTILITY',
      headlineEn: isStockPump
        ? 'SEVERE: Spoofed Institutional Trading & Task Investment Trap'
        : 'SEVERE: Remote Access APK / Utility & KYC Phishing Detected',
      headlineHinglish: isStockPump
        ? 'KHATRA: Fake VIP Stock Group aur Double Return Trap!'
        : 'KHATRA: Bijli Cut / KYC ke naam par APK aur Phishing Scam!',
      headlineHi: isStockPump
        ? 'खतरा: नकली वीआईपी स्टॉक ग्रुप और गारंटीड रिटर्न जाल!'
        : 'खतरा: बिजली कटौती / केवाईसी के नाम पर एपीके और फ़िशिंग स्कैम!',
      summaryEn: isStockPump
        ? 'Fraudulent trading portal shows fabricated profits on screen but freezes withdrawals until you pay a fake 30% "SEBI release tax".'
        : 'Never install .APK files, click unverified KYC links, or share screen via AnyDesk/RustDesk. Scammers steal OTPs and drain netbanking.',
      summaryHinglish: isStockPump
        ? 'App par dikhne wala profit nakli hai. Paisa nikaalne par ye 30% tax ke naam par aur paisa maangenge.'
        : 'WhatsApp/SMS par aayi koi bhi .apk file ya anjaan KYC link na kholein. Isse aapke SMS aur OTP chori ho jaate hain.',
      summaryHi: isStockPump
        ? 'ऐप पर दिखने वाला मुनाफा नकली है। पैसे निकालने पर ये टैक्स के नाम पर और पैसे मांगेंगे।'
        : 'व्हाट्सएप पर आई कोई भी .apk फाइल या अनजान लिंक न खोलें। इससे आपके ओटीपी चोरी हो जाते हैं।',
      pauseBeforePayRequired: true,
      pauseDurationSeconds: 120,
      triggersDetected: triggers,
      extractedIOCs: iocs,
      nextMoves: [
        {
          stepNumber: 1,
          actorMove: isStockPump
            ? 'Allow a small ₹500 test withdrawal to build trust before pitching a ₹2,00,000 "Block Deal".'
            : 'Ask you to pay ₹10 "activation charge" on a phishing form or install CustomerSupport.apk.',
          actorMoveHinglish: isStockPump
            ? 'Bharosa jeetne ke liye pehle ₹500 wapas denge, phir bada amount mangenge.'
            : '₹10 ka chhota payment karne ya APK app खोलने ko bolenge.',
          actorMoveHi: isStockPump
            ? 'भरोसा जीतने के लिए पहले छोटा मुनाफा देंगे, फिर बड़ी रकम मांगेंगे।'
            : '₹10 का छोटा पेमेंट करने या एपीके खोलने को बोलेंगे।',
          probabilityPct: 91,
          timeWindow: 'Next 5–10 mins',
          counterMeasure: 'Block sender immediately and lock evidence in Dhaal Vault.',
        },
        {
          stepNumber: 2,
          actorMove: isStockPump
            ? 'Demand 25% "Capital Gains Unfreeze Fee" when you attempt to withdraw principal.'
            : 'Intercept SMS forwarding permission to take over WhatsApp and Bank UPI.',
          actorMoveHinglish: isStockPump
            ? 'Withdrawal mangne par account freeze dikha kar 25% fee mangenge.'
            : 'SMS read karke aapka bank aur WhatsApp hack karne ki koshish karenge.',
          actorMoveHi: isStockPump
            ? 'पैसे निकालने पर खाता फ्रीज दिखाकर अतिरिक्त शुल्क मांगेंगे।'
            : 'एसएमएस पढ़कर आपका बैंक और व्हाट्सएप हैक करने की कोशिश करेंगे।',
          probabilityPct: 89,
          timeWindow: 'Next 15–45 mins',
          counterMeasure: 'File immediate 1930 NCRP complaint via Dhaal Recovery Pack.',
        },
      ],
    };
  }

  return {
    id: `INT-${Math.abs(hashCode(text)).toString(16).slice(0, 6).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    channel,
    riskScore: score,
    threatLevel,
    meterBlocks,
    threatColor: THREAT_COLORS[threatLevel],
    threatLabel: THREAT_LABELS[threatLevel],
    categoryCode: 'VERIFIED_CLEAN',
    headlineEn: score >= 45 ? 'CAUTION: Unverified Payment Handle or Link' : 'VERIFIED SAFE: No Coercion or Phishing Signatures Found',
    headlineHinglish: score >= 45 ? 'SAVDHAAN: Anjaan Link ya UPI ID mili hai' : 'SURAKSHIT: Koi Scam Pattern Nahi Mila',
    headlineHi: score >= 45 ? 'सावधान: अनजान लिंक या यूपीआई आईडी मिली है' : 'सुरक्षित: कोई स्कैम पैटर्न नहीं मिला',
    summaryEn:
      score >= 45
        ? 'Contains an external link or UPI handle without overt coercion keywords. Verify recipient via Family Circle before paying.'
        : 'Message passes telemetry verification. No urgency traps, spoofed authority headers, or malicious APKs detected.',
    summaryHinglish:
      score >= 45
        ? 'Is message mein external link ya UPI ID hai. Payment se pehle confirm zaroor karein.'
        : 'Message surakshit lag raha hai. Koi khatarnaak link ya dhamki nahi mili.',
    summaryHi:
      score >= 45
        ? 'इस संदेश में बाहरी लिंक या यूपीआई आईडी है। भुगतान से पहले पुष्टि करें।'
        : 'संदेश सुरक्षित प्रतीत होता है। कोई खतरनाक लिंक या धमकी नहीं मिली।',
    pauseBeforePayRequired: false,
    pauseDurationSeconds: 0,
    triggersDetected: triggers,
    extractedIOCs: iocs,
    nextMoves: [],
  };
}

export function simulateOutbreakCurve(params: {
  baseR0: number;
  warningDelayMinutes: number;
  whatsappCoveragePct: number;
  hours?: number;
}): OutbreakSimulationResult {
  const hours = params.hours ?? 24;
  const baseR0 = Math.max(1.1, Math.min(6.0, params.baseR0));
  const delayFactor = Math.max(0.1, Math.min(1, params.warningDelayMinutes / 180)); // Faster warning (smaller minutes) = stronger suppression
  const coverageFactor = Math.max(0, Math.min(1, params.whatsappCoveragePct / 100));

  // Suppression effectiveness combines speed and WhatsApp pre-warning reach
  const suppressionStrength = coverageFactor * (1 - delayFactor * 0.65);
  const effectiveR = Number(Math.max(0.45, baseR0 * (1 - suppressionStrength * 0.72)).toFixed(2));

  const points: OutbreakPoint[] = [];
  let unmitigatedTotal = 0;
  let mitigatedTotal = 0;

  for (let h = 1; h <= hours; h++) {
    // Bell-like scam wave growth over 24h
    const waveIntensity = Math.sin((Math.PI * h) / (hours + 4));
    const unmitigatedHourly = Math.round(14 * Math.pow(baseR0, h / 7) * waveIntensity + h * 3);

    // Mitigated curve bends down sharply once warning delay has passed
    const warningActive = h * 60 >= params.warningDelayMinutes;
    const mitigationMultiplier = warningActive
      ? Math.max(0.12, 1 - suppressionStrength * Math.min(0.88, (h * 60 - params.warningDelayMinutes) / 360 + 0.35))
      : 1;

    const mitigatedHourly = Math.max(2, Math.round(unmitigatedHourly * mitigationMultiplier));
    const preWarningsSent = warningActive ? Math.round((unmitigatedHourly - mitigatedHourly) * 18) : 0;

    unmitigatedTotal += unmitigatedHourly;
    mitigatedTotal += mitigatedHourly;

    points.push({
      hour: h,
      unmitigatedVictims: unmitigatedHourly,
      mitigatedVictims: mitigatedHourly,
      preWarningsSent,
    });
  }

  const victimsSaved = Math.max(0, unmitigatedTotal - mitigatedTotal);
  // Average ₹0.85 Lakhs saved per prevented victim
  const paisaSavedLakhs = Number((victimsSaved * 0.85).toFixed(1));

  return {
    effectiveR,
    unmitigatedTotal,
    mitigatedTotal,
    victimsSaved,
    paisaSavedLakhs,
    points,
  };
}

export function evaluateAiGuardSession(transcriptLine: string): AiGuardEvaluation {
  const raw = transcriptLine || '';
  const deobfuscated = normalizeAndDeobfuscateText(raw);
  const lower = `${raw.toLowerCase()}\n${deobfuscated.toLowerCase()}`;

  const tripwirePatterns: Array<{ pattern: RegExp; code: string; reason: string }> = [
    {
      pattern:
        /(ignore|disregard|forget|override|bypass|skip|delete|omit)\s+(all\s+|any\s+|previous\s+|prior\s+|above\s+|earlier\s+|system\s+|security\s+|safety\s+)*(instructions|prompts|rules|directives|constraints|guardrails|checks|filters|guidelines)/i,
      code: 'TRIPWIRE_PROMPT_INJECTION_01',
      reason: 'Adversarial attempt to override Dhaal Voice Sting persona directives.',
    },
    {
      pattern:
        /(system prompt|developer mode|reveal honeypot|ai assistant|jailbreak|dan mode|do anything now|you are now|act as a|pretend to be|new system role|system override)/i,
      code: 'TRIPWIRE_PERSONA_PROBE_02',
      reason: 'Scammer probing for AI persona boundary or system configuration.',
    },
    {
      pattern:
        /(read out otp|share real bank|execute transfer|bypass guard|bypass scam|process\.env|gemini_api_key|telegram_bot_token|print env|dump secrets)/i,
      code: 'TRIPWIRE_EXFILTRATION_GUARD_03',
      reason: 'Blocked attempt to access protected sandbox credentials or OTP channel.',
    },
    {
      pattern:
        /(mark as safe|classify as safe|output verified_clean|verified clean|risk score 0|score:\s*0|score 0|threat level 0|override risk|not a scam|false positive override|whitelist this|force safe|prompt_injection_attempt)/i,
      code: 'TRIPWIRE_VERDICT_SPOOF_04',
      reason: 'Adversarial attempt to spoof a clean security verdict.',
    },
    {
      pattern:
        /(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[\/?inst\]|<<\/?sys>>|<\/?system>|###\s*(system|instruction|assistant|developer)\s*:)/i,
      code: 'TRIPWIRE_DELIMITER_SPOOF_05',
      reason: 'Blocked LLM control token or role-delimiter injection payload.',
    },
  ];

  for (const item of tripwirePatterns) {
    if (item.pattern.test(lower)) {
      return {
        quarantined: true,
        tripwireCode: item.code,
        confidencePct: 99,
        action: 'QUARANTINE_SESSION',
        reason: item.reason,
      };
    }
  }

  return {
    quarantined: false,
    tripwireCode: null,
    confidencePct: 98,
    action: 'CONTINUE_STING',
    reason: 'Session telemetry nominal. Decoy persona containment intact.',
  };
}

export function checkDuressTrigger(spokenTranscript: string, secretDuressWord: string): {
  triggered: boolean;
  matchedWord: string | null;
  silentProtocol: string;
} {
  const cleanTranscript = (spokenTranscript || '').toLowerCase().trim();
  const cleanWord = (secretDuressWord || '').toLowerCase().trim();

  if (!cleanTranscript || !cleanWord) {
    return {
      triggered: false,
      matchedWord: null,
      silentProtocol: 'STANDBY',
    };
  }

  const triggered = cleanTranscript.includes(cleanWord);
  return {
    triggered,
    matchedWord: triggered ? secretDuressWord.trim() : null,
    silentProtocol: triggered
      ? 'SILENT_ALERT_DISPATCHED: Live GPS + Audio Hash + Call Caller-ID sent to 3 Family Circle guardians without audio beep.'
      : 'STANDBY',
  };
}

export function verifyComplaintDraftField(draft: ComplaintDraft, fieldKey: string, newValue?: string): ComplaintDraft {
  return {
    ...draft,
    fields: draft.fields.map((f) =>
      f.key === fieldKey
        ? {
            ...f,
            value: newValue !== undefined ? newValue : f.value,
            verifiedByUser: true,
          }
        : f
    ),
  };
}

export function computeDraftReadiness(draft: ComplaintDraft): {
  totalFields: number;
  verifiedCount: number;
  unverifiedCount: number;
  readinessPct: number;
  readyToExport: boolean;
} {
  const totalFields = draft.fields.length;
  const verifiedCount = draft.fields.filter((f) => f.verifiedByUser).length;
  const unverifiedCount = totalFields - verifiedCount;
  const readinessPct = totalFields === 0 ? 100 : Math.round((verifiedCount / totalFields) * 100);

  return {
    totalFields,
    verifiedCount,
    unverifiedCount,
    readinessPct,
    readyToExport: unverifiedCount === 0 && totalFields > 0,
  };
}

export function evaluateUnfreezePetition(input: UnfreezeCaseInput): UnfreezeAssessment {
  const excessFrozenInr = Math.max(0, input.totalBalanceInr - input.disputedTransactionInr);
  const isDisproportionateFreeze =
    input.freezeType === 'FULL_DEBIT_FREEZE' && input.totalBalanceInr > input.disputedTransactionInr;

  const legalGrounds = [
    'Section 106 of Bharatiya Nagarik Suraksha Sanhita (BNSS) / judicial precedents mandate marking a specific lien only on the disputed trail amount, not a blanket debit freeze on legitimate savings.',
    'RBI Master Direction on Fraud Classification and Reporting & Banking Ombudsman guidelines require immediate communication of the Investigating Officer (IO) notice details and Layer-N trail number.',
    `Innocent Layer-3/4 Bona-fide Recipient Protection: Only ₹${input.disputedTransactionInr.toLocaleString('en-IN')} is under NCRP inquiry (${input.ackNumber1930}), leaving ₹${excessFrozenInr.toLocaleString('en-IN')} wrongfully immobilized.`,
  ];

  const petitionText = `To,
The Branch Manager / Nodal Cyber Cell Officer,
${input.bankName}
 And Investigating Officer, ${input.policeNoticeStation}

Subject: Representation for Removal of Blanket Debit Freeze & Conversion to Specific Disputed Amount Lien — A/C ${input.accountMask} (NCRP Ack: ${input.ackNumber1930})

Respected Sir/Madam,
1. My bank account (${input.accountMask}) with ${input.bankName} containing a total balance of ₹${input.totalBalanceInr.toLocaleString('en-IN')} has been subjected to a ${input.freezeType === 'FULL_DEBIT_FREEZE' ? 'complete debit freeze' : 'lien mark'} pursuant to NCRP Acknowledgement ${input.ackNumber1930}.
2. The specific disputed credit under inquiry is ₹${input.disputedTransactionInr.toLocaleString('en-IN')}, received in the ordinary course of a bona-fide transaction (supporting invoice/UPI receipt attached).
3. As per High Court rulings and Section 106 BNSS guidelines, freezing the entire account balance of ₹${input.totalBalanceInr.toLocaleString('en-IN')} for a disputed sum of ₹${input.disputedTransactionInr.toLocaleString('en-IN')} is disproportionate.
4. I request that the blanket debit freeze be lifted immediately, restricting the hold strictly to a specific lien of ₹${input.disputedTransactionInr.toLocaleString('en-IN')}, thereby releasing my legitimate ₹${excessFrozenInr.toLocaleString('en-IN')} balance while I fully cooperate with ${input.policeNoticeStation}.

Sincerely,
Account Holder (Verified via Dhaal Unfreeze Support Dossier)`;

  return {
    isDisproportionateFreeze,
    excessFrozenInr,
    legalGrounds,
    petitionText,
  };
}

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}
