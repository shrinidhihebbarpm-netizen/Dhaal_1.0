import { ComplaintDraft, LanguageMode } from './scamEngine';

export interface PresetScenario {
  id: string;
  title: string;
  channel: 'whatsapp' | 'sms' | 'voice' | 'upi';
  sender: string;
  tag: string;
  payload: string;
  voiceDuration?: string;
}

export interface ScamGraphNode {
  id: string;
  label: string;
  type: 'MULE_UPI' | 'SPOOF_PHONE' | 'PHISH_DOMAIN' | 'CAMPAIGN_CLUSTER' | 'BANK_AC';
  confidencePct: number;
  reportsCount: number;
  source: string;
  status: 'ACTIVE_THREAT' | 'FROZEN_1930' | 'HONEYPOT_TAGGED';
  region: string;
  x: number;
  y: number;
  connections: string[];
}

export function inferGraphNodeType(label: string): ScamGraphNode['type'] {
  const lower = label.toLowerCase();
  if (lower.includes('@')) return 'MULE_UPI';
  if (/^\+?\d[\d\s-]{6,}$/.test(label.trim())) return 'SPOOF_PHONE';
  if (
    lower.includes('http') ||
    lower.includes('.com') ||
    lower.includes('.in') ||
    lower.includes('.apk') ||
    lower.includes('tg://')
  ) {
    return 'PHISH_DOMAIN';
  }
  if (
    lower.includes('hdfc') ||
    lower.includes('sbi') ||
    lower.includes('icici') ||
    lower.includes('axis') ||
    lower.includes('a/c') ||
    /\b\d{9,18}\b/.test(lower)
  ) {
    return 'BANK_AC';
  }
  return 'CAMPAIGN_CLUSTER';
}

export interface FamilyMember {
  id: string;
  name: string;
  relation: string;
  phone: string;
  language: 'English' | 'Hinglish' | 'Hindi';
  lastDrillScore: number;
  status: 'PROTECTED' | 'IN_CALL_WATCH' | 'DRILL_PENDING';
}

export interface EvidenceItem {
  id: string;
  timestamp: string;
  type: 'WHATSAPP_SCREENSHOT' | 'VOICE_NOTE_HASH' | 'UPI_REQUEST' | 'STING_TRANSCRIPT';
  title: string;
  suspectId: string;
  sha256: string;
  verified: boolean;
}

export const PRESET_SCENARIOS: PresetScenario[] = [
  {
    id: 'sc-digital-arrest',
    title: 'FedEx / CBI "Digital Arrest" Video Call Threat',
    channel: 'whatsapp',
    sender: '+91 98214 77019 (Fake CBI Cyber Cell)',
    tag: 'LEVEL 4 · DIGITAL ARREST',
    payload:
      'URGENT NOTICE FROM MUMBAI CYBER CRIME & CBI: Parcel #FX-9920184 booked under your Aadhaar contains 450g MDMA narcotics & 5 passports to Iran. Non-bailable Arrest Warrant issued by Supreme Court. Join Skype Video Interrogation under Digital Arrest immediately. Transfer 85% liquid balance (₹4,50,000) to RBI Supervision Escrow UPI rbi.verify99@okaxis for forensic clearance or call IO Vikram 9876543210.',
  },
  {
    id: 'sc-upi-collect',
    title: 'Wrong UPI Credit SMS + Collect PIN Reversal',
    channel: 'upi',
    sender: '+91 70421 88312 (Personal Mobile SMS)',
    tag: 'LEVEL 4 · UPI COLLECT TRAP',
    payload:
      'Rs. 15,000.00 credited to your A/c XX4821 via UPI Ref 4304918271. Bro I sent ₹15,000 by mistake for my mother ICU hospital bill! Please approve the collect request and enter UPI PIN to refund to help.care@ybl urgently.',
  },
  {
    id: 'sc-bescom-apk',
    title: 'Electricity Bill Disconnect Tonight + .APK File',
    channel: 'sms',
    sender: 'VM-PWRDSK (Spoofed Header)',
    tag: 'LEVEL 3 · REMOTE APK',
    payload:
      'Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because previous month bill was not updated. Immediately install BillUpdate_Support.apk or call Electricity Officer Sharma at 8890123456 and share screen via AnyDesk.',
  },
  {
    id: 'sc-vip-stock',
    title: 'WhatsApp VIP Institutional IPO Block Deal Group',
    channel: 'whatsapp',
    sender: 'FII Institutional Quant Club C-14',
    tag: 'LEVEL 3 · PIG BUTCHERING',
    payload:
      'Congratulations members! Today our VIP group hit 240% upper circuit on institutional QIB seat allocation. Deposit ₹2,00,000 into pool account 918273645501 (IFSC UTIB0000124) via trade.fii-pro-india.com to unlock guaranteed double return before Friday IPO listing.',
  },
  {
    id: 'sc-safe-bank',
    title: 'Legitimate Bank OTP Advisory (Safe Control)',
    channel: 'sms',
    sender: 'AD-HDFCBK',
    tag: 'LEVEL 0 · CLEAN',
    payload:
      'HDFC Bank Alert: Never share your OTP, UPI PIN, or NetBanking password with anyone. Bank officials or police never ask for money transfers or video call interrogations.',
  },
];

export const INITIAL_SCAM_GRAPH: ScamGraphNode[] = [
  {
    id: 'CAMPAIGN-DA-09',
    label: 'FedEx/CBI Digital Arrest Ring #09',
    type: 'CAMPAIGN_CLUSTER',
    confidencePct: 99,
    reportsCount: 412,
    source: 'NCRP 1930 + Dhaal Voice Sting',
    status: 'ACTIVE_THREAT',
    region: 'NCR / Mewat / Cambodia VoIP Relay',
    x: 420,
    y: 170,
    connections: ['NODE-UPI-1', 'NODE-PH-1', 'NODE-AC-1'],
  },
  {
    id: 'NODE-UPI-1',
    label: 'rbi.verify99@okaxis',
    type: 'MULE_UPI',
    confidencePct: 98,
    reportsCount: 147,
    source: 'Voice Sting Extraction + 42 Victim Screenshots',
    status: 'ACTIVE_THREAT',
    region: 'Layer-1 Mule Merchant VPA',
    x: 200,
    y: 95,
    connections: ['CAMPAIGN-DA-09', 'NODE-AC-1'],
  },
  {
    id: 'NODE-PH-1',
    label: '+91 98214 77019',
    type: 'SPOOF_PHONE',
    confidencePct: 96,
    reportsCount: 289,
    source: 'WhatsApp Bot Forward Telemetry',
    status: 'ACTIVE_THREAT',
    region: 'SIM Box Cluster (Jamtara/Alwar)',
    x: 210,
    y: 265,
    connections: ['CAMPAIGN-DA-09', 'NODE-DOM-1'],
  },
  {
    id: 'NODE-AC-1',
    label: 'A/C 918273645501 (IFSC UTIB0000124)',
    type: 'BANK_AC',
    confidencePct: 94,
    reportsCount: 83,
    source: 'Dhaal Honeypot Call #ST-409',
    status: 'FROZEN_1930',
    region: 'Current Account Mule (Surat)',
    x: 640,
    y: 95,
    connections: ['CAMPAIGN-DA-09', 'NODE-UPI-1', 'CAMPAIGN-IPO-04'],
  },
  {
    id: 'CAMPAIGN-IPO-04',
    label: 'FII Quant VIP Stock Syndicate',
    type: 'CAMPAIGN_CLUSTER',
    confidencePct: 95,
    reportsCount: 198,
    source: 'Telegram/WhatsApp Group Honeytrap',
    status: 'ACTIVE_THREAT',
    region: 'Cross-Border USDT Off-Ramp',
    x: 650,
    y: 245,
    connections: ['NODE-AC-1', 'NODE-DOM-1', 'NODE-UPI-2'],
  },
  {
    id: 'NODE-DOM-1',
    label: 'trade.fii-pro-india.com',
    type: 'PHISH_DOMAIN',
    confidencePct: 97,
    reportsCount: 164,
    source: 'DNS Cert Transparency + Dhaal Scanner',
    status: 'HONEYPOT_TAGGED',
    region: 'Cloudflare Masked APK Host',
    x: 430,
    y: 300,
    connections: ['NODE-PH-1', 'CAMPAIGN-IPO-04'],
  },
  {
    id: 'NODE-UPI-2',
    label: 'help.care@ybl',
    type: 'MULE_UPI',
    confidencePct: 91,
    reportsCount: 64,
    source: 'UPI Collect Trap Reports',
    status: 'ACTIVE_THREAT',
    region: 'P2P Layer-2 Mule Account',
    x: 810,
    y: 170,
    connections: ['CAMPAIGN-IPO-04'],
  },
];

export const INITIAL_FAMILY_CIRCLE: FamilyMember[] = [
  {
    id: 'fam-1',
    name: 'Rajesh Sharma (Papa)',
    relation: 'Father · Senior Citizen (68 yrs)',
    phone: '+91 98110 44201',
    language: 'Hindi',
    lastDrillScore: 92,
    status: 'PROTECTED',
  },
  {
    id: 'fam-2',
    name: 'Sunita Sharma (Maa)',
    relation: 'Mother · Homemaker (64 yrs)',
    phone: '+91 98110 44202',
    language: 'Hinglish',
    lastDrillScore: 74,
    status: 'DRILL_PENDING',
  },
  {
    id: 'fam-3',
    name: 'Aarav Sharma',
    relation: 'Primary Guardian · Admin',
    phone: '+91 98201 99104',
    language: 'English',
    lastDrillScore: 98,
    status: 'PROTECTED',
  },
];

export const INITIAL_EVIDENCE_VAULT: EvidenceItem[] = [
  {
    id: 'EV-9041',
    timestamp: '2026-10-31 09:42:18 IST',
    type: 'WHATSAPP_SCREENSHOT',
    title: 'Forged CBI / Narcotics Arrest Warrant PDF & Chat Log',
    suspectId: '+91 98214 77019',
    sha256: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    verified: true,
  },
  {
    id: 'EV-9042',
    timestamp: '2026-10-31 09:46:05 IST',
    type: 'STING_TRANSCRIPT',
    title: 'Dhaal Voice Sting #ST-409 Audio & Mule UPI Disclosure',
    suspectId: 'rbi.verify99@okaxis',
    sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    verified: true,
  },
];

export const INITIAL_COMPLAINT_DRAFT: ComplaintDraft = {
  incidentId: 'DHAAL-1930-88412',
  ncrpCategory: 'Cyber Extortion / Digital Arrest Impersonation (CBI/Customs)',
  fields: [
    {
      key: 'incidentDateTime',
      label: 'Incident Date & Time (IST)',
      value: '2026-10-31 09:40 IST',
      aiDrafted: true,
      verifiedByUser: false,
    },
    {
      key: 'suspectIdentifier',
      label: 'Suspect Phone / WhatsApp & Impersonated Agency',
      value: '+91 98214 77019 / +91 98765 43210 (Impersonating Mumbai Cyber Crime & CBI Officer Vikram)',
      aiDrafted: true,
      verifiedByUser: false,
    },
    {
      key: 'muleUpiAndBank',
      label: 'Suspect Beneficiary VPA / Mule Account (Extracted via Multimodal Scan)',
      value: 'UPI: rbi.verify99@okaxis | A/C: 918273645501 (IFSC: UTIB0000124)',
      aiDrafted: true,
      verifiedByUser: false,
    },
    {
      key: 'disputedAmountAndUtr',
      label: 'Disputed / Attempted Extortion Amount & 12-Digit UTR',
      value: '₹4,50,000 (Attempted Extortion Blocked / UTR: 430419882711)',
      aiDrafted: true,
      verifiedByUser: false,
    },
    {
      key: 'narrativeSummary',
      label: 'Structured NCRP Incident Narrative (1930 Format)',
      value:
        'Caller contacted via video call displaying forged CBI ID and Supreme Court warrant alleging MDMA parcel under my Aadhaar. Coerced victim to remain on continuous video surveillance ("Digital Arrest") and demanded ₹4,50,000 RTGS/UPI transfer to rbi.verify99@okaxis. Dhaal AI intercepted the payload, preserved SHA-256 evidence hashes, and mapped the connected mule account.',
      aiDrafted: true,
      verifiedByUser: false,
    },
  ],
};

export const LOCALIZED_COPY: Record<
  LanguageMode,
  {
    badge: string;
    heroTitle: string;
    heroSubtitle: string;
    primaryCta: string;
    secondaryCta: string;
    whatsappHeadline: string;
    whatsappSub: string;
    pauseBannerTitle: string;
    pauseBannerBody: string;
  }
> = {
  en: {
    badge: 'INDIA CYBER DEFENSE · 1930 NCRP INTEGRATED',
    heroTitle: 'Stop Scammers Before a Single Paisa Leaves Your Bank.',
    heroSubtitle:
      'Dhaal detects scams early from uploaded images, call recordings, and text messages—predicting the scammer’s next move with a 2-minute Pause Lock, alerting your user-defined Family Circle, mapping connected scam networks on the Radar, and generating verified 1930 recovery & bank unfreeze dossiers.',
    primaryCta: 'Upload Image, Audio or Text',
    secondaryCta: 'Explore Scam Radar & Outbreak Sim',
    whatsappHeadline: 'Upload Any Screenshot, Audio Recording, or Message Directly in Dhaal',
    whatsappSub:
      '100% free in-app OCR and audio transcription. Upload any suspicious warrant image, call recording, or message to verify before paying.',
    pauseBannerTitle: '2-MINUTE "PAUSE BEFORE YOU PAY" LOCK ARMED',
    pauseBannerBody:
      'Scammers manufacture artificial panic so you transfer money before thinking. Take a 120-second breath while Dhaal verifies the recipient and alerts your trusted contact.',
  },
  hinglish: {
    badge: 'BHARAT CYBER SURAKSHA · 1930 NCRP INTEGRATED',
    heroTitle: 'Ek Paisa Bhi Katne Se Pehle Scammers Ko Rokein.',
    heroSubtitle:
      'Dhaal uploaded screenshots, call recordings, aur text messages se nakli "Digital Arrest" aur UPI traps ko turant pakadta hai—2-minute Pause Lock lagata hai, aapke Family Circle ko alert bhejta hai, Scam Radar par connected accounts map karta hai, aur 1930 complaint va Bank Account Unfreeze mein madad karta hai.',
    primaryCta: 'Image, Audio ya Text Upload Karein',
    secondaryCta: 'Scam Radar aur Outbreak Simulator Dekhein',
    whatsappHeadline: 'Koi Bhi Screenshot, Call Recording ya Message Dhaal Mein Upload Karein',
    whatsappSub:
      'Bina kisi extra subscription ke screenshot, audio note, ya message upload karein aur turant Hindi/Hinglish mein sach jaanein.',
    pauseBannerTitle: '2-MINUTE "PAUSE BEFORE YOU PAY" SURAKSHA LOCK CHALU',
    pauseBannerBody:
      'Scammers dara kar jaldbazi mein paisa transfer karwate hain. 120 second rukein jab tak Dhaal account check kar raha hai aur aapki family ko inform kar raha hai.',
  },
  hi: {
    badge: 'भारत साइबर सुरक्षा कवच · 1930 NCRP एकीकृत',
    heroTitle: 'एक पैसा भी कटने से पहले साइबर ठगों को रोकें।',
    heroSubtitle:
      'ढाल (Dhaal) अपलोड किए गए स्क्रीनशॉट, कॉल रिकॉर्डिंग और संदेशों से फर्जी "डिजिटल अरेस्ट" और यूपीआई जाल को तुरंत पकड़ता है—भुगतान से पहले 2-मिनट का सुरक्षा लॉक लगाता है, आपके परिवार को सचेत करता है, स्कैम रडार पर ठगों के नेटवर्क को जोड़ता है और 1930 शिकायत व फ्रीज बैंक खाता खुलवाने में सहायता करता है।',
    primaryCta: 'इमेज, ऑडियो या टेक्स्ट अपलोड करें',
    secondaryCta: 'स्कैम रडार और आउटब्रेक सिम्युलेटर देखें',
    whatsappHeadline: 'कोई भी स्क्रीनशॉट, कॉल रिकॉर्डिंग या संदेश सीधे ढाल (Dhaal) में अपलोड करें',
    whatsappSub:
      'संदिग्ध वारंट इमेज, ऑडियो रिकॉर्डिंग या मैसेज अपलोड करें और हिंदी में तुरंत सुरक्षा विश्लेषण पाएं।',
    pauseBannerTitle: '2-मिनट "भुगतान से पहले रुकें" (Pause Before You Pay) सुरक्षा लॉक सक्रिय',
    pauseBannerBody:
      'ठग डर पैदा करके जल्दबाजी में पैसे ट्रांसफर करवाते हैं। भुगतान करने से पहले 120 सेकंड रुकें और अपने परिवार के सुरक्षा कोड से पुष्टि करें।',
  },
};
