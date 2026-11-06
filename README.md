# 🛡️ Dhaal — AI Cyber Defense & Scam Interceptor

> Detects scams before payment. Predicts the scammer's next move. Helps victims recover their money.

Built in one day at **CodeDay Bengaluru**, 31 October 2026.

**Live app:** [dhaal-scam-interceptor.ai.studio](https://dhaal-scam-interceptor.ai.studio/)
**Telegram bot:** [@DhaalTELEBot](https://t.me/DhaalTELEBot)

---

## The Problem

Scammers use fake calls and messages to loot people's money, while victims often lack timely protection and struggle to recover their money or deal with frozen bank accounts.

## The Solution

Dhaal uses AI to detect scams early, warn people before they lose money, alert family members, track scam networks, and help victims recover their money through complaint support — all in one place.

---

## Features

### 🔍 Interceptor — Hybrid AI Scam Detection (Heuristic + Gemini Second-Pass Reasoning)
Paste a message, upload a screenshot, or drop a voice note. Dhaal uses a calibrated two-stage engine:
- **Pass 1 (Deterministic Behavioral & Obfuscation-Resistant Engine):** Instant detection across 7 threat categories with de-obfuscation for spaced/dot-separated UPI handles, phone numbers, and keywords, plus genuine bank/merchant safe-advisory recognition.
- **Pass 2 (Gemini Flash Reasoning with 5s Hard Timeout & LRU Cache):** Ambiguous inputs automatically escalate to Gemini for contextual social-engineering analysis, with an automatic hard fallback to the deterministic engine if offline or rate-limited, and disagreement logging for continuous calibration.
- **Rich Forensics Output:**
  - A risk score (0–100) and a 5-level threat meter (`Level 0: Verified Safe` → `Level 4: Critical`)
  - Scam classification (`DIGITAL_ARREST_COERCION`, `UPI_COLLECT_TRAP`, `STOCK_VIP_PUMP`, `FAKE_KYC_FREEZE`, `COURIER_PARCEL_DRUGS`, `LOTTERY_PRIZE_HARVEST`, `VOICE_CLONE_SOS`, or `VERIFIED_CLEAN`)
  - Extracted Indicators of Compromise (IOCs) — mule UPI IDs, spoofed phone numbers, bank accounts/IFSCs, phishing domains/APKs, and impersonated entities
  - Full trilingual output in **English, Hinglish, and Hindi**
  - **SHA-256 Evidence Vault** locking with tamper-evident hashes for police submission

### ⏸️ Next-Move Prediction + 120s Pause Before You Pay Lock
For every high-risk verdict, Dhaal predicts the scammer's next 3 tactical moves — each with a probability percentage, an estimated time window, and a specific counter-measure — and activates a mandatory **120-second cooling-off lock** (`Pause Before Pay`) to break the panic cycle before any UPI or RTGS transfer happens.

### 🎙️ Controlled AI Voice Sting (Honeypot Decoy)
Deploy a synthetic decoy persona in **Hindi, Hinglish, or English** to keep scammers occupied on the line and extract hidden mule bank accounts, IFSC codes, and UPI handles without exposing the victim's real voice or identity.

### 🤖 Autonomous 24/7 Telegram Protection (`@DhaalTELEBot`)
A live Telegram bot that operates independently of whether the web app is open:
- Supports both **authenticated Telegram Webhooks** (`X-Telegram-Bot-Api-Secret-Token`) and **verified background polling fallback** with persistent update deduplication
- Ingests forwarded text messages, screenshots (via **Gemini Vision OCR**), and voice notes/audio files (via **Gemini Audio Transcription**) from DMs or monitored family/community groups
- Replies directly in-chat with the structured threat verdict, risk score, extracted IOCs, and immediate safety steps

### 🕸️ Live Idempotent Scam Radar
An interactive threat-intelligence graph linking mule UPI IDs, spoofed phone numbers, phishing domains, and bank accounts into campaign clusters:
- Automatically ingests and links IOCs from every Interceptor scan and Telegram bot detection
- **Idempotent aggregation:** Repeated reports of the same UPI ID, phone number, or domain increment its report count and confidence score (`confidencePct`) rather than duplicating nodes
- Tracks node status (`ACTIVE_THREAT`, `FROZEN_1930`, `HONEYPOT_TAGGED`) across regional clusters

### 📉 Epidemiological Outbreak Simulation ($R_0$ Curve Flattening)
Models how early community warnings flatten a scam wave's spread — comparing unmitigated vs. Dhaal-mitigated victim curves over 24 hours based on base reproduction number ($R_0$), warning delay, and WhatsApp/Telegram coverage, calculating **estimated victims saved** and **lakhs of rupees protected**.

### 👨‍👩‍👧 Family Safety Circle, Daily Safety Code & Consensual Drills
- Build a private, persisted **Family Circle** with each member's relationship/role and preferred language (`English`, `Hinglish`, `Hindi`)
- Rotate an **Encrypted Daily Safety Code** (e.g., `KAVACH-749`) to verify genuine family calls against AI voice-cloning scams
- Configure a **Family Telegram Group Chat ID** to automatically broadcast emergency alerts to the whole family when a high-risk scam or duress trigger fires
- Run consensual **Family Practice Drills** simulating fake CBI/Customs/KYC calls to train family members and track their readiness score

### 🔑 Zero-Leak Secret Duress Word Protocol
A secret codeword that, when spoken naturally during a forced "Digital Arrest" video call, silently flags the session and dispatches an emergency SOS to the Family Circle and Telegram group without alerting the scammer watching the screen:
- **Server-side isolation:** Never hardcoded in client bundles, never returned in plaintext via APIs, and strictly redacted (`"duressWordSet": true`) in backup exports

### 📋 1930 NCRP Recovery Pack & Section 106 BNSS / 102 CrPC Bank Unfreeze Support
- **Human-Verified 1930 / NCRP Dossier:** AI-assembled cybercrime complaint drafts where every AI-drafted field remains explicitly flagged until verified by the user, with a live readiness percentage meter
- **Wrongful Bank Account Freeze Challenge:** Calculates disproportionate freeze amounts (full debit freeze vs. disputed lien amount) and generates a ready-to-submit legal representation letter citing **Section 106 BNSS (formerly Section 102 CrPC)** for Nodal Bank Officers and Cyber Crime IOs

### 🧯 Multi-Layer AI Guard & Production Hardening
- **Adversarial Prompt-Injection Quarantine:** Inspects user text, Base64 payloads, Unicode tags, LLM control tokens, and uploaded image EXIF/metadata (`AIGuard`) for jailbreak or score-override attempts, immediately quarantining malicious sessions (`TRIPWIRE_PROMPT_INJECTION_01`)
- **Proxy-Aware Token-Bucket Rate Limiting:** Protects all mutating API routes and webhooks using `X-Forwarded-For` client IP extraction (20 req/min burst protection)
- **Fault-Isolated UI:** Every major view is wrapped in a dedicated React Error Boundary (`ViewErrorBoundary`)
- **Atomic Persistence & Redacted Export:** Atomic `.tmp`-and-rename writes with per-file in-process locks, plus a token-guarded `GET /api/export` endpoint

### 📖 Story Site
A cinematic, stacking-cards scroll narrative explaining Dhaal's mission, live capabilities, and architecture, ending in the Telegram bot's QR code and direct onboarding.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite 8 + TypeScript, Tailwind CSS v4 |
| Animation | Motion (`motion/react`) |
| Icons | Lucide React |
| Backend | Express (via `tsx`), `server.ts` |
| AI | Google Gemini API (`@google/genai`) — second-pass scam reasoning, image OCR, and audio transcription |
| Messaging | Telegram Bot API (Webhook + Polling Fallback + Family Group Alerts) |
| Persistence | Atomic JSON store with per-file write locks (`src/utils/persistence.ts`) |
| Testing & CI | Node.js Test Runner (`node:test`, 28 unit & integration tests) + GitHub Actions (`.github/workflows/test.yml`) |
| Hosting | Google AI Studio / Cloud Run |

## Project Structure

```
├── server.ts                          # Express server: Gemini OCR/audio/reasoning, Telegram webhook + polling, persistence & rate-limiting APIs
├── .env.example                       # Template for environment variables (no secrets committed)
├── .github/workflows/test.yml         # CI pipeline running TypeScript lint, unit tests, and production build
├── src/
│   ├── App.tsx                        # Application shell, navigation, error boundaries, and state sync
│   ├── components/
│   │   ├── InterceptorView.tsx        # Multimodal scam detection, verdict card, next-move prediction, 120s pause lock & voice sting
│   │   ├── ScamRadarView.tsx          # Interactive IOC threat graph & epidemiological outbreak simulation
│   │   ├── FamilyAndRecoveryView.tsx  # Family Circle, Telegram alert config, Duress Word, 1930 NCRP draft & bank unfreeze generator
│   │   ├── StoryLandingView.tsx       # Cinematic scroll story site & live Telegram bot onboarding
│   │   ├── StackingCardsDeck.tsx      # Stacking-cards scroll effect
│   │   ├── MagnificationDock.tsx      # macOS-style floating navigation dock
│   │   └── ViewErrorBoundary.tsx      # Per-view fault isolation error boundary
│   └── utils/
│       ├── scamEngine.ts              # Core detection, de-obfuscation, Gemini escalation merge, AI Guard, outbreak & legal petition logic
│       ├── scamEngine.test.ts         # 28 automated unit & integration tests (detection, AI Guard, persistence, rate limiter, redaction)
│       ├── persistence.ts             # Atomic file writes, in-process locks, rate limiter & redacted export builder
│       └── seedData.ts                # Calibrated preset scenarios & baseline scam intelligence graph
```

## Running Locally

```bash
git clone https://github.com/shrinidhihebbarpm-netizen/Dhaal_1.0.git
cd Dhaal_1.0
npm install

# Copy .env.example to .env and fill in:
# GEMINI_API_KEY           — from Google AI Studio (required for OCR, audio transcription & Pass-2 AI reasoning)
# TELEGRAM_BOT_TOKEN       — from @BotFather (optional, for live Telegram bot & family alerts)
# EXPORT_TOKEN             — optional shared secret for GET /api/export
# TELEGRAM_WEBHOOK_SECRET  — optional custom secret for Telegram webhook header validation

npm run dev
```

### Running Tests & Type Checks

```bash
npm test       # Runs the 28-test suite via node:test (tsx --test src/utils/scamEngine.test.ts)
npm run lint   # Runs TypeScript type checking (tsc --noEmit)
npm run build  # Builds the production client bundle
```

## Team

Built by Priyesh Raj, Shrinidhi Hebbar P M, and team for CodeDay Bengaluru 2026.

## License

MIT
