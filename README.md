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

### 🔍 Interceptor — AI Scam Detection
Paste a message, forward a screenshot, or drop a voice note. Gemini extracts the threat and returns:
- A risk score (0–100) and a 5-level threat meter (Safe → Critical)
- The scam category (Digital Arrest / Coercion, UPI Collect Trap, Stock/VIP Pump, Fake KYC, Fake Delivery, Lottery/Prize, Voice-Clone SOS, or Verified Clean)
- Extracted indicators of compromise — UPI IDs, phone numbers, bank accounts, phishing domains, and the impersonated entity
- Full output in **English, Hinglish, and Hindi**

### ⏸️ Next-Move Prediction + Pause Before You Pay
For every high-risk verdict, Dhaal predicts the scammer's next several moves — each with a probability, a time window, and a specific counter-measure — and triggers a mandatory pause before any transfer.

### 🤖 Telegram Protection
A live bot (`@DhaalTELEBot`) that ingests forwarded text, photos, and voice notes from DMs or monitored groups. Images are read via Gemini OCR, voice notes via Gemini audio transcription, and the bot replies in-chat with the verdict.

### 🕸️ Scam Radar
A live threat graph linking mule UPI IDs, spoofed phone numbers, phishing domains, and bank accounts into campaign clusters, each with a confidence score and status (Active Threat / Frozen under 1930 / Honeypot-tagged).

### 📉 Outbreak Simulation
Models how early warnings flatten a scam wave's spread — unmitigated vs. mitigated victim curves over time, with an estimate of victims and money saved.

### 👨‍👩‍👧 Family Circle
Add family members with their preferred language (English / Hinglish / Hindi), track protection status, and run consensual **Family Drills** that score how well they spot fake-officer scripts.

### 🔑 Duress Word
A secret word that, spoken during a monitored call, silently flags the session and alerts the family circle without tipping off the caller.

### 📋 Recovery Pack
AI-assembled 1930/NCRP complaint drafts and bank-freeze (Section 102 CrPC) unfreeze petitions — every AI-filled field stays flagged as unverified until a human confirms it, with a readiness check before submission.

### 🧯 AI Guard
Evaluates live session transcripts for prompt-injection and hijack attempts and quarantines the session if a tripwire fires.

### 📖 Story Site
A cinematic, stacking-cards scroll narrative explaining Dhaal, ending in the Telegram bot's QR code.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite 8 + TypeScript, Tailwind CSS v4 |
| Animation | Motion (Framer Motion) |
| Icons | Lucide React |
| Backend | Express (via `tsx`), `server.ts` |
| AI | Google Gemini API (`@google/genai`) — text, OCR, and audio transcription |
| Messaging | Telegram Bot API |
| Hosting | Google AI Studio |

## Project Structure

```
├── server.ts                        # Express server: Gemini analysis + Telegram bot integration
├── src/
│   ├── App.tsx                      # Shell, navigation, family-member state
│   ├── components/
│   │   ├── InterceptorView.tsx      # Scam detection + verdict + pause screen
│   │   ├── ScamRadarView.tsx        # Threat graph + outbreak simulation
│   │   ├── FamilyAndRecoveryView.tsx# Family Circle, Duress Word, Recovery Pack
│   │   ├── StoryLandingView.tsx     # Cinematic scroll story site
│   │   ├── StackingCardsDeck.tsx    # Stacking-cards scroll effect
│   │   └── MagnificationDock.tsx    # macOS-style nav dock
│   └── utils/
│       ├── scamEngine.ts            # Core detection, prediction, AI Guard, outbreak & complaint logic
│       └── seedData.ts              # Demo scenarios + seeded scam graph data
```

## Running Locally

```bash
git clone https://github.com/shrinidhihebbarpm-netizen/Dhaal_1.0.git
cd Dhaal_1.0
npm install

# Copy .env.example to .env and fill in:
# GEMINI_API_KEY      — from Google AI Studio
# TELEGRAM_BOT_TOKEN   — from @BotFather (optional, for live Telegram sync)

npm run dev
```

## Team

Built by Priyesh Raj, Shrinidhi Hebbar P M, and team for CodeDay Bengaluru 2026.

## License

MIT
