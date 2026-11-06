import React, { useState, useEffect } from 'react';
import { ArrowRight, Upload, Volume2, QrCode, Copy, Check, Send } from 'lucide-react';
import { LanguageMode } from '../utils/scamEngine';
import { PRESET_SCENARIOS } from '../utils/seedData';
import { StackingCardsDeck } from './StackingCardsDeck';
import { apiFetch } from '../context/AuthContext';

interface StoryLandingViewProps {
  language: LanguageMode;
  onLanguageChange: (lang: LanguageMode) => void;
  onLaunchInterceptor: (presetPayload?: string) => void;
  onNavigateTab: (tab: 'story' | 'interceptor' | 'radar' | 'family') => void;
  onQuickAlertFamily?: () => void;
}

const ATTACHED_TELEGRAM_QR_SRC =
  '/assets/aistudio/qrcode_422062407_788f07776ef5957f8376b611396aefc4_3100e8db.png';

export const StoryLandingView: React.FC<StoryLandingViewProps> = ({
  language,
  onLaunchInterceptor,
  onNavigateTab,
}) => {
  const [botUsername, setBotUsername] = useState<string>('DhaalTELEBot');
  const [connectedBotName, setConnectedBotName] = useState<string | null>('DhaalTELEBot');
  const [copiedLink, setCopiedLink] = useState(false);

  useEffect(() => {
    let active = true;
    apiFetch('/api/telegram/status')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!active || !data) return;
        if (data.configured && data.botUsername) {
          setConnectedBotName(data.botUsername);
          setBotUsername(data.botUsername);
        }
      })
      .catch(() => {
        // Silent background check
      });
    return () => {
      active = false;
    };
  }, []);

  const cleanUsername =
    (botUsername || 'DhaalTELEBot').replace(/^@+/, '').trim() || 'DhaalTELEBot';
  const telegramDeepLink = `https://t.me/${cleanUsername}`;

  const handleUsernameChange = (val: string) => {
    const sanitized = val.replace(/\s+/g, '');
    setBotUsername(sanitized);
  };

  const handleCopyDeepLink = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(telegramDeepLink);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    }
  };

  const heroTitleText =
    language === 'en'
      ? 'The Shield Against Modern Cyber Fraud.'
      : language === 'hinglish'
      ? 'Ek Paisa Bhi Katne Se Pehle Scammers Ko Rokein.'
      : 'एक पैसा भी कटने से पहले साइबर ठगों को रोकें।';

  const shortBriefText =
    language === 'en'
      ? 'Dhaal is an AI cyber-defense console that detects scams across uploaded images, audio calls, and text before you pay, alerts your family circle, maps connected scammer networks, and generates verified 1930 & bank-unfreeze dossiers.'
      : language === 'hinglish'
      ? 'Dhaal ek AI cyber-defense console hai jo paise bhejne se pehle image, audio aur text scams pakadta hai, family circle ko alert karta hai, scammer network map karta hai, aur 1930 complaint tayaar karta hai.'
      : 'ढाल एक एआई साइबर-रक्षा कंसोल है जो पैसे भेजने से पहले इमेज, ऑडियो और टेक्स्ट स्कैम पकड़ता है, परिवार को अलर्ट करता है, ठगों का नेटवर्क मैप करता है और 1930 शिकायत तैयार करता है।';

  const speakBrief = () => {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(shortBriefText);
      utterance.lang = language === 'hi' ? 'hi-IN' : 'en-IN';
      utterance.rate = 1.0;
      window.speechSynthesis.speak(utterance);
    }
  };

  return (
    <div className="space-y-8 pt-4 pb-16">
      {/* =====================================================================
          1. VERY SHORT BRIEF ABOUT THE WEBPAGE
         ===================================================================== */}
      <section aria-label="Webpage Brief" className="editorial-panel p-6 sm:p-8">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2.5 max-w-3xl">
            <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#d42020] dark:text-[#ff5c5c] font-bold">
              Dhaal Defence · Pre-Payment AI Shield, Family SOS &amp; 1930 Recovery
            </div>
            <h1 className="font-display italic font-semibold text-3xl sm:text-5xl leading-[1.06] text-[#1a1a1a] dark:text-[#f2f0eb]">
              {heroTitleText}
            </h1>
            <p className="text-sm sm:text-base text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
              {shortBriefText}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => onLaunchInterceptor(PRESET_SCENARIOS[0].payload)}
              className="px-6 py-3.5 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#d42020] dark:hover:bg-[#ff5c5c] text-white dark:text-[#0f1115] dark:hover:text-white font-mono text-xs uppercase tracking-[0.1em] font-bold transition-colors flex items-center gap-2.5 cursor-pointer whitespace-nowrap"
            >
              <Upload className="w-4 h-4" />
              <span>Upload Image, Audio or Text</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <button
              type="button"
              onClick={speakBrief}
              className="px-4 py-3.5 bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#222733] text-[#1a1a1a] dark:text-[#f2f0eb] border border-[#ddd] dark:border-[#262b36] font-mono text-xs uppercase tracking-[0.08em] flex items-center gap-2 cursor-pointer whitespace-nowrap"
              aria-label="Listen to Brief"
            >
              <Volume2 className="w-4 h-4 text-[#d42020] dark:text-[#ff5c5c]" />
              <span>Voice Brief</span>
            </button>
          </div>
        </div>
      </section>

      {/* =====================================================================
          2. STACKING CARDS PORTFOLIO ANIMATION (ONLY ON LANDING PAGE)
         ===================================================================== */}
      <StackingCardsDeck
        onNavigateTab={onNavigateTab}
        onLaunchInterceptor={() => onLaunchInterceptor(PRESET_SCENARIOS[0].payload)}
      />

      {/* =====================================================================
          3. STORY FINALE: TELEGRAM BOT PROTECTION QR BRIDGE
         ===================================================================== */}
      <section
        aria-label="Telegram Protection QR Bridge"
        className="editorial-panel p-6 sm:p-10 border-t-2 border-t-[#1a1a1a] dark:border-t-[#f2f0eb]"
      >
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          <div className="lg:col-span-7 space-y-4">
            <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-[#d42020] dark:text-[#ff5c5c] font-bold flex items-center gap-2">
              <QrCode className="w-3.5 h-3.5" />
              <span>
                {connectedBotName
                  ? `Live Bot Connected · @${connectedBotName}`
                  : 'Instant Mobile Protection · Telegram Bot Bridge'}
              </span>
            </div>

            <h2 className="font-display italic font-semibold text-2xl sm:text-4xl leading-[1.1] text-[#1a1a1a] dark:text-[#f2f0eb]">
              {language === 'en'
                ? 'Forward Any Suspicious Message, Screenshot, or Voice Note on Telegram.'
                : language === 'hinglish'
                ? 'Koi Bhi Shakiya Message, Screenshot ya Voice Note Telegram Bot Par Bhejein.'
                : 'कोई भी संदिग्ध संदेश, स्क्रीनशॉट या वॉयस नोट सीधे टेलीग्राम बॉट पर भेजें।'}
            </h2>

            <p className="text-sm sm:text-base text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed max-w-2xl">
              {language === 'en'
                ? 'Scan the QR code to open the Dhaal Telegram Bot on your phone. Send or forward any WhatsApp/SMS text, payment screenshot, or call recording — the bot automatically analyzes it and replies directly inside your Telegram chat while syncing with the Live Interceptor.'
                : language === 'hinglish'
                ? 'Apne phone se QR scan karein aur Dhaal Telegram Bot kholein. Koi bhi suspicious screenshot, audio call ya link bhejein — bot turant Telegram chat mein hi pura scam analysis reply karega.'
                : 'अपने फोन से क्यूआर कोड स्कैन करें और ढाल टेलीग्राम बॉट खोलें। किसी भी संदिग्ध स्क्रीनशॉट, ऑडियो कॉल या लिंक को भेजें — बॉट तुरंत चैट में ही जवाब देगा।'}
            </p>

            <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl">
              <div className="p-3 bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36]">
                <label
                  htmlFor="tg-bot-handle-input"
                  className="block font-mono text-[10px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af] mb-1"
                >
                  Target Bot Handle (@username)
                </label>
                <div className="flex items-center gap-1.5">
                  <span className="font-mono text-xs text-[#6b6b6b]">@</span>
                  <input
                    id="tg-bot-handle-input"
                    type="text"
                    value={cleanUsername}
                    onChange={(e) => handleUsernameChange(e.target.value)}
                    placeholder="DhaalTELEBot"
                    className="w-full bg-transparent font-mono text-xs text-[#1a1a1a] dark:text-[#f2f0eb] focus:outline-none"
                  />
                </div>
              </div>

              <div className="p-3 bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] flex flex-col justify-between">
                <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]">
                  Deep Link Endpoint
                </span>
                <div className="flex items-center justify-between gap-2 mt-1">
                  <span className="font-mono text-xs text-[#1a1a1a] dark:text-[#f2f0eb] truncate">
                    t.me/{cleanUsername}
                  </span>
                  <button
                    type="button"
                    onClick={handleCopyDeepLink}
                    className="font-mono text-[10px] uppercase tracking-wider text-[#d42020] dark:text-[#ff5c5c] hover:underline flex items-center gap-1 shrink-0 cursor-pointer"
                  >
                    {copiedLink ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedLink ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-2 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => onNavigateTab('interceptor')}
                className="px-5 py-3 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#d42020] dark:hover:bg-[#ff5c5c] text-white dark:text-[#0f1115] dark:hover:text-white font-mono text-xs uppercase tracking-[0.1em] font-bold transition-colors flex items-center gap-2 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Open Live Telegram Sync Console</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Attached QR Code Image Frame */}
          <div className="lg:col-span-5 flex flex-col items-center lg:items-end">
            <div className="p-5 bg-white text-[#1a1a1a] border-2 border-[#1a1a1a] dark:border-[#f2f0eb] max-w-[260px] w-full space-y-3">
              <div className="flex items-center justify-between border-b border-[#e5e5e5] pb-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.1em] font-bold text-[#1a1a1a]">
                  DHAAL · TELEGRAM QR
                </span>
                <span className="font-mono text-[10px] text-[#d42020] font-bold">24×7 SHIELD</span>
              </div>

              <div className="aspect-square w-full bg-white p-1 border border-[#eae8e1] flex items-center justify-center">
                <img
                  src={ATTACHED_TELEGRAM_QR_SRC}
                  alt={`Telegram QR code for @${cleanUsername}`}
                  className="w-full h-full object-contain"
                />
              </div>

              <div className="pt-1 border-t border-[#e5e5e5] flex items-center justify-between font-mono text-[10px] text-[#555]">
                <span className="truncate">@{cleanUsername}</span>
                <span className="uppercase font-bold text-[#1a1a1a]">SCAN TO LINK</span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};


