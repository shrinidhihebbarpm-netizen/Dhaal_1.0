import React, { useRef, useState } from 'react';
import {
  motion,
  useScroll,
  useTransform,
  useSpring,
} from 'motion/react';
import {
  ArrowRight,
  BookOpen,
  ShieldAlert,
  Radar,
  Users,
  Upload,
  Play,
  RotateCcw,
  Layers,
} from 'lucide-react';

export type PortfolioTabId = 'story' | 'interceptor' | 'radar' | 'family';

interface StackingCardsDeckProps {
  onNavigateTab: (tab: PortfolioTabId) => void;
  onLaunchInterceptor: () => void;
}

interface PortfolioCardData {
  id: PortfolioTabId;
  number: string;
  tabLabel: string;
  kicker: string;
  title: string;
  summary: string;
  ctaLabel: string;
  stickyTopPx: number;
  borderTopClass: string;
  accentTextClass: string;
  badgeBgClass: string;
  ctaClass: string;
  icon: React.ReactNode;
  metrics: Array<{ label: string; value: string }>;
}

const DECK_CARDS: PortfolioCardData[] = [
  {
    id: 'story',
    number: '01',
    tabLabel: 'Story & Mission',
    kicker: 'CARD 01 / 04 · THE PROTECTION LOOP',
    title: 'Pre-Payment Warning, Family SOS & 1930 Recovery in One Loop',
    summary:
      'Dhaal stops cyber fraud before money leaves your account—combining early AI detection, a 120-second cooling lock, family circle verification, and legal recovery.',
    ctaLabel: 'Try Live Scam Scan',
    stickyTopPx: 96,
    borderTopClass: 'border-t-[#1a1a1a] dark:border-t-[#f2f0eb]',
    accentTextClass: 'text-[#1a1a1a] dark:text-[#f2f0eb]',
    badgeBgClass: 'bg-[#1a1a1a] text-white dark:bg-[#f2f0eb] dark:text-[#0f1115]',
    ctaClass:
      'bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#d42020] dark:hover:bg-[#ff5c5c] text-white dark:text-[#0f1115] dark:hover:text-white',
    icon: <BookOpen className="w-4 h-4" />,
    metrics: [
      { label: 'Input Modes', value: 'Image · Audio · Text' },
      { label: 'Languages', value: 'English · Hinglish · हिंदी' },
      { label: 'Safety Lock', value: '120s Pause Before Pay' },
    ],
  },
  {
    id: 'interceptor',
    number: '02',
    tabLabel: 'Scam Interceptor',
    kicker: 'CARD 02 / 04 · MULTIMODAL AI INTERCEPTOR',
    title: 'Upload Warrant Screenshots, Call Audio, or SMS for Instant Verdict',
    summary:
      'Scans forged CBI/RBI arrest warrants via OCR, transcribes Hinglish/Hindi voice calls, forecasts the scammer’s next 3 moves, and locks hasty UPI transfers for 2 minutes.',
    ctaLabel: 'Open Scam Interceptor',
    stickyTopPx: 148,
    borderTopClass: 'border-t-[#d42020]',
    accentTextClass: 'text-[#d42020] dark:text-[#ff5c5c]',
    badgeBgClass: 'bg-[#d42020] text-white',
    ctaClass: 'bg-[#d42020] hover:bg-[#b51818] text-white',
    icon: <ShieldAlert className="w-4 h-4" />,
    metrics: [
      { label: 'Image OCR', value: 'Fake Warrants & Receipts' },
      { label: 'Voice Scan', value: 'Audio Upload & Mic' },
      { label: 'Prediction', value: 'Next 3 Coercion Moves' },
    ],
  },
  {
    id: 'radar',
    number: '03',
    tabLabel: 'Scam Radar',
    kicker: 'CARD 03 / 04 · USER-DRIVEN NETWORK GRAPH',
    title: 'Live Attribution Graph Linking Every Extracted Scammer Entity',
    summary:
      'Updates strictly from your scanned inputs and manual entries—automatically linking connected Mule UPI IDs, spoofed phone numbers, bank accounts, and phishing domains.',
    ctaLabel: 'Open Scam Radar',
    stickyTopPx: 200,
    borderTopClass: 'border-t-[#2e7d32]',
    accentTextClass: 'text-[#2e7d32] dark:text-[#4ade80]',
    badgeBgClass: 'bg-[#2e7d32] text-white',
    ctaClass: 'bg-[#2e7d32] hover:bg-[#1b5e20] text-white',
    icon: <Radar className="w-4 h-4" />,
    metrics: [
      { label: 'Data Source', value: '100% User-Input Driven' },
      { label: 'Entity Links', value: 'UPI · Phone · Bank · URL' },
      { label: 'Graph Mode', value: 'Interactive SVG Cluster' },
    ],
  },
  {
    id: 'family',
    number: '04',
    tabLabel: 'Family & Recovery',
    kicker: 'CARD 04 / 04 · CUSTOM CIRCLE & 1930 DOSSIER',
    title: 'Your Trusted Family Circle, Silent Duress Word & Bank Unfreeze',
    summary:
      'Add your own family members and define what each entity is to you. Trigger silent SOS alerts, verify AI-drafted 1930 complaints, and generate Section 106 BNSS bank unfreeze petitions.',
    ctaLabel: 'Open Family & Recovery',
    stickyTopPx: 252,
    borderTopClass: 'border-t-[#b45309]',
    accentTextClass: 'text-[#b45309] dark:text-[#fbbf24]',
    badgeBgClass: 'bg-[#b45309] text-white',
    ctaClass:
      'bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#b45309] dark:hover:bg-[#fbbf24] text-white dark:text-[#0f1115]',
    icon: <Users className="w-4 h-4" />,
    metrics: [
      { label: 'Guardians', value: 'User-Defined Entities' },
      { label: '1930 Filing', value: 'Human-Verified Dossier' },
      { label: 'Bank Relief', value: 'BNSS Sec 106 Petition' },
    ],
  },
];

interface StickyCardItemProps {
  card: PortfolioCardData;
  index: number;
  total: number;
  demoOffsetIndex: number | null;
  onCardClick: () => void;
}

const StickyCardItem: React.FC<StickyCardItemProps> = ({
  card,
  index,
  total,
  demoOffsetIndex,
  onCardClick,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Track scroll progress of this specific card wrapper
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start start', 'end start'],
  });

  // As the user scrolls down and the next card slides over this sticky card,
  // scale this card down smoothly (e.g. 0.94, 0.96, 0.98, 1.0) so they stack like a deck of cards.
  const minScale = 1 - (total - 1 - index) * 0.022;
  const rawScale = useTransform(scrollYProgress, [0, 1], [1, minScale]);
  const smoothScale = useSpring(rawScale, {
    mass: 0.12,
    stiffness: 170,
    damping: 22,
  });

  // If the user triggered the in-place "Preview Stack Animation", also animate scale/y
  const isUnderDemoStack = demoOffsetIndex !== null && index < demoOffsetIndex;
  const isWaitingBelowDemo = demoOffsetIndex !== null && index > demoOffsetIndex;

  return (
    <div
      ref={containerRef}
      id={`stack-card-${card.number}`}
      style={{
        top: `${card.stickyTopPx}px`,
        zIndex: (index + 1) * 10,
      }}
      className="sticky mb-28 sm:mb-36 last:mb-12"
    >
      <motion.article
        style={{
          scale: smoothScale,
          transformOrigin: 'top center',
        }}
        initial={{ opacity: 0, y: 70 }}
        animate={{
          opacity: isWaitingBelowDemo ? 0.35 : 1,
          y: isWaitingBelowDemo ? 90 : isUnderDemoStack ? -2 : 0,
        }}
        transition={{
          type: 'spring',
          stiffness: 130,
          damping: 18,
          delay: demoOffsetIndex === null ? index * 0.08 : 0,
        }}
        className={`editorial-panel border-t-4 ${card.borderTopClass} bg-white dark:bg-[#161920] px-6 py-6 sm:px-9 sm:py-7 shadow-[0_-16px_42px_rgba(0,0,0,0.12)] dark:shadow-[0_-18px_48px_rgba(0,0,0,0.75)]`}
      >
        {/* Card Content */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          <div className="lg:col-span-7 space-y-3">
            <h2 className="font-display italic text-2xl sm:text-4xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb] leading-[1.12]">
              {card.title}
            </h2>
            <p className="text-sm sm:text-base text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
              {card.summary}
            </p>
            <div className="pt-2">
              <button
                type="button"
                onClick={onCardClick}
                className={`px-6 py-3 ${card.ctaClass} font-mono text-xs uppercase tracking-[0.1em] font-bold inline-flex items-center gap-2.5 cursor-pointer transition-colors whitespace-nowrap`}
              >
                {card.id === 'interceptor' ? <Upload className="w-4 h-4" /> : card.icon}
                <span>{card.ctaLabel}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Right 5 Cols: 3 Compact Key Specs */}
          <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-1 gap-2.5 font-mono text-xs">
            {card.metrics.map((m) => (
              <div
                key={m.label}
                className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] px-4 py-3 flex items-center justify-between gap-2"
              >
                <span className="text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]">
                  {m.label}
                </span>
                <span className="font-bold text-[#1a1a1a] dark:text-[#f2f0eb] text-right">
                  {m.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </motion.article>
    </div>
  );
};

export const StackingCardsDeck: React.FC<StackingCardsDeckProps> = ({
  onNavigateTab,
  onLaunchInterceptor,
}) => {
  return (
    <section
      id="portfolio-stacking-deck"
      aria-label="Portfolio Stacking Cards"
      className="space-y-6"
    >
      {/* Sticky Stacking Cards Container */}
      <div className="relative pt-2 pb-[36vh]">
        {DECK_CARDS.map((card, index) => (
          <StickyCardItem
            key={card.id}
            card={card}
            index={index}
            total={DECK_CARDS.length}
            demoOffsetIndex={null}
            onCardClick={() => {
              if (card.id === 'story' || card.id === 'interceptor') {
                onLaunchInterceptor();
              } else {
                onNavigateTab(card.id);
              }
            }}
          />
        ))}
      </div>
    </section>
  );
};
