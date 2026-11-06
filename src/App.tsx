/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Moon, Sun, Upload, BookOpen, ShieldAlert, Radar, Users } from 'lucide-react';
import { StoryLandingView } from './components/StoryLandingView';
import { InterceptorView } from './components/InterceptorView';
import { ScamRadarView } from './components/ScamRadarView';
import { FamilyAndRecoveryView } from './components/FamilyAndRecoveryView';
import { ViewErrorBoundary } from './components/ViewErrorBoundary';
import { MagnificationDock, DockItemData } from './components/MagnificationDock';


import {
  LanguageMode,
  ScamAnalysisResult,
  ComplaintDraft,
  analyzeScamPayload,
} from './utils/scamEngine';
import {
  PRESET_SCENARIOS,
  INITIAL_EVIDENCE_VAULT,
  INITIAL_COMPLAINT_DRAFT,
  ScamGraphNode,
  FamilyMember,
  EvidenceItem,
} from './utils/seedData';

type ActiveTab = 'story' | 'interceptor' | 'radar' | 'family';

function inferNodeType(label: string): ScamGraphNode['type'] {
  const lower = label.toLowerCase();
  if (lower.includes('@')) return 'MULE_UPI';
  if (/^\+?\d[\d\s-]{6,}$/.test(label.trim())) return 'SPOOF_PHONE';
  if (lower.includes('http') || lower.includes('.com') || lower.includes('.in') || lower.includes('.apk') || lower.includes('tg://')) {
    return 'PHISH_DOMAIN';
  }
  if (lower.includes('hdfc') || lower.includes('sbi') || lower.includes('icici') || lower.includes('axis') || lower.includes('a/c') || /\b\d{9,18}\b/.test(lower)) {
    return 'BANK_AC';
  }
  return 'CAMPAIGN_CLUSTER';
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('story');

  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.localStorage.getItem('dhaal_theme') === 'dark';
    }
    return false;
  });

  const [language, setLanguage] = useState<LanguageMode>('en');
  const [interceptorPayload, setInterceptorPayload] = useState<string>(
    PRESET_SCENARIOS[0].payload
  );

  // User-driven Scam Radar: starts empty and only updates based on new user inputs and connected entities
  const [scamGraphNodes, setScamGraphNodes] = useState<ScamGraphNode[]>([]);

  // User-defined Family Safety Circle: no random pre-populated people
  const [familyMembers, setFamilyMembers] = useState<FamilyMember[]>([]);

  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>(INITIAL_EVIDENCE_VAULT);
  const [complaintDraft, setComplaintDraft] = useState<ComplaintDraft>(INITIAL_COMPLAINT_DRAFT);
  const [familyAlertStatus, setFamilyAlertStatus] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (isDarkMode) {
      root.classList.add('dark');
      window.localStorage.setItem('dhaal_theme', 'dark');
    } else {
      root.classList.remove('dark');
      window.localStorage.setItem('dhaal_theme', 'light');
    }
  }, [isDarkMode]);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeTab]);

  // Helper to add a primary node and all connected entity labels into the Scam Radar graph
  const handleAddNodesWithConnections = (
    primary: { label: string; type: ScamGraphNode['type']; source: string },
    connectedLabels: string[],
    existingParentId?: string
  ) => {
    setScamGraphNodes((prev) => {
      const next = prev.map((n) => ({ ...n, connections: [...(n.connections || [])] }));

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
        return presetSlots[(idx - 1) % presetSlots.length];
      };

      const upsertNode = (
        label: string,
        type: ScamGraphNode['type'],
        source: string
      ): ScamGraphNode => {
        const clean = label.trim();
        const existing = next.find((n) => n.label.toLowerCase() === clean.toLowerCase());
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
          const connNode = upsertNode(connLabel, inferNodeType(connLabel), primary.source);
          linkNodes(primaryNode, connNode);
        });

      // Fix #5: Persist nodes to server scamReports.json
      fetch('/api/scam-reports/upsert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          primary,
          connectedLabels,
          existingParentId,
        }),
      }).catch(() => {});

      return next;
    });
  };


  // Automatically sync extracted IOCs & connected entities from user scans/uploads into Scam Radar
  const handleSyncAnalysisToRadar = (analysis: ScamAnalysisResult, sourceLabel: string) => {
    const primaryLabel =
      analysis.extractedIOCs.impersonatedEntity &&
      analysis.extractedIOCs.impersonatedEntity !== 'Unverified Sender'
        ? `${analysis.extractedIOCs.impersonatedEntity} (${analysis.categoryCode})`
        : `User Scan: ${analysis.categoryCode}`;

    const connectedEntities: string[] = [
      ...analysis.extractedIOCs.upiIds,
      ...analysis.extractedIOCs.phoneNumbers,
      ...analysis.extractedIOCs.bankAccounts,
      ...analysis.extractedIOCs.domains,
    ];

    // If no explicit regex IOC was matched, still connect the detected trigger or category
    if (connectedEntities.length === 0 && analysis.triggersDetected.length > 0) {
      connectedEntities.push(analysis.triggersDetected[0]);
    }

    handleAddNodesWithConnections(
      {
        label: primaryLabel,
        type: 'CAMPAIGN_CLUSTER',
        source: sourceLabel,
      },
      connectedEntities
    );
  };

  const handleLaunchInterceptor = (presetPayload?: string) => {
    const payloadToUse = presetPayload || interceptorPayload;
    if (presetPayload) {
      setInterceptorPayload(presetPayload);
      const res = analyzeScamPayload(presetPayload, 'sms');
      handleSyncAnalysisToRadar(res, 'Story Live Intercept');
    }
    setActiveTab('interceptor');
    void payloadToUse;
  };

  const handleAddEvidence = (item: EvidenceItem) => {
    setEvidenceList((prev) => [item, ...prev]);
  };

  const handlePushToComplaintDraft = (analysis: ScamAnalysisResult) => {
    const suspectPhones = analysis.extractedIOCs.phoneNumbers.join(', ') || '+91 98214 77019';
    const suspectUpis = analysis.extractedIOCs.upiIds.join(', ') || 'rbi.verify99@okaxis';
    const updated: ComplaintDraft = {
      incidentId: `DHAAL-1930-${Math.floor(10000 + Math.random() * 89999)}`,
      ncrpCategory: `${analysis.categoryCode} (${analysis.extractedIOCs.impersonatedEntity})`,
      fields: [
        {
          key: 'incidentDateTime',
          label: 'Incident Date & Time (IST)',
          value: new Date().toLocaleString('en-IN') + ' IST',
          aiDrafted: true,
          verifiedByUser: false,
        },
        {
          key: 'suspectIdentifier',
          label: 'Suspect Phone & Impersonated Agency',
          value: `${suspectPhones} (${analysis.extractedIOCs.impersonatedEntity})`,
          aiDrafted: true,
          verifiedByUser: false,
        },
        {
          key: 'muleUpiAndBank',
          label: 'Suspect Beneficiary VPA / Mule Account',
          value: `UPI: ${suspectUpis} | Domains: ${analysis.extractedIOCs.domains.join(', ') || 'N/A'}`,
          aiDrafted: true,
          verifiedByUser: false,
        },
        {
          key: 'disputedAmountAndUtr',
          label: 'Disputed / Attempted Extortion Amount & UTR',
          value: 'Attempted Extortion Intercepted Pre-Payment (Pause Lock Triggered)',
          aiDrafted: true,
          verifiedByUser: false,
        },
        {
          key: 'narrativeSummary',
          label: 'Structured NCRP Incident Narrative (1930 Format)',
          value: `${analysis.headlineEn}. ${analysis.summaryEn} Triggers identified: ${analysis.triggersDetected.join('; ')}.`,
          aiDrafted: true,
          verifiedByUser: false,
        },
      ],
    };
    setComplaintDraft(updated);
    setActiveTab('family');
  };

  // Load persisted family members, scam reports, and complaint drafts on mount
  useEffect(() => {
    fetch('/api/family')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && Array.isArray(data.members)) {
          setFamilyMembers(data.members);
        }
      })
      .catch(() => {});

    fetch('/api/scam-reports')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && Array.isArray(data.nodes) && data.nodes.length > 0) {
          setScamGraphNodes(data.nodes);
        }
      })
      .catch(() => {});

    fetch('/api/complaint-drafts')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && Array.isArray(data.drafts) && data.drafts.length > 0) {
          setComplaintDraft(data.drafts[0]);
        }
      })
      .catch(() => {});
  }, []);

  const handleAlertFamily = (reason: string) => {
    setFamilyAlertStatus(`EMERGENCY ALERT SENT TO FAMILY CIRCLE: ${reason}`);
    setFamilyMembers((prev) =>
      prev.map((m) => ({
        ...m,
        status: 'IN_CALL_WATCH',
      }))
    );
    // Dispatch alert to configured Family Telegram group (Fix #3)
    fetch('/api/family/alert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alertType: 'CRITICAL_SCAM_INTERCEPT',
        message: `🚨 *DHAAL EMERGENCY ALERT*: An interceptor event was triggered for your family member.\nReason: ${reason}`,
      }),
    }).catch(() => {});
  };

  const handleAddFamilyMember = (memberInput: {
    name: string;
    relation: string;
    phone: string;
    language: 'English' | 'Hinglish' | 'Hindi';
  }) => {
    const newMember: FamilyMember = {
      id: `fam-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      name: memberInput.name,
      relation: memberInput.relation,
      phone: memberInput.phone,
      language: memberInput.language,
      lastDrillScore: 85,
      status: 'PROTECTED',
    };
    setFamilyMembers((prev) => [...prev, newMember]);
    fetch('/api/family', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newMember),
    }).catch(() => {});
  };

  const handleRemoveFamilyMember = (id: string) => {
    setFamilyMembers((prev) => prev.filter((m) => m.id !== id));
    fetch(`/api/family/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }).catch(() => {});
  };

  const handleUpdateFamilyMember = (id: string, patch: Partial<FamilyMember>) => {
    setFamilyMembers((prev) =>
      prev.map((m) => (m.id === id ? { ...m, ...patch } : m))
    );
    fetch(`/api/family/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }).catch(() => {});
  };


  const navItems: Array<{ id: ActiveTab; label: string }> = [
    { id: 'story', label: 'Story' },
    { id: 'interceptor', label: 'Interceptor' },
    { id: 'radar', label: 'Radar' },
    { id: 'family', label: 'Family' },
  ];

  const dockItems: DockItemData[] = [
    {
      id: 'dock-item-story',
      icon: <BookOpen size={21} />,
      label: 'Story',
      isActive: activeTab === 'story',
      onClick: () => setActiveTab('story'),
    },
    {
      id: 'dock-item-interceptor',
      icon: <ShieldAlert size={21} />,
      label: 'Interceptor',
      isActive: activeTab === 'interceptor',
      onClick: () => setActiveTab('interceptor'),
    },
    {
      id: 'dock-item-radar',
      icon: <Radar size={21} />,
      label: 'Radar',
      isActive: activeTab === 'radar',
      onClick: () => setActiveTab('radar'),
    },
    {
      id: 'dock-item-family',
      icon: <Users size={21} />,
      label: 'Family',
      isActive: activeTab === 'family',
      onClick: () => setActiveTab('family'),
    },
  ];

  return (
    <div className="min-h-screen bg-[#f8f7f4] dark:bg-[#0f1115] text-[#1a1a1a] dark:text-[#f2f0eb] flex flex-col transition-colors duration-150">
      {/* STRICT 3-ZONE EDITORIAL TOP BAR CONTRACT */}
      <header className="sticky top-0 z-40 bg-[#f8f7f4] dark:bg-[#0f1115] border-b border-[#ddd] dark:border-[#262b36]">
        <div className="max-w-[1440px] mx-auto px-[4vw] h-20 flex items-center justify-between gap-8">
          {/* Zone 1: Single text element wordmark */}
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('story');
            }}
            className="font-mono text-sm font-bold uppercase tracking-[0.1em] text-[#1a1a1a] dark:text-[#f2f0eb] whitespace-nowrap shrink-0"
          >
            Dhaal Defence
          </a>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={() => handleLaunchInterceptor()}
              className="px-5 py-2.5 text-xs font-mono uppercase tracking-[0.1em] text-white dark:text-[#0f1115] bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#d42020] dark:hover:bg-[#ff5c5c] dark:hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Upload &amp; Inspect
            </button>
          </div>
        </div>

        {/* Mobile Compact Single-Row Tab Bar (<768px) */}
        <nav
          aria-label="Mobile Navigation"
          className="flex md:hidden items-center justify-between px-4 py-2 bg-white dark:bg-[#161920] border-t border-[#ddd] dark:border-[#262b36] overflow-x-auto gap-2"
        >
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              className={`px-3 py-1 text-xs font-mono uppercase whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === item.id
                  ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                  : 'text-[#6b6b6b] dark:text-[#9ca3af]'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      {/* MAIN WORKSPACE CONTAINER */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-[4vw] pt-4">
        {/* Contextual Workspace Utility Bar with Multimodal Upload Shortcut, Language Switcher & Dark Mode Toggle */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-[#ddd] dark:border-[#262b36]">
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
            <span>Editorial Security Console</span>
            <span>·</span>
            <button
              type="button"
              onClick={() => setActiveTab('interceptor')}
              className="flex items-center gap-1.5 text-[#2e7d32] dark:text-[#4ade80] font-bold hover:underline cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload Image · Audio · Text (Free In-App Scanner)</span>
            </button>
          </div>

          <div className="flex items-center gap-3">
            {/* Language Switcher */}
            <div
              role="group"
              aria-label="Select Language Mode"
              className="flex items-center bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-0.5"
            >
              {(['en', 'hinglish', 'hi'] as LanguageMode[]).map((lang) => (
                <button
                  key={lang}
                  type="button"
                  onClick={() => setLanguage(lang)}
                  className={`px-2.5 py-1 text-xs font-mono transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    language === lang
                      ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                      : 'text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-white'
                  }`}
                >
                  {lang === 'en' ? 'English' : lang === 'hinglish' ? 'Hinglish' : 'हिंदी'}
                </button>
              ))}
            </div>

            {/* Dark Mode Toggle Button */}
            <button
              type="button"
              onClick={() => setIsDarkMode((prev) => !prev)}
              aria-label={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              aria-pressed={isDarkMode}
              className="px-3.5 py-1.5 bg-white dark:bg-[#161920] hover:bg-[#eae8e1] dark:hover:bg-[#222733] text-[#1a1a1a] dark:text-[#f2f0eb] border border-[#ddd] dark:border-[#262b36] font-mono text-xs uppercase tracking-[0.08em] flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {isDarkMode ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-[#fbbf24]" />
                  <span>Light Mode</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-[#1a1a1a]" />
                  <span>Dark Mode</span>
                </>
              )}
            </button>
          </div>
        </div>

        {activeTab === 'story' && (
          <ViewErrorBoundary viewName="Story Landing">
            <StoryLandingView
              language={language}
              onLanguageChange={setLanguage}
              onLaunchInterceptor={handleLaunchInterceptor}
              onNavigateTab={setActiveTab}
              onQuickAlertFamily={() => handleAlertFamily('Triggered from Live Intercept Preview')}
            />
          </ViewErrorBoundary>
        )}

        {activeTab === 'interceptor' && (
          <ViewErrorBoundary viewName="Live Interceptor">
            <InterceptorView
              language={language}
              onLanguageChange={setLanguage}
              initialPayload={interceptorPayload}
              onAddEvidence={handleAddEvidence}
              onPushToComplaintDraft={handlePushToComplaintDraft}
              onAlertFamily={handleAlertFamily}
              familyAlertStatus={familyAlertStatus}
              onSyncAnalysisToRadar={handleSyncAnalysisToRadar}
              onNavigateToRadar={() => setActiveTab('radar')}
              familyMembers={familyMembers}
            />
          </ViewErrorBoundary>
        )}

        {activeTab === 'radar' && (
          <ViewErrorBoundary viewName="Scam Radar">
            <ScamRadarView
              nodes={scamGraphNodes}
              onAddNodesWithConnections={handleAddNodesWithConnections}
              onClearNodes={() => {
                setScamGraphNodes([]);
                fetch('/api/scam-reports/clear', { method: 'POST' }).catch(() => {});
              }}
              onGoToInterceptor={() => setActiveTab('interceptor')}
              language={language}
            />
          </ViewErrorBoundary>
        )}

        {activeTab === 'family' && (
          <ViewErrorBoundary viewName="Family & Recovery">
            <FamilyAndRecoveryView
              familyMembers={familyMembers}
              onAddFamilyMember={handleAddFamilyMember}
              onRemoveFamilyMember={handleRemoveFamilyMember}
              onUpdateFamilyMember={handleUpdateFamilyMember}
              evidenceList={evidenceList}
              complaintDraft={complaintDraft}
              onUpdateComplaintDraft={setComplaintDraft}
            />
          </ViewErrorBoundary>
        )}
      </main>

      {/* FLOATING MAGNIFICATION DOCK (STORY · INTERCEPTOR · RADAR · FAMILY) */}
      <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50">
        <MagnificationDock
          items={dockItems}
          panelHeight={68}
          baseItemSize={50}
          magnification={76}
        />
      </div>

      {/* QUIET EDITORIAL FOOTER */}
      <footer className="border-t border-[#ddd] dark:border-[#262b36] bg-[#f8f7f4] dark:bg-[#0f1115] pt-6 pb-28 mt-auto transition-colors duration-150">
        <div className="max-w-[1440px] mx-auto px-[4vw] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
          <div>
            Cyber Helpline: 1930 · BNSS Section 106 Compliance Ready
          </div>
          <div className="flex flex-wrap items-center gap-4">
            <button
              type="button"
              onClick={() => setActiveTab('interceptor')}
              className="text-[#2e7d32] dark:text-[#4ade80] font-bold hover:underline cursor-pointer uppercase"
            >
              Multimodal Upload: Image · Audio · Text
            </button>
            <span>·</span>
            <button
              type="button"
              onClick={() => setActiveTab('family')}
              className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold hover:text-[#d42020] dark:hover:text-[#ff5c5c] cursor-pointer uppercase"
            >
              1930 &amp; Bank Unfreeze Dossier
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
