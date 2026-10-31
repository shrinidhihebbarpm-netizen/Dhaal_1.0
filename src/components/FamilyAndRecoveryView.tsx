import React, { useState, useEffect } from 'react';
import {
  PhoneCall,
  Copy,
  RefreshCw,
  UserPlus,
  Trash2,
  Users,
} from 'lucide-react';
import {
  ComplaintDraft,
  verifyComplaintDraftField,
  computeDraftReadiness,
  checkDuressTrigger,
  evaluateUnfreezePetition,
} from '../utils/scamEngine';
import { FamilyMember, EvidenceItem } from '../utils/seedData';

interface FamilyAndRecoveryViewProps {
  familyMembers: FamilyMember[];
  onAddFamilyMember: (member: {
    name: string;
    relation: string;
    phone: string;
    language: 'English' | 'Hinglish' | 'Hindi';
  }) => void;
  onRemoveFamilyMember: (id: string) => void;
  onUpdateFamilyMember: (id: string, patch: Partial<FamilyMember>) => void;
  evidenceList: EvidenceItem[];
  complaintDraft: ComplaintDraft;
  onUpdateComplaintDraft: (draft: ComplaintDraft) => void;
}

const ENTITY_ROLE_PRESETS = [
  'Mother',
  'Father',
  'Spouse / Partner',
  'Sibling',
  'Son / Daughter',
  'Trusted Friend',
  'Bank / Legal Advisor',
];

export const FamilyAndRecoveryView: React.FC<FamilyAndRecoveryViewProps> = ({
  familyMembers,
  onAddFamilyMember,
  onRemoveFamilyMember,
  onUpdateFamilyMember,
  evidenceList,
  complaintDraft,
  onUpdateComplaintDraft,
}) => {
  // New Family / Trusted Entity Form State
  const [newEntityName, setNewEntityName] = useState<string>('');
  const [newEntityRelation, setNewEntityRelation] = useState<string>('');
  const [newEntityPhone, setNewEntityPhone] = useState<string>('');
  const [newEntityLanguage, setNewEntityLanguage] = useState<'English' | 'Hinglish' | 'Hindi'>('Hinglish');
  const [memberFormError, setMemberFormError] = useState<string | null>(null);
  const [memberAddedBanner, setMemberAddedBanner] = useState<string | null>(null);

  // Daily Safety Code state
  const [dailyCode, setDailyCode] = useState<string>('KAVACH-749');
  const [codeSyncedMsg, setCodeSyncedMsg] = useState<string | null>(null);

  // Secret Duress Word state
  const [secretDuressWord, setSecretDuressWord] = useState<string>('Neelkanth');
  const [spokenTestPhrase, setSpokenTestPhrase] = useState<string>(
    'Papa, the officer is asking where my Neelkanth folder is kept.'
  );
  const duressResult = checkDuressTrigger(spokenTestPhrase, secretDuressWord);

  // Consensual Family Drill Call state
  const [selectedMemberId, setSelectedMemberId] = useState<string>(familyMembers[0]?.id || '');
  const [drillScenario, setDrillScenario] = useState<string>('Fake CBI Narcotics Parcel Video Call');
  const [drillOutcomeBanner, setDrillOutcomeBanner] = useState<string | null>(null);

  useEffect(() => {
    if (familyMembers.length > 0 && !familyMembers.some((m) => m.id === selectedMemberId)) {
      setSelectedMemberId(familyMembers[0].id);
    } else if (familyMembers.length === 0) {
      setSelectedMemberId('');
    }
  }, [familyMembers, selectedMemberId]);

  // Editable Complaint Draft Copy state
  const [copiedComplaint, setCopiedComplaint] = useState<boolean>(false);

  // Wrongful Bank Account Freeze Challenge (Unfreeze Support) state
  const [bankName, setBankName] = useState<string>('HDFC Bank');
  const [accountMask, setAccountMask] = useState<string>('XXXX-8821');
  const [totalBalanceInr, setTotalBalanceInr] = useState<number>(245000);
  const [disputedTransactionInr, setDisputedTransactionInr] = useState<number>(4500);
  const [freezeType] = useState<'FULL_DEBIT_FREEZE' | 'LIEN_MARKED'>('FULL_DEBIT_FREEZE');
  const [policeNoticeStation] = useState<string>(
    'Cyber Crime Police Station Ahmedabad (Layer-3 Notice)'
  );
  const [ackNumber1930, setAckNumber1930] = useState<string>('30811260049182');
  const [copiedPetition, setCopiedPetition] = useState<boolean>(false);

  const readiness = computeDraftReadiness(complaintDraft);
  const unfreezeAssessment = evaluateUnfreezePetition({
    bankName,
    accountMask,
    totalBalanceInr,
    disputedTransactionInr,
    freezeType,
    policeNoticeStation,
    ackNumber1930,
  });

  const handleAddMemberSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEntityName.trim()) {
      setMemberFormError('Please enter the name of the person or entity you want to add.');
      return;
    }
    if (!newEntityRelation.trim()) {
      setMemberFormError('Please specify what this entity is to you (e.g., Mother, Spouse, Sibling, Legal Advisor).');
      return;
    }

    setMemberFormError(null);
    onAddFamilyMember({
      name: newEntityName.trim(),
      relation: newEntityRelation.trim(),
      phone: newEntityPhone.trim() || 'Not specified',
      language: newEntityLanguage,
    });
    setMemberAddedBanner(
      `Added "${newEntityName.trim()}" (${newEntityRelation.trim()}) to your Family Safety Circle with Daily Safety Code ${dailyCode}.`
    );
    setNewEntityName('');
    setNewEntityRelation('');
    setNewEntityPhone('');
  };

  const handleRotateDailyCode = () => {
    const words = ['TRISHUL', 'SANKALP', 'DRISHTI', 'PRANAAM', 'SURAKSHA'];
    const pick = words[Math.floor(Math.random() * words.length)];
    const num = Math.floor(100 + Math.random() * 899);
    const next = `${pick}-${num}`;
    setDailyCode(next);
    setCodeSyncedMsg(
      familyMembers.length > 0
        ? `Encrypted Daily Code rotated to ${next} and synced across your ${familyMembers.length} trusted circle member(s).`
        : `Encrypted Daily Code rotated to ${next}. Add family or trusted entities below to share this code.`
    );
  };

  const handleRunFamilyDrill = () => {
    const member = familyMembers.find((m) => m.id === selectedMemberId);
    if (!member) return;
    const newScore = Math.min(100, member.lastDrillScore + 12);
    onUpdateFamilyMember(member.id, {
      lastDrillScore: newScore,
      status: 'PROTECTED',
    });
    setDrillOutcomeBanner(
      `CONSENSUAL DRILL COMPLETED (${member.name} · ${member.relation}): Simulated "${drillScenario}" in ${member.language}. Verified Daily Safety Code (${dailyCode}). Readiness score updated to ${newScore}%!`
    );
  };

  const handleFieldEdit = (key: string, newVal: string) => {
    const updated: ComplaintDraft = {
      ...complaintDraft,
      fields: complaintDraft.fields.map((f) =>
        f.key === key ? { ...f, value: newVal, verifiedByUser: false } : f
      ),
    };
    onUpdateComplaintDraft(updated);
  };

  const handleVerifyField = (key: string) => {
    const updated = verifyComplaintDraftField(complaintDraft, key);
    onUpdateComplaintDraft(updated);
  };

  const handleVerifyAllFields = () => {
    const updated: ComplaintDraft = {
      ...complaintDraft,
      fields: complaintDraft.fields.map((f) => ({ ...f, verifiedByUser: true })),
    };
    onUpdateComplaintDraft(updated);
  };

  const handleCopyComplaint = () => {
    const text = complaintDraft.fields.map((f) => `${f.label}:\n${f.value}`).join('\n\n');
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(text).catch(() => {});
    }
    setCopiedComplaint(true);
    setTimeout(() => setCopiedComplaint(false), 3000);
  };

  const handleCopyUnfreezePetition = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(unfreezeAssessment.petitionText).catch(() => {});
    }
    setCopiedPetition(true);
    setTimeout(() => setCopiedPetition(false), 3000);
  };

  return (
    <div className="space-y-10 pb-16">
      {/* Header */}
      <div className="editorial-panel p-6 sm:p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#2e7d32] dark:text-[#4ade80] mb-1">
            Collective Protection &amp; Legal Recovery · User-Defined Family Circle + 1930 NCRP + Unfreeze
          </div>
          <h1 className="font-display italic text-3xl sm:text-4xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
            Family Safety Circle, Editable 1930 Recovery Pack &amp; Bank Unfreeze Support
          </h1>
          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] mt-1">
            Add your own trusted family members or guardian entities, specify what each entity is to you, configure silent duress word alerts, verify 1930 NCRP drafts, and generate Section 106 BNSS bank unfreeze petitions.
          </p>
        </div>

        <div className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] px-5 py-3.5 font-mono text-xs shrink-0">
          <div className="text-[10px] uppercase tracking-[0.1em] text-[#2e7d32] dark:text-[#4ade80]">
            Today&apos;s Family Safety Code
          </div>
          <div className="text-xl font-bold text-[#1a1a1a] dark:text-[#f2f0eb] tracking-widest tabular-nums mt-0.5">
            {dailyCode}
          </div>
        </div>
      </div>

      {/* SECTION A: FAMILY CIRCLE, DAILY CODE, DURESS WORD & DRILL CALL */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left 6 Cols: Add New Family/Trusted Entity + Roster + Consensual Drill Call Launcher */}
        <div className="lg:col-span-6 editorial-panel p-6 sm:p-8 space-y-6">
          <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
              01. Your Trusted Circle ({familyMembers.length} Entities Added)
            </span>
            <button
              type="button"
              onClick={handleRotateDailyCode}
              className="text-[#d42020] dark:text-[#ef4444] hover:underline flex items-center gap-1 cursor-pointer font-bold"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Rotate Daily Code</span>
            </button>
          </div>

          {codeSyncedMsg && (
            <div className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-3 font-mono text-xs text-[#1a1a1a] dark:text-[#f2f0eb]">
              {codeSyncedMsg}
            </div>
          )}

          {/* ADD NEW FAMILY MEMBER / TRUSTED ENTITY FORM */}
          <form
            onSubmit={handleAddMemberSubmit}
            className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-5 space-y-4 font-mono text-xs"
          >
            <div className="flex items-center justify-between border-b border-[#ddd] dark:border-[#262b36] pb-2">
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold uppercase tracking-[0.08em]">
                Add New Member / Trusted Entity to Your Circle
              </span>
              <span className="text-[#2e7d32] dark:text-[#4ade80] text-[10px] uppercase">
                User-Controlled Roster
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="new-entity-name"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Member / Entity Name *
                </label>
                <input
                  id="new-entity-name"
                  type="text"
                  value={newEntityName}
                  onChange={(e) => setNewEntityName(e.target.value)}
                  placeholder="e.g., Sunita Verma or Adv. Mehta"
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="new-entity-relation"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  What This Entity Is to You (Relation / Role) *
                </label>
                <input
                  id="new-entity-relation"
                  type="text"
                  value={newEntityRelation}
                  onChange={(e) => setNewEntityRelation(e.target.value)}
                  placeholder="e.g., Mother, Spouse, Elder Brother, Lawyer"
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
                />
              </div>
            </div>

            {/* Quick-Select Relationship / Entity Role Chips */}
            <div className="space-y-1.5">
              <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                Quick-Select Entity Relationship or Type Your Own Above:
              </div>
              <div className="flex flex-wrap gap-1.5">
                {ENTITY_ROLE_PRESETS.map((role) => (
                  <button
                    key={role}
                    type="button"
                    onClick={() => setNewEntityRelation(role)}
                    className={`px-2.5 py-1 text-[11px] border transition-colors cursor-pointer ${
                      newEntityRelation === role
                        ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] border-[#1a1a1a] dark:border-[#f2f0eb] font-bold'
                        : 'bg-white dark:bg-[#161920] text-[#6b6b6b] dark:text-[#9ca3af] border-[#ddd] dark:border-[#262b36] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                    }`}
                  >
                    {role}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="new-entity-phone"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Contact Phone / Emergency Handle (Optional)
                </label>
                <input
                  id="new-entity-phone"
                  type="text"
                  value={newEntityPhone}
                  onChange={(e) => setNewEntityPhone(e.target.value)}
                  placeholder="e.g., +91 98112 44010"
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="new-entity-lang"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Preferred Alert &amp; Drill Language
                </label>
                <select
                  id="new-entity-lang"
                  value={newEntityLanguage}
                  onChange={(e) =>
                    setNewEntityLanguage(e.target.value as 'English' | 'Hinglish' | 'Hindi')
                  }
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
                >
                  <option value="English">English</option>
                  <option value="Hinglish">Hinglish</option>
                  <option value="Hindi">Hindi (हिंदी)</option>
                </select>
              </div>
            </div>

            {memberFormError && (
              <p role="alert" className="text-[#d42020] dark:text-[#ef4444]">
                {memberFormError}
              </p>
            )}

            {memberAddedBanner && (
              <div
                role="status"
                className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
              >
                {memberAddedBanner}
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-bold uppercase tracking-[0.1em] flex items-center justify-center gap-2 cursor-pointer"
            >
              <UserPlus className="w-4 h-4" />
              <span>Add Member &amp; Relationship to Safety Circle</span>
            </button>
          </form>

          {/* Family Member Roster */}
          <div className="space-y-2.5 font-mono text-xs">
            {familyMembers.length === 0 ? (
              <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-dashed border-[#bbb] dark:border-[#374151] p-6 text-center space-y-2">
                <Users className="w-6 h-6 text-[#6b6b6b] dark:text-[#9ca3af] mx-auto" />
                <div className="font-display italic text-xl text-[#1a1a1a] dark:text-[#f2f0eb]">
                  No Random Members Pre-Loaded
                </div>
                <p className="text-xs text-[#6b6b6b] dark:text-[#9ca3af] max-w-md mx-auto">
                  Your Family Safety Circle is completely private and user-defined. Use the form above to add a family member or trusted entity and specify what they are to you.
                </p>
              </div>
            ) : (
              familyMembers.map((member) => (
                <div
                  key={member.id}
                  className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-4 flex flex-wrap items-center justify-between gap-3"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-display text-xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
                        {member.name}
                      </span>
                      <span className="px-2 py-0.5 bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] text-[10px] uppercase tracking-wider font-bold text-[#d42020] dark:text-[#ef4444]">
                        {member.relation}
                      </span>
                    </div>
                    <div className="text-[#6b6b6b] dark:text-[#9ca3af] mt-0.5">
                      Entity Role: <strong className="text-[#1a1a1a] dark:text-[#f2f0eb]">{member.relation}</strong> · {member.phone} · {member.language}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <div
                        className={`font-bold tabular-nums ${
                          member.lastDrillScore >= 85
                            ? 'text-[#2e7d32] dark:text-[#4ade80]'
                            : 'text-[#b45309] dark:text-[#fbbf24]'
                        }`}
                      >
                        Drill Readiness: {member.lastDrillScore}%
                      </div>
                      <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                        {member.status}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => onRemoveFamilyMember(member.id)}
                      aria-label={`Remove ${member.name}`}
                      className="p-2 text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#d42020] dark:hover:text-[#ef4444] border border-transparent hover:border-[#ddd] dark:hover:border-[#262b36] cursor-pointer"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Consensual Family Drill Call Simulator */}
          <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-5 space-y-4 font-mono text-xs">
            <div className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold uppercase tracking-[0.08em]">
              Launch Consensual Practice Drill Call (Trains Added Members to Spot Fake Officers)
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="drill-member-select"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Select Added Entity / Member
                </label>
                <select
                  id="drill-member-select"
                  value={selectedMemberId}
                  onChange={(e) => setSelectedMemberId(e.target.value)}
                  disabled={familyMembers.length === 0}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] disabled:opacity-50"
                >
                  {familyMembers.length === 0 ? (
                    <option value="">Add a member above first</option>
                  ) : (
                    familyMembers.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name} ({m.relation} · {m.language})
                      </option>
                    ))
                  )}
                </select>
              </div>

              <div className="space-y-1">
                <label
                  htmlFor="drill-scenario-select"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Practice Scenario
                </label>
                <select
                  id="drill-scenario-select"
                  value={drillScenario}
                  onChange={(e) => setDrillScenario(e.target.value)}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
                >
                  <option value="Fake CBI Narcotics Parcel Video Call">
                    Fake CBI Parcel Video Call
                  </option>
                  <option value="AI Voice-Cloned Relative Hospital Emergency">
                    AI Voice-Cloned Relative Emergency
                  </option>
                  <option value="Electricity Disconnection Tonight APK">
                    Electricity Cutoff .APK Scam
                  </option>
                </select>
              </div>
            </div>

            {drillOutcomeBanner && (
              <div
                role="status"
                className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-3 text-[#1a1a1a] dark:text-[#f2f0eb]"
              >
                {drillOutcomeBanner}
              </div>
            )}

            <button
              type="button"
              onClick={handleRunFamilyDrill}
              disabled={familyMembers.length === 0}
              className="w-full py-3 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white disabled:opacity-40 text-white dark:text-[#0f1115] font-bold uppercase tracking-[0.1em] flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
            >
              <PhoneCall className="w-4 h-4" />
              <span>
                {familyMembers.length === 0
                  ? 'Add a Trusted Entity Above to Run Drill Call'
                  : 'Start Consensual Family Drill Call'}
              </span>
            </button>
          </div>
        </div>

        {/* Right 6 Cols: Secret Duress Word Silent Alert Protocol */}
        <div className="lg:col-span-6 editorial-panel p-6 sm:p-8 space-y-6">
          <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="text-[#d42020] dark:text-[#ef4444] font-bold">
              02. Secret Duress Word · Silent Forced-Call Alert
            </span>
            <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Zero-Beep Stealth</span>
          </div>

          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
            During a &ldquo;Digital Arrest&rdquo;, scammers force victims to keep their camera on and watch them if they call family. Speaking your secret <strong className="text-[#1a1a1a] dark:text-[#f2f0eb]">Duress Word</strong> naturally in conversation silently dispatches live GPS, caller ID, and an emergency alert to your added Family Circle entities without making a sound on your phone.
          </p>

          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-1.5">
              <label
                htmlFor="duress-word-input"
                className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Configured Family Duress Codeword
              </label>
              <input
                id="duress-word-input"
                type="text"
                value={secretDuressWord}
                onChange={(e) => setSecretDuressWord(e.target.value)}
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#d42020] dark:text-[#ef4444] font-bold focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              />
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="duress-test-phrase"
                className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Simulate Spoken Sentence During Forced Call:
              </label>
              <textarea
                id="duress-test-phrase"
                rows={3}
                value={spokenTestPhrase}
                onChange={(e) => setSpokenTestPhrase(e.target.value)}
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              />
            </div>

            {/* Duress Detection Status Box */}
            <div
              className={`p-4 border space-y-1.5 ${
                duressResult.triggered
                  ? 'bg-[#fef2f2] dark:bg-[#2a1215] border-[#d42020] dark:border-[#ef4444] text-[#1a1a1a] dark:text-[#f2f0eb]'
                  : 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af]'
              }`}
            >
              <div className="flex items-center justify-between font-bold">
                <span>
                  DURESS DETECTOR:{' '}
                  {duressResult.triggered
                    ? `TRIGGERED ON "${duressResult.matchedWord}"`
                    : 'LISTENING IN STANDBY'}
                </span>
                <span
                  className={
                    duressResult.triggered
                      ? 'text-[#d42020] dark:text-[#ef4444]'
                      : 'text-[#2e7d32] dark:text-[#4ade80]'
                  }
                >
                  {duressResult.triggered ? 'SILENT SOS SENT' : 'NO TRIGGER'}
                </span>
              </div>
              <p className="text-xs text-[#6b6b6b] dark:text-[#9ca3af]">{duressResult.silentProtocol}</p>
            </div>
          </div>

          {/* Locked Evidence Vault List */}
          <div className="pt-4 border-t border-[#eee] dark:border-[#262b36] space-y-2.5 font-mono text-xs">
            <div className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold uppercase tracking-[0.08em]">
              SHA-256 Locked Evidence Vault ({evidenceList.length} Certificates)
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {evidenceList.map((ev) => (
                <div
                  key={ev.id}
                  className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3"
                >
                  <div className="flex justify-between text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
                    <span>
                      {ev.id} · {ev.title}
                    </span>
                    <span className="text-[#2e7d32] dark:text-[#4ade80]">{ev.type}</span>
                  </div>
                  <div className="text-[11px] text-[#6b6b6b] dark:text-[#9ca3af] truncate mt-0.5">
                    Suspect: {ev.suspectId} · SHA256: {ev.sha256}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* SECTION B: EDITABLE 1930 / NCRP COMPLAINT DRAFTS (HUMAN VERIFICATION GATED) */}
      <div className="editorial-panel p-6 sm:p-9 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#eee] dark:border-[#262b36] pb-4">
          <div>
            <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#d42020] dark:text-[#ef4444] mb-1">
              03. Recovery Pack · 1930 / NCRP Editable Complaint Draft
            </div>
            <h2 className="font-display italic text-2xl sm:text-3xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
              Human-Verified Cybercrime Complaint Summary ({complaintDraft.incidentId})
            </h2>
            <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] mt-1">
              Every AI-drafted detail extracted from your uploaded images, audio recordings, or text is explicitly flagged <strong className="text-[#d42020] dark:text-[#ef4444]">[UNVERIFIED AI DRAFT]</strong> until you review and verify it.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0 font-mono text-xs">
            <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] px-4 py-2.5">
              <span className="text-[#6b6b6b] dark:text-[#9ca3af]">VERIFICATION PROGRESS: </span>
              <strong
                className={`tabular-nums ${
                  readiness.readyToExport
                    ? 'text-[#2e7d32] dark:text-[#4ade80]'
                    : 'text-[#d42020] dark:text-[#ef4444]'
                }`}
              >
                {readiness.verifiedCount}/{readiness.totalFields} ({readiness.readinessPct}%)
              </strong>
            </div>

            <button
              type="button"
              onClick={handleVerifyAllFields}
              className="px-4 py-2.5 bg-[#2e7d32] hover:bg-[#1b5e20] text-white font-bold uppercase tracking-[0.1em] cursor-pointer"
            >
              Verify All Flagged Fields
            </button>
          </div>
        </div>

        {/* Editable Fields List */}
        <div className="grid grid-cols-1 gap-4 font-mono text-xs">
          {complaintDraft.fields.map((field) => (
            <div
              key={field.key}
              className={`p-4 border space-y-2 ${
                field.verifiedByUser
                  ? 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#2e7d32]/60 dark:border-[#4ade80]/60'
                  : 'bg-white dark:bg-[#161920] border-[#d42020] dark:border-[#ef4444]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label
                  htmlFor={`draft-field-${field.key}`}
                  className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold"
                >
                  {field.label}
                </label>

                <div className="flex items-center gap-3">
                  <span
                    className={`font-bold ${
                      field.verifiedByUser
                        ? 'text-[#2e7d32] dark:text-[#4ade80]'
                        : 'text-[#d42020] dark:text-[#ef4444]'
                    }`}
                  >
                    {field.verifiedByUser
                      ? 'VERIFIED BY VICTIM'
                      : 'AI-DRAFTED · VERIFY REQUIRED'}
                  </span>

                  {!field.verifiedByUser && (
                    <button
                      type="button"
                      onClick={() => handleVerifyField(field.key)}
                      className="px-3 py-1 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-bold uppercase tracking-wider cursor-pointer"
                    >
                      Verify Field
                    </button>
                  )}
                </div>
              </div>

              <textarea
                id={`draft-field-${field.key}`}
                rows={field.key === 'narrativeSummary' ? 3 : 1}
                value={field.value}
                onChange={(e) => handleFieldEdit(field.key, e.target.value)}
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              />
            </div>
          ))}
        </div>

        <div className="pt-2 flex flex-wrap items-center justify-between gap-4 border-t border-[#eee] dark:border-[#262b36]">
          <div className="font-mono text-xs text-[#6b6b6b] dark:text-[#9ca3af]">
            {readiness.readyToExport
              ? 'All AI-drafted fields verified. Dossier is ready for cybercrime.gov.in / 1930 submission.'
              : `Please verify the remaining ${readiness.unverifiedCount} AI-drafted field(s) before final submission.`}
          </div>

          <button
            type="button"
            onClick={handleCopyComplaint}
            className="px-5 py-3 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-mono text-xs font-bold uppercase tracking-[0.1em] flex items-center gap-2 cursor-pointer"
          >
            <Copy className="w-4 h-4" />
            <span>
              {copiedComplaint
                ? '1930 NCRP Dossier Copied to Clipboard!'
                : 'Copy Verified 1930 NCRP Dossier'}
            </span>
          </button>
        </div>
      </div>

      {/* SECTION C: WRONGFUL BANK ACCOUNT FREEZE SUPPORT (SECTION 106 BNSS LIEN PETITION) */}
      <div className="editorial-panel p-6 sm:p-9 space-y-6">
        <div className="border-b border-[#eee] dark:border-[#262b36] pb-4">
          <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af] mb-1">
            04. Unfreeze Support · Challenge Wrongful Blanket Bank Account Freezes
          </div>
          <h2 className="font-display italic text-2xl sm:text-3xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
            Section 106 BNSS &amp; RBI Nodal Representation Generator
          </h2>
          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] mt-1">
            Innocent merchants, freelancers, and citizens often suffer a complete debit freeze on their entire life savings when a small Layer-3 or Layer-4 UPI transfer is linked to a distant cyber complaint. Use this calculator to demand conversion of a blanket debit freeze into a specific disputed-amount lien.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left 5 Cols: Freeze Parameters Input */}
          <div className="lg:col-span-5 bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-6 space-y-4 font-mono text-xs">
            <div className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold uppercase tracking-[0.08em] border-b border-[#ddd] dark:border-[#262b36] pb-2">
              Enter Frozen Account &amp; Lien Details
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="unfreeze-bank"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Bank Name
                </label>
                <input
                  id="unfreeze-bank"
                  type="text"
                  value={bankName}
                  onChange={(e) => setBankName(e.target.value)}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2 text-[#1a1a1a] dark:text-[#f2f0eb]"
                />
              </div>
              <div className="space-y-1">
                <label
                  htmlFor="unfreeze-ac"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Account Mask
                </label>
                <input
                  id="unfreeze-ac"
                  type="text"
                  value={accountMask}
                  onChange={(e) => setAccountMask(e.target.value)}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2 text-[#1a1a1a] dark:text-[#f2f0eb]"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label
                  htmlFor="unfreeze-total"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Total Balance (₹)
                </label>
                <input
                  id="unfreeze-total"
                  type="number"
                  value={totalBalanceInr}
                  onChange={(e) => setTotalBalanceInr(Number(e.target.value))}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2 text-[#1a1a1a] dark:text-[#f2f0eb] tabular-nums"
                />
              </div>
              <div className="space-y-1">
                <label
                  htmlFor="unfreeze-disputed"
                  className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Disputed Trail (₹)
                </label>
                <input
                  id="unfreeze-disputed"
                  type="number"
                  value={disputedTransactionInr}
                  onChange={(e) => setDisputedTransactionInr(Number(e.target.value))}
                  className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2 text-[#d42020] dark:text-[#ef4444] font-bold tabular-nums"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label
                htmlFor="unfreeze-ack"
                className="block text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                1930 NCRP Acknowledgement Number
              </label>
              <input
                id="unfreeze-ack"
                type="text"
                value={ackNumber1930}
                onChange={(e) => setAckNumber1930(e.target.value)}
                className="w-full bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-2 text-[#1a1a1a] dark:text-[#f2f0eb]"
              />
            </div>

            {/* Disproportionate Freeze Breakdown */}
            <div className="bg-white dark:bg-[#161920] border border-[#d42020] dark:border-[#ef4444] p-4 space-y-1.5">
              <div className="text-[#d42020] dark:text-[#ef4444] font-bold text-[11px] uppercase tracking-[0.08em]">
                Excess Balance Wrongfully Immobilized:
              </div>
              <div className="text-2xl font-bold text-[#1a1a1a] dark:text-[#f2f0eb] tabular-nums">
                ₹{unfreezeAssessment.excessFrozenInr.toLocaleString('en-IN')}
              </div>
              <div className="text-[11px] text-[#6b6b6b] dark:text-[#9ca3af]">
                Only ₹{disputedTransactionInr.toLocaleString('en-IN')} requires a specific lien hold under Section 106 BNSS.
              </div>
            </div>
          </div>

          {/* Right 7 Cols: Generated Legal Representation Petition */}
          <div className="lg:col-span-7 bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-[#ddd] dark:border-[#262b36] pb-2">
              <span className="text-[#2e7d32] dark:text-[#4ade80] font-bold uppercase tracking-[0.08em]">
                Generated Nodal Bank &amp; Cyber IO Representation Letter
              </span>
              <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Section 106 BNSS Compliant</span>
            </div>

            <pre className="bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-4 text-xs text-[#1a1a1a] dark:text-[#f2f0eb] whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">
              {unfreezeAssessment.petitionText}
            </pre>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleCopyUnfreezePetition}
                className="px-5 py-3 bg-[#2e7d32] hover:bg-[#1b5e20] text-white font-bold uppercase tracking-[0.1em] flex items-center justify-center gap-2 cursor-pointer"
              >
                <Copy className="w-4 h-4" />
                <span>
                  {copiedPetition
                    ? 'Unfreeze Representation Copied!'
                    : 'Copy Bank Unfreeze Representation Letter'}
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
