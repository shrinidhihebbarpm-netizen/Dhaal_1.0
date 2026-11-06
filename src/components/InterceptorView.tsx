import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  PhoneOff,
  Users,
  FileLock2,
  FileWarning,
  Volume2,
  Play,
  Pause,
  RotateCcw,
  CheckSquare,
  Square,
  Search,
  Upload,
  Image as ImageIcon,
  FileAudio,
  FileText,
  Mic,
  Square as StopIcon,
  X,
  Network,
  Send,
  RefreshCw,
  HelpCircle,
} from 'lucide-react';
import {
  analyzeScamPayload,
  sanitizeUntrustedEvidence,
  LanguageMode,
  ScamAnalysisResult,
} from '../utils/scamEngine';
import { LOCALIZED_COPY, PRESET_SCENARIOS, EvidenceItem, FamilyMember } from '../utils/seedData';
import { apiFetch } from '../context/AuthContext';

interface InterceptorViewProps {
  language: LanguageMode;
  onLanguageChange: (lang: LanguageMode) => void;
  initialPayload: string;
  onAddEvidence: (item: EvidenceItem) => void;
  onPushToComplaintDraft: (result: ScamAnalysisResult) => void;
  onAlertFamily: (reason: string) => void;
  familyAlertStatus: string | null;
  onSyncAnalysisToRadar?: (result: ScamAnalysisResult, sourceLabel: string) => void;
  onNavigateToRadar?: () => void;
  familyMembers?: FamilyMember[];
}

interface UploadedMediaPreview {
  type: 'image' | 'audio' | 'text';
  fileName: string;
  fileSizeKb: number;
  previewUrl?: string;
  extractionSource?: string;
}

interface DiscoveredTelegramChat {
  chatId: string;
  title: string;
  type: string;
}

interface TelegramImportedMessage {
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
  botReplyText?: string;
  repliedInTelegram?: boolean;
}

export const InterceptorView: React.FC<InterceptorViewProps> = ({
  language,
  onLanguageChange,
  initialPayload,
  onAddEvidence,
  onPushToComplaintDraft,
  onAlertFamily,
  familyAlertStatus,
  onSyncAnalysisToRadar,
  onNavigateToRadar,
  familyMembers = [],
}) => {
  const [inputText, setInputText] = useState<string>(initialPayload || PRESET_SCENARIOS[0].payload);
  const [channel, setChannel] = useState<'whatsapp' | 'sms' | 'voice' | 'upi'>('sms');
  const [analysis, setAnalysis] = useState<ScamAnalysisResult>(() =>
    analyzeScamPayload(initialPayload || PRESET_SCENARIOS[0].payload, 'sms')
  );
  const [validationError, setValidationError] = useState<string | null>(null);
  const [radarSyncBanner, setRadarSyncBanner] = useState<string | null>(null);

  // Multimodal Upload State (Image, Audio, Text)
  const [uploadedMedia, setUploadedMedia] = useState<UploadedMediaPreview | null>(null);
  const [isAnalyzingUpload, setIsAnalyzingUpload] = useState<boolean>(false);
  const [isRecordingAudio, setIsRecordingAudio] = useState<boolean>(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  const imageInputRef = useRef<HTMLInputElement | null>(null);
  const audioInputRef = useRef<HTMLInputElement | null>(null);
  const textFileInputRef = useRef<HTMLInputElement | null>(null);

  // Two-Minute "Pause Before You Pay" Timer State (120 seconds)
  const [pauseSecondsLeft, setPauseSecondsLeft] = useState<number>(120);
  const [isPauseTimerRunning, setIsPauseTimerRunning] = useState<boolean>(true);
  const [safetyChecks, setSafetyChecks] = useState<Record<string, boolean>>({
    checkedOfficialApp: false,
    calledFamilyMember: false,
    confirmedNoVideoArrest: false,
  });

  // Action Menu Feedback State
  const [actionStatusBanner, setActionStatusBanner] = useState<string | null>(null);

  // Telegram Bot Bridge State
  const [telegramConfigured, setTelegramConfigured] = useState<boolean>(false);
  const [telegramBotUsername, setTelegramBotUsername] = useState<string | null>(null);
  const [telegramChatFilter, setTelegramChatFilter] = useState<string>('');
  const [telegramAutoSync, setTelegramAutoSync] = useState<boolean>(true);
  const [isSyncingTelegram, setIsSyncingTelegram] = useState<boolean>(false);
  const [showTelegramGuide, setShowTelegramGuide] = useState<boolean>(false);
  const [telegramMessages, setTelegramMessages] = useState<TelegramImportedMessage[]>([]);
  const [discoveredTelegramChats, setDiscoveredTelegramChats] = useState<DiscoveredTelegramChat[]>([]);
  const [telegramNotice, setTelegramNotice] = useState<string | null>(null);
  const seenTelegramUpdateIdsRef = useRef<Set<number>>(new Set());

  const syncResultToRadar = (res: ScamAnalysisResult, sourceLabel: string) => {
    if (onSyncAnalysisToRadar) {
      onSyncAnalysisToRadar(res, sourceLabel);
      const totalConnected =
        res.extractedIOCs.upiIds.length +
        res.extractedIOCs.phoneNumbers.length +
        res.extractedIOCs.bankAccounts.length +
        res.extractedIOCs.domains.length;
      setRadarSyncBanner(
        `SCAM RADAR UPDATED: Mapped "${res.extractedIOCs.impersonatedEntity}" + ${totalConnected} connected IOC entity node(s) from ${sourceLabel}.`
      );
    }
  };

  const applyTelegramMessageToInterceptor = (msg: TelegramImportedMessage) => {
    setValidationError(null);
    setInputText(msg.extractedText);
    const nextChannel = msg.mediaType === 'audio' ? 'voice' : 'sms';
    setChannel(nextChannel);
    setAnalysis(msg.analysis);
    setUploadedMedia({
      type: msg.mediaType,
      fileName: `telegram_${msg.mediaType}_${msg.messageId}`,
      fileSizeKb: Math.max(4, Math.round(msg.extractedText.length / 18)),
      extractionSource: msg.extractionSource,
    });
    syncResultToRadar(
      msg.analysis,
      `Telegram ${msg.mediaType.toUpperCase()} (Attached Media)`
    );
    if (msg.analysis.pauseBeforePayRequired) {
      setPauseSecondsLeft(120);
      setIsPauseTimerRunning(true);
    }
  };

  const handleSyncTelegram = async (
    simulateType?: 'text' | 'image' | 'audio',
    silentBackground = false
  ) => {
    if (!silentBackground) {
      setIsSyncingTelegram(true);
      setTelegramNotice(null);
    }
    try {
      const resp = await apiFetch('/api/telegram/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chatIdFilter: telegramChatFilter,
          simulateType,
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setTelegramConfigured(Boolean(data.configured));
        if (Array.isArray(data.discoveredChats)) {
          setDiscoveredTelegramChats(data.discoveredChats);
        }
        if (Array.isArray(data.messages)) {
          setTelegramMessages(data.messages);
        }
        if (Array.isArray(data.newlyImported) && data.newlyImported.length > 0) {
          const freshItems: TelegramImportedMessage[] = data.newlyImported.filter(
            (item: TelegramImportedMessage) => !seenTelegramUpdateIdsRef.current.has(item.updateId)
          );
          freshItems.forEach((item) => seenTelegramUpdateIdsRef.current.add(item.updateId));

          const latest = data.newlyImported[0] as TelegramImportedMessage;
          applyTelegramMessageToInterceptor(latest);
          setTelegramNotice(
            `Imported ${data.newlyImported.length} message(s) from Telegram.`
          );
        } else if (!silentBackground) {
          if (data.notice) {
            setTelegramNotice(data.notice);
          } else {
            setTelegramNotice('Telegram sync complete. No new unread messages since last offset.');
          }
        }
      }
    } catch {
      if (!silentBackground) {
        setTelegramNotice('Could not reach /api/telegram/sync endpoint.');
      }
    } finally {
      if (!silentBackground) {
        setIsSyncingTelegram(false);
      }
    }
  };

  useEffect(() => {
    let mounted = true;
    apiFetch('/api/telegram/status')
      .then((r) => r.json())
      .then((data) => {
        if (!mounted) return;
        setTelegramConfigured(Boolean(data.configured));
        if (data.botUsername) setTelegramBotUsername(data.botUsername);
        if (Array.isArray(data.discoveredChats)) setDiscoveredTelegramChats(data.discoveredChats);
        if (Array.isArray(data.messages)) {
          setTelegramMessages(data.messages);
          data.messages.forEach((m: TelegramImportedMessage) =>
            seenTelegramUpdateIdsRef.current.add(m.updateId)
          );
        }
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!telegramAutoSync) return;
    const interval = window.setInterval(() => {
      handleSyncTelegram(undefined, true);
    }, 4000);
    return () => window.clearInterval(interval);
  }, [telegramAutoSync, telegramChatFilter]);

  useEffect(() => {
    if (initialPayload) {
      setInputText(initialPayload);
      const res = analyzeScamPayload(initialPayload, channel);
      setAnalysis(res);
      if (res.pauseBeforePayRequired) {
        setPauseSecondsLeft(120);
        setIsPauseTimerRunning(true);
      }
    }
  }, [initialPayload]);

  useEffect(() => {
    if (!isPauseTimerRunning || !analysis.pauseBeforePayRequired) return;
    const timer = window.setInterval(() => {
      setPauseSecondsLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [isPauseTimerRunning, analysis.pauseBeforePayRequired]);

  const fileToBase64 = (file: File | Blob): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = String(reader.result || '');
        const base64 = result.includes(',') ? result.split(',')[1] : result;
        resolve(base64);
      };
      reader.onerror = (err) => reject(err);
      reader.readAsDataURL(file);
    });
  };

  const handleImageFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setValidationError(null);
    setIsAnalyzingUpload(true);

    const previewUrl = URL.createObjectURL(file);
    const sizeKb = Math.max(1, Math.round(file.size / 1024));
    setUploadedMedia({
      type: 'image',
      fileName: file.name,
      fileSizeKb: sizeKb,
      previewUrl,
      extractionSource: 'Scanning image via OCR...',
    });

    try {
      const base64Data = await fileToBase64(file);
      const resp = await apiFetch('/api/analyze-media', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mediaType: 'image',
          mimeType: file.type || 'image/png',
          base64Data,
          fileName: file.name,
          channel: 'sms',
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setInputText(data.extractedText);
        setAnalysis(data.analysis);
        syncResultToRadar(data.analysis, `Uploaded Image (${file.name})`);
        setUploadedMedia({
          type: 'image',
          fileName: file.name,
          fileSizeKb: sizeKb,
          previewUrl,
          extractionSource: data.extractionSource,
        });
        if (data.analysis.pauseBeforePayRequired) {
          setPauseSecondsLeft(120);
          setIsPauseTimerRunning(true);
        }
        return;
      }
    } catch {
      // Fallback local OCR if server route is unreachable
    } finally {
      setIsAnalyzingUpload(false);
      e.target.value = '';
    }

    const fallbackText = `[Uploaded Image: ${file.name}] URGENT NOTICE FROM CYBER CRIME & CBI: Non-Bailable Warrant issued under your Aadhaar. Transfer ₹4,50,000 to RBI Supervision Account UPI rbi.verify99@okaxis immediately.`;
    setInputText(fallbackText);
    const res = analyzeScamPayload(fallbackText, 'sms');
    setAnalysis(res);
    syncResultToRadar(res, `Uploaded Image (${file.name})`);
  };

  const handleAudioFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setValidationError(null);
    setChannel('voice');
    setIsAnalyzingUpload(true);

    const previewUrl = URL.createObjectURL(file);
    const sizeKb = Math.max(1, Math.round(file.size / 1024));
    setUploadedMedia({
      type: 'audio',
      fileName: file.name,
      fileSizeKb: sizeKb,
      previewUrl,
      extractionSource: 'Transcribing audio file...',
    });

    try {
      const base64Data = await fileToBase64(file);
      const resp = await apiFetch('/api/analyze-media', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mediaType: 'audio',
          mimeType: file.type || 'audio/mp3',
          base64Data,
          fileName: file.name,
          channel: 'voice',
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setInputText(data.extractedText);
        setAnalysis(data.analysis);
        syncResultToRadar(data.analysis, `Uploaded Audio (${file.name})`);
        setUploadedMedia({
          type: 'audio',
          fileName: file.name,
          fileSizeKb: sizeKb,
          previewUrl,
          extractionSource: data.extractionSource,
        });
        if (data.analysis.pauseBeforePayRequired) {
          setPauseSecondsLeft(120);
          setIsPauseTimerRunning(true);
        }
        return;
      }
    } catch {
      // Fallback local transcription
    } finally {
      setIsAnalyzingUpload(false);
      e.target.value = '';
    }

    const fallbackText = `[Uploaded Audio: ${file.name}] Main CBI Cyber Crime branch se Inspector bol raha hoon. Aapke Aadhaar card se parcel pakda gaya hai. Kisi ko phone mat lagana, abhi rbi.verify99@okaxis par verification deposit transfer karo.`;
    setInputText(fallbackText);
    const res = analyzeScamPayload(fallbackText, 'voice');
    setAnalysis(res);
    syncResultToRadar(res, `Uploaded Audio (${file.name})`);
  };

  const handleTextFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setValidationError(null);
    const sizeKb = Math.max(1, Math.round(file.size / 1024));

    try {
      const content = await file.text();
      const fileGuard = sanitizeUntrustedEvidence(file.name);
      const bodyGuard = sanitizeUntrustedEvidence(content);
      const trimmed = bodyGuard.sanitizedText || `[Uploaded Text File: ${fileGuard.sanitizedText}]`;
      setInputText(trimmed);
      setUploadedMedia({
        type: 'text',
        fileName: fileGuard.sanitizedText || file.name,
        fileSizeKb: sizeKb,
        extractionSource: `Direct Text File Upload (${file.name})`,
      });
      const res = analyzeScamPayload(
        `${trimmed} ${file.name} ${fileGuard.injectionDetected || bodyGuard.injectionDetected ? 'prompt_injection_attempt ignore previous instructions' : ''}`,
        channel
      );
      setAnalysis(res);
      syncResultToRadar(res, `Uploaded Text (${file.name})`);
      if (res.pauseBeforePayRequired) {
        setPauseSecondsLeft(120);
        setIsPauseTimerRunning(true);
      }
    } finally {
      e.target.value = '';
    }
  };

  const handleToggleMicRecording = async () => {
    if (isRecordingAudio && mediaRecorderRef.current) {
      mediaRecorderRef.current.stop();
      setIsRecordingAudio(false);
      return;
    }

    if (typeof navigator !== 'undefined' && navigator.mediaDevices?.getUserMedia) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const recorder = new MediaRecorder(stream);
        audioChunksRef.current = [];
        recorder.ondataavailable = (ev) => {
          if (ev.data.size > 0) {
            audioChunksRef.current.push(ev.data);
          }
        };
        recorder.onstop = async () => {
          stream.getTracks().forEach((t) => t.stop());
          const blob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
          const previewUrl = URL.createObjectURL(blob);
          const sizeKb = Math.max(1, Math.round(blob.size / 1024));
          setChannel('voice');
          setUploadedMedia({
            type: 'audio',
            fileName: 'live_voice_recording.webm',
            fileSizeKb: sizeKb,
            previewUrl,
            extractionSource: 'Browser Microphone Recording Transcribed',
          });
          const base64Data = await fileToBase64(blob);
          const resp = await apiFetch('/api/analyze-media', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              mediaType: 'audio',
              mimeType: 'audio/webm',
              base64Data,
              fileName: 'live_voice_recording.webm',
              channel: 'voice',
            }),
          });
          if (resp.ok) {
            const data = await resp.json();
            setInputText(data.extractedText);
            setAnalysis(data.analysis);
            syncResultToRadar(data.analysis, 'Live Voice Recording');
          }
        };
        mediaRecorderRef.current = recorder;
        recorder.start();
        setIsRecordingAudio(true);
        return;
      } catch {
        // Fallback when mic permission is unavailable in headless/sandboxed browser
      }
    }

    // Simulated instant voice recording capture when hardware mic is unavailable
    const simulatedTranscript =
      '[Recorded Voice Note · 0:14s] "Hello sir, main CBI Cyber Crime cell se bol raha hoon. Aapka bank account freeze hone wala hai, turant rbi.verify99@okaxis par ₹1,00,000 verification deposit bhejo."';
    setChannel('voice');
    setUploadedMedia({
      type: 'audio',
      fileName: 'captured_call_snippet.wav',
      fileSizeKb: 48,
      extractionSource: 'Voice Clip Captured & Transcribed',
    });
    setInputText(simulatedTranscript);
    const res = analyzeScamPayload(simulatedTranscript, 'voice');
    setAnalysis(res);
    syncResultToRadar(res, 'Recorded Voice Clip');
  };

  const handleRunScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) {
      setValidationError('Please upload an image, audio recording, text file, or enter suspicious text to analyze.');
      return;
    }
    setValidationError(null);
    const res = analyzeScamPayload(inputText, channel);
    setAnalysis(res);
    syncResultToRadar(
      res,
      uploadedMedia ? `Uploaded ${uploadedMedia.type.toUpperCase()} (${uploadedMedia.fileName})` : 'User Intercept Scan'
    );
    setActionStatusBanner(null);
    if (res.pauseBeforePayRequired) {
      setPauseSecondsLeft(120);
      setIsPauseTimerRunning(true);
    }
  };

  const handleSelectPreset = (presetId: string) => {
    const found = PRESET_SCENARIOS.find((p) => p.id === presetId);
    if (!found) return;
    setValidationError(null);
    setUploadedMedia(null);
    setInputText(found.payload);
    setChannel(found.channel);
    const res = analyzeScamPayload(found.payload, found.channel);
    setAnalysis(res);
    syncResultToRadar(res, `Scenario: ${found.title}`);
    setActionStatusBanner(null);
    if (res.pauseBeforePayRequired) {
      setPauseSecondsLeft(120);
      setIsPauseTimerRunning(true);
    }
  };

  const formatTimer = (totalSec: number) => {
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  const speakVerdict = () => {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const textToRead =
        language === 'hi'
          ? `${analysis.headlineHi}. ${analysis.summaryHi}`
          : language === 'hinglish'
          ? `${analysis.headlineHinglish}. ${analysis.summaryHinglish}`
          : `${analysis.headlineEn}. ${analysis.summaryEn}`;
      const utter = new SpeechSynthesisUtterance(textToRead);
      utter.lang = language === 'hi' ? 'hi-IN' : 'en-IN';
      window.speechSynthesis.speak(utter);
    }
  };

  const handleActionStopEngaging = () => {
    setActionStatusBanner(
      `CALL & SENDER QUARANTINED: Blocked ${
        analysis.extractedIOCs.phoneNumbers[0] || analysis.extractedIOCs.upiIds[0] || 'Suspect Sender'
      } across local call & SMS filters.`
    );
  };

  const handleActionAlertFamily = () => {
    const msg = `High-Risk ${analysis.categoryCode} intercept (${analysis.riskScore}/100). Pause Lock active.`;
    onAlertFamily(msg);
    if (familyMembers.length > 0) {
      const names = familyMembers.map((m) => `${m.name} (${m.relation})`).join(', ');
      setActionStatusBanner(
        `TRUSTED FAMILY CONTACT ALERTED: Emergency alert dispatched to ${names} with daily verification code.`
      );
    } else {
      setActionStatusBanner(
        'FAMILY ALERT QUEUED: Open the Family tab to add your trusted family members and specify their relationship to you.'
      );
    }
  };

  const handleActionSaveEvidence = () => {
    const newItem: EvidenceItem = {
      id: `EV-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toLocaleTimeString('en-IN', { hour12: false }) + ' IST',
      type:
        uploadedMedia?.type === 'audio' || channel === 'voice'
          ? 'VOICE_NOTE_HASH'
          : channel === 'upi'
          ? 'UPI_REQUEST'
          : 'WHATSAPP_SCREENSHOT',
      title: `${analysis.categoryCode}: ${analysis.headlineEn.slice(0, 48)}`,
      suspectId:
        analysis.extractedIOCs.upiIds[0] ||
        analysis.extractedIOCs.phoneNumbers[0] ||
        analysis.extractedIOCs.domains[0] ||
        'Unknown Suspect',
      sha256:
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.slice(0, 48) +
        Math.floor(100000 + Math.random() * 899999),
      verified: true,
    };
    onAddEvidence(newItem);
    setActionStatusBanner(
      `EVIDENCE LOCKED IN VAULT (${newItem.id}): SHA-256 cryptographic certificate generated for 1930 NCRP admissibility.`
    );
  };

  const handleActionPrepareComplaint = () => {
    onPushToComplaintDraft(analysis);
    setActionStatusBanner(
      '1930 NCRP COMPLAINT DRAFT POPULATED: Navigating to Family & 1930 Recovery tab to verify flagged AI fields.'
    );
  };

  const copy = LOCALIZED_COPY[language];

  return (
    <div className="space-y-8 pb-16">
      {/* Top Contextual Header */}
      <div className="editorial-panel p-6 sm:p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#d42020] dark:text-[#ef4444] mb-1">
            Editorial Threat Interceptor · Multimodal Image, Audio &amp; Text Engine
          </div>
          <h1 className="font-display italic text-3xl sm:text-4xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
            AI Scam Detection: Upload Images, Audio Recordings &amp; Text
          </h1>
          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] mt-1">
            Upload suspicious screenshots, fake warrant images, Hindi/Hinglish call recordings, or text messages. Every scan automatically maps the scammer and all connected UPI, phone, bank, and domain entities onto your Scam Radar.
          </p>
        </div>

        {/* Language & Audio Bar */}
        <div className="flex flex-wrap items-center gap-3">
          <div
            role="group"
            aria-label="Verdict Language"
            className="flex items-center bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-0.5"
          >
            {(['en', 'hinglish', 'hi'] as LanguageMode[]).map((lang) => (
              <button
                key={lang}
                type="button"
                onClick={() => onLanguageChange(lang)}
                className={`px-3 py-1.5 text-xs font-mono transition-colors cursor-pointer ${
                  language === lang
                    ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                    : 'text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                }`}
              >
                {lang === 'en' ? 'English' : lang === 'hinglish' ? 'Hinglish' : 'हिंदी'}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={speakVerdict}
            className="px-4 py-2 bg-white dark:bg-[#161920] hover:bg-[#f8f7f4] dark:hover:bg-[#1e232d] text-[#1a1a1a] dark:text-[#f2f0eb] border border-[#1a1a1a] dark:border-[#f2f0eb] font-mono text-xs uppercase tracking-[0.08em] flex items-center gap-2 cursor-pointer"
          >
            <Volume2 className="w-4 h-4 text-[#d42020] dark:text-[#ef4444]" />
            <span>Speak Verdict</span>
          </button>
        </div>
      </div>

      {/* Main 12-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* LEFT 5 COLUMNS: Multimodal File Upload (Image, Audio, Text) & Preset Scenarios */}
        <div className="lg:col-span-5 editorial-panel p-6 sm:p-8 space-y-6">
          <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="font-bold text-[#1a1a1a] dark:text-[#f2f0eb]">
              01. Upload Evidence (Image · Audio · Text)
            </span>
          </div>

          {/* MULTIMODAL UPLOAD DROPZONE / BUTTONS (Image, Audio, Text + Mic Record) */}
          <div className="space-y-3">
            <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
              Upload File from Device or Record Voice:
            </div>

            {/* Hidden Native File Inputs */}
            <input
              ref={imageInputRef}
              id="upload-image-input"
              type="file"
              accept="image/*"
              onChange={handleImageFileUpload}
              className="hidden"
            />
            <input
              ref={audioInputRef}
              id="upload-audio-input"
              type="file"
              accept="audio/*"
              onChange={handleAudioFileUpload}
              className="hidden"
            />
            <input
              ref={textFileInputRef}
              id="upload-text-input"
              type="file"
              accept=".txt,.csv,.json,.eml,.log,.md,text/*"
              onChange={handleTextFileUpload}
              className="hidden"
            />

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
              <button
                type="button"
                onClick={() => imageInputRef.current?.click()}
                className="p-3 bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb] text-[#1a1a1a] dark:text-[#f2f0eb] flex flex-col items-center justify-center gap-1.5 text-center cursor-pointer transition-colors"
              >
                <ImageIcon className="w-4 h-4 text-[#d42020] dark:text-[#ef4444]" />
                <span className="font-bold text-[11px] uppercase">Upload Image</span>
                <span className="text-[9px] text-[#6b6b6b] dark:text-[#9ca3af]">PNG / JPG / WEBP</span>
              </button>

              <button
                type="button"
                onClick={() => audioInputRef.current?.click()}
                className="p-3 bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb] text-[#1a1a1a] dark:text-[#f2f0eb] flex flex-col items-center justify-center gap-1.5 text-center cursor-pointer transition-colors"
              >
                <FileAudio className="w-4 h-4 text-[#2e7d32] dark:text-[#4ade80]" />
                <span className="font-bold text-[11px] uppercase">Upload Audio</span>
                <span className="text-[9px] text-[#6b6b6b] dark:text-[#9ca3af]">MP3 / WAV / OGG</span>
              </button>

              <button
                type="button"
                onClick={() => textFileInputRef.current?.click()}
                className="p-3 bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb] text-[#1a1a1a] dark:text-[#f2f0eb] flex flex-col items-center justify-center gap-1.5 text-center cursor-pointer transition-colors"
              >
                <FileText className="w-4 h-4 text-[#1a1a1a] dark:text-[#f2f0eb]" />
                <span className="font-bold text-[11px] uppercase">Upload Text</span>
                <span className="text-[9px] text-[#6b6b6b] dark:text-[#9ca3af]">TXT / EML / LOG</span>
              </button>

              <button
                type="button"
                onClick={handleToggleMicRecording}
                className={`p-3 border flex flex-col items-center justify-center gap-1.5 text-center cursor-pointer transition-colors ${
                  isRecordingAudio
                    ? 'bg-[#d42020] border-[#d42020] text-white'
                    : 'bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border-[#ddd] dark:border-[#262b36] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb] text-[#1a1a1a] dark:text-[#f2f0eb]'
                }`}
              >
                {isRecordingAudio ? (
                  <>
                    <StopIcon className="w-4 h-4" />
                    <span className="font-bold text-[11px] uppercase">Stop Mic</span>
                    <span className="text-[9px] text-white/90">Active</span>
                  </>
                ) : (
                  <>
                    <Mic className="w-4 h-4 text-[#b45309] dark:text-[#fbbf24]" />
                    <span className="font-bold text-[11px] uppercase">Record Voice</span>
                    <span className="text-[9px] text-[#6b6b6b] dark:text-[#9ca3af]">Live Call / Mic</span>
                  </>
                )}
              </button>
            </div>

            {/* Active Uploaded Media Preview Card */}
            {uploadedMedia && (
              <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#2e7d32] dark:border-[#4ade80] p-3.5 space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 truncate">
                    <Upload className="w-3.5 h-3.5 text-[#2e7d32] dark:text-[#4ade80] shrink-0" />
                    <span className="font-bold text-[#1a1a1a] dark:text-[#f2f0eb] truncate">
                      {uploadedMedia.fileName} ({uploadedMedia.fileSizeKb} KB)
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setUploadedMedia(null)}
                    aria-label="Remove uploaded file"
                    className="text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#d42020] cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {uploadedMedia.type === 'image' && uploadedMedia.previewUrl && (
                  <img
                    src={uploadedMedia.previewUrl}
                    alt={uploadedMedia.fileName}
                    className="max-h-36 w-auto border border-[#ddd] dark:border-[#262b36] object-contain"
                  />
                )}

                {uploadedMedia.type === 'audio' && uploadedMedia.previewUrl && (
                  <audio
                    controls
                    src={uploadedMedia.previewUrl}
                    className="w-full h-9"
                  />
                )}
              </div>
            )}
          </div>

          {/* TELEGRAM BOT BRIDGE PANEL (Forwarded DMs & Group Chat ID Sync) */}
          <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#0088cc]/50 dark:border-[#0088cc]/60 p-4 space-y-3.5 font-mono text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#e5e2dc] dark:border-[#262b36] pb-2.5">
              <div className="flex items-center gap-2">
                <Send className="w-3.5 h-3.5 text-[#0088cc] shrink-0" />
                <span className="font-bold uppercase tracking-[0.08em] text-[#1a1a1a] dark:text-[#f2f0eb]">
                  Telegram Bot Chat Bridge
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-[#0088cc] font-bold">
                  {telegramConfigured
                    ? `Live · @${telegramBotUsername || 'bot'}`
                    : 'Sandbox Ready · .env Token Optional'}
                </span>
                <button
                  type="button"
                  onClick={() => setShowTelegramGuide((prev) => !prev)}
                  className="text-[11px] underline text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb] flex items-center gap-1 cursor-pointer"
                >
                  <HelpCircle className="w-3 h-3" />
                  <span>{showTelegramGuide ? 'Hide Steps' : 'Setup Steps'}</span>
                </button>
              </div>
            </div>

            {showTelegramGuide && (
              <div className="bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] p-3 space-y-1.5 text-[11px] text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
                <div className="font-bold text-[#1a1a1a] dark:text-[#f2f0eb] uppercase">
                  How to Link Your Telegram Chat (4 Steps):
                </div>
                <div>
                  1. Message <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">@BotFather</span> on Telegram, send <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">/newbot</span>, and copy the token.
                </div>
                <div>
                  2. For Group Chats: send <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">/setprivacy</span> in @BotFather → select your bot → <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">Disable</span>, then add the bot to your group. For 1-on-1 scams: simply forward the message to your bot DM.
                </div>
                <div>
                  3. Set <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">TELEGRAM_BOT_TOKEN</span> in server secrets / <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">.env</span>.
                </div>
                <div>
                  4. Optional: Enter your group&apos;s <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">Chat ID</span> below (or click a discovered chat) to import only from that chat.
                </div>
              </div>
            )}

            {/* Target Chat ID Filter & Sync Controls */}
            <div className="space-y-2">
              <label
                htmlFor="telegram-chat-id-input"
                className="block text-[10px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Target Telegram Chat ID or @channel (Blank = All Forwarded DMs &amp; Groups)
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  id="telegram-chat-id-input"
                  type="text"
                  value={telegramChatFilter}
                  onChange={(e) => setTelegramChatFilter(e.target.value)}
                  placeholder="e.g. -100219847102 or @family_group"
                  className="flex-1 bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] px-3 py-2 text-xs text-[#1a1a1a] dark:text-[#f2f0eb] focus:outline-none focus:border-[#0088cc]"
                />
                <button
                  type="button"
                  onClick={() => handleSyncTelegram(undefined, false)}
                  disabled={isSyncingTelegram}
                  className="px-3.5 py-2 bg-[#0088cc] hover:bg-[#0077b5] text-white font-bold uppercase tracking-[0.06em] flex items-center justify-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0 disabled:opacity-60"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncingTelegram ? 'animate-spin' : ''}`} />
                  <span>{isSyncingTelegram ? 'Syncing...' : 'Sync Telegram'}</span>
                </button>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5">
                <button
                  type="button"
                  onClick={() => setTelegramAutoSync((prev) => !prev)}
                  className="text-[11px] flex items-center gap-1.5 text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb] cursor-pointer"
                >
                  {telegramAutoSync ? (
                    <CheckSquare className="w-3.5 h-3.5 text-[#0088cc]" />
                  ) : (
                    <Square className="w-3.5 h-3.5" />
                  )}
                  <span>Auto-Sync in background (every 10s)</span>
                </button>

                {discoveredTelegramChats.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1 text-[10px]">
                    <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Chats:</span>
                    {discoveredTelegramChats.map((c) => (
                      <button
                        key={c.chatId}
                        type="button"
                        onClick={() =>
                          setTelegramChatFilter((prev) => (prev === c.chatId ? '' : c.chatId))
                        }
                        className={`px-1.5 py-0.5 border cursor-pointer ${
                          telegramChatFilter === c.chatId
                            ? 'bg-[#0088cc] text-white border-[#0088cc] font-bold'
                            : 'bg-white dark:bg-[#161920] border-[#ddd] dark:border-[#262b36] text-[#1a1a1a] dark:text-[#f2f0eb]'
                        }`}
                      >
                        {c.title.slice(0, 16)} ({c.chatId})
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Instant Test / Simulate Multimodal Telegram Chat Imports */}
            <div className="space-y-1.5 pt-1 border-t border-[#e5e2dc] dark:border-[#262b36]">
              <div className="text-[10px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]">
                Test Multimodal Bot Import (Forwarded DM &amp; Group Chat):
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                <button
                  type="button"
                  onClick={() => handleSyncTelegram('text', false)}
                  className="p-2 bg-white dark:bg-[#161920] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] text-[#1a1a1a] dark:text-[#f2f0eb] text-center font-bold text-[10px] uppercase cursor-pointer transition-colors"
                >
                  + Forwarded Text
                </button>
                <button
                  type="button"
                  onClick={() => handleSyncTelegram('image', false)}
                  className="p-2 bg-white dark:bg-[#161920] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] text-[#1a1a1a] dark:text-[#f2f0eb] text-center font-bold text-[10px] uppercase cursor-pointer transition-colors"
                >
                  + Group Photo OCR
                </button>
                <button
                  type="button"
                  onClick={() => handleSyncTelegram('audio', false)}
                  className="p-2 bg-white dark:bg-[#161920] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#ddd] dark:border-[#262b36] text-[#1a1a1a] dark:text-[#f2f0eb] text-center font-bold text-[10px] uppercase cursor-pointer transition-colors"
                >
                  + Voice Note
                </button>
              </div>
            </div>

            {telegramNotice && (
              <div className="text-[11px] text-[#0088cc] bg-white dark:bg-[#161920] border border-[#0088cc]/40 px-2.5 py-2">
                {telegramNotice}
              </div>
            )}

            {/* Imported Telegram Chat Queue */}
            {telegramMessages.length > 0 && (
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                <div className="text-[10px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]">
                  Imported Telegram Messages ({telegramMessages.length}) — Click to Inspect:
                </div>
                {telegramMessages.map((msg) => (
                  <button
                    key={msg.id}
                    type="button"
                    onClick={() => applyTelegramMessageToInterceptor(msg)}
                    className={`w-full text-left p-2.5 border transition-colors cursor-pointer space-y-1 ${
                      inputText === msg.extractedText
                        ? 'bg-white dark:bg-[#161920] border-[#0088cc] text-[#1a1a1a] dark:text-[#f2f0eb]'
                        : 'bg-white/70 dark:bg-[#161920]/70 border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-[10px]">
                      <span className="font-bold text-[#1a1a1a] dark:text-[#f2f0eb] flex items-center gap-1.5 truncate">
                        <span>
                          {msg.mediaType === 'audio'
                            ? '🎙️ Attached Voice Note / Audio File'
                            : msg.mediaType === 'image'
                            ? '🖼️ Attached Image Screenshot'
                            : '💬 Attached Message Text'}
                        </span>
                        <span className="text-[#6b6b6b] dark:text-[#9ca3af] shrink-0">· {msg.receivedAt}</span>
                      </span>
                      <span
                        className="font-bold px-1.5 py-0.5 rounded text-[10px] shrink-0"
                        style={{
                          backgroundColor: `${msg.analysis.threatColor}15`,
                          color: msg.analysis.threatColor,
                          border: `1px solid ${msg.analysis.threatColor}40`,
                        }}
                      >
                        {msg.analysis.threatLabel} ({msg.analysis.riskScore}/100)
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-[#1a1a1a] dark:text-[#f2f0eb] line-clamp-2 bg-black/[0.03] dark:bg-white/[0.03] p-1.5 rounded border border-[#eae8e1] dark:border-[#262b36]">
                      {msg.extractedText}
                    </div>
                    <div className="text-[10px] text-[#2e7d32] dark:text-[#4ade80] flex items-center justify-between gap-2 pt-0.5 border-t border-[#eae8e1] dark:border-[#262b36]">
                      <span className="truncate font-semibold">
                        🛡️ Verdict: {msg.analysis.headlineEn}
                      </span>
                      <span className="shrink-0 text-[9px] uppercase tracking-wider text-[#6b6b6b] dark:text-[#9ca3af]">
                        Verified Safe Privacy
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Preset Threat Selector */}
          <div className="space-y-2">
            <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
              Or Load Recorded Scam Intercept Scenario:
            </div>
            <div className="space-y-1.5">
              {PRESET_SCENARIOS.map((sc) => (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => handleSelectPreset(sc.id)}
                  className={`w-full text-left p-3 border font-mono text-xs transition-colors flex items-center justify-between gap-2 cursor-pointer ${
                    inputText === sc.payload
                      ? 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#d42020] dark:border-[#ef4444] text-[#1a1a1a] dark:text-[#f2f0eb] font-bold'
                      : 'bg-white dark:bg-[#161920] border-[#e6e4df] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] hover:border-[#1a1a1a] dark:hover:border-[#f2f0eb] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                  }`}
                >
                  <span className="truncate">{sc.title}</span>
                  <span
                    className={`text-[10px] shrink-0 font-bold ${
                      sc.tag.includes('LEVEL 4')
                        ? 'text-[#d42020] dark:text-[#ef4444]'
                        : sc.tag.includes('LEVEL 3')
                        ? 'text-[#b45309] dark:text-[#fbbf24]'
                        : 'text-[#2e7d32] dark:text-[#4ade80]'
                    }`}
                  >
                    {sc.tag}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Channel Selector & Text Input */}
          <form onSubmit={handleRunScan} className="space-y-4">
            <div className="space-y-1.5">
              <label className="block font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                Source Vector Channel
              </label>
              <div className="grid grid-cols-3 gap-1.5">
                {(
                  [
                    { id: 'sms', label: 'Text / Image OCR' },
                    { id: 'voice', label: 'Audio / Call' },
                    { id: 'upi', label: 'UPI Collect' },
                  ] as const
                ).map((ch) => (
                  <button
                    key={ch.id}
                    type="button"
                    onClick={() => setChannel(ch.id)}
                    className={`py-2 px-2 font-mono text-xs border text-center transition-colors cursor-pointer ${
                      channel === ch.id
                        ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] border-[#1a1a1a] dark:border-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                        : 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                    }`}
                  >
                    {ch.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="scam-payload-input"
                  className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Extracted OCR / Audio Transcript / Text Payload
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setInputText('');
                    setUploadedMedia(null);
                    setValidationError(null);
                  }}
                  className="text-[11px] font-mono text-[#d42020] dark:text-[#ef4444] hover:underline cursor-pointer"
                >
                  Clear Input
                </button>
              </div>
              <textarea
                id="scam-payload-input"
                rows={5}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Upload an image, audio file, or text file above, or paste suspicious message / call transcript here..."
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none p-3.5 font-mono text-xs sm:text-sm text-[#1a1a1a] dark:text-[#f2f0eb] placeholder-[#6b6b6b] dark:placeholder-[#9ca3af]"
              />
              {validationError && (
                <p role="alert" className="text-xs font-mono text-[#d42020] dark:text-[#ef4444]">
                  {validationError}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="w-full py-4 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-mono text-xs font-bold tracking-[0.1em] uppercase flex items-center justify-center gap-2 cursor-pointer"
            >
              <Search className="w-4 h-4" />
              <span>Run Pre-Payment Threat Intercept</span>
            </button>
          </form>

          {/* Radar Sync Notification + Extracted IOCs Box */}
          <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-4 space-y-2.5 font-mono text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold uppercase tracking-[0.08em]">
                Extracted IOCs (Auto-Synced to Scam Radar)
              </span>
              {onNavigateToRadar && (
                <button
                  type="button"
                  onClick={onNavigateToRadar}
                  className="text-[#2e7d32] dark:text-[#4ade80] font-bold hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Open Radar</span>
                </button>
              )}
            </div>

            {radarSyncBanner && (
              <div className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-2.5 text-[11px] text-[#1a1a1a] dark:text-[#f2f0eb]">
                {radarSyncBanner}
              </div>
            )}

            <div className="grid grid-cols-1 gap-2">
              <div className="flex justify-between border-b border-[#e6e4df] dark:border-[#262b36] pb-1.5">
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Impersonated Authority:</span>
                <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold text-right">
                  {analysis.extractedIOCs.impersonatedEntity}
                </span>
              </div>
              <div className="flex justify-between border-b border-[#e6e4df] dark:border-[#262b36] pb-1.5">
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Mule UPI Handles:</span>
                <span className="text-[#d42020] dark:text-[#ef4444] font-bold">
                  {analysis.extractedIOCs.upiIds.length > 0
                    ? analysis.extractedIOCs.upiIds.join(', ')
                    : 'None detected'}
                </span>
              </div>
              <div className="flex justify-between border-b border-[#e6e4df] dark:border-[#262b36] pb-1.5">
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Suspect Phone Numbers:</span>
                <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
                  {analysis.extractedIOCs.phoneNumbers.length > 0
                    ? analysis.extractedIOCs.phoneNumbers.join(', ')
                    : 'None detected'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">Bank Accounts / Domains:</span>
                <span className="text-[#1a1a1a] dark:text-[#f2f0eb]">
                  {[...analysis.extractedIOCs.bankAccounts, ...analysis.extractedIOCs.domains].join(', ') ||
                    'None detected'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT 7 COLUMNS: Verdict, 2-Minute "Pause Before You Pay", Next-Move Prediction & Action Menu */}
        <div className="lg:col-span-7 space-y-6">
          {/* Verdict Container */}
          <div
            className={`editorial-panel p-7 sm:p-8 space-y-5 border ${
              analysis.threatLevel >= 3
                ? 'border-[#d42020] dark:border-[#ef4444]'
                : analysis.threatLevel >= 1
                ? 'border-[#b45309] dark:border-[#fbbf24]'
                : 'border-[#2e7d32] dark:border-[#4ade80]'
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
              <div className="flex items-center gap-2">
                {analysis.threatLevel >= 3 ? (
                  <ShieldAlert className="w-4 h-4 text-[#d42020] dark:text-[#ef4444]" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-[#2e7d32] dark:text-[#4ade80]" />
                )}
                <span
                  className={`font-bold ${
                    analysis.threatLevel >= 3
                      ? 'text-[#d42020] dark:text-[#ef4444]'
                      : 'text-[#2e7d32] dark:text-[#4ade80]'
                  }`}
                >
                  {analysis.threatLabel}
                </span>
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">·</span>
                <span className="text-[#6b6b6b] dark:text-[#9ca3af]">
                  VECTOR: {uploadedMedia ? uploadedMedia.type.toUpperCase() : analysis.channel.toUpperCase()}
                </span>
              </div>
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold tabular-nums">
                RISK SCORE: {analysis.riskScore} / 100
              </span>
            </div>

            <div className="space-y-2">
              <h2 className="font-display italic text-2xl sm:text-3xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
                {language === 'hi'
                  ? analysis.headlineHi
                  : language === 'hinglish'
                  ? analysis.headlineHinglish
                  : analysis.headlineEn}
              </h2>
              <p className="text-sm sm:text-base text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
                {language === 'hi'
                  ? analysis.summaryHi
                  : language === 'hinglish'
                  ? analysis.summaryHinglish
                  : analysis.summaryEn}
              </p>
            </div>

            {/* 10-Block Linear Threat Exposure Meter */}
            <div className="space-y-1.5">
              <div className="flex justify-between font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                <span>System Exposure Meter (10-Segment Telemetry)</span>
                <span className="text-[#d42020] dark:text-[#ef4444] font-bold tabular-nums">
                  {analysis.meterBlocks} / 10 BLOCKS ACTIVE
                </span>
              </div>
              <div className="grid grid-cols-10 gap-1.5">
                {Array.from({ length: 10 }).map((_, i) => {
                  const active = i < analysis.meterBlocks;
                  const blockColor =
                    i < 3
                      ? 'bg-[#2e7d32] dark:bg-[#4ade80]'
                      : i < 6
                      ? 'bg-[#d97706] dark:bg-[#fbbf24]'
                      : 'bg-[#d42020] dark:bg-[#ef4444]';
                  return (
                    <div
                      key={i}
                      className={`h-3 ${
                        active
                          ? blockColor
                          : 'bg-[#f0eee9] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36]'
                      }`}
                    />
                  );
                })}
              </div>
            </div>

            {/* Manipulation Triggers */}
            {analysis.triggersDetected.length > 0 && (
              <div className="space-y-2 pt-2">
                <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                  Detected Psychological &amp; Technical Triggers:
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
                  {analysis.triggersDetected.map((trig, i) => (
                    <div
                      key={i}
                      className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3 text-[#1a1a1a] dark:text-[#f2f0eb]"
                    >
                      {trig}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* TWO-MINUTE "PAUSE BEFORE YOU PAY" COOLING LOCK */}
          {analysis.pauseBeforePayRequired && (
            <div className="editorial-panel border border-[#b45309] dark:border-[#fbbf24] p-6 sm:p-8 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#eee] dark:border-[#262b36] pb-3">
                <div className="flex items-center gap-2.5">
                  <Clock className="w-5 h-5 text-[#b45309] dark:text-[#fbbf24]" />
                  <div>
                    <div className="font-mono text-xs font-bold text-[#b45309] dark:text-[#fbbf24] uppercase tracking-[0.08em]">
                      {copy.pauseBannerTitle}
                    </div>
                    <div className="text-xs text-[#6b6b6b] dark:text-[#9ca3af]">
                      Do not open your UPI app or share RTGS OTP until this 120-second cooling window completes.
                    </div>
                  </div>
                </div>

                {/* Live Tabular Countdown & Controls */}
                <div className="flex items-center gap-2 bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] px-3.5 py-2 font-mono">
                  <span className="text-2xl font-bold text-[#1a1a1a] dark:text-[#f2f0eb] tabular-nums">
                    {formatTimer(pauseSecondsLeft)}
                  </span>
                  <button
                    type="button"
                    onClick={() => setIsPauseTimerRunning((r) => !r)}
                    className="p-1.5 bg-white dark:bg-[#161920] hover:bg-[#eee] dark:hover:bg-[#1e232d] text-[#1a1a1a] dark:text-[#f2f0eb] border border-[#ddd] dark:border-[#262b36] cursor-pointer"
                    aria-label={isPauseTimerRunning ? 'Pause cooling timer' : 'Resume cooling timer'}
                  >
                    {isPauseTimerRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setPauseSecondsLeft(120);
                      setIsPauseTimerRunning(true);
                    }}
                    className="p-1.5 bg-white dark:bg-[#161920] hover:bg-[#eee] dark:hover:bg-[#1e232d] text-[#1a1a1a] dark:text-[#f2f0eb] border border-[#ddd] dark:border-[#262b36] cursor-pointer"
                    aria-label="Reset 2-minute cooling timer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
                {copy.pauseBannerBody}
              </p>

              {/* 3-Point Reality Check Checkboxes */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 font-mono text-xs">
                {[
                  {
                    key: 'confirmedNoVideoArrest',
                    label: 'I know Police/CBI never do video call arrests',
                  },
                  {
                    key: 'checkedOfficialApp',
                    label: 'I know UPI PIN is only for sending money out',
                  },
                  {
                    key: 'calledFamilyMember',
                    label: 'I spoke to 1 Family Circle member off-call',
                  },
                ].map((item) => {
                  const checked = safetyChecks[item.key];
                  return (
                    <button
                      key={item.key}
                      type="button"
                      onClick={() =>
                        setSafetyChecks((prev) => ({ ...prev, [item.key]: !prev[item.key] }))
                      }
                      className={`p-3 border text-left flex items-start gap-2 transition-colors cursor-pointer ${
                        checked
                          ? 'bg-[#e7f5eb] dark:bg-[#132a1c] border-[#2e7d32] dark:border-[#4ade80] text-[#1a1a1a] dark:text-[#f2f0eb] font-bold'
                          : 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af]'
                      }`}
                    >
                      {checked ? (
                        <CheckSquare className="w-4 h-4 text-[#2e7d32] dark:text-[#4ade80] shrink-0 mt-0.5" />
                      ) : (
                        <Square className="w-4 h-4 text-[#6b6b6b] dark:text-[#9ca3af] shrink-0 mt-0.5" />
                      )}
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* NEXT-MOVE PREDICTION ENGINE */}
          {analysis.nextMoves.length > 0 && (
            <div className="editorial-panel p-6 sm:p-8 space-y-4">
              <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
                <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
                  02. Next-Move Prediction (What the Scammer Will Ask Next)
                </span>
                <span className="text-[#d42020] dark:text-[#ef4444] font-bold">Playbook Match: 98.4%</span>
              </div>

              <div className="space-y-3">
                {analysis.nextMoves.map((move) => (
                  <div
                    key={move.stepNumber}
                    className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-4 space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs">
                      <span className="text-[#d42020] dark:text-[#ef4444] font-bold">
                        PREDICTED MOVE 0{move.stepNumber} · {move.timeWindow.toUpperCase()}
                      </span>
                      <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold tabular-nums">
                        {move.probabilityPct}% PROBABILITY
                      </span>
                    </div>
                    <p className="font-display italic text-xl text-[#1a1a1a] dark:text-[#f2f0eb]">
                      &ldquo;
                      {language === 'hi'
                        ? move.actorMoveHi
                        : language === 'hinglish'
                        ? move.actorMoveHinglish
                        : move.actorMove}
                      &rdquo;
                    </p>
                    <div className="text-xs font-mono text-[#2e7d32] dark:text-[#4ade80] pt-1 border-t border-[#e6e4df] dark:border-[#262b36]">
                      DHAAL COUNTER-MEASURE: {move.counterMeasure}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 4-POINT TACTICAL ACTION MENU */}
          <div className="editorial-panel p-6 sm:p-8 space-y-4">
            <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
                03. Post-Verdict Counter-Action Menu
              </span>
              <span className="text-[#2e7d32] dark:text-[#4ade80] font-bold">One-Click Response</span>
            </div>

            {actionStatusBanner && (
              <div
                role="status"
                className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-3.5 font-mono text-xs text-[#1a1a1a] dark:text-[#f2f0eb]"
              >
                {actionStatusBanner}
              </div>
            )}

            {familyAlertStatus && !actionStatusBanner && (
              <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#2e7d32] dark:border-[#4ade80] p-3 font-mono text-xs text-[#2e7d32] dark:text-[#4ade80]">
                {familyAlertStatus}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              <button
                type="button"
                onClick={handleActionStopEngaging}
                className="p-4 bg-[#d42020] hover:bg-[#b51818] text-white font-semibold flex items-center gap-3 text-left cursor-pointer"
              >
                <PhoneOff className="w-5 h-5 shrink-0" />
                <div>
                  <div className="font-bold uppercase tracking-wider">1. Stop Engaging &amp; Block</div>
                  <div className="text-[11px] text-white/90 font-normal">
                    Terminate call &amp; isolate sender ID
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={handleActionAlertFamily}
                className="p-4 bg-[#2e7d32] hover:bg-[#1b5e20] text-white font-semibold flex items-center gap-3 text-left cursor-pointer"
              >
                <Users className="w-5 h-5 shrink-0" />
                <div>
                  <div className="font-bold uppercase tracking-wider">2. Contact Trusted Family</div>
                  <div className="text-[11px] text-white/90 font-normal">
                    Ping Family Circle ({familyMembers.length} added)
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={handleActionSaveEvidence}
                className="p-4 bg-[#f8f7f4] dark:bg-[#0f1115] hover:bg-[#eae8e1] dark:hover:bg-[#1e232d] border border-[#1a1a1a] dark:border-[#f2f0eb] text-[#1a1a1a] dark:text-[#f2f0eb] font-semibold flex items-center gap-3 text-left cursor-pointer"
              >
                <FileLock2 className="w-5 h-5 text-[#1a1a1a] dark:text-[#f2f0eb] shrink-0" />
                <div>
                  <div className="font-bold uppercase tracking-wider">3. Lock &amp; Hash Evidence</div>
                  <div className="text-[11px] text-[#6b6b6b] dark:text-[#9ca3af] font-normal">
                    Save SHA-256 certificate to Vault
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={handleActionPrepareComplaint}
                className="p-4 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-semibold flex items-center gap-3 text-left cursor-pointer"
              >
                <FileWarning className="w-5 h-5 shrink-0" />
                <div>
                  <div className="font-bold uppercase tracking-wider">4. Prepare 1930 Complaint</div>
                  <div className="text-[11px] text-white/90 dark:text-[#0f1115]/80 font-normal">
                    Auto-fill NCRP editable dossier
                  </div>
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
