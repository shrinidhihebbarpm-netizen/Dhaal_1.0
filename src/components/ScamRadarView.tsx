import React, { useState, useEffect } from 'react';
import {
  Send,
  PlusCircle,
  Trash2,
  Share2,
  ArrowRight,
} from 'lucide-react';
import { ScamGraphNode } from '../utils/seedData';
import { LanguageMode } from '../utils/scamEngine';

interface ScamRadarViewProps {
  nodes: ScamGraphNode[];
  onAddNodesWithConnections: (
    primary: {
      label: string;
      type: ScamGraphNode['type'];
      source: string;
    },
    connectedLabels: string[],
    existingParentId?: string
  ) => void;
  onClearNodes: () => void;
  onGoToInterceptor: () => void;
  language: LanguageMode;
}

export const ScamRadarView: React.FC<ScamRadarViewProps> = ({
  nodes,
  onAddNodesWithConnections,
  onClearNodes,
  onGoToInterceptor,
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>(nodes[0]?.id || '');
  const [filterType, setFilterType] = useState<string>('ALL');

  // Outbreak Pre-Warning Broadcast State
  const [targetCircle, setTargetCircle] = useState<string>(
    'Delhi NCR & Mumbai Senior Citizen Cluster (Community Opt-in)'
  );
  const [preWarningStatus, setPreWarningStatus] = useState<string | null>(null);
  const [preWarningCount, setPreWarningCount] = useState<number>(0);

  // Add New Node + Connected Entities to Reliable Scam Graph State
  const [newIdentifier, setNewIdentifier] = useState<string>('');
  const [newType, setNewType] = useState<ScamGraphNode['type']>('MULE_UPI');
  const [connectedEntitiesInput, setConnectedEntitiesInput] = useState<string>('');
  const [connectToExistingId, setConnectToExistingId] = useState<string>('');
  const [newSource, setNewSource] = useState<string>('User Scanned Evidence + UTR Match');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (nodes.length > 0 && (!selectedNodeId || !nodes.some((n) => n.id === selectedNodeId))) {
      setSelectedNodeId(nodes[0].id);
    } else if (nodes.length === 0) {
      setSelectedNodeId('');
    }
  }, [nodes, selectedNodeId]);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[0] || null;

  const filteredNodes =
    filterType === 'ALL' ? nodes : nodes.filter((n) => n.type === filterType);

  const handleDispatchPreWarning = () => {
    if (!selectedNode) return;
    setPreWarningCount((c) => c + 1);
    setPreWarningStatus(
      `OUTBREAK PRE-WARNING DISPATCHED: Broadcasted alert for "${selectedNode.label}" and its ${selectedNode.connections.length} connected node(s) to ${targetCircle}.`
    );
  };

  const handleAddGraphNode = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIdentifier.trim()) {
      setFormError('Enter a UPI ID, phone number, domain, bank account, or campaign name to add to the Radar.');
      return;
    }
    setFormError(null);
    const connectedList = connectedEntitiesInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    onAddNodesWithConnections(
      {
        label: newIdentifier.trim(),
        type: newType,
        source: newSource,
      },
      connectedList,
      connectToExistingId || undefined
    );

    setFormSuccess(
      `Added "${newIdentifier.trim()}"${
        connectedList.length > 0 ? ` and ${connectedList.length} connected entity node(s)` : ''
      } to the live Scam Radar.`
    );
    setNewIdentifier('');
    setConnectedEntitiesInput('');
  };

  const getNodeColor = (type: ScamGraphNode['type']) => {
    switch (type) {
      case 'CAMPAIGN_CLUSTER':
        return '#d42020';
      case 'MULE_UPI':
        return '#b45309';
      case 'BANK_AC':
        return '#1a1a1a';
      case 'SPOOF_PHONE':
        return '#4a4a4a';
      case 'PHISH_DOMAIN':
        return '#2e7d32';
    }
  };

  return (
    <div className="space-y-8 pb-16">
      {/* Header */}
      <div className="editorial-panel p-6 sm:p-8 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#d42020] dark:text-[#ef4444] mb-1">
            User-Driven Threat Telemetry · Dynamic Scam Graph &amp; Outbreak Radar
          </div>
          <h1 className="font-display italic text-3xl sm:text-4xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
            Scam Radar: Live User-Input Attribution Graph
          </h1>
          <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] mt-1">
            Updates strictly from your scanned inputs in the Interceptor and identifiers you add below—automatically mapping every connected UPI handle, phone number, bank account, and impersonated entity.
          </p>
        </div>

        <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] px-5 py-3.5 font-mono text-xs flex items-center gap-6 shrink-0">
          <div>
            <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
              User-Linked Entities
            </div>
            <div className="text-lg font-bold text-[#1a1a1a] dark:text-[#f2f0eb] tabular-nums">
              {nodes.length} Active Nodes
            </div>
          </div>
          <div className="border-l border-[#ddd] dark:border-[#262b36] pl-6">
            <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
              Alerts Dispatched
            </div>
            <div className="text-lg font-bold text-[#2e7d32] dark:text-[#4ade80] tabular-nums">
              {preWarningCount}
            </div>
          </div>
        </div>
      </div>

      {/* Top Row: Interactive Reliable Scam Graph (7 cols) + Node Attribution & Outbreak Pre-Warning (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* LEFT 7 COLS: Interactive SVG Network Graph */}
        <div className="lg:col-span-7 editorial-panel p-6 sm:p-8 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
              01. Live User-Input Attribution Graph
            </span>
            <div className="flex items-center gap-3">
              {nodes.length > 0 && (
                <button
                  type="button"
                  onClick={onClearNodes}
                  className="text-[#d42020] dark:text-[#ef4444] hover:underline flex items-center gap-1 cursor-pointer font-bold"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear Radar</span>
                </button>
              )}
              <span className="text-[#2e7d32] dark:text-[#4ade80] font-bold">
                {nodes.length === 0 ? 'Awaiting User Input' : `${nodes.length} Connected Nodes`}
              </span>
            </div>
          </div>

          {nodes.length === 0 ? (
            <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-8 text-center space-y-4">
              <Share2 className="w-8 h-8 text-[#d42020] dark:text-[#ef4444] mx-auto" />
              <div className="space-y-1.5 max-w-lg mx-auto">
                <h2 className="font-display italic text-2xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb]">
                  No User Inputs Linked Yet
                </h2>
                <p className="text-xs sm:text-sm text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
                  Scam Radar starts completely blank and only maps real inputs you provide. Add a suspect identifier and its connected entities in the form below, or scan an image, audio recording, or message in the Interceptor.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={onGoToInterceptor}
                  className="px-5 py-3 bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] font-mono text-xs font-bold uppercase tracking-[0.1em] flex items-center gap-2 cursor-pointer"
                >
                  <span>Scan Input in Interceptor to Populate Radar</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Interactive SVG Canvas */}
              <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-2 overflow-x-auto">
                <svg
                  viewBox="0 0 920 360"
                  className="w-full h-[320px] min-w-[600px]"
                  role="img"
                  aria-label="User-driven Scam Graph linking Mule UPI IDs, Bank Accounts, Phone Numbers, and Scam Campaigns"
                >
                  {/* Subtle Archival Radar Rings */}
                  <circle cx="460" cy="180" r="75" fill="none" stroke="var(--border-color)" strokeWidth="1" />
                  <circle cx="460" cy="180" r="145" fill="none" stroke="var(--border-color)" strokeWidth="1" />
                  <circle cx="460" cy="180" r="220" fill="none" stroke="var(--border-color)" strokeWidth="1" />

                  {/* Edges between connected nodes */}
                  {nodes.map((node) =>
                    node.connections.map((targetId) => {
                      const target = nodes.find((n) => n.id === targetId);
                      if (!target) return null;
                      const isHighlighted =
                        selectedNode && (node.id === selectedNode.id || target.id === selectedNode.id);
                      return (
                        <line
                          key={`${node.id}-${target.id}`}
                          x1={node.x}
                          y1={node.y}
                          x2={target.x}
                          y2={target.y}
                          stroke={isHighlighted ? '#d42020' : '#8a8880'}
                          strokeWidth={isHighlighted ? '2.5' : '1.5'}
                        />
                      );
                    })
                  )}

                  {/* Graph Nodes */}
                  {nodes.map((node) => {
                    const isSelected = selectedNode?.id === node.id;
                    const color = getNodeColor(node.type);
                    return (
                      <g
                        key={node.id}
                        onClick={() => setSelectedNodeId(node.id)}
                        className="cursor-pointer"
                      >
                        {isSelected && (
                          <rect
                            x={node.x - 74}
                            y={node.y - 26}
                            width={148}
                            height={52}
                            fill="none"
                            stroke="var(--ink)"
                            strokeWidth="1.5"
                          />
                        )}
                        <rect
                          x={node.x - 70}
                          y={node.y - 22}
                          width={140}
                          height={44}
                          fill="#ffffff"
                          stroke={color}
                          strokeWidth={isSelected ? '2.5' : '1.5'}
                        />
                        <text
                          x={node.x}
                          y={node.y - 4}
                          textAnchor="middle"
                          fill="#1a1a1a"
                          fontSize="10"
                          fontWeight="700"
                          fontFamily="Space Mono, monospace"
                        >
                          {node.label.length > 18 ? node.label.slice(0, 17) + '…' : node.label}
                        </text>
                        <text
                          x={node.x}
                          y={node.y + 12}
                          textAnchor="middle"
                          fill={color}
                          fontSize="9"
                          fontFamily="Space Mono, monospace"
                        >
                          {node.type} · {node.confidencePct}%
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>

              {/* Graph Legend & Node Selector Buttons */}
              <div className="space-y-2 pt-1">
                <div className="font-mono text-[11px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                  Select User-Added Entity to Inspect Connected Nodes:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {nodes.map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => setSelectedNodeId(n.id)}
                      className={`px-2.5 py-1.5 font-mono text-xs border transition-colors cursor-pointer ${
                        selectedNode?.id === n.id
                          ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] border-[#1a1a1a] dark:border-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                          : 'bg-[#f8f7f4] dark:bg-[#0f1115] border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] hover:text-[#1a1a1a] dark:hover:text-[#f2f0eb]'
                      }`}
                    >
                      {n.label}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {/* RIGHT 5 COLS: Selected Node Telemetry + Outbreak Pre-Warning */}
        <div className="lg:col-span-5 space-y-6">
          {/* Selected Node Dossier */}
          <div className="editorial-panel p-6 sm:p-8 space-y-4">
            <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
                Node Attribution &amp; Connected Links
              </span>
              <span className="text-[#d42020] dark:text-[#ef4444] font-bold tabular-nums">
                {selectedNode ? selectedNode.id : 'NO NODE SELECTED'}
              </span>
            </div>

            {selectedNode ? (
              <div className="space-y-3 font-mono text-xs">
                <div>
                  <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                    Entity Identifier
                  </div>
                  <div className="font-display italic text-2xl font-semibold text-[#1a1a1a] dark:text-[#f2f0eb] mt-0.5">
                    {selectedNode.label}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3">
                    <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                      Entity Type
                    </div>
                    <div className="text-sm font-bold text-[#2e7d32] dark:text-[#4ade80]">
                      {selectedNode.type}
                    </div>
                  </div>
                  <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3">
                    <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                      Connected Nodes
                    </div>
                    <div className="text-sm font-bold text-[#d42020] dark:text-[#ef4444] tabular-nums">
                      {selectedNode.connections.length} Linked Entities
                    </div>
                  </div>
                </div>

                <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3 space-y-1">
                  <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                    Input Source Lineage:
                  </div>
                  <div className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">{selectedNode.source}</div>
                </div>

                {/* Connected Entities List */}
                <div className="bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#e6e4df] dark:border-[#262b36] p-3 space-y-1.5">
                  <div className="text-[10px] uppercase tracking-[0.1em] text-[#6b6b6b] dark:text-[#9ca3af]">
                    Directly Connected Graph Entities:
                  </div>
                  {selectedNode.connections.length === 0 ? (
                    <div className="text-[#6b6b6b] dark:text-[#9ca3af]">No connected child nodes yet.</div>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {selectedNode.connections.map((connId) => {
                        const target = nodes.find((n) => n.id === connId);
                        if (!target) return null;
                        return (
                          <button
                            key={connId}
                            type="button"
                            onClick={() => setSelectedNodeId(target.id)}
                            className="px-2 py-1 bg-white dark:bg-[#161920] border border-[#ddd] dark:border-[#262b36] text-[#1a1a1a] dark:text-[#f2f0eb] hover:border-[#d42020] cursor-pointer"
                          >
                            {target.label} ({target.type})
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <p className="text-xs font-mono text-[#6b6b6b] dark:text-[#9ca3af]">
                Add an identifier below or scan a message in the Interceptor to inspect node connections.
              </p>
            )}
          </div>

          {/* Outbreak Pre-Warning Dispatcher */}
          <div className="editorial-panel border border-[#d42020] dark:border-[#ef4444] p-6 sm:p-8 space-y-4">
            <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
              <span className="text-[#d42020] dark:text-[#ef4444] font-bold">
                Community Outbreak Pre-Warning Dispatch
              </span>
              <span className="text-[#1a1a1a] dark:text-[#f2f0eb]">Proactive Immunization</span>
            </div>

            <p className="text-xs text-[#6b6b6b] dark:text-[#9ca3af] leading-relaxed">
              Broadcast an early outbreak alert for{' '}
              <strong className="text-[#1a1a1a] dark:text-[#f2f0eb]">
                {selectedNode ? selectedNode.label : 'your reported scam network'}
              </strong>{' '}
              and its connected identifiers to warn likely next targets.
            </p>

            <div className="space-y-2 font-mono text-xs">
              <label
                htmlFor="target-cohort-select"
                className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Target At-Risk Community Cohort:
              </label>
              <select
                id="target-cohort-select"
                value={targetCircle}
                onChange={(e) => setTargetCircle(e.target.value)}
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] font-mono text-xs focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              >
                <option value="Delhi NCR & Mumbai Senior Citizen Cluster (Community Opt-in)">
                  Delhi NCR &amp; Mumbai Senior Citizen Cluster
                </option>
                <option value="Bengaluru & Hyderabad Tech/IPO Retail Investors">
                  Bengaluru &amp; Hyderabad Tech/IPO Investors
                </option>
                <option value="All-India Hindi/Hinglish Family Circles">
                  All-India Hindi/Hinglish Family Circles
                </option>
              </select>
            </div>

            {preWarningStatus && (
              <div
                role="status"
                className="bg-[#e7f5eb] dark:bg-[#132a1c] border border-[#2e7d32] dark:border-[#4ade80] p-3 font-mono text-xs text-[#1a1a1a] dark:text-[#f2f0eb]"
              >
                {preWarningStatus}
              </div>
            )}

            <button
              type="button"
              disabled={!selectedNode}
              onClick={handleDispatchPreWarning}
              className={`w-full py-3.5 font-mono text-xs font-bold uppercase tracking-[0.1em] flex items-center justify-center gap-2 cursor-pointer ${
                selectedNode
                  ? 'bg-[#d42020] hover:bg-[#b51818] text-white'
                  : 'bg-[#e6e4df] dark:bg-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] cursor-not-allowed'
              }`}
            >
              <Send className="w-4 h-4" />
              <span>Broadcast Outbreak Pre-Warning</span>
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Row: Link New Scam ID + Connected Entities Form (5 cols) + Full Attribution Table (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Link New Scam ID + Connected Entities Form */}
        <div className="lg:col-span-5 editorial-panel p-6 sm:p-8 space-y-4">
          <div className="flex items-center justify-between border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
              02. Add Scam Identifier &amp; Connected Entities
            </span>
            <span className="text-[#2e7d32] dark:text-[#4ade80] font-bold">User Input</span>
          </div>

          <form onSubmit={handleAddGraphNode} className="space-y-4 font-mono text-xs">
            <div className="space-y-1.5">
              <label
                htmlFor="new-node-id"
                className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Primary Suspect VPA / Phone / Account / Campaign
              </label>
              <input
                id="new-node-id"
                type="text"
                value={newIdentifier}
                onChange={(e) => setNewIdentifier(e.target.value)}
                placeholder="e.g. rbi.verify99@okaxis or +91 98214 77019"
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              />
              {formError && (
                <p role="alert" className="text-[#d42020] dark:text-[#ef4444]">
                  {formError}
                </p>
              )}
              {formSuccess && (
                <p role="status" className="text-[#2e7d32] dark:text-[#4ade80]">
                  {formSuccess}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="connected-entities-input"
                className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
              >
                Connected Entities (Comma-Separated UPIs, Phones, Domains, or Authority)
              </label>
              <input
                id="connected-entities-input"
                type="text"
                value={connectedEntitiesInput}
                onChange={(e) => setConnectedEntitiesInput(e.target.value)}
                placeholder="e.g. +91 98214 77019, Fake CBI Parcel Ring, A/C 918273645501"
                className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb] focus:border-[#1a1a1a] dark:focus:border-[#f2f0eb] focus:outline-none"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label
                  htmlFor="new-node-type"
                  className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Primary Identifier Type
                </label>
                <select
                  id="new-node-type"
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as ScamGraphNode['type'])}
                  className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
                >
                  <option value="MULE_UPI">MULE_UPI</option>
                  <option value="SPOOF_PHONE">SPOOF_PHONE</option>
                  <option value="BANK_AC">BANK_AC</option>
                  <option value="PHISH_DOMAIN">PHISH_DOMAIN</option>
                  <option value="CAMPAIGN_CLUSTER">CAMPAIGN_CLUSTER</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="new-node-source"
                  className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Evidence Source
                </label>
                <select
                  id="new-node-source"
                  value={newSource}
                  onChange={(e) => setNewSource(e.target.value)}
                  className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
                >
                  <option value="User Scanned Evidence + UTR Match">User Scanned Evidence</option>
                  <option value="Uploaded Screenshot OCR">Uploaded Screenshot OCR</option>
                  <option value="Uploaded Audio Call Transcript">Uploaded Audio Transcript</option>
                  <option value="1930 NCRP Escalation Feed">1930 NCRP Escalation</option>
                </select>
              </div>
            </div>

            {nodes.length > 0 && (
              <div className="space-y-1.5">
                <label
                  htmlFor="connect-existing-select"
                  className="block text-[11px] uppercase tracking-[0.08em] text-[#6b6b6b] dark:text-[#9ca3af]"
                >
                  Also Link to Existing Radar Node (Optional)
                </label>
                <select
                  id="connect-existing-select"
                  value={connectToExistingId}
                  onChange={(e) => setConnectToExistingId(e.target.value)}
                  className="w-full bg-[#f8f7f4] dark:bg-[#0f1115] border border-[#ddd] dark:border-[#262b36] p-2.5 text-[#1a1a1a] dark:text-[#f2f0eb]"
                >
                  <option value="">-- Create New Independent Cluster --</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.label} ({n.type})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              type="submit"
              className="w-full py-3.5 bg-[#1a1a1a] dark:bg-[#f2f0eb] hover:bg-[#333333] dark:hover:bg-white text-white dark:text-[#0f1115] font-bold uppercase tracking-[0.1em] flex items-center justify-center gap-2 cursor-pointer"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Add Identifier &amp; Connected Nodes to Radar</span>
            </button>
          </form>
        </div>

        {/* Filterable Attribution Ledger Table */}
        <div className="lg:col-span-7 editorial-panel p-6 sm:p-8 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#eee] dark:border-[#262b36] pb-3 font-mono text-[11px] uppercase tracking-[0.1em]">
            <span className="text-[#1a1a1a] dark:text-[#f2f0eb] font-bold">
              User-Reported Scam Graph Registry ({filteredNodes.length} Entities)
            </span>
            <div className="flex flex-wrap gap-1">
              {['ALL', 'MULE_UPI', 'SPOOF_PHONE', 'BANK_AC', 'PHISH_DOMAIN', 'CAMPAIGN_CLUSTER'].map((ft) => (
                <button
                  key={ft}
                  type="button"
                  onClick={() => setFilterType(ft)}
                  className={`px-2.5 py-1 text-[10px] cursor-pointer ${
                    filterType === ft
                      ? 'bg-[#1a1a1a] dark:bg-[#f2f0eb] text-white dark:text-[#0f1115] font-bold'
                      : 'bg-[#f8f7f4] dark:bg-[#0f1115] text-[#6b6b6b] dark:text-[#9ca3af] border border-[#ddd] dark:border-[#262b36]'
                  }`}
                >
                  {ft}
                </button>
              ))}
            </div>
          </div>

          {filteredNodes.length === 0 ? (
            <div className="py-12 text-center font-mono text-xs text-[#6b6b6b] dark:text-[#9ca3af]">
              No entities in this view yet. Add a suspect identifier on the left or run a scan in the Interceptor.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#ddd] dark:border-[#262b36] text-[#6b6b6b] dark:text-[#9ca3af] text-[11px] uppercase tracking-[0.08em]">
                    <th className="py-2.5 pr-3">Identifier</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Source Lineage</th>
                    <th className="py-2.5 pl-3 text-right">Connected</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNodes.map((n, idx) => (
                    <tr
                      key={n.id}
                      onClick={() => setSelectedNodeId(n.id)}
                      className={`border-b border-[#eee] dark:border-[#262b36] cursor-pointer transition-colors ${
                        idx % 2 === 0
                          ? 'bg-white dark:bg-[#161920]'
                          : 'bg-[#f8f7f4] dark:bg-[#0f1115]'
                      } hover:bg-[#f0eee9] dark:hover:bg-[#1e232d]`}
                    >
                      <td className="py-3 pr-3 font-bold text-[#1a1a1a] dark:text-[#f2f0eb]">{n.label}</td>
                      <td className="py-3 px-3 text-[#6b6b6b] dark:text-[#9ca3af]">{n.type}</td>
                      <td className="py-3 px-3 text-[#6b6b6b] dark:text-[#9ca3af]">{n.source}</td>
                      <td className="py-3 pl-3 text-right font-bold text-[#2e7d32] dark:text-[#4ade80] tabular-nums">
                        {n.connections.length} link(s)
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
