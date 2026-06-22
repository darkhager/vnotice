"use client";
import React, { useState } from "react";

interface FiltersProps {
  activeSeverities?: string[];
  onToggleSeverity?: (sev: string) => void;
  activeKeywords?: string[];
  onAddKeyword?: (kw: string) => void;
  onRemoveKeyword?: (kw: string) => void;
  activeFeedsFilter?: string[];
  onToggleFeedFilter?: (feedName: string) => void;
  feeds?: any[];
  onResetFilters?: () => void;
}

export default function Filters({
  activeSeverities = ["all"],
  onToggleSeverity = () => {},
  activeKeywords = [],
  onAddKeyword = () => {},
  onRemoveKeyword = () => {},
  activeFeedsFilter = ["all"],
  onToggleFeedFilter = () => {},
  feeds = [],
  onResetFilters = () => {}
}: FiltersProps) {
  const [keywordInput, setKeywordInput] = useState("");

  const getPillClass = (baseClass: string, activeClass: string, isAct: boolean) => {
    return `px-3 py-1 text-sm font-medium rounded-full transition-all duration-200 cursor-pointer ${
      isAct ? activeClass : baseClass
    }`;
  };

  return (
    <div className="glass-panel p-6 rounded-xl flex flex-col gap-6 border border-white/5 bg-black/25">
      <div className="space-y-4">
        {/* Severity selection row */}
        <div className="flex flex-col gap-2">
          <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">Severity:</span>
          <div className="flex flex-wrap gap-2">
            {[
              { id: "all", label: "All", active: "bg-sky-500 text-white border-sky-400/20" },
              { id: "critical", label: "Critical", active: "bg-red-500 text-white border-red-400/20" },
              { id: "high", label: "High", active: "bg-orange-500 text-white border-orange-400/20" },
              { id: "medium", label: "Medium", active: "bg-yellow-500 text-black border-yellow-400/20 font-bold" },
              { id: "low", label: "Low", active: "bg-green-500 text-white border-green-400/20" }
            ].map(sev => (
              <button
                key={sev.id}
                type="button"
                onClick={() => onToggleSeverity(sev.id)}
                className={getPillClass(
                  "bg-white/5 border border-white/5 text-gray-400 hover:bg-white/10 hover:text-white",
                  sev.active,
                  activeSeverities.includes(sev.id)
                )}
              >
                {sev.label}
              </button>
            ))}
          </div>
        </div>

        {/* Multi-Keyword Tag Filter (Input & Pills) */}
        <div className="space-y-2 pt-3 border-t border-white/5">
          <span className="block text-xs font-bold text-gray-400 uppercase tracking-widest">
            Keyword Filter
          </span>
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Add keyword and press Enter..."
              value={keywordInput}
              onChange={(e) => setKeywordInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && keywordInput.trim() !== "") {
                  e.preventDefault();
                  onAddKeyword(keywordInput.trim());
                  setKeywordInput("");
                }
              }}
              className="w-full bg-white/[0.01] hover:bg-white/[0.02] border border-white/5 rounded-xl py-2 px-3 text-white placeholder-gray-500 focus:border-sky-500/50 focus:outline-none text-[0.85em] transition duration-200"
            />
            <button
              type="button"
              onClick={() => {
                if (keywordInput.trim() !== "") {
                  onAddKeyword(keywordInput.trim());
                  setKeywordInput("");
                }
              }}
              className="px-3 py-1.5 bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/30 rounded-xl text-sky-400 text-xs font-bold transition-all"
            >
              Add
            </button>
          </div>
          
          {activeKeywords.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {activeKeywords.map((kw) => (
                <button
                  key={kw}
                  type="button"
                  onClick={() => onRemoveKeyword(kw)}
                  className="px-2 py-0.5 text-[10px] font-bold bg-sky-500/10 hover:bg-red-500/10 border border-sky-500/20 hover:border-red-500/30 text-sky-400 hover:text-red-400 rounded-lg transition duration-150 flex items-center gap-1 group"
                  title="Click to remove keyword"
                >
                  <span>{kw}</span>
                  <span className="text-gray-500 group-hover:text-red-400">✕</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* RSS Feed Filter checklist */}
        <div className="space-y-2 pt-3 border-t border-white/5">
          <span className="block text-xs font-bold text-gray-400 uppercase tracking-widest">
            Filter by Threat Source
          </span>
          <div className="flex flex-col gap-1.5 max-h-40 overflow-y-auto pr-1">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={activeFeedsFilter.includes("all")}
                onChange={() => onToggleFeedFilter("all")}
                className="rounded border-white/10 bg-black/40 text-sky-500 focus:ring-sky-500/50"
              />
              <span className="text-xs font-bold text-gray-300">All Sources</span>
            </label>
            {feeds.map((feed) => {
              const isChecked = activeFeedsFilter.includes(feed.name);
              return (
                <label key={feed.name} className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => onToggleFeedFilter(feed.name)}
                    className="rounded border-white/10 bg-black/40 text-sky-500 focus:ring-sky-500/50"
                  />
                  <span className="text-xs text-gray-400 hover:text-white truncate" title={feed.name}>
                    {feed.name}
                  </span>
                </label>
              );
            })}
          </div>
        </div>
      </div>
      
      <div className="flex justify-between items-center pt-3 border-t border-white/5">
        <button 
          onClick={onResetFilters}
          className="w-full px-4 py-2 text-xs font-bold bg-white/[0.01] hover:bg-red-500/10 border border-white/5 hover:border-red-500/30 text-gray-400 hover:text-red-400 rounded-xl transition duration-200 flex items-center justify-center gap-1.5"
        >
          🔄 Reset Filters to Default
        </button>
      </div>
    </div>
  );
}
