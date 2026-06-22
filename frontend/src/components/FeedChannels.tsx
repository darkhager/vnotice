"use client";
import React, { useState, useEffect } from "react";
import { Plus, Terminal, RefreshCw } from "lucide-react";

interface Feed {
  name: string;
  url: string;
  active: boolean;
}

interface FeedChannelsProps {
  feeds: Feed[];
  onToggleFeed: (idx: number) => void;
  onOpenAddModal: () => void;
  logs: string[];
}

export default function FeedChannels({
  feeds,
  onToggleFeed,
  onOpenAddModal,
  logs,
}: FeedChannelsProps) {
  const activeCount = feeds.filter((f) => f.active).length;

  return (
    <div className="h-full flex flex-col gap-3 min-h-0">
      {/* Top Section: Feed Channels List */}
      <div className="flex-[3] glass-panel p-4 flex flex-col min-h-0 border border-white/5 shadow-xl relative overflow-hidden">
        <div className="flex justify-between items-center mb-4 flex-shrink-0 relative z-10">
          <h2 className="font-bold text-white flex items-center gap-2">
            📡 Feed Channels
            <span className="bg-sky-500 text-white text-xs px-2 py-0.5 rounded-full font-semibold animate-pulse">
              {activeCount} / {feeds.length}
            </span>
          </h2>
          <button
            onClick={onOpenAddModal}
            className="text-xs bg-sky-500 hover:bg-sky-600 text-white px-2.5 py-1.5 rounded-lg flex items-center gap-1 transition font-semibold"
          >
            <Plus className="w-3.5 h-3.5" /> Add Source
          </button>
        </div>

        <div className="flex-1 overflow-y-auto pr-1 space-y-2.5 relative z-10">
          {feeds.length === 0 ? (
            <div className="text-sm text-gray-500 text-center mt-10">
              No feed channels configured yet.
            </div>
          ) : (
            feeds.map((feed, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 border border-white/5 rounded-xl bg-black/20 hover:bg-black/30 transition-colors"
              >
                <div className="min-w-0 flex-1 mr-3">
                  <h4 className="font-semibold text-sm text-white truncate">{feed.name}</h4>
                  <p className="text-[11px] text-gray-500 truncate mt-0.5">{feed.url}</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer flex-shrink-0">
                  <input
                    type="checkbox"
                    className="sr-only peer"
                    checked={feed.active}
                    onChange={() => onToggleFeed(idx)}
                  />
                  <div className="w-9 h-5 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-gray-400 peer-checked:after:bg-white after:border-none after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-sky-500"></div>
                </label>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Bottom Section: Audit & System Logs Console */}
      <div className="flex-[2] glass-panel p-4 flex flex-col min-h-0 border border-white/5 shadow-xl relative">
        <div className="flex justify-between items-center mb-2 flex-shrink-0">
          <h2 className="font-bold text-sm text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-sky-400" />
            ⚡ Audit & System Logs
          </h2>
        </div>
        <div className="flex-1 overflow-y-auto pr-1 bg-black/40 rounded-lg p-3 font-mono text-[11px] text-gray-400 border border-white/5 leading-relaxed space-y-1.5">
          {logs.map((log, index) => {
            let logClass = "text-gray-400";
            if (log.includes("[SYS]")) {
              logClass = "text-gray-300";
            } else if (log.includes("[NET]")) {
              logClass = "text-yellow-500/90";
            } else if (log.includes("[SEC]")) {
              logClass = "text-red-400/90";
            } else if (log.includes("[OK]")) {
              logClass = "text-green-400/90";
            }
            return (
              <div key={index} className={`break-words select-none font-medium ${logClass}`}>
                {log}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
