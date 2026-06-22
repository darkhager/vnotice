"use client";
import React from "react";
import { AlertOctagon, AlertTriangle, Rss, BarChart2, Search } from "lucide-react";

interface Vulnerability {
  id: string;
  name: string;
  vendor: string;
  product: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  score: number;
  epss: number;
  date: string;
  url: string;
}

interface OverviewStatsProps {
  vulnerabilities: Vulnerability[];
  activeFeedsCount: number;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  activeSeverity: string;
  setActiveSeverity: (s: string) => void;
  onExportCSV: () => void;
  onExportJSON: () => void;
}

export default function OverviewStats({
  vulnerabilities,
  activeFeedsCount,
  searchQuery,
  setSearchQuery,
  activeSeverity,
  setActiveSeverity,
  onExportCSV,
  onExportJSON,
}: OverviewStatsProps) {
  // Count stats
  const criticalCount = vulnerabilities.filter((v) => v.severity.toLowerCase() === "critical").length;
  const highCount = vulnerabilities.filter((v) => v.severity.toLowerCase() === "high").length;
  const totalCount = vulnerabilities.length;

  return (
    <div className="h-full flex flex-col gap-4">
      {/* 4 Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 flex-shrink-0">
        {/* Critical Widget */}
        <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-red-500/10 shadow-lg">
          <div className="absolute top-0 right-0 p-2 text-red-500 opacity-10">
            <AlertOctagon size={40} />
          </div>
          <div className="text-3xl font-extrabold text-red-500 relative z-10 select-none">
            {criticalCount}
          </div>
          <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mt-1 relative z-10">
            Critical
          </div>
        </div>

        {/* High Widget */}
        <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-orange-500/10 shadow-lg">
          <div className="absolute top-0 right-0 p-2 text-orange-500 opacity-10">
            <AlertTriangle size={40} />
          </div>
          <div className="text-3xl font-extrabold text-orange-500 relative z-10 select-none">
            {highCount}
          </div>
          <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mt-1 relative z-10">
            High
          </div>
        </div>

        {/* Feeds Widget */}
        <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-sky-500/10 shadow-lg">
          <div className="absolute top-0 right-0 p-2 text-sky-400 opacity-10">
            <Rss size={40} />
          </div>
          <div className="text-3xl font-extrabold text-sky-400 relative z-10 select-none">
            {activeFeedsCount}
          </div>
          <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mt-1 relative z-10">
            Active Feeds
          </div>
        </div>

        {/* Total Widget */}
        <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-green-500/10 shadow-lg">
          <div className="absolute top-0 right-0 p-2 text-green-500 opacity-10">
            <BarChart2 size={40} />
          </div>
          <div className="text-3xl font-extrabold text-green-500 relative z-10 select-none">
            {totalCount}
          </div>
          <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mt-1 relative z-10">
            Total Threat
          </div>
        </div>
      </div>

      {/* Live Filters Hub */}
      <div className="flex-1 glass-panel p-4 flex flex-col justify-center gap-3 border border-white/5 shadow-xl relative">
        <div className="flex justify-between items-center">
          <div className="font-bold text-sm text-white uppercase tracking-wider">
            🛡️ Live Filters Hub
          </div>
          <div className="flex gap-2">
            <button
              onClick={onExportCSV}
              className="px-2.5 py-1 text-xs glass-panel hover:bg-white/5 border border-white/10 rounded transition text-gray-300 font-medium"
            >
              CSV
            </button>
            <button
              onClick={onExportJSON}
              className="px-2.5 py-1 text-xs glass-panel hover:bg-white/5 border border-white/10 rounded transition text-gray-300 font-medium"
            >
              JSON
            </button>
          </div>
        </div>

        <div className="relative">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVEs, products, brands, or descriptions..."
            className="w-full bg-black/35 border border-white/10 rounded-lg py-2 pl-9 pr-4 text-white placeholder-gray-500 focus:border-sky-400 focus:outline-none text-sm transition"
          />
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-gray-400 font-semibold uppercase tracking-wider mr-1">
            Severity:
          </span>
          <div className="flex flex-wrap gap-1.5">
            {["all", "critical", "high", "medium", "low"].map((sev) => {
              const isActive = activeSeverity === sev;
              let btnClass = "";
              
              if (isActive) {
                switch (sev) {
                  case "critical":
                    btnClass = "bg-red-500 text-white shadow-md shadow-red-500/10";
                    break;
                  case "high":
                    btnClass = "bg-orange-500 text-white shadow-md shadow-orange-500/10";
                    break;
                  case "medium":
                    btnClass = "bg-yellow-500 text-black font-semibold";
                    break;
                  case "low":
                    btnClass = "bg-green-500 text-white shadow-md shadow-green-500/10";
                    break;
                  default:
                    btnClass = "bg-sky-500 text-white shadow-md shadow-sky-500/10";
                }
              } else {
                switch (sev) {
                  case "critical":
                    btnClass = "glass-panel border-red-500/20 text-red-400 hover:bg-red-500/10";
                    break;
                  case "high":
                    btnClass = "glass-panel border-orange-500/20 text-orange-400 hover:bg-orange-500/10";
                    break;
                  case "medium":
                    btnClass = "glass-panel border-yellow-500/20 text-yellow-400 hover:bg-yellow-500/10";
                    break;
                  case "low":
                    btnClass = "glass-panel border-green-500/20 text-green-400 hover:bg-green-500/10";
                    break;
                  default:
                    btnClass = "glass-panel border-white/10 text-gray-300 hover:bg-white/5";
                }
              }

              return (
                <button
                  key={sev}
                  onClick={() => setActiveSeverity(sev)}
                  className={`px-3 py-1 text-xs rounded-full font-medium transition duration-200 capitalize ${btnClass}`}
                >
                  {sev}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
