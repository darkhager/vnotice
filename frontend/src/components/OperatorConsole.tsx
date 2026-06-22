"use client";
import React from "react";
import { Shield, RefreshCw, Settings, LogOut } from "lucide-react";

interface UserProfile {
  id: string;
  name: string;
  avatar: string;
  role: string;
  email: string;
  preferences: {
    theme: "dark" | "light";
    textSize: "sm" | "md" | "lg" | "xl" | "2xl";
    vulnerabilityMinSeverity: "low" | "medium" | "high" | "critical";
    emailAlertsEnabled: boolean;
    desktopAlertsEnabled: boolean;
    browserAlertsEnabled: boolean;
    teamsAlertsEnabled?: boolean;
    teamsWebhookUrl?: string;
    smsAlertsEnabled?: boolean;
    smsTwilioSid?: string;
    smsTwilioToken?: string;
    smsPhoneNumber?: string;
  };
}

interface OperatorConsoleProps {
  profile: UserProfile;
  onSwitchUser: () => void;
  onOpenSettings: () => void;
  onSyncFeeds: () => void;
  isSyncing: boolean;
}

export default function OperatorConsole({
  profile,
  onSwitchUser,
  onOpenSettings,
  onSyncFeeds,
  isSyncing,
}: OperatorConsoleProps) {
  return (
    <div className="h-full flex flex-col glass-panel p-5 border border-white/5 shadow-2xl relative overflow-hidden">
      {/* Decorative backdrop glow */}
      <div className="absolute -top-12 -left-12 w-24 h-24 bg-sky-500/10 rounded-full filter blur-xl"></div>
      
      <div className="flex items-center gap-3 mb-6 relative z-10">
        <Shield className="w-8 h-8 text-sky-400" />
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">Vnotice</h1>
          <p className="text-xs text-gray-400">Vulnerability Advisory Monitor</p>
        </div>
      </div>

      <div className="bg-black/30 p-4 rounded-xl border border-white/5 flex items-center justify-between mb-6 relative z-10">
        <div className="flex items-center gap-3 min-w-0">
          <div className="text-3xl bg-sky-500/15 p-2 rounded-full border border-sky-400/30 flex-shrink-0 select-none">
            {profile.avatar}
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-white truncate max-w-[150px]">{profile.name}</div>
            <div className="text-xs text-sky-400 font-medium tracking-wide uppercase mt-0.5">
              {profile.role}
            </div>
          </div>
        </div>
        <button
          onClick={onSwitchUser}
          className="text-gray-400 hover:text-white p-1.5 hover:bg-white/5 rounded-lg transition"
          title="Switch User Profile"
        >
          <LogOut className="w-5 h-5" />
        </button>
      </div>

      <div className="space-y-3.5 mb-6 relative z-10">
        <div className="flex justify-between items-center text-sm border-b border-white/5 pb-2">
          <div className="flex items-center gap-2">
            <div
              className={`w-2.5 h-2.5 rounded-full ${
                profile.preferences.desktopAlertsEnabled ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]" : "bg-red-500"
              }`}
            ></div>
            <span className="text-gray-300">OS Push Alerts:</span>
          </div>
          <span className="font-medium text-white">
            {profile.preferences.desktopAlertsEnabled ? "Active" : "Disabled"}
          </span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <div className="flex items-center gap-2">
            <div
              className={`w-2.5 h-2.5 rounded-full ${
                profile.preferences.emailAlertsEnabled ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]" : "bg-red-500"
              }`}
            ></div>
            <span className="text-gray-300">Email Alerts:</span>
          </div>
          <span className="font-medium text-white">
            {profile.preferences.emailAlertsEnabled ? "Active" : "Disabled"}
          </span>
        </div>
      </div>

      <div className="mt-auto flex gap-2 relative z-10">
        <button
          onClick={onSyncFeeds}
          disabled={isSyncing}
          className="flex-1 py-2.5 bg-sky-500 hover:bg-sky-600 disabled:bg-sky-850 text-white rounded-lg font-semibold flex items-center justify-center gap-2 transition shadow-md shadow-sky-500/10 text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${isSyncing ? "animate-spin" : ""}`} />
          {isSyncing ? "Syncing..." : "Sync Feeds"}
        </button>
        <button
          onClick={onOpenSettings}
          className="flex-1 py-2.5 glass-panel text-white hover:bg-white/5 border border-white/10 rounded-lg font-semibold flex items-center justify-center gap-2 transition text-sm"
        >
          <Settings className="w-4 h-4 text-sky-400" /> Settings
        </button>
      </div>
    </div>
  );
}
