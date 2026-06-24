"use client";
import React, { useState } from "react";
import { User, ShieldAlert } from "lucide-react";

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
  credentials: {
    smtpHost?: string;
    smtpPort?: string;
    smtpUser?: string;
    smtpPass?: string;
  };
}

interface ProfileSelectionProps {
  profiles: UserProfile[];
  onSelectProfile: (id: string) => void;
  onCreateProfile: (profile: UserProfile) => void;
  defaultProfileId?: string;   // shown first and badged as the default account
}

const avatars = ["🛡️", "🕵️", "💻", "🚀", "⚡", "⚙️"];

export default function ProfileSelection({
  profiles,
  onSelectProfile,
  onCreateProfile,
  defaultProfileId,
}: ProfileSelectionProps) {
  // Default (admin) account first, everything else after.
  const ordered = [...profiles].sort((a, b) =>
    a.id === defaultProfileId ? -1 : b.id === defaultProfileId ? 1 : 0);
  const [isCreating, setIsCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newAvatar, setNewAvatar] = useState("🛡️");
  const [newEmail, setNewEmail] = useState("");

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;

    const newProfile: UserProfile = {
      id: (typeof window !== "undefined" && window.crypto && window.crypto.randomUUID) 
        ? window.crypto.randomUUID() 
        : "id-" + Math.random().toString(36).substring(2, 15) + "-" + Date.now().toString(36),
      name: newName.trim(),
      avatar: newAvatar,
      role: "Security Operator",
      email: newEmail.trim() || `${newName.trim().toLowerCase().replace(/[^a-z0-9]/g, "")}@vnotice.local`,
      preferences: {
        theme: "dark",
        textSize: "md",
        vulnerabilityMinSeverity: "medium",
        emailAlertsEnabled: newEmail.trim() !== "",
        desktopAlertsEnabled: true,
        browserAlertsEnabled: true,
      },
      credentials: {},
    };

    onCreateProfile(newProfile);
    setIsCreating(false);
    setNewName("");
    setNewAvatar("🛡️");
    setNewEmail("");
  };

  return (
    <div className="flex items-center justify-center min-h-[85vh] p-4">
      <div className="glass-panel p-8 rounded-2xl shadow-2xl max-w-2xl w-full border border-white/10">
        <div className="flex justify-center mb-4">
          <ShieldAlert className="w-16 h-16 text-red-500 animate-pulse" />
        </div>
        <h1 className="text-3xl font-extrabold text-center mb-2 tracking-tight text-white">
          Welcome to Vnotice
        </h1>
        <p className="text-center text-gray-400 mb-8 max-w-md mx-auto">
          Access your personalized threat intelligence feeds & alert preferences
        </p>

        {!isCreating ? (
          <>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-8">
              {ordered.map((p) => {
                const isDefault = p.id === defaultProfileId;
                return (
                <div
                  key={p.id}
                  onClick={() => onSelectProfile(p.id)}
                  className={`relative glass-panel p-6 rounded-xl text-center cursor-pointer border transition-all flex flex-col items-center gap-2 ${isDefault ? "border-sky-400/60 shadow-[0_0_20px_rgba(56,189,248,0.25)]" : "border-white/5 hover:border-sky-400 hover:shadow-[0_0_20px_rgba(56,189,248,0.25)]"}`}
                >
                  {isDefault && (
                    <span className="absolute top-2 right-2 text-[9px] font-bold bg-sky-500/20 border border-sky-400/40 text-sky-300 px-1.5 py-0.5 rounded-full">★ DEFAULT</span>
                  )}
                  <div className="text-5xl mb-2 filter drop-shadow-md select-none">{p.avatar}</div>
                  <div className="font-semibold text-lg text-white truncate max-w-full">{p.name}</div>
                  <div className="text-xs text-sky-400 font-medium tracking-wider uppercase">
                    {p.role}
                  </div>
                </div>
                );
              })}
            </div>

            <div className="text-center relative my-6 flex items-center justify-center">
              <div className="absolute left-0 right-0 h-[1px] bg-white/10"></div>
              <span className="bg-[#0f172a] px-4 relative z-10 text-gray-500 font-medium text-sm">
                or
              </span>
            </div>

            <button
              onClick={() => setIsCreating(true)}
              className="w-full py-3 px-4 glass-panel border border-dashed border-white/20 rounded-xl hover:border-sky-400 hover:bg-white/5 transition-all text-gray-300 font-semibold flex items-center justify-center gap-2"
            >
              ➕ Create New User Profile
            </button>
          </>
        ) : (
          <form onSubmit={handleCreate} className="space-y-5 animate-fadeIn">
            <h3 className="text-xl font-bold text-white mb-2">Create Security Profile</h3>
            
            <div className="space-y-1">
              <label className="block text-sm font-medium text-gray-300">Profile Name / Role</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-white focus:border-sky-400 focus:ring-1 focus:ring-sky-400 focus:outline-none placeholder-gray-600 transition"
                placeholder="e.g. SOC Manager, Security Analyst"
                required
              />
            </div>
            
            <div className="space-y-1">
              <label className="block text-sm font-medium text-gray-300">Destination Email (Alerts)</label>
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="w-full bg-black/30 border border-white/10 rounded-lg p-3 text-white focus:border-sky-400 focus:ring-1 focus:ring-sky-400 focus:outline-none placeholder-gray-600 transition"
                placeholder="e.g. analyst@vnotice.com"
              />
            </div>
            
            <div className="space-y-3">
              <label className="block text-sm font-medium text-gray-300">Select Profile Avatar</label>
              <div className="flex justify-between p-2 bg-black/20 rounded-lg border border-white/5">
                {avatars.map((a) => (
                  <button
                    key={a}
                    type="button"
                    onClick={() => setNewAvatar(a)}
                    className={`text-3xl p-2 rounded-xl border-2 transition-all ${
                      newAvatar === a
                        ? "border-sky-400 bg-sky-500/10 scale-110"
                        : "border-transparent hover:bg-white/5 hover:scale-105"
                    }`}
                  >
                    {a}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-4 pt-4 border-t border-white/5">
              <button
                type="button"
                onClick={() => setIsCreating(false)}
                className="flex-1 py-2.5 glass-panel rounded-lg text-gray-400 hover:text-white hover:bg-white/5 transition-all font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 py-2.5 bg-sky-500 hover:bg-sky-600 text-white rounded-lg transition-all font-semibold shadow-lg shadow-sky-500/20"
              >
                Create & Enter
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
