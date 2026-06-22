"use client";
import React, { useState, useEffect } from "react";
import { X, Save } from "lucide-react";

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

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  profile: UserProfile;
  onSave: (updates: Partial<UserProfile>) => void;
}

export default function SettingsModal({
  isOpen,
  onClose,
  profile,
  onSave,
}: SettingsModalProps) {
  const [localPrefs, setLocalPrefs] = useState(profile?.preferences);
  const [localCreds, setLocalCreds] = useState(profile?.credentials);

  // Sync internal state when profile or modal opens
  useEffect(() => {
    if (profile) {
      setLocalPrefs(profile.preferences);
      setLocalCreds(profile.credentials || {});
    }
  }, [profile, isOpen]);

  if (!isOpen || !profile || !localPrefs || !localCreds) return null;

  const handleSave = () => {
    onSave({
      preferences: localPrefs,
      credentials: localCreds,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-2xl max-h-[90vh] flex flex-col rounded-2xl overflow-hidden shadow-2xl border border-white/10 animate-scaleUp">
        {/* Header */}
        <div className="flex justify-between items-center p-4.5 border-b border-white/10 bg-black/25 flex-shrink-0">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            ⚙️ Preferences & Settings
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition p-1 hover:bg-white/5 rounded-lg"
          >
            <X size={22} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Section: Appearance */}
          <section className="space-y-4">
            <h3 className="text-base font-bold border-b border-white/5 pb-2 text-sky-400 uppercase tracking-wider">
              Appearance Configuration
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Theme Palette
                </label>
                <select
                  value={localPrefs.theme}
                  onChange={(e) =>
                    setLocalPrefs({ ...localPrefs, theme: e.target.value as any })
                  }
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                >
                  <option value="dark">Dark / Glassmorphism</option>
                  <option value="light">Light Mode</option>
                </select>
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Global Text Size
                </label>
                <select
                  value={localPrefs.textSize}
                  onChange={(e) =>
                    setLocalPrefs({ ...localPrefs, textSize: e.target.value as any })
                  }
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                >
                  <option value="sm">Small</option>
                  <option value="md">Medium (Default)</option>
                  <option value="lg">Large</option>
                </select>
              </div>
            </div>
          </section>

          {/* Section: Alert Preferences */}
          <section className="space-y-4">
            <h3 className="text-base font-bold border-b border-white/5 pb-2 text-sky-400 uppercase tracking-wider">
              Alert Notifications
            </h3>
            <div className="space-y-3.5">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Minimum Vulnerability Severity Threshold
                </label>
                <select
                  value={localPrefs.vulnerabilityMinSeverity}
                  onChange={(e) =>
                    setLocalPrefs({ ...localPrefs, vulnerabilityMinSeverity: e.target.value as any })
                  }
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                >
                  <option value="low">Low & Higher</option>
                  <option value="medium">Medium & Higher</option>
                  <option value="high">High & Higher</option>
                  <option value="critical">Critical Only</option>
                </select>
              </div>

              {/* Toggles */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                <label className="flex items-center gap-3 cursor-pointer p-3 border border-white/5 rounded-xl bg-black/15 hover:bg-black/25 transition">
                  <input
                    type="checkbox"
                    checked={localPrefs.desktopAlertsEnabled}
                    onChange={(e) =>
                      setLocalPrefs({ ...localPrefs, desktopAlertsEnabled: e.target.checked })
                    }
                    className="w-4 h-4 rounded border-gray-300 text-sky-500 focus:ring-sky-500 accent-sky-500"
                  />
                  <div className="flex flex-col">
                    <span className="text-sm font-semibold text-white">Enable OS Push Alerts</span>
                    <span className="text-[10px] text-gray-500">Show notification popups on desktop</span>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer p-3 border border-white/5 rounded-xl bg-black/15 hover:bg-black/25 transition">
                  <input
                    type="checkbox"
                    checked={localPrefs.emailAlertsEnabled}
                    onChange={(e) =>
                      setLocalPrefs({ ...localPrefs, emailAlertsEnabled: e.target.checked })
                    }
                    className="w-4 h-4 rounded border-gray-300 text-sky-500 focus:ring-sky-500 accent-sky-500"
                  />
                  <div className="flex flex-col">
                    <span className="text-sm font-semibold text-white">Enable Email Alerts</span>
                    <span className="text-[10px] text-gray-500">Send alerts to this account&apos;s email</span>
                  </div>
                </label>
              </div>

            </div>
          </section>

          {/* Section: SMTP Credentials */}
          <section className="space-y-4">
            <h3 className="text-base font-bold border-b border-white/5 pb-2 text-sky-400 uppercase tracking-wider">
              Email Server Credentials (SMTP)
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  SMTP Host Address
                </label>
                <input
                  type="text"
                  value={localCreds.smtpHost || ""}
                  onChange={(e) =>
                    setLocalCreds({ ...localCreds, smtpHost: e.target.value })
                  }
                  placeholder="smtp.gmail.com"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  SMTP Port
                </label>
                <input
                  type="text"
                  value={localCreds.smtpPort || ""}
                  onChange={(e) =>
                    setLocalCreds({ ...localCreds, smtpPort: e.target.value })
                  }
                  placeholder="587"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  SMTP Username
                </label>
                <input
                  type="text"
                  value={localCreds.smtpUser || ""}
                  onChange={(e) =>
                    setLocalCreds({ ...localCreds, smtpUser: e.target.value })
                  }
                  placeholder="alerts@company.com"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  SMTP Password / App Secret
                </label>
                <input
                  type="password"
                  value={localCreds.smtpPass || ""}
                  onChange={(e) =>
                    setLocalCreds({ ...localCreds, smtpPass: e.target.value })
                  }
                  placeholder="••••••••"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-black/25 flex justify-end gap-3 flex-shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 glass-panel border border-white/10 hover:bg-white/5 rounded-lg text-gray-300 font-semibold text-sm transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-5 py-2 bg-sky-500 hover:bg-sky-600 text-white rounded-lg font-semibold text-sm transition flex items-center gap-1.5 shadow-lg shadow-sky-500/10"
          >
            <Save className="w-4 h-4" /> Save Preferences
          </button>
        </div>
      </div>
    </div>
  );
}
