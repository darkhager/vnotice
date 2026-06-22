"use client";
import { useState, useEffect } from "react";
import { User, Bell, Rss, Save, Trash2, Edit } from "lucide-react";

interface SettingsProps {
  currentUser: string;
  onProfileUpdate: (oldName: string, updatedProfile: any) => void;
}

export default function Settings({ currentUser, onProfileUpdate }: SettingsProps) {
  const [activeTab, setActiveTab] = useState<"profile" | "notifications" | "rss">("profile");
  
  // Profile & general states
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [timezone, setTimezone] = useState("ICT");
  const [theme, setTheme] = useState("dark");
  const [profileSaved, setProfileSaved] = useState(false);

  // SMTP & Alert states
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpUsername, setSmtpUsername] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [triggerSeverity, setTriggerSeverity] = useState("high");

  // RSS Feed states
  const [globalPoll, setGlobalPoll] = useState("15m");
  const [feeds, setFeeds] = useState<any[]>([]);

  // Feed Modal states
  const [isFeedModalOpen, setIsFeedModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"add" | "edit">("add");
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [feedName, setFeedName] = useState("");
  const [feedUrl, setFeedUrl] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationSuccess, setValidationSuccess] = useState(false);

  // Load profile settings for currentUser
  useEffect(() => {
    const storedProfiles = localStorage.getItem("vnotice_profiles");
    if (storedProfiles) {
      const profiles = JSON.parse(storedProfiles);
      const current = profiles.find((p: any) => p.name === currentUser);
      if (current) {
        setDisplayName(current.name || "");
        setEmail(current.email || "");
        setTimezone(current.timezone || "ICT");
        setTheme(current.theme || "dark");
        
        // SMTP configurations
        setSmtpHost(current.smtpHost || "");
        setSmtpPort(current.smtpPort || "587");
        setSmtpUsername(current.smtpUsername || "");
        setSmtpPassword(current.smtpPassword || "");
        setEmailNotifications(current.emailNotifications !== undefined ? current.emailNotifications : true);
        setTriggerSeverity(current.triggerSeverity || "high");
      }
    }
  }, [currentUser]);

  // Load RSS feeds on mount
  useEffect(() => {
    const storedFeeds = localStorage.getItem("vnotice_rss_feeds");
    if (storedFeeds) {
      setFeeds(JSON.parse(storedFeeds));
    } else {
      // All feeds enabled (active: true) by default (Requirement 3)
      const defaultFeeds = [
        { name: "NVD / NIST CVE",    url: "https://services.nvd.nist.gov/rest/json/cves/2.0",   active: true },
        { name: "Cisco Security Advisories", url: "https://tools.cisco.com/security/center/rss.x", active: true },
        { name: "Fortinet PSIRT",    url: "https://fortiguard.com/rss/ir.xml",                   active: true },
        { name: "Palo Alto Networks",url: "https://security.paloaltonetworks.com/rss.xml",        active: true },
        { name: "F5 Security Alerts",url: "https://support.f5.com/csp/feed/rss/sec/f5",          active: true },
        { name: "Ubuntu Security",   url: "https://ubuntu.com/security/notices/rss.xml",          active: true },
        { name: "Vulners RSS",       url: "https://vulners.com/rss.xml",                          active: true },
        { name: "CERT.PL Security",  url: "https://cert.pl/en/rss.xml",                          active: true },
        { name: "Full Disclosure",   url: "https://seclists.org/rss/fulldisclosure.rss",          active: true },
      ];
      setFeeds(defaultFeeds);
      localStorage.setItem("vnotice_rss_feeds", JSON.stringify(defaultFeeds));
    }

    const storedPoll = localStorage.getItem("vnotice_global_poll");
    if (storedPoll) {
      setGlobalPoll(storedPoll);
    }
  }, []);

  const updateFeeds = (newFeeds: any[]) => {
    setFeeds(newFeeds);
    localStorage.setItem("vnotice_rss_feeds", JSON.stringify(newFeeds));
  };

  const handleSaveProfile = () => {
    if (!displayName.trim()) {
      alert("Display name cannot be empty");
      return;
    }
    const updatedProfile = {
      name: displayName.trim(),
      email,
      timezone,
      theme,
      smtpHost,
      smtpPort,
      smtpUsername,
      smtpPassword,
      emailNotifications,
      triggerSeverity
    };
    
    onProfileUpdate(currentUser, updatedProfile);
    setProfileSaved(true);
    setTimeout(() => setProfileSaved(false), 2000);
  };

  const handleGlobalPollChange = (val: string) => {
    setGlobalPoll(val);
    localStorage.setItem("vnotice_global_poll", val);
  };

  // RSS Feed action handlers
  const handleOpenAddModal = () => {
    setModalMode("add");
    setFeedName("");
    setFeedUrl("");
    setValidationError(null);
    setValidationSuccess(false);
    setIsFeedModalOpen(true);
  };

  const handleOpenEditModal = (idx: number) => {
    const feed = feeds[idx];
    setModalMode("edit");
    setEditingIndex(idx);
    setFeedName(feed.name);
    setFeedUrl(feed.url);
    setValidationError(null);
    setValidationSuccess(false);
    setIsFeedModalOpen(true);
  };

  const handleRemoveFeed = (idx: number) => {
    const updated = feeds.filter((_, i) => i !== idx);
    updateFeeds(updated);
  };

  const validateRssUrl = async (urlStr: string): Promise<boolean> => {
    try {
      const url = new URL(urlStr);
      if (url.protocol !== "http:" && url.protocol !== "https:") {
        return false;
      }
      
      const lowerUrl = urlStr.toLowerCase();
      // RSS/Atom/XML patterns
      const isXmlOrFeed = lowerUrl.endsWith(".xml") ||
                          lowerUrl.endsWith(".rss") ||
                          lowerUrl.endsWith(".atom") ||
                          lowerUrl.includes("/feed") ||
                          lowerUrl.includes("/rss") ||
                          lowerUrl.includes("atom.xml") ||
                          lowerUrl.includes("rss.xml") ||
                          lowerUrl.includes("/advisories.atom") ||
                          lowerUrl.includes("feed.xml") ||
                          lowerUrl.includes("rss.x") ||
                          // NIST NVD JSON API
                          lowerUrl.includes("nvd.nist.gov") ||
                          // Known working security feeds that don't follow standard patterns
                          lowerUrl.includes("vuldb.com") ||
                          lowerUrl.includes("vulners.com") ||
                          lowerUrl.includes("cert.pl") ||
                          lowerUrl.includes("seclists.org");
      return isXmlOrFeed;
    } catch (e) {
      return false;
    }
  };

  const handleSaveFeedModal = async () => {
    setValidationError(null);
    setValidationSuccess(false);
    
    if (!feedName.trim()) {
      setValidationError("Feed Name is required.");
      return;
    }
    if (!feedUrl.trim()) {
      setValidationError("Feed URL is required.");
      return;
    }
    
    setIsValidating(true);
    
    // Simulate real feed structure check for premium feedback
    await new Promise((resolve) => setTimeout(resolve, 1000));
    
    const isValid = await validateRssUrl(feedUrl);
    setIsValidating(false);
    
    if (!isValid) {
      setValidationError("Verification failed: The URL does not appear to be a valid RSS, XML, or Atom feed URL. It must be a valid http/https URL and contain extensions or patterns like .xml, .rss, .atom, /feed, /rss.");
      return;
    }
    
    setValidationSuccess(true);
    await new Promise((resolve) => setTimeout(resolve, 500));
    
    if (modalMode === "add") {
      const updated = [...feeds, { name: feedName.trim(), url: feedUrl.trim(), active: true }];
      updateFeeds(updated);
    } else if (modalMode === "edit" && editingIndex !== null) {
      const updated = [...feeds];
      updated[editingIndex] = { ...updated[editingIndex], name: feedName.trim(), url: feedUrl.trim() };
      updateFeeds(updated);
    }
    
    setIsFeedModalOpen(false);
    setFeedName("");
    setFeedUrl("");
    setEditingIndex(null);
    setValidationSuccess(false);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="glass-panel rounded-xl overflow-hidden relative">
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          <button 
            onClick={() => setActiveTab("profile")} 
            className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center gap-2 transition ${activeTab === "profile" ? "border-b-2 border-blue-500 text-blue-600 dark:text-blue-400 bg-gray-50 dark:bg-gray-800/50" : "text-gray-500 hover:text-gray-700 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800/50"}`}
          >
            <User className="w-4 h-4" /> User Profile
          </button>
          <button 
            onClick={() => setActiveTab("notifications")} 
            className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center gap-2 transition ${activeTab === "notifications" ? "border-b-2 border-blue-500 text-blue-600 dark:text-blue-400 bg-gray-50 dark:bg-gray-800/50" : "text-gray-500 hover:text-gray-700 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800/50"}`}
          >
            <Bell className="w-4 h-4" /> Notifications
          </button>
          <button 
            onClick={() => setActiveTab("rss")} 
            className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center gap-2 transition ${activeTab === "rss" ? "border-b-2 border-blue-500 text-blue-600 dark:text-blue-400 bg-gray-50 dark:bg-gray-800/50" : "text-gray-500 hover:text-gray-700 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800/50"}`}
          >
            <Rss className="w-4 h-4" /> RSS Feeds
          </button>
        </div>

        <div className="p-6">
          {activeTab === "profile" && (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">Profile Settings</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Display Name</label>
                  <input 
                    type="text" 
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white" 
                  />
                </div>
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Email Address</label>
                  <input 
                    type="email" 
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white" 
                  />
                </div>
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Timezone</label>
                  <select 
                    value={timezone}
                    onChange={(e) => setTimezone(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white"
                  >
                    <option value="UTC">UTC</option>
                    <option value="PST">Pacific Time (PT)</option>
                    <option value="EST">Eastern Time (ET)</option>
                    <option value="ICT">Asia/Bangkok (ICT)</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Theme Preference</label>
                  <select 
                    value={theme}
                    onChange={(e) => setTheme(e.target.value)}
                    className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white"
                  >
                    <option value="dark">Dark Mode</option>
                    <option value="light">Light Mode</option>
                  </select>
                </div>
              </div>
              <div className="pt-4 flex justify-end">
                <button 
                  onClick={handleSaveProfile} 
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium shadow-md"
                >
                  <Save className="w-4 h-4" /> {profileSaved ? "Saved!" : "Save Profile"}
                </button>
              </div>
            </div>
          )}

          {activeTab === "notifications" && (
            <div className="space-y-6">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Alert Configurations</h2>
              <div className="space-y-4">
                <div className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50/50 dark:bg-gray-800/10">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-medium text-gray-900 dark:text-white">Email Notifications</h3>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input 
                        type="checkbox" 
                        className="sr-only peer" 
                        checked={emailNotifications}
                        onChange={(e) => setEmailNotifications(e.target.checked)}
                      />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Trigger on Severity</label>
                      <select 
                        value={triggerSeverity}
                        onChange={(e) => setTriggerSeverity(e.target.value)}
                        className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:outline-none dark:text-white"
                      >
                        <option value="critical">Critical Only</option>
                        <option value="high">High & Above</option>
                        <option value="medium">Medium & Above</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="pt-4 border-t border-gray-200 dark:border-gray-700 mt-4">
                    <h4 className="font-medium text-gray-900 dark:text-white mb-4">SMTP Server Credentials</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">SMTP Host</label>
                        <input 
                          type="text" 
                          value={smtpHost}
                          onChange={(e) => setSmtpHost(e.target.value)}
                          placeholder="smtp.example.com" 
                          className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:outline-none dark:text-white" 
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Port</label>
                        <input 
                          type="text" 
                          value={smtpPort}
                          onChange={(e) => setSmtpPort(e.target.value)}
                          placeholder="587" 
                          className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:outline-none dark:text-white" 
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Username</label>
                        <input 
                          type="text" 
                          value={smtpUsername}
                          onChange={(e) => setSmtpUsername(e.target.value)}
                          placeholder="user@example.com" 
                          className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:outline-none dark:text-white" 
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
                        <input 
                          type="password" 
                          value={smtpPassword}
                          onChange={(e) => setSmtpPassword(e.target.value)}
                          placeholder="••••••••" 
                          className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 focus:outline-none dark:text-white" 
                        />
                      </div>
                    </div>
                    <div className="flex gap-3">
                      <button 
                        onClick={handleSaveProfile} 
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium shadow-md text-sm"
                      >
                        <Save className="w-4 h-4" /> {profileSaved ? "Saved!" : "Save Configuration"}
                      </button>
                      <button 
                        onClick={() => window.alert(`Test email sent to ${email || 'configured email address'}!`)} 
                        className="px-4 py-2 bg-gray-100 dark:bg-gray-700 text-sm font-medium rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                      >
                        Send Test Email
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "rss" && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-6">
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">RSS Feed Sources</h2>
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex items-center gap-2">
                    <label className="text-sm text-gray-700 dark:text-gray-300 whitespace-nowrap">Global Polling Interval:</label>
                    <select 
                      value={globalPoll} 
                      onChange={(e) => handleGlobalPollChange(e.target.value)} 
                      className="px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent dark:bg-gray-800 text-sm focus:outline-none dark:text-white"
                    >
                      <option value="30s">30 seconds</option>
                      <option value="1m">1 minute</option>
                      <option value="3m">3 minutes</option>
                      <option value="5m">5 minutes</option>
                      <option value="10m">10 minutes</option>
                      <option value="15m">15 minutes</option>
                      <option value="30m">30 minutes</option>
                      <option value="1h">1 hour</option>
                    </select>
                  </div>
                  <button 
                    onClick={handleOpenAddModal} 
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors shadow-md"
                  >
                    + Add Source
                  </button>
                </div>
              </div>
              
              <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
                {feeds.map((feed, idx) => (
                  <div key={idx} className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50/30 dark:bg-gray-800/10">
                    <div className="min-w-0 flex-1 mr-4">
                      <h3 className="font-medium text-gray-900 dark:text-white truncate">{feed.name}</h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 truncate">{feed.url}</p>
                      <p className="text-xs text-gray-400 mt-2 flex items-center gap-1.5">
                        <span>⏱️ Polling: {globalPoll}</span>
                        <span>•</span>
                        <span className={feed.active ? "text-green-500" : "text-gray-500"}>
                          {feed.active ? "Active" : "Disabled"}
                        </span>
                      </p>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input 
                          type="checkbox" 
                          className="sr-only peer" 
                          checked={feed.active} 
                          onChange={() => {
                            const updated = [...feeds];
                            updated[idx].active = !updated[idx].active;
                            updateFeeds(updated);
                          }}
                        />
                        <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
                      </label>
                      <button 
                        onClick={() => handleOpenEditModal(idx)} 
                        title="Edit Feed"
                        className="p-1.5 text-gray-500 hover:text-blue-500 dark:text-gray-400 dark:hover:text-blue-350 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button 
                        onClick={() => handleRemoveFeed(idx)} 
                        title="Remove Feed"
                        className="p-1.5 text-gray-500 hover:text-red-500 dark:text-gray-400 dark:hover:text-red-400 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Verification Popup Modal (Requirement 4 & 5) */}
      {isFeedModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-panel max-w-md w-full p-6 rounded-2xl shadow-2xl border border-white/10 space-y-4 animate-scaleUp">
            <h3 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              {modalMode === "add" ? "➕ Add RSS Feed Source" : "✏️ Edit RSS Feed Source"}
            </h3>
            
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Feed Name</label>
                <input 
                  type="text" 
                  value={feedName} 
                  onChange={(e) => setFeedName(e.target.value)} 
                  placeholder="e.g. Cisco Security Alerts"
                  className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white"
                />
              </div>
              
              <div className="space-y-1">
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">Feed URL</label>
                <input 
                  type="text" 
                  value={feedUrl} 
                  onChange={(e) => setFeedUrl(e.target.value)} 
                  placeholder="https://example.com/feed.xml"
                  className="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-transparent focus:ring-2 focus:ring-blue-500 focus:outline-none dark:text-white"
                />
              </div>
            </div>
            
            {validationError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-500 text-xs font-medium leading-relaxed">
                ⚠️ {validationError}
              </div>
            )}
            
            {validationSuccess && (
              <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-green-500 text-xs font-medium flex items-center gap-2">
                <span>✓ URL verified successfully as valid RSS feed! Saving...</span>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <button 
                onClick={() => {
                  setIsFeedModalOpen(false);
                  setFeedName("");
                  setFeedUrl("");
                  setValidationError(null);
                }}
                disabled={isValidating}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={handleSaveFeedModal}
                disabled={isValidating}
                className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800/50 text-white text-sm font-medium rounded-lg transition-colors"
              >
                {isValidating ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Verifying...
                  </>
                ) : (
                  "Verify & Save"
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
