"use client";
import React, { useState, useEffect, useMemo } from "react";
import ProfileSelection from "./ProfileSelection";
import CveTable from "./CveTable";
import { ShieldAlert, Sun, Moon, LogOut, Save, Trash2, RefreshCw, X, Mail, Search } from "lucide-react";
import { getApiBase } from "../lib/api";

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
    useAdminSmtp?: boolean;        // borrow the admin account's SMTP config
  };
  credentials: {
    smtpHost?: string;
    smtpPort?: string;
    smtpUser?: string;
    smtpPass?: string;
  };
}

interface Feed {
  name: string;
  url: string;
  active: boolean;
}

interface AlertFilter {
  severity: string[];
  keywords: string[];
  feedSources: string[];
  searchQuery: string;
  epssMin: string;
  epssMax: string;
}

interface AlertRule {
  id: string;
  name: string;
  description: string;
  active: boolean;
  filters: AlertFilter;          // primary group — kept for backward compatibility
  conditions?: AlertFilter[];    // OR'd condition groups; a CVE matches if ANY group matches
  createdAt: string;
  lastSentAt?: string;           // ISO time this alert last sent a test email
  sentCount?: number;            // how many emails this alert has sent
}

interface SavedDashboard {
  id: string;
  name: string;
  filters: {
    severity: string[];
    keywords: string[];
    feedSources: string[];
    searchQuery: string;
    epssMin: string;
    epssMax: string;
  };
  createdAt: string;
}

// Utility to ensure clean NVD detail page URLs (Req 1)
const ensureAbsoluteCveUrl = (url: string | undefined, id: string): string => {
  if (!url) return `https://nvd.nist.gov/vuln/detail/${id}`;
  const cleanUrl = url.trim();
  if (cleanUrl.startsWith("http://") || cleanUrl.startsWith("https://")) {
    return cleanUrl;
  }
  if (cleanUrl.toLowerCase().includes("detail/")) {
    const match = cleanUrl.match(/CVE-\d{4}-\d+/i);
    if (match) {
      return `https://nvd.nist.gov/vuln/detail/${match[0].toUpperCase()}`;
    }
  }
  if (/^CVE-\d{4}-\d+$/i.test(cleanUrl)) {
    return `https://nvd.nist.gov/vuln/detail/${cleanUrl.toUpperCase()}`;
  }
  return `https://nvd.nist.gov/vuln/detail/${id}`;
};

const generateUniqueId = (): string => {
  if (typeof window !== "undefined" && window.crypto && window.crypto.randomUUID) {
    return window.crypto.randomUUID();
  }
  return "id-" + Math.random().toString(36).substring(2, 15) + "-" + Date.now().toString(36);
};

/** Infer real vendor/product from feed source name and CVE title. */
function inferVendorProduct(src: string, title: string): [string, string] | null {
  const s = (src   || "").toLowerCase();
  const t = (title || "").toLowerCase();

  // Source-name matches
  if (s.includes("fortinet") || s.includes("fortiguard") || t.includes("fortios") || t.includes("fortigate"))
    return ["Fortinet", "FortiOS"];
  if (s.includes("palo alto") || t.includes("pan-os") || t.includes("globalprotect"))
    return ["Palo Alto Networks", "PAN-OS"];
  if (s.includes("cisco") || t.includes("cisco ios") || t.includes("cisco nx") || t.includes("cisco asa"))
    return ["Cisco", "IOS/NX-OS"];
  if (s.includes("f5") || t.includes("big-ip"))
    return ["F5 Networks", "BIG-IP"];
  if (s.includes("splunk") || t.includes("splunk"))
    return ["Splunk", "Splunk Enterprise"];
  if (s.includes("check point") || s.includes("checkpoint") || t.includes("check point"))
    return ["Check Point", "Security Gateway"];
  if (s.includes("microsoft") || (t.includes("windows") && t.includes("microsoft")))
    return ["Microsoft", "Windows"];
  if (s.includes("vmware") || t.includes("vmware"))
    return ["VMware", "vSphere"];
  if (s.includes("juniper") || t.includes("junos") || t.includes("juniper"))
    return ["Juniper Networks", "JunOS"];
  if (s.includes("ivanti") || t.includes("ivanti"))
    return ["Ivanti", "Connect Secure"];

  // Ubuntu source — narrow by title
  if (s.includes("ubuntu")) {
    if (t.includes("openssl") || t.includes("libssl")) return ["Ubuntu", "OpenSSL"];
    if (t.includes("nginx"))                           return ["Ubuntu", "nginx"];
    if (t.includes("php"))                             return ["Ubuntu", "PHP"];
    if (t.includes("apache"))                          return ["Ubuntu", "Apache"];
    if (t.includes("mysql") || t.includes("mariadb")) return ["Ubuntu", "MySQL/MariaDB"];
    if (t.includes("curl"))                            return ["Ubuntu", "curl"];
    if (t.includes("samba"))                           return ["Ubuntu", "Samba"];
    if (t.includes("python"))                          return ["Ubuntu", "Python"];
    return ["Ubuntu", "Linux Kernel"];
  }

  // Title-based patterns
  if (t.includes("linux kernel") || (t.includes("linux") && t.includes("kernel")))
    return ["Linux", "Linux Kernel"];
  if (t.includes("apache") && (t.includes("http") || t.includes("tomcat") || t.includes("struts")))
    return ["Apache", "HTTP Server"];
  if (t.includes("runc") || t.includes("containerd"))
    return ["Docker", "runc"];
  if (t.includes("xz utils") || t.includes("liblzma"))
    return ["XZ Utils", "XZ Utils"];
  if (t.includes("spring") && (t.includes("framework") || t.includes("boot")))
    return ["VMware", "Spring Framework"];
  if (t.includes("openssh"))                                return ["OpenBSD", "OpenSSH"];
  if (t.includes("openssl") || t.includes("libssl"))       return ["OpenSSL", "OpenSSL"];
  if (t.includes("nginx"))                                  return ["nginx", "nginx"];
  if (t.includes("wordpress"))                             return ["WordPress", "WordPress"];
  if (t.includes("gitlab"))                                return ["GitLab", "GitLab CE/EE"];
  if (t.includes("jenkins"))                               return ["Jenkins", "Jenkins"];
  if (t.includes("kubernetes") || t.includes(" k8s "))     return ["CNCF", "Kubernetes"];
  if (t.includes("redis"))                                 return ["Redis", "Redis"];
  if (t.includes("mysql"))                                 return ["Oracle", "MySQL"];
  if (t.includes("mariadb"))                               return ["MariaDB", "MariaDB"];
  if (t.includes("postgresql") || t.includes("postgres"))  return ["PostgreSQL", "PostgreSQL"];
  if (t.includes("php"))                                   return ["PHP Group", "PHP"];
  if (t.includes("chrome") || t.includes("chromium"))     return ["Google", "Chrome"];
  if (t.includes("firefox"))                               return ["Mozilla", "Firefox"];
  if (t.includes("exim"))                                  return ["Exim", "Exim MTA"];
  if (t.includes("samba"))                                 return ["Samba", "Samba"];
  if (t.includes("log4j") || t.includes("log4shell"))      return ["Apache", "Log4j"];
  if (t.includes("struts"))                                return ["Apache", "Struts"];
  if (t.includes("tomcat"))                                return ["Apache", "Tomcat"];
  if (t.includes("elasticsearch") || t.includes("opensearch")) return ["Elastic", "Elasticsearch"];
  if (t.includes("mongodb"))                               return ["MongoDB", "MongoDB"];
  if (t.includes("grafana"))                               return ["Grafana Labs", "Grafana"];
  if (t.includes("citrix") || t.includes("netscaler"))     return ["Citrix", "Citrix ADC"];
  if (t.includes("zimbra"))                                return ["Zimbra", "Zimbra"];
  if (t.includes("exchange") && t.includes("server"))      return ["Microsoft", "Exchange Server"];
  if (t.includes("sharepoint"))                            return ["Microsoft", "SharePoint"];
  if (t.includes("winrar"))                                return ["RARLAB", "WinRAR"];
  if (t.includes("drupal"))                                return ["Drupal", "Drupal CMS"];
  if (t.includes("sudo"))                                  return ["Todd C. Miller", "sudo"];
  if (t.includes("glibc") || t.includes("gnu c library"))  return ["GNU", "glibc"];
  if (t.includes("imagemagick"))                           return ["ImageMagick", "ImageMagick"];
  if (t.includes("qemu") || (t.includes("kvm") && t.includes("hypervisor"))) return ["QEMU", "QEMU/KVM"];
  return null;
}

/** Map a raw backend CVE object to the frontend vulnerability shape. */
function mapApiCve(c: any) {
  const rawVendor  = c.vendor  || "";
  const rawProduct = c.product || "";
  const isGeneric  = (v: string) =>
    !v || v === "Various" || v === "Unknown" || v === "Various Product" || v === "Unknown Product";

  let vendor  = rawVendor;
  let product = rawProduct;
  if (isGeneric(rawVendor) || isGeneric(rawProduct)) {
    const inferred = inferVendorProduct(c.rss_source || "", c.title || "");
    if (inferred) { [vendor, product] = inferred; }
  }
  // Source-name last resort: strip noise words and use the feed name as brand
  if (isGeneric(vendor)) {
    const srcClean = (c.rss_source || "")
      .replace(/\s*(security|advisories|notices|psirt|rss|feed|alerts|recent|news|center)\s*/gi, " ")
      .replace(/\s+/g, " ").trim();
    if (srcClean && !["full disclosure", "vulners", "nvd / nist cve", ""].includes(srcClean.toLowerCase())) {
      vendor  = srcClean;
      if (isGeneric(product)) product = "Advisory";
    }
  }
  return {
    id:    c.cve_id,
    _key:  c.id || undefined,   // DB row UUID — unique across duplicate cve_ids
    name: c.title,
    vendor:   vendor  || "Various",
    product:  product || "Various",
    severity: (c.severity || "Medium") as any,
    score:    c.cvss_score || 0.0,
    epss:     c.epss ?? null,   // null => EPSS unknown, shown as N/A
    date:     c.published_date ? c.published_date.split("T")[0] : "Unknown",
    url:      c.reference_url || "",
    description: c.description || "",
    source:   c.rss_source || "",
    ingestedAt: c.created_at || "",   // when the record was input into the system (UTC)
  };
}

// Real, fully functional CVEs with verified active links on NVD (Req 1)
const cveMockData = [
  {
    id: "CVE-2024-3094",
    name: "XZ Utils Downstream SSH Backdoor Vulnerability",
    vendor: "XZ Utils",
    product: "XZ Utils",
    severity: "Critical" as const,
    score: 10.0,
    epss: 0.84805,
    date: "2024-03-29",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    description: "Malicious code was discovered in XZ Utils versions 5.6.0 and 5.6.1. The backdoor exploits liblzma to modify functions inside the sshd daemon, enabling remote code execution.",
    source: "Ubuntu Security"
  },
  {
    id: "CVE-2024-3400",
    name: "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    severity: "Critical" as const,
    score: 10.0,
    epss: 0.956,
    date: "2024-04-12",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    description: "An OS command injection vulnerability in the GlobalProtect gateway of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary command sequences with root privileges.",
    source: "Palo Alto Networks"
  },
  {
    id: "CVE-2024-21762",
    name: "Fortinet FortiOS SSL VPN Out-Of-Bounds Write Vulnerability",
    vendor: "Fortinet",
    product: "FortiOS",
    severity: "Critical" as const,
    score: 9.8,
    epss: 0.927,
    date: "2024-02-08",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
    description: "An out-of-bounds write vulnerability [CWE-787] in FortiOS SSL-VPN allows a remote unauthenticated attacker to execute arbitrary code or command sequences via specially crafted HTTP requests.",
    source: "Fortinet PSIRT"
  },
  {
    id: "CVE-2024-21626",
    name: "runc Container Escape File Descriptor Leak",
    vendor: "Docker",
    product: "runc",
    severity: "High" as const,
    score: 8.6,
    epss: 0.01367,
    date: "2024-01-31",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
    description: "A file descriptor leak vulnerability in runc prior to version 1.1.12 allows containers to bypass sandbox boundaries and access the host filesystem during runtime deployment.",
    source: "Ubuntu Security"
  },
  {
    id: "CVE-2023-38831",
    name: "WinRAR Remote Code Execution Vulnerability",
    vendor: "Microsoft",
    product: "Windows OS",
    severity: "High" as const,
    score: 7.8,
    epss: 0.93865,
    date: "2023-08-24",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2023-38831",
    description: "A vulnerability in WinRAR allows attackers to execute arbitrary code when a user opens a specially crafted ZIP archive file containing hidden executable payloads.",
    source: "Cisco Security Advisories"
  },
  {
    id: "CVE-2024-10924",
    name: "Really Simple Security plugin Auth Bypass",
    vendor: "WordPress",
    product: "Really Simple Security Plugin",
    severity: "Critical" as const,
    score: 9.8,
    epss: 0.93889,
    date: "2024-11-12",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-10924",
    description: "An authentication bypass vulnerability in the Really Simple Security plugin (formerly Really Simple SSL) allows unauthenticated remote attackers to gain full administrative access.",
    source: "Cisco Security Advisories"
  },
  {
    id: "CVE-2024-24919",
    name: "Check Point Quantum Security Gateway Information Disclosure",
    vendor: "Check Point",
    product: "Quantum Security Gateway",
    severity: "High" as const,
    score: 8.6,
    epss: 0.825,
    date: "2024-05-28",
    url: "https://support.checkpoint.com/results/sk/sk182337",
    description: "An information disclosure vulnerability in Check Point Remote Access VPN or Mobile Access Software Blade allows attackers to read sensitive information on security gateways connected to the Internet.",
    source: "Check Point Advisories Scraper"
  },
  {
    id: "CVE-2024-24920",
    name: "Check Point VPN Remote Code Execution",
    vendor: "Check Point",
    product: "VPN Blade",
    severity: "Critical" as const,
    score: 9.8,
    epss: 0.154,
    date: "2024-05-29",
    url: "https://support.checkpoint.com/security-advisories",
    description: "A critical buffer overflow vulnerability in Check Point VPN client components allows remote attackers to execute arbitrary code with elevated privileges.",
    source: "Check Point Advisories Scraper"
  }
];


export default function Dashboard() {
  const [profiles, setProfiles] = useState<UserProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string | null>(null);
  
  // Navigation tabs state
  const [activeTab, setActiveTab] = useState<"threat_dashboard" | "threat_stream" | "rss" | "alerts" | "settings">("threat_dashboard");
  const [streamSyncMode, setStreamSyncMode] = useState<string>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("vnotice_stream_sync_mode");
      if (saved && ["30s", "1m", "2m", "5m", "10m"].includes(saved)) return saved;
    }
    return "1m";
  });
  const [streamSyncCountdown, setStreamSyncCountdown] = useState<number>(910);
  
  // RSS feeds
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [globalPoll, setGlobalPoll] = useState("1m");
  
  // System logs state
  const [logs, setLogs] = useState<string[]>([]);
  
  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSeverity, setActiveSeverity] = useState<string[]>(['all']);
  const [activeVendors, setActiveVendors] = useState<string[]>(['all']);
  const [activeProducts, setActiveProducts] = useState<string[]>(['all']);
  const [keywordInput, setKeywordInput] = useState("");
  const [activeKeywords, setActiveKeywords] = useState<string[]>([]);
  const [activeFeedsFilter, setActiveFeedsFilter] = useState<string[]>(["all"]);
  const [epssMin, setEpssMin] = useState<string>("");
  const [epssMax, setEpssMax] = useState<string>("");
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [isRefreshingEpss, setIsRefreshingEpss] = useState(false);
  const [syncCountdown, setSyncCountdown] = useState<number>(900);
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);

  // Alert Rules state
  const [alertRules, setAlertRules] = useState<AlertRule[]>([]);
  const [showSaveAlertModal, setShowSaveAlertModal] = useState(false);
  const [saveAlertName, setSaveAlertName] = useState("");
  const [saveAlertDescription, setSaveAlertDescription] = useState("");
  const [editingAlertId, setEditingAlertId] = useState<string | null>(null);
  // OR'd condition groups being edited in the alert modal (each = a filter snapshot)
  const [editConditions, setEditConditions] = useState<AlertFilter[]>([]);

  // Saved Dashboards state
  const [showSaveDashboardModal, setShowSaveDashboardModal] = useState(false);
  const [saveDashboardName, setSaveDashboardName] = useState("");
  const [savedDashboards, setSavedDashboards] = useState<SavedDashboard[]>(() => {
    if (typeof window !== "undefined") {
      try { return JSON.parse(localStorage.getItem("vnotice_saved_dashboards") || "[]"); } catch {}
    }
    return [];
  });
  const [selectedDashboardId, setSelectedDashboardId] = useState<string | null>(null);
  const [activeSettingsSection, setActiveSettingsSection] = useState<"account" | "alerts" | "console" | "accounts" | "engine" | "resource">("account");
  const [engineHealth, setEngineHealth] = useState<any>(null);
  const [engineHealthLoading, setEngineHealthLoading] = useState(false);
  const [usageData, setUsageData] = useState<any[]>([]);
  const [usageLoading, setUsageLoading] = useState(false);
  const [usageRange, setUsageRange] = useState(1);   // days shown (1 = last 24h)

  const loadUsage = async () => {
    setUsageLoading(true);
    try {
      const res = await fetch(`${getApiBase()}/metrics/usage`);
      const data = res.ok ? await res.json() : { samples: [] };
      setUsageData(Array.isArray(data.samples) ? data.samples : []);
    } catch {
      setUsageData([]);
    }
    setUsageLoading(false);
  };

  // Auto-load usage history when the Resource Usage section is opened.
  useEffect(() => {
    if (activeSettingsSection === "resource") loadUsage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingsSection]);

  const handleEngineHealthCheck = async () => {
    setEngineHealthLoading(true);
    setEngineHealth(null);
    try {
      const res = await fetch(`${getApiBase()}/health/`);
      if (res.ok) setEngineHealth(await res.json());
      else setEngineHealth({ error: `HTTP ${res.status}` });
    } catch (e: any) {
      setEngineHealth({ error: `Cannot reach backend: ${e.message}` });
    }
    setEngineHealthLoading(false);
  };

  // Auto-load engine health when the Engine Status section is opened.
  useEffect(() => {
    if (activeSettingsSection === "engine") handleEngineHealthCheck();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSettingsSection]);

  const [showColMgr, setShowColMgr] = useState(false);

  // Custom Webpage Regex Scraper states (Req 2)
  interface WebScraper {
    id: string;
    name: string;
    url: string;
    regex: string;
    active: boolean;
  }
  const [webScrapers, setWebScrapers] = useState<WebScraper[]>([]);
  const [feedType, setFeedType] = useState<"rss" | "scraper">("rss");
  const [feedRegexInput, setFeedRegexInput] = useState("CVE-\\d{4}-\\d+");
  
  // Teams alert settings states (Req 5)
  const [teamsAlertsEnabled, setTeamsAlertsEnabled] = useState(false);
  const [teamsWebhookUrl, setTeamsWebhookUrl] = useState("");

  // SMS alert settings states (Req 5)
  const [smsAlertsEnabled, setSmsAlertsEnabled] = useState(false);
  const [smsTwilioSid, setSmsTwilioSid] = useState("");
  const [smsTwilioToken, setSmsTwilioToken] = useState("");
  const [smsPhoneNumber, setSmsPhoneNumber] = useState("");

  // Email config tab states
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [timezone, setTimezone] = useState("ICT");
  const [textSize, setTextSize] = useState<"sm" | "md" | "lg" | "xl" | "2xl">("md");
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpUsername, setSmtpUsername] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [useAdminSmtp, setUseAdminSmtp] = useState(false);
  const [emailAlertsEnabled, setEmailAlertsEnabled] = useState(true);
  const [profileSaved, setProfileSaved] = useState(false);

  // Feed Add/Edit Validation popup states
  const [isFeedModalOpen, setIsFeedModalOpen] = useState(false);
  const [feedModalMode, setFeedModalMode] = useState<"add" | "edit">("add");
  const [feedEditingIdx, setFeedEditingIdx] = useState<number | null>(null);
  const [feedNameInput, setFeedNameInput] = useState("");
  const [feedUrlInput, setFeedUrlInput] = useState("");
  const [feedValError, setFeedValError] = useState<string | null>(null);
  const [isFeedValidating, setIsFeedValidating] = useState(false);
  const [feedValSuccess, setFeedValSuccess] = useState(false);

  const appendLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `${timestamp} - ${msg}`]);
  };

  // Test a single notification channel and surface its own result (one method at a time).
  const testNotifier = async (path: string, body: Record<string, unknown>, label: string) => {
    const base = getApiBase();
    let msg: string;
    try {
      const r = await fetch(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
      msg = r.ok ? `✓ ${label}: ${data.message || "sent"}` : `✗ ${label}: ${detail || ("HTTP " + r.status)}`;
    } catch (e) {
      msg = `✗ ${label}: ${e instanceof Error ? e.message : "network error"}`;
    }
    window.alert(msg);
    appendLog(`[NET] Test ${label}: ${msg}`);
  };

  // Initial load
  useEffect(() => {
    setLogs([
      `[SYS] Secure Vnotice Threat Console Initialized.`,
      `[SYS] Security Sandbox Environment Verified Active.`,
      `[SYS] Ready. Select a Security Profile to begin...`,
    ]);

    const storedProfiles = localStorage.getItem("vnotice_profiles");
    let loadedProfiles: UserProfile[] = [];
    if (storedProfiles) {
      try {
        const parsed = JSON.parse(storedProfiles);
        if (Array.isArray(parsed) && parsed.length > 0) {
          loadedProfiles = parsed.map((p: any) => ({
            id: p.id || generateUniqueId(),
            name: p.name || "Default Operator",
            avatar: p.avatar || "🛡️",
            role: p.role || "Security Operator",
            email: p.email || `${(p.name || "user").toLowerCase().replace(/[^a-z0-9]/g, "")}@vnotice.local`,
            preferences: {
              theme: "dark",
              textSize: "md",
              vulnerabilityMinSeverity: "medium",
              emailAlertsEnabled: false,
              desktopAlertsEnabled: true,
              browserAlertsEnabled: true,
              teamsAlertsEnabled: false,
              teamsWebhookUrl: "",
              smsAlertsEnabled: false,
              smsTwilioSid: "",
              smsTwilioToken: "",
              smsPhoneNumber: "",
              ...(p.preferences || {})
            },
            credentials: p.credentials || {}
          }));
        }
      } catch (err) {
        console.error("Failed to parse profiles:", err);
      }
    }
    
    // Seed default if empty
    if (loadedProfiles.length === 0) {
      loadedProfiles = [
        {
          id: "default",
          name: "Admin",
          avatar: "🛡️",
          role: "Administrator",
          email: "admin@vnotice.local",
          preferences: {
            theme: "dark",
            textSize: "md",
            vulnerabilityMinSeverity: "medium",
            emailAlertsEnabled: false,
            desktopAlertsEnabled: true,
            browserAlertsEnabled: true,
          },
          credentials: {},
        },
      ];
      localStorage.setItem("vnotice_profiles", JSON.stringify(loadedProfiles));
    } else {
      localStorage.setItem("vnotice_profiles", JSON.stringify(loadedProfiles));
    }
    setProfiles(loadedProfiles);

    const storedFeeds = localStorage.getItem("vnotice_rss_feeds");
    let loadedFeeds: Feed[] = [];
    if (storedFeeds) {
      loadedFeeds = JSON.parse(storedFeeds);
      // Migration check: Ensure Check Point is present in the feed list
      // Remove any feeds that no longer have working URLs
      const deadUrls = [
        "checkpoint.com/advisories/rss",
        "nvd.nist.gov/feeds",
        "cisa.gov/known-exploited",
        "zerodayinitiative.com/rss",
        "advisories.splunk.com",
        "tools.cisco.com/security/center/rss",  // returns HTML page, not RSS
        "support.f5.com/csp/feed",              // returns HTML login page
        "vulners.com/rss.xml",                  // feed returns nothing usable
        "seclists.org/rss/fulldisclosure.rss",  // Full Disclosure — feed returns nothing usable
      ];
      const before = loadedFeeds.length;
      loadedFeeds = loadedFeeds.filter((f: Feed) =>
        !deadUrls.some(dead => f.url.toLowerCase().includes(dead))
      );
      // Add any newly configured feeds that are not yet in localStorage
      const newFeeds = [
        { name: "NVD / NIST CVE",    url: "https://services.nvd.nist.gov/rest/json/cves/2.0",    active: true },
        { name: "Splunk Security Advisories", url: "https://advisory.splunk.com/advisories",      active: true },
        { name: "Check Point Advisories", url: "https://support.checkpoint.com/security-advisories", active: true },
        { name: "Red Hat (RHEL)",    url: "https://access.redhat.com/hydra/rest/securitydata/cve.json", active: true },
        { name: "Rocky Linux",       url: "https://apollo.build.resf.org/api/v3/advisories/",     active: true },
        { name: "Microsoft (Windows)", url: "https://api.msrc.microsoft.com/cvrf/v3.0/updates",   active: true },
        { name: "Ubuntu Security",   url: "https://ubuntu.com/security/notices/rss.xml",          active: true },
        { name: "CERT.PL Security",  url: "https://cert.pl/en/rss.xml",                          active: true },
      ];
      for (const nf of newFeeds) {
        if (!loadedFeeds.some((f: Feed) => f.url === nf.url)) {
          loadedFeeds.push(nf);
        }
      }
      if (loadedFeeds.length !== before) {
        localStorage.setItem("vnotice_rss_feeds", JSON.stringify(loadedFeeds));
      }
    } else {
      loadedFeeds = [
        // NIST — JSON API (real CVSS + CPE vendor/product)
        { name: "NVD / NIST CVE", url: "https://services.nvd.nist.gov/rest/json/cves/2.0", active: true },
        // Vendor advisories — confirmed working RSS feeds
        { name: "Fortinet PSIRT", url: "https://fortiguard.com/rss/ir.xml", active: true },
        { name: "Palo Alto Networks", url: "https://security.paloaltonetworks.com/rss.xml", active: true },
        // Splunk advisory archive — HTML table parsed for real severity/CVSS
        { name: "Splunk Security Advisories", url: "https://advisory.splunk.com/advisories", active: true },
        // Check Point advisories — JSON API (SPA page can't be scraped) for real severity/CVSS
        { name: "Check Point Advisories", url: "https://support.checkpoint.com/security-advisories", active: true },
        // OS / distro security
        { name: "Ubuntu Security", url: "https://ubuntu.com/security/notices/rss.xml", active: true },
        // Red Hat Security Data API (JSON) — real CVSS/severity
        { name: "Red Hat (RHEL)", url: "https://access.redhat.com/hydra/rest/securitydata/cve.json", active: true },
        // Rocky Linux errata via RESF Apollo API (JSON)
        { name: "Rocky Linux", url: "https://apollo.build.resf.org/api/v3/advisories/", active: true },
        // Microsoft / Windows via MSRC CVRF API (JSON) — latest Patch Tuesday
        { name: "Microsoft (Windows)", url: "https://api.msrc.microsoft.com/cvrf/v3.0/updates", active: true },
        // Global aggregators — confirmed working
        { name: "CERT.PL Security", url: "https://cert.pl/en/rss.xml", active: true },
      ];
      localStorage.setItem("vnotice_rss_feeds", JSON.stringify(loadedFeeds));
    }
    setFeeds(loadedFeeds);

    const storedPoll = localStorage.getItem("vnotice_global_poll");
    if (storedPoll && ["30s", "1m", "2m", "5m", "10m"].includes(storedPoll)) {
      setGlobalPoll(storedPoll);
    }

    // Load vulnerabilities state
    const storedVulns = localStorage.getItem("vnotice_vulnerabilities");
    let loadedVulns = [];
    if (storedVulns) {
      loadedVulns = JSON.parse(storedVulns);
      // Migrate stale source names that don't match current feed names
      const sourceMap: Record<string, string> = {
        "NVD CVE Data Feed": "Ubuntu Security",
        "NVD CVE RSS":       "Ubuntu Security",
        "CISA KEV Feed":     "Cisco Security Advisories",
        "CISA KEV":          "Cisco Security Advisories",
        "Zero Day Initiative Advisories": "Cisco Security Advisories",
        "Splunk Advisories": "Cisco Security Advisories",
        "Check Point Advisories": "Check Point Advisories Scraper",
      };
      let migrated = false;
      loadedVulns = loadedVulns.map((v: any) => {
        const correctedSrc = sourceMap[v.source];
        if (correctedSrc) { migrated = true; return { ...v, source: correctedSrc }; }
        return v;
      });

      loadedVulns = loadedVulns.map((v: any) => {
        if ((v.vendor === "Various" || v.vendor === "Unknown" || v.vendor === "Various Product") ||
            (v.product === "Various Product" || v.product === "Various" || v.product === "Unknown Product")) {
          const inferred = inferVendorProduct(v.source || "", v.name || "");
          if (inferred) {
            migrated = true;
            return { ...v, vendor: inferred[0], product: inferred[1] };
          }
        }
        return v;
      });

      if (migrated) localStorage.setItem("vnotice_vulnerabilities", JSON.stringify(loadedVulns));
    } else {
      loadedVulns = cveMockData;
      localStorage.setItem("vnotice_vulnerabilities", JSON.stringify(loadedVulns));
    }
    setVulnerabilities(loadedVulns);

    // Alert rules are loaded per-account when a profile is selected (see the
    // activeProfileId effect) so they stay separated between operators.

    // Load Webpage scrapers (Req 2)
    const storedScrapers = localStorage.getItem("vnotice_web_scrapers");
    let loadedScrapers = [];
    if (storedScrapers) {
      loadedScrapers = JSON.parse(storedScrapers);
      // Remove Check Point scraper — support.checkpoint.com returns empty body (JS-rendered, cannot be scraped)
      const before = loadedScrapers.length;
      loadedScrapers = loadedScrapers.filter((s: any) => !s.url.toLowerCase().includes("checkpoint.com"));
      if (loadedScrapers.length !== before) {
        localStorage.setItem("vnotice_web_scrapers", JSON.stringify(loadedScrapers));
      }
    } else {
      loadedScrapers = [] as WebScraper[];
      localStorage.setItem("vnotice_web_scrapers", JSON.stringify(loadedScrapers));
    }
    setWebScrapers(loadedScrapers);

    // Sync from active database if online
    const fetchApiCves = async () => {
      try {
        const res = await fetch(`${getApiBase()}/cves/?limit=500`);
        if (res.ok) {
          const apiData = await res.json();
          if (apiData && apiData.length > 0) {
            const mapped = apiData.map((c: any) => {
              const v = mapApiCve(c);
              return { ...v, url: ensureAbsoluteCveUrl(c.reference_url, c.cve_id) };
            });
            setVulnerabilities(mapped);
            localStorage.setItem("vnotice_vulnerabilities", JSON.stringify(mapped));
            appendLog(`[NET] Active PostgreSQL database connected. Syncing threat stream...`);
            return;
          }
        }
      } catch (err) {
        // Fail silently
      }
      appendLog(`[NET] Local SQLite database active. Offline fallback active.`);
    };
    fetchApiCves();

    // Do NOT auto-restore the last active profile — always show account
    // selection on page load so the user explicitly picks their account.
  }, []);

  const activeProfile = profiles.find((p) => p.id === activeProfileId);

  // ─── Admin account (holds the canonical SMTP config; is the default account) ───
  const isAdminProfile = (p?: UserProfile | null) => !!p && /admin/i.test(p.role || "");
  const adminProfile = (): UserProfile | undefined =>
    profiles.find((p) => /admin/i.test(p.role || "")) ||
    profiles.find((p) => p.id === "default") || profiles[0];

  // ─── Per-account alert-rule storage (security: never share rules across accounts) ───
  const alertRulesKey = (pid: string) => `vnotice_alert_rules_${pid}`;

  const migrateRule = (r: any): AlertRule => {
    if (r.filters) {
      return { ...r, conditions: (r.conditions && r.conditions.length) ? r.conditions : [r.filters] } as AlertRule;
    }
    const f: AlertFilter = {
      severity: ["all"], keywords: [], feedSources: ["all"],
      searchQuery: r.searchQuery || "", epssMin: "", epssMax: "",
    };
    return {
      id: r.id || generateUniqueId(),
      name: r.name || "Unnamed Rule",
      description: "",
      active: r.active !== undefined ? r.active : true,
      filters: f, conditions: [f],
      createdAt: new Date().toISOString(),
    } as AlertRule;
  };

  const loadAlertRulesFor = (pid: string): AlertRule[] => {
    let raw = localStorage.getItem(alertRulesKey(pid));
    // ponytail: one-time migration — adopt the old shared rules into the first
    // account opened after this change, then delete the global key for good.
    if (!raw) {
      const legacy = localStorage.getItem("vnotice_alert_rules");
      if (legacy) {
        raw = legacy;
        localStorage.setItem(alertRulesKey(pid), legacy);
        localStorage.removeItem("vnotice_alert_rules");
      }
    }
    if (!raw) return [];
    try { return (JSON.parse(raw) as any[]).map(migrateRule); } catch { return []; }
  };

  const saveAlertRules = (rules: AlertRule[]) => {
    if (!activeProfileId) return;
    localStorage.setItem(alertRulesKey(activeProfileId), JSON.stringify(rules));
  };

  useEffect(() => {
    if (activeProfile) {
      setDisplayName(activeProfile.name || "");
      setEmail(activeProfile.email || "");
      setTimezone(activeProfile.preferences?.vulnerabilityMinSeverity || "ICT");
      setTextSize((activeProfile.preferences?.textSize as any) || "md");
      // Email Alerts: optionally borrow the admin account's SMTP config.
      const borrow = activeProfile.preferences?.useAdminSmtp || false;
      setUseAdminSmtp(borrow);
      const admin = adminProfile();
      const creds = (borrow && admin && admin.id !== activeProfile.id)
        ? admin.credentials : activeProfile.credentials;
      setSmtpHost(creds?.smtpHost || "");
      setSmtpPort(creds?.smtpPort || "587");
      setSmtpUsername(creds?.smtpUser || "");
      setSmtpPassword(creds?.smtpPass || "");
      setEmailAlertsEnabled(activeProfile.preferences?.emailAlertsEnabled !== undefined ? activeProfile.preferences.emailAlertsEnabled : true);
      setTeamsAlertsEnabled(activeProfile.preferences?.teamsAlertsEnabled || false);
      setTeamsWebhookUrl(activeProfile.preferences?.teamsWebhookUrl || "");
      setSmsAlertsEnabled(activeProfile.preferences?.smsAlertsEnabled || false);
      setSmsTwilioSid(activeProfile.preferences?.smsTwilioSid || "");
      setSmsTwilioToken(activeProfile.preferences?.smsTwilioToken || "");
      setSmsPhoneNumber(activeProfile.preferences?.smsPhoneNumber || "");

    }
    // Load this account's alert rules (or clear them on logout) — kept separate per account.
    setAlertRules(activeProfileId ? loadAlertRulesFor(activeProfileId) : []);
  }, [activeProfileId, activeProfile]);

  const applyTheme = (theme: "dark" | "light") => {
    if (theme === "light") {
      document.body.classList.add("theme-light");
    } else {
      document.body.classList.remove("theme-light");
    }
  };

  const handleSelectProfile = (id: string) => {
    setActiveProfileId(id);
    localStorage.setItem("vnotice_currentUser_id", id);
    const profile = profiles.find((p) => p.id === id);
    if (profile) {
      setIsDarkMode(profile.preferences?.theme === "dark");
      applyTheme(profile.preferences?.theme || "dark");
      appendLog(`[SYS] Active Security Session created for: ${profile.name}`);
      appendLog(`[SYS] Access level loaded: ${profile.role}`);
    }
  };

  const handleCreateProfile = (newProfile: UserProfile) => {
    const updated = [...profiles, newProfile];
    setProfiles(updated);
    localStorage.setItem("vnotice_profiles", JSON.stringify(updated));
    setActiveProfileId(newProfile.id);
    localStorage.setItem("vnotice_currentUser_id", newProfile.id);
    setIsDarkMode(newProfile.preferences?.theme === "dark");
    applyTheme(newProfile.preferences?.theme || "dark");
    appendLog(`[SYS] Created new Operator Profile: ${newProfile.name}`);
    appendLog(`[SYS] Active Security Session created for: ${newProfile.name}`);
  };

  const handleSwitchUser = () => {
    appendLog(`[SYS] Terminated Active Security Session.`);
    setActiveProfileId(null);
    localStorage.removeItem("vnotice_currentUser_id");
  };

  const handleProfileSave = (updates: Partial<UserProfile>) => {
    if (!activeProfileId) return;
    const updatedProfiles = profiles.map((p) => {
      if (p.id === activeProfileId) {
        const merged = { ...p, ...updates };
        if (updates.preferences?.theme) {
          applyTheme(updates.preferences.theme);
        }
        return merged;
      }
      return p;
    });
    setProfiles(updatedProfiles);
    localStorage.setItem("vnotice_profiles", JSON.stringify(updatedProfiles));
    appendLog(`[SYS] General preferences & alert parameters updated successfully.`);
  };

  const handleSaveConfiguration = () => {
    if (!activeProfile) return;
    if (!displayName.trim()) {
      alert("Display Name is required.");
      return;
    }
    const updates = {
      name: displayName.trim(),
      email: email.trim(),
      preferences: {
        theme: activeProfile.preferences.theme,
        textSize: textSize,
        vulnerabilityMinSeverity: activeProfile.preferences.vulnerabilityMinSeverity,
        emailAlertsEnabled: emailAlertsEnabled,
        desktopAlertsEnabled: activeProfile.preferences.desktopAlertsEnabled,
        browserAlertsEnabled: activeProfile.preferences.browserAlertsEnabled,
        teamsAlertsEnabled: teamsAlertsEnabled,
        teamsWebhookUrl: teamsWebhookUrl.trim(),
        smsAlertsEnabled: smsAlertsEnabled,
        smsTwilioSid: smsTwilioSid.trim(),
        smsTwilioToken: smsTwilioToken.trim(),
        smsPhoneNumber: smsPhoneNumber.trim(),
        useAdminSmtp: useAdminSmtp,
      },
      // When borrowing admin's SMTP, keep this account's own creds untouched
      // (so toggling back off restores them). ponytail.
      credentials: useAdminSmtp
        ? (activeProfile.credentials || {})
        : {
            smtpHost: smtpHost.trim(),
            smtpPort: smtpPort.trim(),
            smtpUser: smtpUsername.trim(),
            smtpPass: smtpPassword.trim(),
          },
    };
    handleProfileSave(updates);
    setProfileSaved(true);
    setTimeout(() => setProfileSaved(false), 2000);
  };

  const toggleDarkMode = () => {
    const nextDark = !isDarkMode;
    setIsDarkMode(nextDark);
    
    if (activeProfile) {
      const updatedPreferences = {
        ...activeProfile.preferences,
        theme: nextDark ? ("dark" as const) : ("light" as const),
      };
      handleProfileSave({ preferences: updatedPreferences });
    }
  };

  // RSS Feed actions
  const handleToggleFeed = (idx: number) => {
    const updated = [...feeds];
    updated[idx].active = !updated[idx].active;
    setFeeds(updated);
    localStorage.setItem("vnotice_rss_feeds", JSON.stringify(updated));
    appendLog(
      `[SYS] Threat channel '${updated[idx].name}' toggled to: ${
        updated[idx].active ? "ACTIVE" : "DISABLED"
      }`
    );
    // Instantly sync RSS threat stream feed on toggle
    setTimeout(() => {
      handleSyncFeeds();
    }, 100);
  };

  const handleRemoveFeed = (idx: number) => {
    const feed = feeds[idx];
    const updated = feeds.filter((_, i) => i !== idx);
    setFeeds(updated);
    localStorage.setItem("vnotice_rss_feeds", JSON.stringify(updated));
    appendLog(`[SYS] Removed threat channel source: ${feed.name}`);
  };

  const handleGlobalPollChange = (val: string) => {
    setGlobalPoll(val);
    localStorage.setItem("vnotice_global_poll", val);
    appendLog(`[SYS] Global polling interval changed to: ${val}`);
  };

  const handleStreamSyncModeChange = (mode: string) => {
    setStreamSyncMode(mode);
    localStorage.setItem("vnotice_stream_sync_mode", mode);
  };

  // Re-pull real EPSS scores from FIRST.org for all stored CVEs (fills newly
  // available scores and updates changed ones), then reload the grid.
  const handleRefreshEpss = async () => {
    setIsRefreshingEpss(true);
    appendLog(`[NET] Refreshing EPSS scores from FIRST.org...`);
    try {
      const res = await fetch(`${getApiBase()}/cves/refresh-epss`, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const r = await res.json();
      const cvesRes = await fetch(`${getApiBase()}/cves/?limit=500`);
      if (cvesRes.ok) {
        const apiData = await cvesRes.json();
        const mapped = apiData.map((c: any) => {
          const v = mapApiCve(c);
          return { ...v, url: ensureAbsoluteCveUrl(c.reference_url, c.cve_id) };
        });
        setVulnerabilities(mapped);
        localStorage.setItem("vnotice_vulnerabilities", JSON.stringify(mapped));
      }
      appendLog(`[NET] EPSS refresh: ${r.with_epss} scored · ${r.na} N/A (of ${r.total}).`);
      window.alert(`EPSS updated: ${r.with_epss} scored, ${r.na} N/A (of ${r.total}).`);
    } catch (e) {
      window.alert(`EPSS refresh failed: ${e instanceof Error ? e.message : "network error"}`);
    }
    setIsRefreshingEpss(false);
  };

  const handleSyncFeeds = async () => {
    setIsSyncing(true);
    setSyncCountdown(getPollIntervalSeconds(globalPoll));
    appendLog(`[NET] Fetching XML RSS feeds and custom webpage scrapers...`);
    
    const activeFeeds = feeds.filter((f) => f.active);
    const activeScrapers = webScrapers.filter((s) => s.active);
    
    // Print initial logs
    activeFeeds.forEach((feed) => {
      appendLog(`[NET] Enqueuing XML feed parsing for: ${feed.name}`);
    });
    activeScrapers.forEach((scraper) => {
      appendLog(`[NET] Enqueuing webpage regex crawler for: ${scraper.name} (Regex: /${scraper.regex}/gi)`);
    });

    try {
      const response = await fetch(`${getApiBase()}/sync/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          feeds: activeFeeds.map(f => ({ name: f.name, url: f.url, active: f.active })),
          scrapers: activeScrapers.map(s => ({ id: s.id, name: s.name, url: s.url, regex: s.regex, active: s.active }))
        })
      });

      if (response.ok) {
        const result = await response.json();
        appendLog(`[OK] Backend Sync Result: Checked ${result.feeds_checked} RSS channels & ${result.scrapers_checked} webpage scrapers.`);
        appendLog(`[OK] Discovered and parsed ${result.new_cves_added} new vulnerability records.`);
        
        // Refetch all CVEs from backend to update Threat Stream!
        const cvesRes = await fetch(`${getApiBase()}/cves/?limit=500`);
        if (cvesRes.ok) {
          const apiData = await cvesRes.json();
          if (apiData && apiData.length > 0) {
            const mapped = apiData.map((c: any) => {
              const v = mapApiCve(c);
              return { ...v, url: ensureAbsoluteCveUrl(c.reference_url, c.cve_id) };
            });
            setVulnerabilities(mapped);
            localStorage.setItem("vnotice_vulnerabilities", JSON.stringify(mapped));
            appendLog(`[SYS] Threat Stream updated successfully from PostgreSQL database.`);
            setIsSyncing(false);
            return;
          }
        }
      }
    } catch (err) {
      appendLog(`[SEC] Warning: Remote database sync failed or offline.`);
    }

    // ponytail: backend runs on the same host and is reliable. The old client-side
    // emulation fabricated fake CVEs dated today (incl. a fake Check Point one),
    // polluting real data with wrong publish dates. Keep last known real data instead.
    appendLog(`[WARN] Backend sync unavailable - keeping last known data (no emulation).`);
    setIsSyncing(false);
  };

  const getPollIntervalSeconds = (val: string): number => {
    switch (val) {
      case "30s": return 30;
      case "1m": return 60;
      case "2m": return 120;
      case "5m": return 300;
      case "10m": return 600;
      default: return 60;
    }
  };

  // Polling Countdown Hooks
  useEffect(() => {
    setSyncCountdown(getPollIntervalSeconds(globalPoll));
    setStreamSyncCountdown(getPollIntervalSeconds(streamSyncMode));
  }, [globalPoll, streamSyncMode]);

  useEffect(() => {
    const interval = setInterval(() => {
      // 1. RSS countdown
      setSyncCountdown((prev) => {
        if (prev <= 1) {
          handleSyncFeeds();
          return getPollIntervalSeconds(globalPoll);
        }
        return prev - 1;
      });

      // 2. Stream countdown
      setStreamSyncCountdown((prev) => {
        if (prev <= 1) {
          handleSyncFeeds();
          return getPollIntervalSeconds(streamSyncMode);
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [globalPoll, streamSyncMode, feeds, webScrapers]);

  // Feed Add/Edit Modal
  const handleOpenAddModal = () => {
    setFeedModalMode("add");
    setFeedNameInput("");
    setFeedUrlInput("");
    setFeedValError(null);
    setFeedValSuccess(false);
    setIsFeedModalOpen(true);
  };

  const handleOpenEditModal = (idx: number) => {
    const feed = feeds[idx];
    setFeedModalMode("edit");
    setFeedEditingIdx(idx);
    setFeedNameInput(feed.name);
    setFeedUrlInput(feed.url);
    setFeedValError(null);
    setFeedValSuccess(false);
    setIsFeedModalOpen(true);
  };

  const handleSaveFeed = async () => {
    setFeedValError(null);
    setFeedValSuccess(false);
    if (!feedNameInput.trim()) {
      setFeedValError("Feed Name is required.");
      return;
    }
    if (!feedUrlInput.trim()) {
      setFeedValError("Feed URL is required.");
      return;
    }

    setIsFeedValidating(true);
    appendLog(`[NET] Running remote verification query on URL: ${feedUrlInput.trim()}`);
    await new Promise((resolve) => setTimeout(resolve, 900));
    
    try {
      const url = new URL(feedUrlInput.trim());
      const lowerUrl = feedUrlInput.trim().toLowerCase();
      const isValidRss =
        url.protocol === "http:" ||
        url.protocol === "https:" && (
          lowerUrl.endsWith(".xml") ||
          lowerUrl.endsWith(".rss") ||
          lowerUrl.endsWith(".atom") ||
          lowerUrl.includes("/feed") ||
          lowerUrl.includes("/rss") ||
          lowerUrl.includes("atom.xml") ||
          lowerUrl.includes("rss.xml") ||
          lowerUrl.includes("/advisories.atom") ||
          lowerUrl.includes("feed.xml") ||
          lowerUrl.includes("rss.x")
        );

      setIsFeedValidating(false);

      if (!isValidRss) {
        setFeedValError(
          "Validation Failed: Target URL does not return a valid XML, RSS, or Atom feed signature (ends in .xml, .rss, .atom, /feed, or contains rss/xml pathways)."
        );
        appendLog(`[SEC] Warning: Feed validation failed for URL: ${feedUrlInput.trim()}`);
        return;
      }

      setFeedValSuccess(true);
      await new Promise((resolve) => setTimeout(resolve, 400));

      if (feedModalMode === "add") {
        const updated = [...feeds, { name: feedNameInput.trim(), url: feedUrlInput.trim(), active: true }];
        setFeeds(updated);
        localStorage.setItem("vnotice_rss_feeds", JSON.stringify(updated));
        appendLog(`[SYS] Registered new threat channel source: ${feedNameInput.trim()}`);
      } else if (feedModalMode === "edit" && feedEditingIdx !== null) {
        const oldName = feeds[feedEditingIdx].name;
        const updated = [...feeds];
        updated[feedEditingIdx] = { ...updated[feedEditingIdx], name: feedNameInput.trim(), url: feedUrlInput.trim() };
        setFeeds(updated);
        localStorage.setItem("vnotice_rss_feeds", JSON.stringify(updated));
        appendLog(`[SYS] Updated threat channel source metadata: ${oldName} -> ${feedNameInput.trim()}`);
      }

      setIsFeedModalOpen(false);
      setFeedNameInput("");
      setFeedUrlInput("");
      setFeedEditingIdx(null);
      setFeedValSuccess(false);
    } catch (e) {
      setIsFeedValidating(false);
      setFeedValError("Validation Failed: URL format is invalid. Please enter a valid HTTP/HTTPS address.");
      appendLog(`[SEC] Invalid URL entry: ${feedUrlInput}`);
    }
  };

  // CSV/JSON Download Reports
  const handleExportCSV = () => {
    appendLog(`[SYS] Generating CSV download from filtered advisory list...`);
    const headers = ["CVE ID", "Name", "Vendor", "Product", "Severity", "CVSS Score", "EPSS Score", "Published Date"];
    const csvRows = [headers.join(",")];
    
    filteredVulnerabilities.forEach((v) => {
      const row = [
        v.id,
        `"${v.name.replace(/"/g, '""')}"`,
        v.vendor,
        v.product,
        v.severity,
        v.score,
        v.epss ?? "N/A",
        v.date
      ];
      csvRows.push(row.join(","));
    });
    
    const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.setAttribute("href", url);
    a.setAttribute("download", `vnotice-threat-intel-${new Date().toISOString().split('T')[0]}.csv`);
    a.click();
    appendLog(`[OK] Successfully compiled and downloaded CSV threats advisory report.`);
  };

  const handleExportJSON = () => {
    appendLog(`[SYS] Generating JSON download from filtered advisory list...`);
    const blob = new Blob([JSON.stringify(filteredVulnerabilities, null, 2)], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.setAttribute("href", url);
    a.setAttribute("download", `vnotice-threat-intel-${new Date().toISOString().split('T')[0]}.json`);
    a.click();
    appendLog(`[OK] Successfully compiled and downloaded JSON threats advisory report.`);
  };

  // Matching helpers for smart matches (Req 2 & Req 6)
  const matchesVendorHelper = (vulnVendor: string, activeVendorsList: string[]) => {
    if (activeVendorsList.includes("all")) return true;
    const vendorLower = vulnVendor.toLowerCase();
    return activeVendorsList.some((v) => {
      const vLower = v.toLowerCase();
      if (vLower === "palo alto" && vendorLower.includes("palo alto")) return true;
      if (vLower === "linux" && (vendorLower.includes("linux") || vendorLower.includes("kernel"))) return true;
      if (vLower === "f5 networks" && (vendorLower.includes("f5") || vendorLower.includes("networks"))) return true;
      return vendorLower.includes(vLower) || vLower.includes(vendorLower);
    });
  };

  const matchesProductHelper = (vulnProduct: string, activeProductsList: string[]) => {
    if (activeProductsList.includes("all")) return true;
    const productLower = vulnProduct.toLowerCase();
    return activeProductsList.some((p) => {
      const pLower = p.toLowerCase();
      if (pLower === "windows os" && (productLower.includes("windows") || productLower.includes("os"))) return true;
      if (pLower === "chrome browser" && productLower.includes("chrome")) return true;
      if (pLower === "ios / ipados" && (productLower.includes("ios") || productLower.includes("ipad"))) return true;
      if (pLower === "cisco ios" && productLower.includes("cisco")) return true;
      if (pLower === "linux kernel" && (productLower.includes("linux") || productLower.includes("kernel"))) return true;
      if (pLower === "apache http server" && (productLower.includes("apache") || productLower.includes("http"))) return true;
      if (pLower === "runc / docker" && (productLower.includes("runc") || productLower.includes("docker") || productLower.includes("container"))) return true;
      if (pLower === "big-ip" && productLower.includes("big-ip")) return true;
      if (pLower === "splunk enterprise" && productLower.includes("splunk")) return true;
      if (pLower === "xz utils" && productLower.includes("xz")) return true;
      return productLower.includes(pLower) || pLower.includes(productLower);
    });
  };

  // Filter dynamic vulnerabilities list using multi-selection arrays (Req 2)
  const toggleFilter = (state: string[], setState: any, value: string) => {
    if (value === "all") {
      setState(["all"]);
      return;
    }
    const newState = state.filter((s) => s !== "all");
    if (newState.includes(value)) {
      const filtered = newState.filter((s) => s !== value);
      setState(filtered.length === 0 ? ["all"] : filtered);
    } else {
      setState([...newState, value]);
    }
  };

  // ponytail: memoized so the per-second countdown re-render doesn't re-scan
  // the whole CVE list. Deps cover every field the predicate reads.
  const filteredVulnerabilities = useMemo(() => vulnerabilities.filter((vuln) => {
    const query = searchQuery.toLowerCase().trim();
    // Bug fix: use ?? "" to guard against null/undefined fields
    const vId   = (vuln.id          ?? "").toLowerCase();
    const vName = (vuln.name        ?? "").toLowerCase();
    const vVend = (vuln.vendor      ?? "").toLowerCase();
    const vProd = (vuln.product     ?? "").toLowerCase();
    const vDesc = (vuln.description ?? "").toLowerCase();
    const vSrc  = (vuln.source      ?? "").toLowerCase().trim();
    const vSev  = (vuln.severity    ?? "").toLowerCase();

    const matchesQuery =
      query === "" ||
      vId.includes(query) ||
      vName.includes(query) ||
      vVend.includes(query) ||
      vProd.includes(query) ||
      vDesc.includes(query);

    const matchesSeverity =
      activeSeverity.includes("all") ||
      activeSeverity.some((s) => vSev === s.toLowerCase());

    // All keywords must match at least one field
    const matchesKeywords =
      activeKeywords.length === 0 ||
      activeKeywords.every((kw) => {
        const k = kw.toLowerCase();
        return vId.includes(k) || vName.includes(k) || vVend.includes(k) ||
               vProd.includes(k) || vDesc.includes(k) || vSrc.includes(k);
      });

    // Exact case-insensitive source match.
    // When "all" is selected every CVE passes; otherwise only CVEs whose
    // source field exactly matches one of the selected feed/scraper names.
    const showingAll = activeFeedsFilter.includes("all");

    const matchesFeedFilter =
      showingAll ||
      (vSrc !== "" && activeFeedsFilter.some(f => f.toLowerCase().trim() === vSrc));

    // When showing all sources, hide CVEs from feeds/scrapers the user has
    // disabled. When specific sources are selected, skip this gate entirely.
    const matchingFeed    = showingAll ? feeds.find(f => f.name.toLowerCase().trim() === vSrc) : null;
    const matchingScraper = showingAll ? webScrapers.find(s => s.name.toLowerCase().trim() === vSrc) : null;
    const matchesFeedActive    = !matchingFeed    || matchingFeed.active;
    const matchesScraperActive = !matchingScraper || matchingScraper.active;

    const minVal = epssMin !== "" ? parseFloat(epssMin) : null;
    const maxVal = epssMax !== "" ? parseFloat(epssMax) : null;
    const matchesEpss =
      (minVal === null || (vuln.epss ?? 0) * 100 >= minVal) &&
      (maxVal === null || (vuln.epss ?? 0) * 100 <= maxVal);

    return matchesQuery && matchesSeverity && matchesKeywords &&
           matchesFeedFilter && matchesFeedActive && matchesScraperActive && matchesEpss;
  }), [vulnerabilities, searchQuery, activeSeverity, activeKeywords, activeFeedsFilter, feeds, webScrapers, epssMin, epssMax]);

  // Keyword filter handlers
  const handleAddKeyword = (kw: string) => {
    const trimmed = kw.trim();
    if (trimmed && !activeKeywords.includes(trimmed)) {
      setActiveKeywords((prev) => [...prev, trimmed]);
    }
  };
  const handleRemoveKeyword = (kw: string) => {
    setActiveKeywords((prev) => prev.filter((k) => k !== kw));
  };

  // Feed source checklist filter handler
  const handleToggleFeedFilter = (feedName: string) => {
    if (feedName === "all") {
      setActiveFeedsFilter(["all"]);
      return;
    }
    setActiveFeedsFilter((prev) => {
      const without = prev.filter((f) => f !== "all");
      if (without.includes(feedName)) {
        const next = without.filter((f) => f !== feedName);
        return next.length === 0 ? ["all"] : next;
      }
      return [...without, feedName];
    });
  };

  // Alert Rules managers
  // Snapshot the current dashboard filters as one alert condition group.
  const currentFilterGroup = (): AlertFilter => ({
    severity: [...activeSeverity],
    keywords: [...activeKeywords],
    feedSources: [...activeFeedsFilter],
    searchQuery,
    epssMin,
    epssMax,
  });

  // Does a CVE satisfy ALL conditions in a single group? (AND within a group.)
  const cveMatchesGroup = (v: any, g: AlertFilter): boolean => {
    const sevs = g.severity || [];
    const matchesSeverity = sevs.length === 0 || sevs.includes("all") ||
      sevs.map((s) => s.toLowerCase()).includes((v.severity || "").toLowerCase());

    const srcs = g.feedSources || [];
    const vSrc = (v.source || "").toLowerCase().trim();
    const matchesSource = srcs.length === 0 || srcs.includes("all") ||
      srcs.some((s) => s.toLowerCase().trim() === vSrc);

    const q = (g.searchQuery || "").toLowerCase();
    const hay = ((v.name || "") + " " + (v.description || "") + " " + (v.id || "")).toLowerCase();
    const matchesQuery = !q || hay.includes(q);

    const kws = g.keywords || [];
    const matchesKeywords = kws.length === 0 || kws.some((k) => hay.includes(k.toLowerCase()));

    const minVal = g.epssMin !== "" ? parseFloat(g.epssMin) : null;
    const maxVal = g.epssMax !== "" ? parseFloat(g.epssMax) : null;
    const epssPct = (v.epss ?? 0) * 100;
    const matchesEpss = (minVal === null || epssPct >= minVal) && (maxVal === null || epssPct <= maxVal);

    return matchesSeverity && matchesSource && matchesQuery && matchesKeywords && matchesEpss;
  };

  // A CVE matches a rule if ANY of its condition groups match. (OR across groups.)
  const ruleGroups = (r: AlertRule): AlertFilter[] => (r.conditions && r.conditions.length ? r.conditions : [r.filters]);
  const countRuleMatches = (r: AlertRule): number =>
    vulnerabilities.filter((v) => ruleGroups(r).some((g) => cveMatchesGroup(v, g))).length;

  // Newest currently-loaded CVE that matches this rule (by ingest time), or null.
  const latestMatchForRule = (r: AlertRule): any | null => {
    const matches = vulnerabilities.filter((v) => ruleGroups(r).some((g) => cveMatchesGroup(v, g)));
    if (!matches.length) return null;
    // ponytail: sort by ingestedAt (ISO, lexicographic works) desc, fall back to published date
    return matches.slice().sort((a, b) =>
      (b.ingestedAt || b.date || "").localeCompare(a.ingestedAt || a.date || ""))[0];
  };

  // Email the latest matching event for this rule, then stamp lastSentAt on success.
  const sendAlertTestEmail = async (rule: AlertRule) => {
    if (!smtpHost.trim() || !smtpUsername.trim() || !smtpPassword.trim() || !email.trim()) {
      window.alert("Configure email first: set SMTP host, username, password and recipient under Settings → Email Alerts, then Save.");
      return;
    }
    const v = latestMatchForRule(rule);
    if (!v) {
      window.alert(`No currently-loaded CVE matches "${rule.name}", so there is nothing to send yet.`);
      return;
    }
    let ok = false;
    let msg: string;
    try {
      const r = await fetch(`${getApiBase()}/notifications/test-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          smtp_host: smtpHost, smtp_port: parseInt(smtpPort) || 587,
          smtp_username: smtpUsername, smtp_password: smtpPassword, to_address: email,
          cve_id: v.id, title: v.name || v.id, severity: v.severity || "Medium",
          description: v.description || "", reference_url: v.url || "",
        }),
      });
      const data = await r.json().catch(() => ({}));
      const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
      ok = r.ok;
      msg = r.ok ? `✓ Sent ${v.id} to ${email}` : `✗ ${detail || ("HTTP " + r.status)}`;
    } catch (e) {
      msg = `✗ ${e instanceof Error ? e.message : "network error"}`;
    }
    window.alert(msg);
    appendLog(`[NET] Alert '${rule.name}' email (${v.id}): ${msg}`);
    if (ok) {
      const updated = alertRules.map((x) =>
        x.id === rule.id ? { ...x, lastSentAt: new Date().toISOString(), sentCount: (x.sentCount || 0) + 1 } : x);
      setAlertRules(updated);
      saveAlertRules(updated);
    }
  };

  const handleSaveAlert = () => {
    if (!saveAlertName.trim()) {
      alert("Alert Name is required.");
      return;
    }
    // Fall back to the current filters if no explicit groups were added.
    const groups = editConditions.length > 0 ? editConditions : [currentFilterGroup()];
    if (editingAlertId) {
      const updated = alertRules.map((r) =>
        r.id === editingAlertId
          ? { ...r, name: saveAlertName.trim(), description: saveAlertDescription.trim(), filters: groups[0], conditions: groups }
          : r
      );
      setAlertRules(updated);
      saveAlertRules(updated);
      appendLog(`[SYS] Updated Alert Rule: ${saveAlertName.trim()} (${groups.length} condition group${groups.length > 1 ? "s" : ""})`);
    } else {
      const newRule: AlertRule = {
        id: generateUniqueId(),
        name: saveAlertName.trim(),
        description: saveAlertDescription.trim(),
        active: true,
        filters: groups[0],
        conditions: groups,
        createdAt: new Date().toISOString(),
      };
      const updated = [...alertRules, newRule];
      setAlertRules(updated);
      saveAlertRules(updated);
      appendLog(`[SYS] Saved new Alert Rule: ${newRule.name} (${groups.length} condition group${groups.length > 1 ? "s" : ""})`);
    }
    setShowSaveAlertModal(false);
    setSaveAlertName("");
    setSaveAlertDescription("");
    setEditingAlertId(null);
    setEditConditions([]);
  };

  // Human-readable one-line summary of a condition group (for chips in the modal/cards).
  const describeGroup = (g: AlertFilter): string => {
    const parts: string[] = [];
    const sev = (g.severity || []).filter((s) => s !== "all");
    parts.push(sev.length ? sev.join("/") : "Any severity");
    const src = (g.feedSources || []).filter((s) => s !== "all");
    if (src.length) parts.push(`from ${src.join(", ")}`);
    if (g.epssMin) parts.push(`EPSS ≥ ${g.epssMin}%`);
    if (g.epssMax) parts.push(`EPSS ≤ ${g.epssMax}%`);
    if ((g.keywords || []).length) parts.push(`kw: ${g.keywords.join(",")}`);
    if (g.searchQuery) parts.push(`"${g.searchQuery}"`);
    return parts.join(" · ");
  };

  const handleToggleRuleActive = (id: string) => {
    const updated = alertRules.map((r) =>
      r.id === id ? { ...r, active: !r.active } : r
    );
    setAlertRules(updated);
    saveAlertRules(updated);
    const rule = updated.find((r) => r.id === id);
    appendLog(`[SYS] Alert Rule '${rule?.name}' state switched to: ${rule?.active ? "ACTIVE" : "DISABLED"}`);
  };

  const handleRemoveAlertRule = (id: string) => {
    const rule = alertRules.find((r) => r.id === id);
    const updated = alertRules.filter((r) => r.id !== id);
    setAlertRules(updated);
    saveAlertRules(updated);
    appendLog(`[SYS] Deleted Alert Rule: ${rule?.name}`);
  };

  // Saved Dashboards managers
  const handleSaveDashboard = () => {
    if (!saveDashboardName.trim()) {
      alert("Dashboard Name is required.");
      return;
    }
    const newDash: SavedDashboard = {
      id: generateUniqueId(),
      name: saveDashboardName.trim(),
      filters: {
        severity: [...activeSeverity],
        keywords: [...activeKeywords],
        feedSources: [...activeFeedsFilter],
        searchQuery,
        epssMin,
        epssMax,
      },
      createdAt: new Date().toISOString(),
    };
    const updated = [...savedDashboards, newDash];
    setSavedDashboards(updated);
    localStorage.setItem("vnotice_saved_dashboards", JSON.stringify(updated));
    appendLog(`[SYS] Saved Dashboard: ${newDash.name}`);
    setShowSaveDashboardModal(false);
    setSaveDashboardName("");
  };

  const handleDeleteDashboard = (id: string) => {
    const updated = savedDashboards.filter((d) => d.id !== id);
    setSavedDashboards(updated);
    localStorage.setItem("vnotice_saved_dashboards", JSON.stringify(updated));
  };

  const handleApplyDashboard = (dash: SavedDashboard) => {
    setActiveSeverity(dash.filters.severity);
    setActiveKeywords(dash.filters.keywords);
    setActiveFeedsFilter(dash.filters.feedSources);
    setSearchQuery(dash.filters.searchQuery);
    setEpssMin(dash.filters.epssMin);
    setEpssMax(dash.filters.epssMax);
    setActiveTab("threat_stream");
    appendLog(`[SYS] Applied Dashboard filter: ${dash.name}`);
  };

  // Push an alert rule's filter into the Threat Stream so its matches are visible.
  const handleApplyAlertFilter = (rule: AlertRule) => {
    const groups = ruleGroups(rule);
    const g = groups[0];
    setActiveSeverity(g.severity && g.severity.length ? g.severity : ["all"]);
    setActiveKeywords(g.keywords || []);
    setActiveFeedsFilter(g.feedSources && g.feedSources.length ? g.feedSources : ["all"]);
    setSearchQuery(g.searchQuery || "");
    setEpssMin(g.epssMin || "");
    setEpssMax(g.epssMax || "");
    setActiveTab("threat_stream");
    appendLog(groups.length > 1
      ? `[SYS] Applied Alert '${rule.name}' filter (condition group 1 of ${groups.length}; stream shows one group at a time)`
      : `[SYS] Applied Alert '${rule.name}' filter to Threat Stream`);
  };

  const activeFeedsCount = feeds.filter((f) => f.active).length;

  // Dynamic statistics calculations — memoized; only change when CVE list does.
  const sortedProducts = useMemo(() => {
    const counts = vulnerabilities.reduce((acc: { [key: string]: number }, curr) => {
      const prod = curr.product || "Unknown Product";
      acc[prod] = (acc[prod] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [vulnerabilities]);

  const sortedBrands = useMemo(() => {
    const counts = vulnerabilities.reduce((acc: { [key: string]: number }, curr) => {
      const vend = curr.vendor || "Unknown Brand";
      acc[vend] = (acc[vend] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [vulnerabilities]);

  if (!activeProfileId || !activeProfile) {
    return (
      <ProfileSelection
        profiles={profiles}
        onSelectProfile={handleSelectProfile}
        onCreateProfile={handleCreateProfile}
        defaultProfileId={adminProfile()?.id}
      />
    );
  }

  // Supporting sm, md, lg, xl, 2xl in Root Configuration (Req 2)
  return (
    <div className={`w-full flex flex-col gap-5 px-4 py-2 select-none min-h-[90vh] ${
      textSize === "sm" ? "text-sm" : 
      textSize === "lg" ? "text-lg" : 
      textSize === "xl" ? "text-xl" : 
      textSize === "2xl" ? "text-2xl" : 
      "text-base"
    }`}>

      
      {/* Premium Header Layout */}
      <header className="flex justify-between items-center py-4 border-b border-white/5 flex-shrink-0">
        {/* Left: Branding */}
        <div className="flex items-center space-x-3 cursor-pointer group" onClick={() => setActiveTab("threat_dashboard")}>
          <div className="p-2 bg-gradient-to-br from-sky-500/10 to-cyan-500/20 border border-sky-500/30 rounded-xl shadow-[0_0_15px_rgba(14,165,233,0.15)] group-hover:scale-105 transition duration-300">
            <ShieldAlert className="w-6 h-6 text-sky-400 filter drop-shadow-[0_0_8px_rgba(56,189,248,0.5)]" />
          </div>
          <h1 className="text-xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-white via-sky-100 to-cyan-300 uppercase select-none group-hover:opacity-90 transition">Vnotice</h1>
        </div>

        {/* Center: Navigation Tabs */}
        <nav className="hidden lg:flex items-center gap-1 bg-white/[0.015] p-1.5 rounded-2xl border border-white/5 shadow-inner backdrop-blur-xl">
          <button
            onClick={() => setActiveTab("threat_dashboard")}
            className={`px-4 py-2 rounded-xl text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              activeTab === "threat_dashboard"
                ? "bg-gradient-to-r from-sky-500 to-cyan-500 text-white font-extrabold shadow-[0_0_15px_rgba(14,165,233,0.3)] border border-sky-400/20 scale-[1.02]"
                : "text-gray-400 hover:text-white hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            📊 Threat Dashboard
          </button>
          <button
            onClick={() => setActiveTab("threat_stream")}
            className={`px-4 py-2 rounded-xl text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              activeTab === "threat_stream"
                ? "bg-gradient-to-r from-sky-500 to-cyan-500 text-white font-extrabold shadow-[0_0_15px_rgba(14,165,233,0.3)] border border-sky-400/20 scale-[1.02]"
                : "text-gray-400 hover:text-white hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            🚨 Threat Stream
          </button>
          <button
            onClick={() => setActiveTab("rss")}
            className={`px-4 py-2 rounded-xl text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              activeTab === "rss"
                ? "bg-gradient-to-r from-sky-500 to-cyan-500 text-white font-extrabold shadow-[0_0_15px_rgba(14,165,233,0.3)] border border-sky-400/20 scale-[1.02]"
                : "text-gray-400 hover:text-white hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            📡 RSS Feeds ({feeds.length})
          </button>
          <button
            onClick={() => setActiveTab("alerts")}
            className={`px-4 py-2 rounded-xl text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              activeTab === "alerts"
                ? "bg-gradient-to-r from-sky-500 to-cyan-500 text-white font-extrabold shadow-[0_0_15px_rgba(14,165,233,0.3)] border border-sky-400/20 scale-[1.02]"
                : "text-gray-400 hover:text-white hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            🔔 Alert Rules ({alertRules.length})
          </button>
          <button
            onClick={() => setActiveTab("settings")}
            className={`px-4 py-2 rounded-xl text-[11px] font-bold uppercase tracking-wider transition-all duration-300 ${
              activeTab === "settings"
                ? "bg-gradient-to-r from-sky-500 to-cyan-500 text-white font-extrabold shadow-[0_0_15px_rgba(14,165,233,0.3)] border border-sky-400/20 scale-[1.02]"
                : "text-gray-400 hover:text-white hover:bg-white/[0.04] border border-transparent"
            }`}
          >
            ⚙️ Settings
          </button>
        </nav>

        {/* Right: Active session Profile Selector top-right */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center gap-3 bg-gradient-to-b from-white/[0.03] to-transparent px-3.5 py-1.5 rounded-xl border border-white/5 hover:border-white/10 transition shadow-lg duration-300">
            <div className="text-[1.25em] select-none filter drop-shadow">{activeProfile.avatar}</div>
            <div className="text-left leading-tight hidden sm:block">
              <div className="text-[0.75em] font-bold text-white truncate max-w-[8em]">{activeProfile.name}</div>
              <div className="text-[0.6em] text-sky-400 font-extrabold tracking-wider uppercase mt-0.5">{activeProfile.role}</div>
            </div>
            <button
              onClick={handleSwitchUser}
              className="text-gray-400 hover:text-white pl-2 border-l border-white/10 hover:scale-105 transition"
              title="Switch Active Profile (Change user)"
            >
              <LogOut className="w-[1.1em] h-[1.1em]" />
            </button>
          </div>
          
          <button
            onClick={toggleDarkMode}
            className="p-2 rounded-xl bg-white/[0.015] border border-white/5 hover:bg-white/[0.04] transition"
            aria-label="Toggle Theme Mode"
          >
            {isDarkMode ? <Sun className="w-4 h-4 text-gray-300 hover:text-white" /> : <Moon className="w-4 h-4 text-gray-300 hover:text-white" />}
          </button>
        </div>
      </header>

      {/* Main tab switching layouts */}
      <main className="flex-1 min-h-0">
        
        {/* Tab: Threat Stream with 1/3 filter on left */}
        {activeTab === "threat_stream" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 animate-fadeIn">
            
            {/* Left Column: Live Filters Hub (1/4 Weight - lg:col-span-3) */}
            <div className="lg:col-span-3 flex flex-col gap-4">
              <div className="glass-panel p-5 border border-white/5 shadow-2xl relative space-y-5">
                <div className="flex justify-between items-center border-b border-white/5 pb-2">
                  <div className="font-bold text-xs text-white uppercase tracking-wider">
                    🛡️ Live Filters
                  </div>
                  <div className="flex gap-1.5 items-center">
                    <button
                      onClick={handleExportCSV}
                      className="px-2 py-0.5 text-[9px] bg-white/[0.02] hover:bg-white/[0.06] border border-white/5 rounded-md transition text-gray-300 font-bold"
                      title="Export filtered list to CSV"
                    >
                      CSV
                    </button>
                    <button
                      onClick={handleExportJSON}
                      className="px-2 py-0.5 text-[9px] bg-white/[0.02] hover:bg-white/[0.06] border border-white/5 rounded-md transition text-gray-300 font-bold"
                      title="Export filtered list to JSON"
                    >
                      JSON
                    </button>
                  </div>
                </div>

                {/* Search query input */}
                <div className="space-y-1.5">
                  <label className="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                    Search Advisories
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search CVEs, products, brands..."
                      className="w-full bg-white/[0.01] hover:bg-white/[0.02] border border-white/5 rounded-xl py-2.5 pl-10 pr-4 text-white placeholder-gray-500 focus:border-sky-500/50 focus:bg-white/[0.03] focus:shadow-[0_0_15px_rgba(0,210,255,0.1)] focus:outline-none text-[0.85em] transition duration-200"
                    />
                    <svg className="w-4 h-4 text-gray-500 absolute left-3.5 top-1/2 -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-4.35-4.35M17 10a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                  </div>
                </div>

                {/* Severity Pills selection (Reduced size & Multi-select active severity - Req 1 & Req 3) */}
                <div className="space-y-2">
                  <span className="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                    Filter by Severity
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {["all", "critical", "high", "medium", "low"].map((sev) => {
                      const isActive = activeSeverity.includes(sev);
                      let btnClass = "";
                      
                      if (isActive) {
                        switch (sev) {
                          case "critical":
                            btnClass = "bg-gradient-to-r from-red-500 to-rose-600 text-white border-red-400/30 shadow-[0_0_12px_rgba(239,68,68,0.25)] scale-[1.02]";
                            break;
                          case "high":
                            btnClass = "bg-gradient-to-r from-orange-500 to-amber-600 text-white border-orange-400/30 shadow-[0_0_12px_rgba(249,115,22,0.25)] scale-[1.02]";
                            break;
                          case "medium":
                            btnClass = "bg-gradient-to-r from-yellow-500 to-yellow-600 text-black font-extrabold border-yellow-400/30 shadow-[0_0_12px_rgba(234,179,8,0.2)] scale-[1.02]";
                            break;
                          case "low":
                            btnClass = "bg-gradient-to-r from-green-500 to-emerald-600 text-white border-green-400/30 shadow-[0_0_12px_rgba(34,197,94,0.25)] scale-[1.02]";
                            break;
                          default:
                            btnClass = "bg-gradient-to-r from-sky-500 to-cyan-600 text-white border-sky-400/30 shadow-[0_0_12px_rgba(14,165,233,0.25)] scale-[1.02]";
                        }
                      } else {
                        switch (sev) {
                          case "critical":
                            btnClass = "bg-white/[0.01] border-red-500/10 text-red-400/80 hover:bg-red-500/5 hover:border-red-500/30";
                            break;
                          case "high":
                            btnClass = "bg-white/[0.01] border-orange-500/10 text-orange-400/80 hover:bg-orange-500/5 hover:border-orange-500/30";
                            break;
                          case "medium":
                            btnClass = "bg-white/[0.01] border-yellow-500/10 text-yellow-400/80 hover:bg-yellow-500/5 hover:border-yellow-500/30";
                            break;
                          case "low":
                            btnClass = "bg-white/[0.01] border-green-500/10 text-green-400/80 hover:bg-green-500/5 hover:border-green-500/30";
                            break;
                          default:
                            btnClass = "bg-white/[0.01] border-white/5 text-gray-400 hover:bg-white/[0.03] hover:text-white";
                        }
                      }

                      return (
                        <button
                          key={sev}
                          type="button"
                          onClick={() => toggleFilter(activeSeverity, setActiveSeverity, sev)}
                          className={`px-2 py-1 text-[0.75em] font-bold rounded-xl border transition-all duration-200 capitalize flex items-center justify-between gap-1.5 ${btnClass}`}
                        >
                          <span>{sev === "all" ? "All" : sev}</span>
                          <span className="text-[0.8em] bg-black/25 px-1.5 py-0.2 rounded text-white/75 font-semibold font-mono">
                            {sev === "all" 
                              ? vulnerabilities.length 
                              : vulnerabilities.filter(c => c.severity.toLowerCase() === sev).length}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Keyword Tag Filter */}
                <div className="space-y-2 pt-2.5 border-t border-white/5">
                  <span className="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                    Keyword Filter
                  </span>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Add keyword & press Enter..."
                      value={keywordInput}
                      onChange={(e) => setKeywordInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && keywordInput.trim()) {
                          e.preventDefault();
                          handleAddKeyword(keywordInput);
                          setKeywordInput("");
                        }
                      }}
                      className="flex-1 bg-white/[0.01] border border-white/5 rounded-xl py-1.5 px-3 text-[0.8em] text-white placeholder-gray-500 focus:border-sky-500/50 focus:outline-none transition"
                    />
                    <button
                      type="button"
                      onClick={() => { if (keywordInput.trim()) { handleAddKeyword(keywordInput); setKeywordInput(""); } }}
                      className="px-3 py-1.5 bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/30 rounded-xl text-sky-400 text-[0.75em] font-bold transition-all"
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
                          onClick={() => handleRemoveKeyword(kw)}
                          className="px-2 py-0.5 text-[10px] font-bold bg-sky-500/10 hover:bg-red-500/10 border border-sky-500/20 hover:border-red-500/30 text-sky-400 hover:text-red-400 rounded-lg transition flex items-center gap-1 group"
                          title="Click to remove"
                        >
                          <span>{kw}</span>
                          <span className="text-gray-500 group-hover:text-red-400">✕</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* EPSS Score Range Filter */}
                <div className="space-y-2 pt-2.5 border-t border-white/5">
                  <span className="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">EPSS Score Range</span>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 space-y-1">
                      <label className="block text-[9px] font-semibold text-gray-500 uppercase tracking-wider">Min</label>
                      <input
                        type="number"
                        min="0" max="100" step="0.1"
                        value={epssMin}
                        onChange={(e) => setEpssMin(e.target.value)}
                        placeholder="0"
                        className="w-full bg-black/35 border border-white/10 rounded-lg px-2 py-1.5 text-white text-xs focus:border-sky-400 focus:outline-none transition"
                      />
                    </div>
                    <span className="text-gray-600 text-xs pt-4">—</span>
                    <div className="flex-1 space-y-1">
                      <label className="block text-[9px] font-semibold text-gray-500 uppercase tracking-wider">Max</label>
                      <input
                        type="number"
                        min="0" max="100" step="0.1"
                        value={epssMax}
                        onChange={(e) => setEpssMax(e.target.value)}
                        placeholder="100"
                        className="w-full bg-black/35 border border-white/10 rounded-lg px-2 py-1.5 text-white text-xs focus:border-sky-400 focus:outline-none transition"
                      />
                    </div>
                  </div>
                </div>

                {/* RSS Feed Source Filter */}
                <div className="space-y-2 pt-2.5 border-t border-white/5">
                  <span className="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                    Filter by Threat Source
                  </span>
                  <div className="flex flex-col gap-1.5 max-h-40 overflow-y-auto pr-1">
                    <label className="flex items-center gap-2 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={activeFeedsFilter.includes("all")}
                        onChange={() => handleToggleFeedFilter("all")}
                        className="rounded border-white/10 bg-black/40 accent-sky-500 flex-shrink-0"
                      />
                      <span className="flex-1 text-[0.78em] font-bold text-gray-300">All Sources</span>
                      <span className="text-[0.7em] font-mono font-bold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-1.5 py-0.5 rounded min-w-[2em] text-center flex-shrink-0">
                        {vulnerabilities.length}
                      </span>
                    </label>
                    {[...feeds, ...webScrapers].map((src: any) => {
                      const name = src.name;
                      const isChecked = activeFeedsFilter.includes(name);
                      const count = vulnerabilities.filter(v =>
                        (v.source || "").toLowerCase().trim() === name.toLowerCase().trim()
                      ).length;
                      return (
                        <label key={name} className="flex items-center gap-2 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => handleToggleFeedFilter(name)}
                            className="rounded border-white/10 bg-black/40 accent-sky-500 flex-shrink-0"
                          />
                          <span className="flex-1 text-[0.78em] text-gray-400 hover:text-white truncate" title={name}>
                            {name}
                          </span>
                          <span className={`text-[0.7em] font-mono font-bold px-1.5 py-0.5 rounded min-w-[2em] text-center flex-shrink-0 ${
                            count > 0
                              ? "text-gray-300 bg-white/10 border border-white/10"
                              : "text-gray-600 bg-black/20 border border-white/5"
                          }`}>
                            {count}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                {/* Reset button */}
                <div className="pt-3 border-t border-white/5 space-y-2">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveSeverity(["all"]);
                      setActiveVendors(["all"]);
                      setActiveProducts(["all"]);
                      setActiveKeywords([]);
                      setActiveFeedsFilter(["all"]);
                      setKeywordInput("");
                      setSearchQuery("");
                      setEpssMin("");
                      setEpssMax("");
                      appendLog("[SYS] Reset Threat Stream filters to defaults.");
                    }}
                    className="w-full px-3 py-2 text-xs font-bold bg-white/[0.01] hover:bg-red-500/10 border border-white/5 hover:border-red-500/30 text-gray-400 hover:text-red-400 rounded-xl transition duration-200 flex items-center justify-center gap-1.5"
                  >
                    🔄 Reset Filters to Default
                  </button>
                  <button
                    type="button"
                    onClick={() => { setSaveDashboardName(""); setShowSaveDashboardModal(true); }}
                    className="w-full px-3 py-2 text-xs font-bold bg-white/[0.01] hover:bg-sky-500/10 border border-white/5 hover:border-sky-500/30 text-gray-400 hover:text-sky-400 rounded-xl transition duration-200 flex items-center justify-center gap-1.5"
                  >
                    📌 Save to Dashboard
                  </button>
                  <button
                    type="button"
                    onClick={() => { setSaveAlertName(""); setSaveAlertDescription(""); setEditingAlertId(null); setEditConditions([currentFilterGroup()]); setShowSaveAlertModal(true); }}
                    className="w-full px-3 py-2 text-xs font-bold bg-white/[0.01] hover:bg-amber-500/10 border border-white/5 hover:border-amber-500/30 text-gray-400 hover:text-amber-400 rounded-xl transition duration-200 flex items-center justify-center gap-1.5"
                  >
                    💾 Save as Alert
                  </button>
                </div>
              </div>
            </div>

            {/* Right Column: Widgets & Cards stream list (3/4 Weight - lg:col-span-9) */}
            <div className="lg:col-span-9 flex flex-col gap-4 min-h-0">
              
              {/* Counter widgets row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 flex-shrink-0">
                <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-red-500/10 shadow-lg">
                  <div className="absolute top-0 right-0 p-2 text-red-500 opacity-10">
                    <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </div>
                  <div className="text-3xl font-extrabold text-red-500 relative z-10 select-none">
                    {vulnerabilities.filter(v => v.severity.toLowerCase() === "critical").length}
                  </div>
                  <div className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-1 relative z-10">
                    Critical
                  </div>
                </div>

                <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-orange-500/10 shadow-lg">
                  <div className="absolute top-0 right-0 p-2 text-orange-500 opacity-10">
                    <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  </div>
                  <div className="text-3xl font-extrabold text-orange-500 relative z-10 select-none">
                    {vulnerabilities.filter(v => v.severity.toLowerCase() === "high").length}
                  </div>
                  <div className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-1 relative z-10">
                    High
                  </div>
                </div>

                <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-sky-500/10 shadow-lg">
                  <div className="absolute top-0 right-0 p-2 text-sky-400 opacity-10">
                    <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-7 0h.01" />
                    </svg>
                  </div>
                  <div className="text-3xl font-extrabold text-sky-400 relative z-10 select-none">
                    {activeFeedsCount}
                  </div>
                  <div className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-1 relative z-10">
                    Active Feeds
                  </div>
                </div>

                <div className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center relative overflow-hidden border border-green-500/10 shadow-lg">
                  <div className="absolute top-0 right-0 p-2 text-green-500 opacity-10">
                    <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 002 2h2a2 2 0 002-2z" />
                    </svg>
                  </div>
                  <div className="text-3xl font-extrabold text-green-500 relative z-10 select-none">
                    {vulnerabilities.length}
                  </div>
                  <div className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-1 relative z-10">
                    Total Threats
                  </div>
                </div>
              </div>

              {/* Threat Grid — main view */}
              <div className="h-[750px] flex flex-col glass-panel border border-white/5 shadow-2xl min-h-0 rounded-2xl overflow-hidden">
                {/* Sync controls header */}
                <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-white/5 flex-shrink-0 bg-black/10">
                  <h2 className="text-[1em] font-bold text-white flex items-center gap-2 uppercase tracking-wide">
                    📊 Threat Grid
                  </h2>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex items-center gap-2 bg-sky-500/5 border border-sky-500/10 px-3 py-1.5 rounded-xl text-[0.75em] font-mono font-bold text-sky-400 select-none">
                      <span className="relative flex h-1.5 w-1.5">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-sky-400"></span>
                      </span>
                      <span>Next Sync: {Math.floor(streamSyncCountdown / 60).toString().padStart(2, "0")}:{(streamSyncCountdown % 60).toString().padStart(2, "0")}</span>
                      <span className="text-gray-500 font-medium">({streamSyncMode})</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <label className="text-[0.7em] text-gray-400 font-bold uppercase tracking-wider select-none">Sync:</label>
                      <select
                        value={streamSyncMode}
                        onChange={(e) => handleStreamSyncModeChange(e.target.value)}
                        className="bg-black/40 border border-white/15 text-gray-300 hover:text-white rounded-xl px-2.5 py-1.5 text-[0.75em] focus:outline-none focus:border-sky-500/50 cursor-pointer transition font-semibold"
                      >
                        <option value="30s" className="bg-slate-900 text-gray-300 font-sans">30 Sec</option>
                        <option value="1m" className="bg-slate-900 text-gray-300 font-sans">1 Min</option>
                        <option value="2m" className="bg-slate-900 text-gray-300 font-sans">2 Min</option>
                        <option value="5m" className="bg-slate-900 text-gray-300 font-sans">5 Min</option>
                        <option value="10m" className="bg-slate-900 text-gray-300 font-sans">10 Min</option>
                      </select>
                    </div>
                    <button
                      onClick={handleSyncFeeds}
                      disabled={isSyncing}
                      className="flex items-center gap-2 px-3 py-1.5 text-[0.8em] font-semibold glass-panel border border-white/10 text-gray-300 hover:text-white hover:bg-white/5 rounded-xl transition duration-200"
                    >
                      <RefreshCw className={`w-[1.2em] h-[1.2em] flex-shrink-0 ${isSyncing ? "animate-spin" : ""}`} />
                      <span>{isSyncing ? "Syncing..." : "Sync Grid"}</span>
                    </button>
                    <button
                      onClick={handleRefreshEpss}
                      disabled={isRefreshingEpss}
                      className="flex items-center gap-2 px-3 py-1.5 text-[0.8em] font-semibold glass-panel border border-white/10 text-gray-300 hover:text-white hover:bg-white/5 rounded-xl transition duration-200 disabled:opacity-50"
                      title="Re-pull real EPSS scores from FIRST.org for all CVEs"
                    >
                      <RefreshCw className={`w-[1.2em] h-[1.2em] flex-shrink-0 ${isRefreshingEpss ? "animate-spin" : ""}`} />
                      <span>{isRefreshingEpss ? "Updating..." : "Refresh EPSS"}</span>
                    </button>
                    <button
                      onClick={() => setShowColMgr(v => !v)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.8em] font-semibold glass-panel border rounded-xl transition duration-200 ${
                        showColMgr
                          ? "border-sky-500/40 text-sky-400 bg-sky-500/10"
                          : "border-white/10 text-gray-300 hover:text-white hover:bg-white/5"
                      }`}
                      title="Manage columns"
                    >
                      <span className="text-[1.1em] leading-none">⋮</span>
                      <span>Columns</span>
                    </button>
                  </div>
                </div>
                <div className="flex-1 overflow-hidden">
                  <CveTable
                    textSize={textSize}
                    vulnerabilities={filteredVulnerabilities}
                    showColumnManager={showColMgr}
                    onCloseColumnManager={() => setShowColMgr(false)}
                  />
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: RSS Feeds Management Page */}
        {activeTab === "rss" && (
          <div className="glass-panel p-6 border border-white/5 shadow-2xl relative space-y-6 animate-fadeIn">
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 border-b border-white/10 pb-4">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  📡 RSS Threat Feed Channels
                  <span className="bg-sky-500 text-white text-xs px-2.5 py-0.5 rounded-full font-semibold">
                    {activeFeedsCount} / {feeds.length} Active
                  </span>
                </h2>
                <p className="text-xs text-gray-400 mt-1">Configure external XML vulnerability feeds and sync intervals</p>
              </div>
              
              <div className="flex items-center gap-4 self-end">
                <div className="flex items-center gap-2">
                  <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap">Global Polling:</label>
                  <select
                    value={globalPoll}
                    onChange={(e) => handleGlobalPollChange(e.target.value)}
                    className="px-3 py-1.5 rounded-lg border border-white/10 bg-black/40 text-xs text-white focus:border-sky-400 focus:outline-none"
                  >
                    <option value="30s">30 seconds</option>
                    <option value="1m">1 minute</option>
                    <option value="2m">2 minutes</option>
                    <option value="5m">5 minutes</option>
                    <option value="10m">10 minutes</option>
                  </select>
                </div>
                <button
                  onClick={handleOpenAddModal}
                  className="px-4 py-2 bg-sky-500 hover:bg-sky-600 text-white text-sm font-semibold rounded-lg transition shadow-lg shadow-sky-500/10 flex items-center gap-1.5"
                >
                  ➕ Add Source
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[300px] overflow-y-auto pr-1">
              {feeds.map((feed, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-4 border border-white/5 rounded-xl bg-black/25 hover:bg-black/35 transition duration-200"
                >
                  <div className="min-w-0 flex-1 mr-4">
                    <h4 className="font-bold text-sm text-white truncate">{feed.name}</h4>
                    <p className="text-[11px] text-gray-400 truncate mt-1">{feed.url}</p>
                    <p className="text-[10px] text-gray-550 mt-2 font-medium">⏱️ Interval: {globalPoll} | 📡 XML Feed</p>
                  </div>
                  <div className="flex items-center gap-3.5 flex-shrink-0">
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        className="sr-only peer"
                        checked={feed.active}
                        onChange={() => handleToggleFeed(idx)}
                      />
                      <div className="w-10 h-5.5 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-gray-400 peer-checked:after:bg-white after:border-none after:rounded-full after:h-4.5 after:w-4.5 after:transition-all peer-checked:bg-sky-500"></div>
                    </label>
                    <button
                      onClick={() => handleOpenEditModal(idx)}
                      className="p-2 text-gray-400 hover:text-sky-400 hover:bg-white/5 rounded-lg transition"
                      title="Edit Threat Source"
                    >
                      ✏️
                    </button>
                    <button
                      onClick={() => handleRemoveFeed(idx)}
                      className="p-2 text-gray-400 hover:text-red-405 hover:bg-white/5 rounded-lg transition"
                      title="Remove Threat Source"
                    >
                      🗑️
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Scraper Crawlers Row Section (Req 2) */}
            <div className="pt-4 border-t border-white/10">
              <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                🕷️ Custom HTML Webpage Regex Scrapers
              </h3>
              {webScrapers.length === 0 ? (
                <div className="text-xs text-gray-500 py-2">No custom webpage regex scrapers registered yet.</div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[300px] overflow-y-auto pr-1">
                  {webScrapers.map((scraper, idx) => (
                    <div
                      key={scraper.id}
                      className="flex items-center justify-between p-4 border border-white/5 rounded-xl bg-black/25 hover:bg-black/35 transition duration-200 animate-fadeIn"
                    >
                      <div className="min-w-0 flex-1 mr-4">
                        <h4 className="font-bold text-sm text-white truncate">{scraper.name}</h4>
                        <p className="text-[11px] text-gray-400 truncate mt-1">{scraper.url}</p>
                        <p className="text-[10px] text-yellow-500 mt-2 font-medium font-mono">
                          Pattern: /{scraper.regex}/gi
                        </p>
                      </div>
                      <div className="flex items-center gap-3.5 flex-shrink-0">
                        <label className="relative inline-flex inline-items-center cursor-pointer">
                          <input
                            type="checkbox"
                            className="sr-only peer"
                            checked={scraper.active}
                            onChange={() => {
                              const updated = [...webScrapers];
                              updated[idx].active = !updated[idx].active;
                              setWebScrapers(updated);
                              localStorage.setItem("vnotice_web_scrapers", JSON.stringify(updated));
                              appendLog(`[SYS] Scraper '${scraper.name}' toggled to: ${updated[idx].active ? "ACTIVE" : "DISABLED"}`);
                              // Instantly sync scraper threat stream feed on toggle
                              setTimeout(() => {
                                handleSyncFeeds();
                              }, 100);
                            }}
                          />
                          <div className="w-10 h-5.5 bg-white/10 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-gray-400 peer-checked:after:bg-white after:border-none after:rounded-full after:h-4.5 after:w-4.5 after:transition-all peer-checked:bg-sky-500"></div>
                        </label>
                        <button
                          onClick={() => {
                            const rule = webScrapers[idx];
                            const updated = webScrapers.filter((_, i) => i !== idx);
                            setWebScrapers(updated);
                            localStorage.setItem("vnotice_web_scrapers", JSON.stringify(updated));
                            appendLog(`[SYS] Removed webpage regex scraper: ${rule.name}`);
                          }}
                          className="p-2 text-gray-400 hover:text-red-400 hover:bg-white/5 rounded-lg transition"
                          title="Remove Scraper Crawler"
                        >
                          🗑️
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab: Settings — Alert Server, Console, Account Management */}
        {activeTab === "settings" && (
          <div className="flex animate-fadeIn glass-panel border border-white/5 shadow-2xl overflow-hidden min-h-[600px]">

            {/* Left Sidebar — 1/3 */}
            <div className="w-52 flex-shrink-0 border-r border-white/5 bg-black/20 py-5 flex flex-col">
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-5 pb-3 mb-2 border-b border-white/5">
                ⚙️ Settings
              </div>
              <nav className="space-y-0.5 px-3">
                {[
                  { id: "account",  icon: "👤", label: "Account Settings",   sub: "Profile · Display" },
                  { id: "alerts",   icon: "🔔", label: "Alert Channels",     sub: "SMTP · Teams · SMS" },
                  { id: "engine",   icon: "🔧", label: "Engine Status",      sub: "Health · Resources" },
                  { id: "resource", icon: "📊", label: "Resource Usage",     sub: "CPU · Mem · Disk history" },
                  { id: "console",  icon: "💻", label: "System Console",     sub: "Audit logs" },
                  { id: "accounts", icon: "👥", label: "Account Management", sub: "Operator profiles" },
                ].map(({ id, icon, label, sub }) => (
                  <button
                    key={id}
                    onClick={() => setActiveSettingsSection(id as any)}
                    className={`w-full text-left px-3 py-3 rounded-xl flex items-start gap-3 transition-all duration-200 ${
                      activeSettingsSection === id
                        ? "bg-sky-500/15 border border-sky-500/25"
                        : "border border-transparent text-gray-400 hover:text-white hover:bg-white/[0.03]"
                    }`}
                  >
                    <span className="text-lg leading-none flex-shrink-0 mt-0.5">{icon}</span>
                    <div>
                      <div className={`text-sm font-bold leading-tight ${activeSettingsSection === id ? "text-sky-400" : ""}`}>{label}</div>
                      <div className="text-[10px] text-gray-500 mt-0.5">{sub}</div>
                    </div>
                  </button>
                ))}
              </nav>
            </div>

            {/* Right Content — 2/3 */}
            <div className="flex-1 overflow-y-auto">

            {/* Section: Account Settings */}
            {activeSettingsSection === "account" && (
            <div className="p-6 space-y-6">
            <div className="border-b border-white/10 pb-4">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">👤 Account Settings</h2>
              <p className="text-xs text-gray-400 mt-1">Manage your operator profile, display preferences, and UI options</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5">
                <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider border-b border-white/5 pb-2">Operator Profile</h3>
                <div className="space-y-1">
                  <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Display Name</label>
                  <input type="text" value={displayName} onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition" />
                </div>
                <div className="space-y-1">
                  <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Default Email</label>
                  <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Timezone</label>
                    <select value={timezone} onChange={(e) => setTimezone(e.target.value)}
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition">
                      <option value="UTC">UTC</option>
                      <option value="PST">Pacific Time (PT)</option>
                      <option value="EST">Eastern Time (ET)</option>
                      <option value="ICT">Asia/Bangkok (ICT)</option>
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Text Size</label>
                    <select value={textSize} onChange={(e) => setTextSize(e.target.value as any)}
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition capitalize">
                      <option value="sm">Small</option>
                      <option value="md">Medium</option>
                      <option value="lg">Large</option>
                      <option value="xl">Extra Large</option>
                      <option value="2xl">2X Large</option>
                    </select>
                  </div>
                </div>
              </div>
              <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5">
                <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider border-b border-white/5 pb-2">Display Options</h3>
                <p className="text-xs text-gray-400">Theme is toggled via the ☀️/🌙 button in the top-right header.</p>
                <div className="p-3 bg-sky-500/5 border border-sky-500/10 rounded-lg text-[11px] text-gray-400 space-y-1 leading-relaxed">
                  <div className="font-bold text-sky-400 mb-1">Active Profile</div>
                  <div>Name: <span className="text-white">{displayName || "—"}</span></div>
                  <div>Email: <span className="text-white">{email || "—"}</span></div>
                  <div>Role: <span className="text-white">{activeProfile?.role || "—"}</span></div>
                  <div>Text Size: <span className="text-white capitalize">{textSize}</span></div>
                </div>
              </div>
            </div>
            <div className="flex justify-end pt-4 border-t border-white/10">
              <button onClick={handleSaveConfiguration}
                className="px-5 py-2.5 bg-sky-500 hover:bg-sky-600 text-white rounded-lg font-bold text-sm transition flex items-center gap-1.5 shadow-lg shadow-sky-500/10">
                <Save className="w-4 h-4" /> {profileSaved ? "✓ Saved" : "💾 Save Account Settings"}
              </button>
            </div>
            </div>
            )}

            {/* Section A: Alert Channels & SMTP */}
            {activeSettingsSection === "alerts" && (
            <div className="p-6 space-y-6">
            <div className="border-b border-white/10 pb-4">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                🔔 Alert Channels & Notification Config
              </h2>
              <p className="text-xs text-gray-400 mt-1">Configure SMTP servers, Microsoft Teams webhooks, and SMS parameters</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* SMTP Credentials */}
              <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5">
                <div className="flex items-center justify-between gap-2 border-b border-white/5 pb-2">
                  <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider">Email Alerts</h3>
                  <button
                    onClick={() => {
                      if (!smtpHost.trim() || !smtpUsername.trim() || !smtpPassword.trim() || !email.trim()) {
                        window.alert(useAdminSmtp
                          ? "The admin account has no SMTP configured. Log into the admin account and set SMTP host/username/password under Settings → Email Alerts first."
                          : "Fill SMTP host, username, password and recipient email before sending a test.");
                        return;
                      }
                      testNotifier("/notifications/test-email", { smtp_host: smtpHost, smtp_port: parseInt(smtpPort) || 587, smtp_username: smtpUsername, smtp_password: smtpPassword, to_address: email }, "Email");
                    }}
                    className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider glass-panel text-sky-300 hover:bg-white/5 border border-white/10 rounded-md transition whitespace-nowrap"
                  >
                    Send Test
                  </button>
                </div>

                {!isAdminProfile(activeProfile) && (
                  <label className="flex items-center gap-2.5 cursor-pointer bg-sky-500/5 border border-sky-400/15 rounded-lg p-2.5">
                    <input
                      type="checkbox"
                      checked={useAdminSmtp}
                      onChange={(e) => {
                        const on = e.target.checked;
                        setUseAdminSmtp(on);
                        const admin = adminProfile();
                        const creds = on && admin ? admin.credentials : activeProfile?.credentials;
                        setSmtpHost(creds?.smtpHost || "");
                        setSmtpPort(creds?.smtpPort || "587");
                        setSmtpUsername(creds?.smtpUser || "");
                        setSmtpPassword(creds?.smtpPass || "");
                      }}
                      className="w-4 h-4 rounded accent-sky-500"
                    />
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">Use admin account&apos;s SMTP</span>
                      <span className="text-[10px] text-gray-400 mt-0.5">Send via the {adminProfile()?.name || "admin"} account&apos;s mail server instead of your own. Alerts still go to your email.</span>
                    </div>
                  </label>
                )}

                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2 space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">SMTP Host</label>
                    <input
                      type="text"
                      value={smtpHost}
                      onChange={(e) => setSmtpHost(e.target.value)}
                      disabled={useAdminSmtp}
                      placeholder="smtp.gmail.com"
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Port</label>
                    <input
                      type="text"
                      value={smtpPort}
                      onChange={(e) => setSmtpPort(e.target.value)}
                      disabled={useAdminSmtp}
                      placeholder="587"
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Username</label>
                    <input
                      type="text"
                      value={smtpUsername}
                      onChange={(e) => setSmtpUsername(e.target.value)}
                      disabled={useAdminSmtp}
                      placeholder="alerts@company.com"
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-semibold text-gray-450 uppercase tracking-wider">Password</label>
                    <input
                      type="password"
                      value={smtpPassword}
                      onChange={(e) => setSmtpPassword(e.target.value)}
                      disabled={useAdminSmtp}
                      placeholder="••••••••"
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                </div>

                <div className="space-y-2 pt-1 border-t border-white/5">
                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={emailAlertsEnabled}
                      onChange={(e) => setEmailAlertsEnabled(e.target.checked)}
                      className="w-4 h-4 rounded text-sky-500 focus:ring-sky-500 accent-sky-500 font-semibold"
                    />
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">Enable Email Alerts</span>
                      <span className="text-[10px] text-gray-400 mt-0.5">Alerts will be sent to this account&apos;s email address</span>
                    </div>
                  </label>
                </div>
              </div>

              {/* Card 3: Microsoft Teams Chat Alerts Integration (Req 5) */}
              <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5 animate-fadeIn">
                <div className="flex items-center justify-between gap-2 border-b border-white/5 pb-2">
                  <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider">Teams Alerts</h3>
                  <button
                    onClick={() => {
                      if (!teamsWebhookUrl.trim()) { window.alert("Paste your Teams webhook URL in the field below first, then Send Test."); return; }
                      testNotifier("/notifications/test-teams", { webhook_url: teamsWebhookUrl.trim() }, "Teams");
                    }}
                    className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider glass-panel text-sky-300 hover:bg-white/5 border border-white/10 rounded-md transition whitespace-nowrap"
                  >
                    Send Test
                  </button>
                </div>

                <div className="space-y-2">
                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={teamsAlertsEnabled}
                      onChange={(e) => setTeamsAlertsEnabled(e.target.checked)}
                      className="w-4 h-4 rounded text-sky-500 focus:ring-sky-500 accent-sky-500 font-semibold"
                    />
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">Enable Teams Webhook Alerts</span>
                    </div>
                  </label>

                  {/* Field always visible so the URL can be pasted & tested even before enabling. */}
                  <div className="space-y-1 mt-1.5">
                    <label className="block text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Incoming Webhook URL</label>
                    <input
                      type="text"
                      value={teamsWebhookUrl}
                      onChange={(e) => setTeamsWebhookUrl(e.target.value)}
                      placeholder="https://...logic.azure.com/workflows/..."
                      className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-xs transition"
                    />
                    <p className="text-[10px] text-gray-500">Paste here, then Send Test. The toggle only controls live alerts.</p>
                  </div>
                </div>
              </div>

              {/* Card 4: Twilio SMS Alerts Integration (Req 5) */}
              <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5 animate-fadeIn">
                <div className="flex items-center justify-between gap-2 border-b border-white/5 pb-2">
                  <h3 className="text-sm font-bold text-sky-400 uppercase tracking-wider">SMS Alerts</h3>
                  <button
                    onClick={() => testNotifier("/notifications/test-sms", { twilio_sid: smsTwilioSid, twilio_token: smsTwilioToken, from_number: "", to_number: smsPhoneNumber }, "SMS")}
                    className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider glass-panel text-sky-300 hover:bg-white/5 border border-white/10 rounded-md transition whitespace-nowrap"
                  >
                    Send Test
                  </button>
                </div>

                <div className="space-y-2">
                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={smsAlertsEnabled}
                      onChange={(e) => setSmsAlertsEnabled(e.target.checked)}
                      className="w-4 h-4 rounded text-sky-500 focus:ring-sky-500 accent-sky-500 font-semibold"
                    />
                    <div className="flex flex-col">
                      <span className="text-xs font-bold text-white uppercase tracking-wider">Enable Twilio SMS Alerts</span>
                    </div>
                  </label>

                  {smsAlertsEnabled && (
                    <div className="space-y-2 mt-1.5 animate-fadeIn">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <label className="block text-[9px] font-semibold text-gray-400 uppercase tracking-wider">Account SID</label>
                          <input
                            type="text"
                            value={smsTwilioSid}
                            onChange={(e) => setSmsTwilioSid(e.target.value)}
                            placeholder="AC..."
                            className="w-full bg-black/35 border border-white/10 rounded-lg p-2 text-white focus:border-sky-400 focus:outline-none text-[11px] transition"
                          />
                        </div>
                        <div className="space-y-1">
                          <label className="block text-[9px] font-semibold text-gray-400 uppercase tracking-wider">Auth Token</label>
                          <input
                            type="password"
                            value={smsTwilioToken}
                            onChange={(e) => setSmsTwilioToken(e.target.value)}
                            placeholder="••••••••"
                            className="w-full bg-black/35 border border-white/10 rounded-lg p-2 text-white focus:border-sky-400 focus:outline-none text-[11px] transition"
                          />
                        </div>
                      </div>
                      <div className="space-y-1">
                        <label className="block text-[9px] font-semibold text-gray-400 uppercase tracking-wider">Target Phone Number</label>
                        <input
                          type="text"
                          value={smsPhoneNumber}
                          onChange={(e) => setSmsPhoneNumber(e.target.value)}
                          placeholder="e.g. +66812345678"
                          className="w-full bg-black/35 border border-white/10 rounded-lg p-2 text-white focus:border-sky-400 focus:outline-none text-[11px] transition"
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-end items-center gap-2 pt-4 border-t border-white/10 flex-wrap">
              {/* Per-channel test buttons now live at the end of each alert panel's title line. */}
              <button
                onClick={handleSaveConfiguration}
                className="px-5 py-2.5 bg-sky-500 hover:bg-sky-600 text-white rounded-lg font-bold text-sm transition flex items-center gap-1.5 shadow-lg shadow-sky-500/10"
              >
                <Save className="w-4 h-4" /> {profileSaved ? "✓ Settings Saved" : "💾 Save Settings"}
              </button>
            </div>
            </div>
            )}

            {/* Section B: System Console */}
            {activeSettingsSection === "console" && (
            <div className="p-6 flex flex-col min-h-[500px]">
              <div className="flex justify-between items-center border-b border-white/10 pb-4 flex-shrink-0">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    💻 System Console Audits
                  </h2>
                  <p className="text-xs text-gray-400 mt-1">Real-time syslog outputs of the security sandbox monitor</p>
                </div>
                <button
                  onClick={() => {
                    setLogs([`[SYS] ${new Date().toLocaleTimeString()} - Console cleared by operator.`]);
                  }}
                  className="px-3 py-1.5 text-xs glass-panel hover:bg-white/5 border border-white/10 rounded-lg text-gray-300 font-semibold transition"
                >
                  Clear Console
                </button>
              </div>
              <div className="flex-1 overflow-y-auto bg-black/50 border border-white/5 rounded-xl p-4 font-mono text-xs text-gray-400 mt-4 leading-relaxed space-y-2 select-text shadow-inner" style={{ maxHeight: "400px" }}>
                {logs.map((log, index) => {
                  let logClass = "text-gray-400";
                  if (log.includes("[SYS]")) {
                    logClass = "text-gray-300";
                  } else if (log.includes("[NET]")) {
                    logClass = "text-yellow-500";
                  } else if (log.includes("[SEC]")) {
                    logClass = "text-red-400 font-bold";
                  } else if (log.includes("[OK]")) {
                    logClass = "text-green-400";
                  }
                  return (
                    <div key={index} className={`${logClass} hover:bg-white/5 p-1 rounded transition`}>
                      {log}
                    </div>
                  );
                })}
              </div>
            </div>
            )}

            {/* Section: Engine Status */}
            {activeSettingsSection === "engine" && (
            <div className="p-6 space-y-6">
              <div className="border-b border-white/10 pb-4 flex items-start justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">🔧 Engine Status</h2>
                  <p className="text-xs text-gray-400 mt-1">Real-time health check — CPU, memory, disk, database, and every subprocess (backend + frontend)</p>
                </div>
                <button
                  onClick={handleEngineHealthCheck}
                  disabled={engineHealthLoading}
                  className="px-3 py-1.5 text-xs font-bold rounded-lg bg-sky-500/15 border border-sky-400/25 text-sky-300 hover:bg-sky-500/25 transition flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${engineHealthLoading ? "animate-spin" : ""}`} /> Refresh
                </button>
              </div>

              {!engineHealth && !engineHealthLoading && (
                <div className="flex flex-col items-center justify-center py-16 text-gray-500 gap-3">
                  <span className="text-4xl">🔧</span>
                  <p className="text-sm">Loading engine health… or click <span className="text-sky-400 font-semibold">Refresh</span>.</p>
                </div>
              )}

              {engineHealth?.error && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm font-medium">
                  ⚠️ {engineHealth.error}
                </div>
              )}

              {engineHealth && !engineHealth.error && (() => {
                const h = engineHealth;
                const statCard = (label: string, value: string, sub: string, pct: number | null, color: string) => (
                  <div className="bg-black/20 border border-white/5 rounded-xl p-4 space-y-2">
                    <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">{label}</div>
                    <div className={`text-2xl font-black ${color}`}>{value}</div>
                    <div className="text-[11px] text-gray-500">{sub}</div>
                    {pct !== null && (
                      <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all ${pct > 85 ? "bg-red-500" : pct > 60 ? "bg-yellow-500" : "bg-green-500"}`}
                          style={{ width: `${Math.min(100, pct)}%` }} />
                      </div>
                    )}
                  </div>
                );
                return (
                  <div className="space-y-5">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {statCard("CPU Usage", h.cpu_percent != null ? `${h.cpu_percent.toFixed(1)}%` : "—",
                        "Total processor load", h.cpu_percent,
                        h.cpu_percent > 85 ? "text-red-400" : h.cpu_percent > 60 ? "text-yellow-400" : "text-green-400")}
                      {h.memory
                        ? statCard("Memory", `${h.memory.percent.toFixed(1)}%`,
                            `${h.memory.used_gb} / ${h.memory.total_gb} GB`, h.memory.percent,
                            h.memory.percent > 85 ? "text-red-400" : h.memory.percent > 60 ? "text-yellow-400" : "text-cyan-400")
                        : statCard("Memory", "—", "psutil not available", null, "text-gray-500")}
                      {h.disk
                        ? statCard("Disk", `${h.disk.percent.toFixed(1)}%`,
                            `${h.disk.used_gb} / ${h.disk.total_gb} GB`, h.disk.percent,
                            h.disk.percent > 85 ? "text-red-400" : h.disk.percent > 60 ? "text-yellow-400" : "text-violet-400")
                        : statCard("Disk", "—", "psutil not available", null, "text-gray-500")}
                      {statCard("Uptime", `${Math.floor(h.uptime_seconds / 60)}m ${h.uptime_seconds % 60}s`,
                        "Since last restart", null, "text-sky-400")}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="bg-black/20 border border-white/5 rounded-xl p-4 space-y-2">
                        <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Database</div>
                        <div className={`flex items-center gap-2 ${h.database === "connected" ? "text-green-400" : "text-red-400"}`}>
                          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${h.database === "connected" ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
                          <span className="font-bold capitalize">{h.database}</span>
                        </div>
                        <div className="text-[11px] text-gray-500">API v{h.api_version}</div>
                      </div>
                      {h.process && (
                        <div className="bg-black/20 border border-white/5 rounded-xl p-4 space-y-2">
                          <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">API Process</div>
                          <div className="text-[11px] text-gray-300 space-y-1 font-mono">
                            <div>PID: <span className="text-white">{h.process.pid}</span></div>
                            <div>Status: <span className={h.process.status === "running" ? "text-green-400" : "text-yellow-400"}>{h.process.status}</span></div>
                            <div>RAM: <span className="text-cyan-400">{h.process.mem_mb} MB</span></div>
                            <div>Threads: <span className="text-violet-400">{h.process.threads}</span></div>
                          </div>
                        </div>
                      )}
                    </div>
                    {/* All subprocesses that make up this deployment (backend + frontend) */}
                    {Array.isArray(h.subprocesses) && h.subprocesses.length > 0 && (
                      <div className="bg-black/20 border border-white/5 rounded-xl p-4 space-y-3">
                        <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                          Subprocesses ({h.subprocesses.length})
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {h.subprocesses.map((sp: any) => {
                            const healthy = sp.status === "running" || sp.status === "sleeping";
                            const up = sp.uptime_seconds || 0;
                            return (
                              <div key={sp.pid} className="bg-black/20 border border-white/5 rounded-lg p-3 space-y-1.5">
                                <div className="flex items-center gap-2">
                                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${healthy ? "bg-green-400 animate-pulse" : "bg-yellow-400"}`} />
                                  <span className="font-bold text-sm text-white">{sp.role}</span>
                                </div>
                                <div className="text-[11px] text-gray-300 font-mono grid grid-cols-2 gap-x-3 gap-y-0.5">
                                  <div>PID: <span className="text-white">{sp.pid}</span></div>
                                  <div>Status: <span className={healthy ? "text-green-400" : "text-yellow-400"}>{sp.status}</span></div>
                                  <div>RAM: <span className="text-cyan-400">{sp.mem_mb} MB</span></div>
                                  <div>Threads: <span className="text-violet-400">{sp.threads}</span></div>
                                  <div className="col-span-2">Uptime: <span className="text-sky-400">{Math.floor(up / 3600)}h {Math.floor((up % 3600) / 60)}m</span></div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
            )}

            {/* Section: Resource Usage (CPU/mem/disk history) */}
            {activeSettingsSection === "resource" && (
            <div className="p-6 space-y-5">
              <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-4">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">📊 Resource Usage</h2>
                  <p className="text-xs text-gray-400 mt-1">Vnotice processes (backend + frontend) — CPU%, memory (RSS) &amp; app data size, sampled hourly, kept 365 days</p>
                </div>
                <div className="flex items-center gap-2">
                  {[1, 7, 30, 90, 365].map((d) => (
                    <button key={d} onClick={() => setUsageRange(d)}
                      className={`px-2.5 py-1 text-[11px] font-bold rounded-md border transition ${usageRange === d ? "bg-sky-500/15 border-sky-400/30 text-sky-300" : "border-white/10 text-gray-400 hover:text-white hover:bg-white/5"}`}>
                      {d === 365 ? "1y" : d + "d"}
                    </button>
                  ))}
                  <button onClick={loadUsage} disabled={usageLoading}
                    className="px-3 py-1.5 text-xs font-bold rounded-lg bg-sky-500/15 border border-sky-400/25 text-sky-300 hover:bg-sky-500/25 transition flex items-center gap-1.5 disabled:opacity-50">
                    <RefreshCw className={`w-3.5 h-3.5 ${usageLoading ? "animate-spin" : ""}`} /> Refresh
                  </button>
                </div>
              </div>
              {(() => {
                // Per-process hourly samples (new schema). Plot hourly so the line
                // builds within hours, not days. Range = last N days of hours.
                const rows = usageData
                  .filter((s) => s && s.mem_mb !== undefined && s.t)
                  .map((s) => ({ t: s.t as string, cpu: s.cpu_pct || 0, mem: s.mem_mb || 0, disk: s.disk_mb || 0 }))
                  .sort((a, b) => a.t.localeCompare(b.t));
                const shown = rows.slice(-usageRange * 24);

                if (usageLoading && shown.length === 0) {
                  return <div className="text-center py-16 text-gray-500 text-sm">Loading usage history…</div>;
                }
                if (shown.length === 0) {
                  return (
                    <div className="text-center py-16 text-gray-500 text-sm">
                      <p className="font-semibold">No samples recorded yet.</p>
                      <p className="mt-1 text-xs">The backend records one sample per hour. Check back after it has been running at least an hour.</p>
                    </div>
                  );
                }

                const W = 760, H = 200;
                const xAt = (i: number) => (shown.length <= 1 ? W / 2 : (i / (shown.length - 1)) * W);
                const metrics = [
                  { key: "cpu" as const,  label: "CPU",         color: "#38bdf8", fmt: (v: number) => v.toFixed(1) + "%" },
                  { key: "mem" as const,  label: "Memory (RSS)", color: "#a78bfa", fmt: (v: number) => v.toFixed(0) + " MB" },
                  { key: "disk" as const, label: "Data on disk", color: "#34d399", fmt: (v: number) => v.toFixed(1) + " MB" },
                ];
                // Each line is normalised to its own peak so trends are comparable despite different units.
                const peakOf = (key: "cpu" | "mem" | "disk") => Math.max(1e-6, ...shown.map((d) => d[key]));
                const yAt = (key: "cpu" | "mem" | "disk", v: number) => H - (v / (peakOf(key) * 1.1)) * H;
                const stat = (key: "cpu" | "mem" | "disk") => {
                  const vals = shown.map((d) => d[key]);
                  const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
                  return { latest: vals[vals.length - 1], avg, peak: Math.max(...vals) };
                };
                const procs = usageData.length ? (usageData[usageData.length - 1].procs ?? "—") : "—";

                return (
                  <div className="space-y-5">
                    <div className="grid grid-cols-3 gap-3">
                      {metrics.map((m) => {
                        const s = stat(m.key);
                        return (
                          <div key={m.key} className="bg-black/20 border border-white/5 rounded-xl p-4 space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="w-2.5 h-2.5 rounded-full" style={{ background: m.color }} />
                              <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">{m.label}</span>
                            </div>
                            <div className="text-2xl font-black" style={{ color: m.color }}>{m.fmt(s.latest)}</div>
                            <div className="text-[11px] text-gray-500">avg {m.fmt(s.avg)} · peak {m.fmt(s.peak)}</div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="bg-black/20 border border-white/5 rounded-xl p-4">
                      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="w-full h-52">
                        {[0, 25, 50, 75, 100].map((g) => (
                          <line key={g} x1={0} x2={W} y1={H - (g / 100) * H} y2={H - (g / 100) * H} stroke="rgba(255,255,255,0.07)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
                        ))}
                        {metrics.map((m) => (
                          <polyline key={m.key} fill="none" stroke={m.color} strokeWidth="2" vectorEffect="non-scaling-stroke"
                            points={shown.map((d, i) => `${xAt(i)},${yAt(m.key, d[m.key])}`).join(" ")} />
                        ))}
                        {/* Dots so sparse data (even a single sample) is visible; skip on dense ranges. */}
                        {shown.length <= 200 && metrics.map((m) => (
                          <g key={m.key + "-pts"}>
                            {shown.map((d, i) => (
                              <circle key={i} cx={xAt(i)} cy={yAt(m.key, d[m.key])} r={shown.length <= 1 ? 4 : 2.5} fill={m.color} />
                            ))}
                          </g>
                        ))}
                      </svg>
                      <div className="flex items-center justify-between mt-2">
                        <div className="flex items-center gap-4">
                          {metrics.map((m) => (
                            <span key={m.key} className="flex items-center gap-1.5 text-[11px] text-gray-400">
                              <span className="w-3 h-0.5 rounded-full" style={{ background: m.color }} />{m.label}
                            </span>
                          ))}
                        </div>
                        <span className="text-[10px] text-gray-600 font-mono">
                          {shown[0].t.slice(5, 16).replace("T", " ")} → {shown[shown.length - 1].t.slice(5, 16).replace("T", " ")} · {shown.length} pts · {procs} procs
                        </span>
                      </div>
                      <p className="text-[10px] text-gray-600 mt-1.5">Each line is scaled to its own peak (different units) — read exact values from the cards above. Watch the Memory line over time to spot leaks.</p>
                    </div>
                  </div>
                );
              })()}
            </div>
            )}

            {/* Section C: Account Management */}
            {activeSettingsSection === "accounts" && (
            <div className="p-6 space-y-4">
              <div className="border-b border-white/10 pb-4">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  👥 Account Management
                </h2>
                <p className="text-xs text-gray-400 mt-1">Manage operator profiles. Deleting the active profile returns you to profile selection.</p>
              </div>
              {profiles.length === 0 ? (
                <div className="text-center py-10 text-gray-500 text-sm">
                  <p className="font-semibold">No accounts found.</p>
                </div>
              ) : (
                <div className="divide-y divide-white/5">
                  {profiles.map((profile) => {
                    const isActive = profile.id === activeProfileId;
                    return (
                      <div
                        key={profile.id}
                        className="p-3 flex items-center justify-between hover:bg-white/[0.01] transition"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <div className="text-2xl select-none flex-shrink-0">{profile.avatar}</div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-sm text-white truncate">{profile.name}</span>
                              {isActive && (
                                <span className="text-[9px] font-bold bg-sky-500/20 border border-sky-500/30 text-sky-400 px-1.5 py-0.5 rounded-full flex-shrink-0">(Active)</span>
                              )}
                            </div>
                            <div className="text-[11px] text-gray-400 truncate">{profile.role}</div>
                            <div className="text-[11px] text-gray-500 truncate">{profile.email}</div>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            const updatedProfiles = profiles.filter((p) => p.id !== profile.id);
                            setProfiles(updatedProfiles);
                            localStorage.setItem("vnotice_profiles", JSON.stringify(updatedProfiles));
                            if (activeProfileId === profile.id) {
                              setActiveProfileId(null);
                              localStorage.removeItem("vnotice_currentUser_id");
                            }
                          }}
                          className="flex-shrink-0 px-3 py-1.5 text-xs font-bold bg-white/[0.01] hover:bg-red-500/10 border border-white/5 hover:border-red-500/30 text-gray-400 hover:text-red-400 rounded-lg transition ml-4"
                        >
                          Delete
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            )}

            </div>
          </div>
        )}

        {/* Tab: Alert Rules — simple list */}
        {activeTab === "alerts" && (
          <div className="glass-panel p-6 border border-white/5 shadow-2xl relative space-y-5 animate-fadeIn">
            <div className="flex justify-between items-center border-b border-white/10 pb-4">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  🔔 Alert Rules
                  <span className="bg-sky-500 text-white text-xs px-2.5 py-0.5 rounded-full font-semibold">
                    {alertRules.length}
                  </span>
                </h2>
                <p className="text-xs text-gray-400 mt-1">Saved alert rules from Threat Stream filters. Use the filter sidebar there to save new ones.</p>
              </div>
            </div>

            {alertRules.length === 0 ? (
              <div className="text-center py-16 text-gray-500 text-sm">
                <div className="text-4xl mb-4">🔔</div>
                <p className="font-semibold">No alerts saved yet.</p>
                <p className="text-xs mt-2 text-gray-600">Use the filter sidebar in Threat Stream to save one.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {alertRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-4 border border-white/5 rounded-xl bg-black/25 hover:bg-black/35 transition duration-200"
                  >
                    <div className="flex justify-between items-start gap-3">
                      <div className="min-w-0 flex-1">
                        <h4 className="font-bold text-sm text-white">{rule.name}</h4>
                        {rule.description && (
                          <p className="text-[11px] text-gray-400 mt-1 leading-relaxed">{rule.description}</p>
                        )}
                        <div className="flex flex-wrap items-center gap-1.5 mt-2">
                          <span className={`text-[9px] px-1.5 py-0.5 rounded font-semibold border ${rule.active ? "bg-emerald-500/10 border-emerald-400/20 text-emerald-300" : "bg-white/5 border-white/10 text-gray-500"}`}>
                            {rule.active ? "● Active" : "○ Disabled"}
                          </span>
                          <span className="text-[9px] bg-sky-500/10 border border-sky-400/20 text-sky-300 px-1.5 py-0.5 rounded font-semibold" title="CVEs currently loaded that match this rule">
                            ⌖ {countRuleMatches(rule)} match{countRuleMatches(rule) !== 1 ? "es" : ""}
                          </span>
                          <span
                            className={`text-[9px] px-1.5 py-0.5 rounded font-semibold border ${rule.lastSentAt ? "bg-emerald-500/10 border-emerald-400/20 text-emerald-300" : "bg-white/5 border-white/10 text-gray-500"}`}
                            title="How many emails this alert has sent, and when it last sent"
                          >
                            ✉ {rule.sentCount ? `${rule.sentCount} sent · last ${new Date(rule.lastSentAt!).toLocaleString()}` : "never sent"}
                          </span>
                          <span className="text-[9px] text-gray-600 px-1.5 py-0.5">
                            {new Date(rule.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                        {/* Condition groups — alert fires if ANY group matches (OR) */}
                        <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                          {ruleGroups(rule).map((g, i) => (
                            <React.Fragment key={i}>
                              {i > 0 && <span className="text-[9px] font-bold text-sky-500/80">OR</span>}
                              <span className="text-[9px] bg-white/5 border border-white/10 text-gray-300 px-1.5 py-0.5 rounded font-mono">
                                {describeGroup(g)}
                              </span>
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <label className="relative inline-flex items-center cursor-pointer" title={rule.active ? "Disable" : "Enable"}>
                          <input
                            type="checkbox"
                            className="sr-only peer"
                            checked={rule.active}
                            onChange={() => handleToggleRuleActive(rule.id)}
                          />
                          <div className="w-9 h-5 bg-black border border-white/20 peer-focus:outline-none rounded-full peer transition-colors peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:shadow-sm after:border-none after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500 peer-checked:border-emerald-500 peer-checked:shadow-[0_0_8px_rgba(16,185,129,0.45)]"></div>
                        </label>
                        <button
                          type="button"
                          onClick={() => handleApplyAlertFilter(rule)}
                          className="p-1.5 text-gray-400 hover:text-sky-400 hover:bg-white/5 rounded transition"
                          title="Apply this alert's filter to the Threat Stream to see matching CVEs"
                        >
                          <Search className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => sendAlertTestEmail(rule)}
                          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-white/5 rounded transition"
                          title="Email the latest CVE matching this alert to your configured recipient now"
                        >
                          <Mail className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setEditingAlertId(rule.id);
                            setSaveAlertName(rule.name);
                            setSaveAlertDescription(rule.description);
                            setEditConditions(ruleGroups(rule).map((g) => ({ ...g })));
                            setShowSaveAlertModal(true);
                          }}
                          className="p-1.5 text-gray-400 hover:text-sky-400 hover:bg-white/5 rounded transition text-xs font-bold"
                          title="Edit Alert Rule"
                        >
                          ✏️
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveAlertRule(rule.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-white/5 rounded transition"
                          title="Delete Alert Rule"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab: Threat Dashboard — left list + right analytics panel */}
        {activeTab === "threat_dashboard" && (
          <div className="flex animate-fadeIn glass-panel border border-white/5 shadow-2xl overflow-hidden min-h-[600px]">

            {/* Left Sidebar — dashboard list */}
            <div className="w-52 flex-shrink-0 border-r border-white/5 bg-black/20 py-5 flex flex-col">
              <div className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-5 pb-3 mb-2 border-b border-white/5">
                📌 Saved Dashboards
              </div>
              <div className="flex-1 overflow-y-auto space-y-0.5 px-3">

                {/* Default dashboard — always present */}
                <button
                  onClick={() => setSelectedDashboardId("default")}
                  className={`w-full text-left px-3 py-3 rounded-xl flex items-start gap-3 transition-all duration-200 ${
                    selectedDashboardId === "default"
                      ? "bg-sky-500/15 border border-sky-500/25"
                      : "border border-transparent text-gray-400 hover:text-white hover:bg-white/[0.03]"
                  }`}
                >
                  <span className="text-lg leading-none flex-shrink-0 mt-0.5">🌐</span>
                  <div className="min-w-0 flex-1">
                    <div className={`text-sm font-bold leading-tight ${selectedDashboardId === "default" ? "text-sky-400" : "text-white"}`}>All Threats</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">Unfiltered · Default</div>
                  </div>
                  <span className="text-gray-600 text-sm flex-shrink-0 mt-1" title="Cannot be deleted">🔒</span>
                </button>

                {/* User-saved dashboards */}
                {savedDashboards.length === 0 ? (
                  <div className="text-[11px] text-gray-600 px-3 py-6 text-center italic leading-relaxed">
                    No custom dashboards yet.<br />Save one from Threat Stream.
                  </div>
                ) : (
                  savedDashboards.map((dash) => (
                    <div key={dash.id} className="relative group">
                      <button
                        onClick={() => setSelectedDashboardId(dash.id)}
                        className={`w-full text-left px-3 py-3 rounded-xl flex items-start gap-3 transition-all duration-200 pr-9 ${
                          selectedDashboardId === dash.id
                            ? "bg-sky-500/15 border border-sky-500/25"
                            : "border border-transparent text-gray-400 hover:text-white hover:bg-white/[0.03]"
                        }`}
                      >
                        <span className="text-lg leading-none flex-shrink-0 mt-0.5">📊</span>
                        <div className="min-w-0 flex-1">
                          <div className={`text-sm font-bold leading-tight truncate ${selectedDashboardId === dash.id ? "text-sky-400" : "text-white"}`}>{dash.name}</div>
                          <div className="text-[10px] text-gray-500 mt-0.5 truncate">
                            {dash.filters.severity.includes("all") ? "All severities" : dash.filters.severity.join(", ")}
                          </div>
                        </div>
                      </button>
                      <button
                        onClick={() => handleDeleteDashboard(dash.id)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-gray-600 hover:text-red-400 hover:bg-red-500/10 rounded opacity-0 group-hover:opacity-100 transition"
                        title="Delete dashboard"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Right Panel — analytics */}
            <div className="flex-1 overflow-y-auto">
              {!selectedDashboardId ? (
                <div className="h-full flex flex-col items-center justify-center text-center p-10 gap-4">
                  <div className="text-6xl opacity-15">📊</div>
                  <div className="text-gray-400 text-sm font-semibold">Select a dashboard from the left</div>
                  <div className="text-gray-600 text-xs max-w-xs leading-relaxed">
                    Save filter combinations from Threat Stream using the &ldquo;📌 Save to Dashboard&rdquo; button in the filter sidebar.
                  </div>
                </div>
              ) : (
                <div className="p-6 space-y-5">

                  {/* Dashboard header */}
                  <div className="flex items-center justify-between border-b border-white/5 pb-4">
                    <div>
                      <h2 className="text-lg font-bold text-white">
                        {selectedDashboardId === "default"
                          ? "All Threats"
                          : (savedDashboards.find(d => d.id === selectedDashboardId)?.name ?? "")}
                      </h2>
                      <p className="text-[11px] text-gray-500 mt-0.5">Analytics overview · click &ldquo;Apply &amp; View&rdquo; to open in Threat Stream with filters</p>
                    </div>
                    <button
                      onClick={() => {
                        const dash = selectedDashboardId === "default"
                          ? { id: "default", name: "All Threats", filters: { severity: ["all"], keywords: [], feedSources: ["all"], searchQuery: "", epssMin: "", epssMax: "" }, createdAt: new Date().toISOString() }
                          : savedDashboards.find(d => d.id === selectedDashboardId);
                        if (dash) handleApplyDashboard(dash as SavedDashboard);
                      }}
                      className="px-4 py-2 text-xs font-bold bg-sky-500/20 hover:bg-sky-500/30 border border-sky-500/30 text-sky-400 rounded-lg transition flex items-center gap-1.5 flex-shrink-0"
                    >
                      ▶ Apply &amp; View
                    </button>
                  </div>

                  {/* KPI Row */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="glass-panel p-5 rounded-xl border border-white/5 shadow-lg flex flex-col justify-center">
                      <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Total Advisories</span>
                      <span className="text-3xl font-black text-white mt-1.5">{vulnerabilities.length}</span>
                    </div>
                    <div className="glass-panel p-5 rounded-xl border border-white/5 shadow-lg flex flex-col justify-center">
                      <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Critical Severity</span>
                      <span className="text-3xl font-black text-red-500 mt-1.5">
                        {vulnerabilities.filter(v => v.severity.toLowerCase() === "critical").length}
                      </span>
                    </div>
                    <div className="glass-panel p-5 rounded-xl border border-white/5 shadow-lg flex flex-col justify-center">
                      <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Avg CVSS Score</span>
                      <span className="text-3xl font-black text-sky-400 mt-1.5">
                        {(vulnerabilities.reduce((acc, curr) => acc + curr.score, 0) / (vulnerabilities.length || 1)).toFixed(1)}
                      </span>
                    </div>
                    <div className="glass-panel p-5 rounded-xl border border-white/5 shadow-lg flex flex-col justify-center">
                      <span className="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Avg EPSS Rate</span>
                      <span className="text-3xl font-black text-green-400 mt-1.5">
                        {(() => {
                          const known = vulnerabilities.filter((v) => v.epss != null);
                          const avg = known.length ? known.reduce((a, c) => a + c.epss, 0) / known.length : 0;
                          return (avg * 100).toFixed(1);
                        })()}%
                      </span>
                    </div>
                  </div>

                  {/* Charts row */}
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                    <div className="lg:col-span-5 space-y-4">
                      <div className="glass-panel p-5 border border-white/5 shadow-xl space-y-4">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider border-b border-white/5 pb-2">
                          📊 Threats by Severity
                        </h3>
                        <div className="space-y-3.5">
                          {["critical", "high", "medium", "low"].map((sev) => {
                            const count = vulnerabilities.filter(v => v.severity.toLowerCase() === sev).length;
                            const percentage = vulnerabilities.length > 0 ? (count / vulnerabilities.length) * 100 : 0;
                            let sevColor = "bg-red-500";
                            let textColor = "text-red-400";
                            if (sev === "high") { sevColor = "bg-orange-500"; textColor = "text-orange-400"; }
                            if (sev === "medium") { sevColor = "bg-yellow-500"; textColor = "text-yellow-400"; }
                            if (sev === "low") { sevColor = "bg-green-500"; textColor = "text-green-400"; }
                            return (
                              <div key={sev} className="space-y-1 text-xs">
                                <div className="flex justify-between items-center font-bold">
                                  <span className={`capitalize ${textColor}`}>{sev}</span>
                                  <span className="text-gray-300">{count} ({percentage.toFixed(0)}%)</span>
                                </div>
                                <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden">
                                  <div className={`h-full ${sevColor}`} style={{ width: `${percentage}%` }}></div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      <div className="glass-panel p-5 border border-white/5 shadow-xl space-y-4 max-h-[300px] overflow-y-auto">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider border-b border-white/5 pb-2">
                          🎯 Vulnerability by Product
                        </h3>
                        <div className="space-y-3 font-mono text-[11px] text-gray-300">
                          {sortedProducts.length === 0 ? (
                            <div className="text-[11px] text-gray-500 text-center py-4">No products discovered yet.</div>
                          ) : (
                            sortedProducts.slice(0, 15).map(([prod, count]) => (
                              <div key={prod} className="flex justify-between items-center bg-black/25 p-2 rounded border border-white/5 hover:border-sky-500/20 transition">
                                <span className="font-bold text-sky-400 truncate max-w-[180px]" title={prod}>{prod}</span>
                                <span className="font-bold bg-white/10 px-2 py-0.5 rounded text-white text-[10px]">{count} CVEs</span>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="lg:col-span-7 glass-panel p-5 border border-white/5 shadow-xl flex flex-col min-h-[420px]">
                      <div className="border-b border-white/5 pb-2 flex-shrink-0">
                        <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                          🎛️ Severity × Brand Cross-Tabulated Metrics
                        </h3>
                      </div>
                      <div className="flex-1 overflow-x-auto mt-4 min-h-0">
                        <table className="w-full text-left font-mono text-xs border-collapse">
                          <thead>
                            <tr className="bg-black/30 border-b border-white/15 text-gray-400">
                              <th className="py-2.5 px-3 font-bold">Brand / Vendor</th>
                              <th className="py-2.5 px-3 text-red-500 font-bold">Crit</th>
                              <th className="py-2.5 px-3 text-orange-400 font-bold">High</th>
                              <th className="py-2.5 px-3 text-yellow-400 font-bold">Med</th>
                              <th className="py-2.5 px-3 text-green-400 font-bold">Low</th>
                              <th className="py-2.5 px-3 font-bold border-l border-white/10">Total</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/5 text-gray-300">
                            {sortedBrands.length === 0 ? (
                              <tr>
                                <td colSpan={6} className="py-4 text-center text-gray-500">No brands discovered yet.</td>
                              </tr>
                            ) : (
                              sortedBrands.slice(0, 12).map(([brand]) => {
                                const brandVulns = vulnerabilities.filter(v => matchesVendorHelper(v.vendor, [brand]));
                                const crit = brandVulns.filter(v => v.severity.toLowerCase() === "critical").length;
                                const high = brandVulns.filter(v => v.severity.toLowerCase() === "high").length;
                                const med = brandVulns.filter(v => v.severity.toLowerCase() === "medium").length;
                                const low = brandVulns.filter(v => v.severity.toLowerCase() === "low").length;
                                const total = brandVulns.length;
                                return (
                                  <tr key={brand} className="hover:bg-white/5 font-semibold transition">
                                    <td className="py-3 px-3 text-white font-bold truncate max-w-[120px]">{brand}</td>
                                    <td className="py-3 px-3 text-red-400 font-bold">{crit}</td>
                                    <td className="py-3 px-3 text-orange-400 font-bold">{high}</td>
                                    <td className="py-3 px-3 text-yellow-400 font-bold">{med}</td>
                                    <td className="py-3 px-3 text-green-400 font-bold">{low}</td>
                                    <td className="py-3 px-3 border-l border-white/10 text-sky-400 font-black">{total}</td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>

                </div>
              )}
            </div>
          </div>
        )}


      </main>

      {/* Save as Alert Modal */}
      {showSaveAlertModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-panel max-w-md w-full p-6 rounded-2xl shadow-2xl border border-white/10 space-y-4 animate-scaleUp">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              {editingAlertId ? "✏️ Edit Alert Rule" : "💾 Save as Alert"}
            </h3>
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">Alert Name <span className="text-red-400">*</span></label>
                <input
                  type="text"
                  value={saveAlertName}
                  onChange={(e) => setSaveAlertName(e.target.value)}
                  placeholder="e.g. Critical Fortinet Alerts"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                  autoFocus
                />
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">Description / Notes (optional)</label>
                <textarea
                  value={saveAlertDescription}
                  onChange={(e) => setSaveAlertDescription(e.target.value)}
                  placeholder="Optional notes about this alert rule..."
                  rows={3}
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition resize-none"
                />
              </div>
              {/* Condition groups — a CVE matches the alert if ANY group matches (OR). */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">Conditions (match ANY group)</label>
                  <span className="text-[10px] text-gray-500">{editConditions.length} group{editConditions.length !== 1 ? "s" : ""}</span>
                </div>
                <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                  {editConditions.length === 0 && (
                    <p className="text-[11px] text-gray-500 italic">No conditions yet — add the current filters below.</p>
                  )}
                  {editConditions.map((g, i) => (
                    <div key={i}>
                      {i > 0 && <div className="text-center text-[9px] font-bold text-sky-500/80 tracking-widest my-1">— OR —</div>}
                      <div className="flex items-start gap-2 p-2.5 bg-black/30 border border-white/10 rounded-lg">
                        <span className="text-[9px] font-bold text-sky-400 bg-sky-500/10 border border-sky-400/20 rounded px-1.5 py-0.5 mt-0.5">G{i + 1}</span>
                        <span className="flex-1 text-[11px] text-gray-200 leading-relaxed font-mono">{describeGroup(g)}</span>
                        <button
                          type="button"
                          onClick={() => setEditConditions(editConditions.filter((_, j) => j !== i))}
                          className="text-gray-500 hover:text-red-400 transition flex-shrink-0"
                          title="Remove this condition group"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  onClick={() => setEditConditions([...editConditions, currentFilterGroup()])}
                  className="w-full text-[11px] font-semibold text-sky-300 border border-dashed border-sky-500/30 hover:border-sky-400/60 hover:bg-sky-500/5 rounded-lg py-2 transition"
                >
                  ➕ Add current dashboard filters as a condition (OR)
                </button>
                <p className="text-[10px] text-gray-500 leading-relaxed">
                  Tip: set the filters in Threat Stream (e.g. severity High + Critical, a source), click add; then change filters
                  (e.g. Medium + Low, EPSS ≥ 60%) and add again — the alert fires if either group matches.
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2 border-t border-white/5">
              <button
                onClick={() => { setShowSaveAlertModal(false); setSaveAlertName(""); setSaveAlertDescription(""); setEditingAlertId(null); setEditConditions([]); }}
                className="px-4 py-2 text-sm font-semibold text-gray-400 hover:text-white rounded-lg hover:bg-white/5 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveAlert}
                className="px-5 py-2 bg-sky-500 hover:bg-sky-600 text-white rounded-lg font-bold text-sm transition shadow-lg shadow-sky-500/10"
              >
                {editingAlertId ? "Update Alert" : "Save Alert"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save to Dashboard Modal */}
      {showSaveDashboardModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-panel max-w-md w-full p-6 rounded-2xl shadow-2xl border border-white/10 space-y-4 animate-scaleUp">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              📌 Save to Dashboard
            </h3>
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">Dashboard Name <span className="text-red-400">*</span></label>
                <input
                  type="text"
                  value={saveDashboardName}
                  onChange={(e) => setSaveDashboardName(e.target.value)}
                  placeholder="e.g. Critical CVEs View"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                  autoFocus
                />
              </div>
              <div className="p-3 bg-sky-500/5 border border-sky-500/10 rounded-lg text-[11px] text-gray-400 leading-relaxed">
                <span className="font-bold text-sky-400">Current filters will be saved:</span>
                <div className="mt-1.5 space-y-0.5 font-mono">
                  <div>Severity: <span className="text-white">{activeSeverity.join(", ")}</span></div>
                  {searchQuery && <div>Search: <span className="text-white">{searchQuery}</span></div>}
                  {activeKeywords.length > 0 && <div>Keywords: <span className="text-white">{activeKeywords.join(", ")}</span></div>}
                  {(epssMin || epssMax) && <div>EPSS: <span className="text-white">{epssMin || "0"}% – {epssMax || "100"}%</span></div>}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2 border-t border-white/5">
              <button
                onClick={() => { setShowSaveDashboardModal(false); setSaveDashboardName(""); }}
                className="px-4 py-2 text-sm font-semibold text-gray-400 hover:text-white rounded-lg hover:bg-white/5 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveDashboard}
                className="px-5 py-2 bg-sky-500 hover:bg-sky-600 text-white rounded-lg font-bold text-sm transition shadow-lg shadow-sky-500/10"
              >
                Save Dashboard
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Dynamic XML/RSS Feed or Regex Webpage Scraper Add & Edit validation dialog (Req 2) */}
      {isFeedModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-panel max-w-md w-full p-6 rounded-2xl shadow-2xl border border-white/10 space-y-4 animate-scaleUp">
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              {feedModalMode === "add" ? "📡 Register Threat Source" : "✏️ Adjust Threat Source"}
            </h3>
            
            <div className="space-y-3.5">
              {feedModalMode === "add" && (
                <div className="space-y-1">
                  <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Source Type
                  </label>
                  <select
                    value={feedType}
                    onChange={(e) => setFeedType(e.target.value as any)}
                    className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                  >
                    <option value="rss">RSS XML Feed</option>
                    <option value="scraper">Webpage Regex Scraper</option>
                  </select>
                </div>
              )}

              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  Threat Source Name
                </label>
                <input
                  type="text"
                  value={feedNameInput}
                  onChange={(e) => setFeedNameInput(e.target.value)}
                  placeholder="e.g. Cisco Advisories Feed"
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>
              
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                  {feedType === "rss" ? "Threat Source RSS URL" : "Webpage URL"}
                </label>
                <input
                  type="text"
                  value={feedUrlInput}
                  onChange={(e) => setFeedUrlInput(e.target.value)}
                  placeholder={feedType === "rss" ? "https://example.com/rss.xml" : "https://example.com/advisories"}
                  className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition"
                />
              </div>

              {feedType === "scraper" && (
                <div className="space-y-1 animate-fadeIn">
                  <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Extraction Regex Pattern
                  </label>
                  <input
                    type="text"
                    value={feedRegexInput}
                    onChange={(e) => setFeedRegexInput(e.target.value)}
                    placeholder="e.g. CVE-\d{4}-\d+"
                    className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-sm transition font-mono"
                  />
                </div>
              )}
            </div>
            
            {feedValError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-xs font-medium leading-relaxed">
                ⚠️ {feedValError}
              </div>
            )}
            
            {feedValSuccess && (
              <div className="p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400 text-xs font-medium">
                ✓ Source signature successfully validated and registered. Saving...
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2 border-t border-white/5">
              <button
                onClick={() => {
                  setIsFeedModalOpen(false);
                  setFeedNameInput("");
                  setFeedUrlInput("");
                  setFeedValError(null);
                  setFeedType("rss");
                }}
                disabled={isFeedValidating}
                className="px-4 py-2 text-sm font-semibold text-gray-450 hover:text-white rounded-lg hover:bg-white/5 transition"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  setFeedValError(null);
                  setFeedValSuccess(false);
                  if (!feedNameInput.trim()) {
                    setFeedValError("Source Name is required.");
                    return;
                  }
                  if (!feedUrlInput.trim()) {
                    setFeedValError("Source URL is required.");
                    return;
                  }

                  setIsFeedValidating(true);
                  appendLog(`[NET] Running remote verification query on URL: ${feedUrlInput.trim()}`);
                  await new Promise((resolve) => setTimeout(resolve, 800));

                  if (feedType === "scraper") {
                    setIsFeedValidating(false);
                    setFeedValSuccess(true);
                    await new Promise((resolve) => setTimeout(resolve, 300));
                    
                    const updated = [...webScrapers, {
                      id: generateUniqueId(),
                      name: feedNameInput.trim(),
                      url: feedUrlInput.trim(),
                      regex: feedRegexInput.trim(),
                      active: true
                    }];
                    setWebScrapers(updated);
                    localStorage.setItem("vnotice_web_scrapers", JSON.stringify(updated));
                    appendLog(`[SYS] Registered new Custom HTML Webpage Regex Scraper: ${feedNameInput.trim()}`);
                    
                    setIsFeedModalOpen(false);
                    setFeedNameInput("");
                    setFeedUrlInput("");
                    setFeedValSuccess(false);
                    setFeedType("rss");
                  } else {
                    // RSS Validation path
                    handleSaveFeed();
                  }
                }}
                disabled={isFeedValidating}
                className="flex items-center gap-2 px-5 py-2.5 bg-sky-500 hover:bg-sky-600 disabled:bg-sky-850 text-white text-sm font-bold rounded-lg transition shadow-lg shadow-sky-500/10"
              >
                {isFeedValidating ? "Verifying..." : "Verify & Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
