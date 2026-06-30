"use client";
import React, { useState, useRef, useEffect, useCallback } from "react";
import { Copy, Check, EyeOff, Eye, ExternalLink, ChevronUp, ChevronDown, X } from "lucide-react";

interface CveItem {
  id: string;
  _key?: string;   // DB UUID — unique even when cve_id repeats across sources
  name: string;
  vendor: string;
  product: string;
  severity: string;
  score: number;
  epss: number | null;
  date: string;
  url: string;
  source?: string;
  ingestedAt?: string;   // ISO timestamp the record was input into the system (UTC)
}

interface CveTableProps {
  textSize?: "sm" | "md" | "lg" | "xl" | "2xl";
  vulnerabilities?: any[];
  showColumnManager?: boolean;
  onCloseColumnManager?: () => void;
  timezone?: string;
}

type ColKey = "cve" | "product" | "severity" | "scores" | "date" | "ingested" | "source";

const ALL_COLUMNS: ColKey[] = ["cve", "product", "severity", "scores", "date", "ingested", "source"];

const COLUMN_LABELS: Record<ColKey, string> = {
  cve:      "CVE ID & Name",
  product:  "Vendor / Product",
  severity: "Severity",
  scores:   "CVSS / EPSS",
  date:     "Published",
  ingested: "Ingested (UTC)",
  source:   "Feed Source",
};

const BASE_WIDTHS: Record<ColKey, number> = {
  cve: 280, product: 180, severity: 110, scores: 180, date: 120, ingested: 150, source: 160,
};

const LS_ORDER  = "vnotice_col_order";
const LS_HIDDEN = "vnotice_col_hidden";
const LS_WIDTHS = "vnotice_col_widths";

function loadLS<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}

// ponytail: map the UI's tz codes to IANA zones and render the stored UTC
// timestamp in the chosen zone via Intl (platform, no deps).
const TZ_IANA: Record<string, string> = {
  UTC: "UTC",
  PST: "America/Los_Angeles",
  EST: "America/New_York",
  ICT: "Asia/Bangkok",
};

function formatInTz(iso: string, tz: string): string {
  if (!iso) return "";
  // Stored value is naive UTC ("YYYY-MM-DD HH:MM:SS[.ffffff]"); mark it UTC so
  // it's parsed as UTC rather than the browser's local zone.
  let s = iso.includes("T") ? iso : iso.replace(" ", "T");
  if (!/[zZ]|[+-]\d\d:?\d\d$/.test(s)) s += "Z";
  const d = new Date(s);
  if (isNaN(d.getTime())) return iso.replace("T", " ").slice(0, 16);
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ_IANA[tz] || "UTC",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(d);
  const p: Record<string, string> = {};
  for (const part of parts) p[part.type] = part.value;
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`;
}

const initialData: CveItem[] = [
  { id: "CVE-2024-3094",  name: "XZ Utils Downstream SSH Backdoor",          vendor: "XZ Utils",   product: "XZ Utils",  severity: "Critical", score: 10.0, epss: 0.84805, date: "2024-03-29", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094" },
  { id: "CVE-2024-3400",  name: "Palo Alto PAN-OS Command Injection",         vendor: "Palo Alto",  product: "PAN-OS",    severity: "Critical", score: 10.0, epss: 0.956,   date: "2024-04-12", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400" },
  { id: "CVE-2024-21626", name: "runc Container Escape File Descriptor Leak", vendor: "Docker",     product: "runc",      severity: "High",     score: 8.6,  epss: 0.01367, date: "2024-01-31", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626" },
  { id: "CVE-2023-38831", name: "WinRAR Remote Code Execution",               vendor: "Microsoft",  product: "Windows OS",severity: "High",     score: 7.8,  epss: 0.93865, date: "2023-08-24", url: "https://nvd.nist.gov/vuln/detail/CVE-2023-38831" },
];

// ponytail: window size — mount this many rows up front, reveal +this on scroll.
// Keeps a 3000-row list from rendering thousands of <tr> at once.
const PAGE = 150;

export default function CveTable({ textSize = "md", vulnerabilities, showColumnManager, onCloseColumnManager, timezone = "UTC" }: CveTableProps) {
  const [data,     setData]     = useState<CveItem[]>(initialData);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(PAGE);

  // Header label for the Ingested column reflects the active timezone.
  const colLabel = (col: ColKey) => col === "ingested" ? `Ingested (${timezone})` : COLUMN_LABELS[col];

  const [columnOrder, setColumnOrder] = useState<ColKey[]>(() => {
    const saved = loadLS<ColKey[]>(LS_ORDER, ALL_COLUMNS);
    return saved.length === ALL_COLUMNS.length ? saved : ALL_COLUMNS;
  });

  const [hiddenCols, setHiddenCols] = useState<ColKey[]>(() =>
    loadLS<ColKey[]>(LS_HIDDEN, [])
  );

  const visibleCols = columnOrder.filter(c => !hiddenCols.includes(c));

  useEffect(() => {
    if (vulnerabilities !== undefined) setData(vulnerabilities.length > 0 ? vulnerabilities : []);
    setVisibleCount(PAGE);   // ponytail: new filter result ⇒ window back to the top
  }, [vulnerabilities]);

  const scale = ({ sm: 0.9, md: 1.0, lg: 1.15, xl: 1.35, "2xl": 1.55 } as Record<string, number>)[textSize] ?? 1.0;
  const scaledWidths = () =>
    Object.fromEntries(ALL_COLUMNS.map(k => [k, Math.round(BASE_WIDTHS[k] * scale)])) as Record<ColKey, number>;
  const [widths, setWidths] = useState<Record<ColKey, number>>(() => {
    const saved = loadLS<Record<ColKey, number> | null>(LS_WIDTHS, null);
    return saved && ALL_COLUMNS.every(k => typeof saved[k] === "number") ? saved : scaledWidths();
  });
  useEffect(() => {
    // Text-size rescaling only applies until the user manually resizes (saved widths win).
    if (loadLS<Record<ColKey, number> | null>(LS_WIDTHS, null)) return;
    setWidths(scaledWidths());
  }, [textSize]);

  // Column resize
  const resizingCol = useRef<ColKey | null>(null);
  const startX      = useRef(0);
  const startW      = useRef(0);
  const onResizeStart = (col: ColKey, e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    resizingCol.current = col; startX.current = e.clientX; startW.current = widths[col];
    const onMove = (ev: MouseEvent) => {
      if (!resizingCol.current) return;
      // Min 24px so a column can be shrunk down to a sliver (text clipped) if wanted.
      setWidths(prev => ({ ...prev, [resizingCol.current!]: Math.max(24, startW.current + ev.clientX - startX.current) }));
    };
    const onUp = () => {
      resizingCol.current = null;
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      // Persist the adjusted widths so they survive reloads.
      setWidths(prev => { localStorage.setItem(LS_WIDTHS, JSON.stringify(prev)); return prev; });
    };
    document.addEventListener("mousemove", onMove); document.addEventListener("mouseup", onUp);
  };

  // Column order
  const moveColumn = (col: ColKey, dir: -1 | 1) => {
    const idx = columnOrder.indexOf(col);
    const target = idx + dir;
    if (target < 0 || target >= columnOrder.length) return;
    const next = [...columnOrder];
    [next[idx], next[target]] = [next[target], next[idx]];
    setColumnOrder(next);
    localStorage.setItem(LS_ORDER, JSON.stringify(next));
  };

  const toggleColumn = (col: ColKey) => {
    const next = hiddenCols.includes(col) ? hiddenCols.filter(c => c !== col) : [...hiddenCols, col];
    setHiddenCols(next);
    localStorage.setItem(LS_HIDDEN, JSON.stringify(next));
  };

  // Close column manager on outside click
  const panelRef = useRef<HTMLDivElement>(null);
  const handleOverlayClick = useCallback((e: React.MouseEvent) => {
    if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
      onCloseColumnManager?.();
    }
  }, [onCloseColumnManager]);

  // Clipboard
  const fallbackCopy = (text: string) => {
    const el = document.createElement("textarea");
    el.value = text; el.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(el); el.focus(); el.select();
    document.execCommand("copy"); document.body.removeChild(el);
  };
  const copyId = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (navigator.clipboard) navigator.clipboard.writeText(id).catch(() => fallbackCopy(id));
    else fallbackCopy(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const severityColor = (s: string) => {
    switch (s.toLowerCase()) {
      case "critical": return "bg-red-500/10 text-red-400 border border-red-500/20";
      case "high":     return "bg-orange-500/10 text-orange-400 border border-orange-500/20";
      case "medium":   return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";
      case "low":      return "bg-green-500/10 text-green-400 border border-green-500/20";
      default:         return "bg-white/5 text-gray-400 border border-white/10";
    }
  };

  const renderCell = (col: ColKey, cve: CveItem) => {
    switch (col) {
      case "cve":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden" style={{ width: widths.cve, minWidth: widths.cve }}>
            {/* Line 1: CVE ID + copy */}
            <button onClick={(e) => copyId(cve.id, e)} title="Copy CVE ID"
              className="font-mono font-bold text-sky-400 hover:text-sky-300 flex items-center gap-1 group/copy">
              <span>{cve.id}</span>
              {copiedId === cve.id
                ? <Check className="w-[0.9em] h-[0.9em] text-green-400 flex-shrink-0" />
                : <Copy className="w-[0.8em] h-[0.8em] text-sky-600 opacity-0 group-hover/copy:opacity-100 flex-shrink-0 transition-opacity" />}
            </button>
            {/* Line 2–3: name (wraps up to 2 lines) */}
            <p className="text-[0.78em] text-gray-400 mt-0.5 leading-snug line-clamp-2">{cve.name}</p>
            {/* Last line: URL */}
            {cve.url && (
              <a href={cve.url} target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="mt-1 flex items-center gap-0.5 text-[0.68em] text-gray-600 hover:text-sky-400 transition-colors group/link max-w-full">
                <ExternalLink className="w-[0.85em] h-[0.85em] flex-shrink-0 group-hover/link:text-sky-400" />
                <span className="truncate">{cve.url.replace(/^https?:\/\//, "")}</span>
              </a>
            )}
          </td>
        );
      case "product":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden" style={{ width: widths.product, minWidth: widths.product }}>
            <span className="font-semibold text-cyan-400 truncate block" title={cve.vendor}>{cve.vendor}</span>
            <div className="text-[0.8em] text-gray-500 mt-0.5 truncate" title={cve.product}>{cve.product}</div>
          </td>
        );
      case "severity":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden" style={{ width: widths.severity, minWidth: widths.severity }}>
            <span className={`px-2 py-0.5 text-[0.75em] font-extrabold rounded-md uppercase tracking-wider ${severityColor(cve.severity)}`}>
              {cve.severity}
            </span>
          </td>
        );
      case "scores":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden" style={{ width: widths.scores, minWidth: widths.scores }}>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-bold font-mono text-orange-400 min-w-[2.2em]">{cve.score?.toFixed(1) ?? "—"}</span>
              <div className="w-[5em] h-[0.3em] bg-white/10 rounded-full overflow-hidden flex-shrink-0">
                <div className={`h-full ${cve.score >= 9 ? "bg-red-500" : cve.score >= 7 ? "bg-orange-500" : "bg-yellow-500"}`}
                  style={{ width: `${((cve.score ?? 0) / 10) * 100}%` }} />
              </div>
            </div>
            <div className="text-[0.75em] text-gray-500 font-mono">
              EPSS: <span className="text-green-400 font-bold">{cve.epss == null ? "N/A" : (cve.epss * 100).toFixed(2) + "%"}</span>
            </div>
          </td>
        );
      case "date":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden font-semibold text-gray-400 font-mono"
            style={{ width: widths.date, minWidth: widths.date }}>
            {cve.date}
          </td>
        );
      case "ingested": {
        // Stored UTC ISO string → convert to the user's selected timezone.
        const ts = formatInTz(cve.ingestedAt || "", timezone);
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden font-mono text-gray-400"
            style={{ width: widths.ingested, minWidth: widths.ingested }}>
            {ts
              ? <span title={`${cve.ingestedAt} UTC`}>{ts}</span>
              : <span className="text-gray-600">—</span>}
          </td>
        );
      }
      case "source":
        return (
          <td key={col} className="py-3 px-4 text-[0.85em] align-top overflow-hidden" style={{ width: widths.source, minWidth: widths.source }}>
            {cve.source ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[0.72em] font-medium bg-violet-500/10 text-violet-400 border border-violet-500/20 max-w-full truncate" title={cve.source}>
                {cve.source}
              </span>
            ) : (
              <span className="text-gray-600 text-[0.75em]">—</span>
            )}
          </td>
        );
    }
  };

  // table-fixed + explicit total width => columns honor their set width and clip,
  // so a column can be dragged narrow enough to hide part of the text.
  const totalWidth = visibleCols.reduce((s, c) => s + (widths[c] || 0), 0);

  return (
    <div className="glass-panel overflow-hidden border border-white/5 shadow-2xl rounded-2xl flex flex-col w-full relative h-full">

      {/* Hidden-columns restore bar */}
      {hiddenCols.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 px-4 py-2 border-b border-white/5 bg-black/10 flex-shrink-0">
          <span className="text-[0.65em] font-bold text-gray-500 uppercase tracking-widest">Hidden:</span>
          {hiddenCols.map(col => (
            <button key={col} onClick={() => toggleColumn(col)}
              className="flex items-center gap-1 px-2 py-0.5 text-[0.7em] font-semibold rounded-lg border border-white/10 bg-white/5 text-gray-400 hover:text-white hover:border-sky-500/40 transition">
              <Eye className="w-2.5 h-2.5" />
              {colLabel(col)}
            </button>
          ))}
        </div>
      )}

      <div
        className="overflow-x-auto w-full flex-1 min-h-0"
        onScroll={(e) => {
          // ponytail: near the bottom ⇒ reveal the next page of rows (load-on-scroll).
          const el = e.currentTarget;
          if (el.scrollHeight - el.scrollTop - el.clientHeight < 400) {
            setVisibleCount((c) => (c < data.length ? c + PAGE : c));
          }
        }}
      >
        <table className="text-left border-collapse select-text" style={{ tableLayout: "fixed", width: totalWidth || "100%" }}>
          <thead>
            <tr className="bg-black/30 border-b border-white/10 text-[0.7em] uppercase font-bold tracking-widest text-gray-400 select-none">
              {visibleCols.map((col) => (
                <th key={col} className="relative overflow-hidden" style={{ width: widths[col], minWidth: widths[col], maxWidth: widths[col] }}>
                  <div className="px-4 py-3">
                    <span className="truncate">{colLabel(col)}</span>
                  </div>
                  {/* Resize handle — drag right edge to resize */}
                  <div
                    onMouseDown={(e) => onResizeStart(col, e)}
                    className="absolute right-0 top-0 bottom-0 w-2 cursor-col-resize z-10 flex items-center justify-center group/resize"
                    title="Drag to resize column"
                  >
                    <div className="w-px h-4 bg-white/15 rounded-full group-hover/resize:bg-sky-500/80 group-hover/resize:h-full transition-all duration-150" />
                  </div>
                </th>
              ))}
            </tr>
          </thead>

          <tbody className="divide-y divide-white/5 text-gray-300">
            {data.length === 0 ? (
              <tr>
                <td colSpan={visibleCols.length} className="py-16 text-center text-gray-500 text-sm">
                  No advisories match the current filters.
                </td>
              </tr>
            ) : (
              data.slice(0, visibleCount).map((cve, idx) => (
                <tr key={cve._key || `${cve.id}_${idx}`} className="hover:bg-white/[0.015] transition-colors">
                  {visibleCols.map((col) => renderCell(col, cve))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Column manager panel — triggered from outside via showColumnManager prop */}
      {showColumnManager && (
        <div className="absolute inset-0 z-50 bg-black/40 backdrop-blur-sm" onClick={handleOverlayClick}>
          <div ref={panelRef} className="absolute top-0 right-0 w-64 h-full bg-[#0d1421] border-l border-white/10 flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 flex-shrink-0">
              <span className="text-xs font-bold text-white uppercase tracking-widest">Manage Columns</span>
              <button onClick={() => onCloseColumnManager?.()} className="p-1 text-gray-500 hover:text-white rounded transition">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto py-1">
              {columnOrder.map((col, idx) => {
                const isHidden = hiddenCols.includes(col);
                return (
                  <div key={col} className={`flex items-center gap-2 px-4 py-2.5 hover:bg-white/5 transition ${isHidden ? "opacity-50" : ""}`}>
                    <span className={`flex-1 text-sm font-medium ${isHidden ? "text-gray-500" : "text-gray-200"}`}>
                      {colLabel(col)}
                    </span>
                    <button onClick={() => moveColumn(col, -1)} disabled={idx === 0}
                      className="p-1 text-gray-500 hover:text-white disabled:opacity-20 disabled:cursor-not-allowed rounded transition"
                      title="Move up">
                      <ChevronUp className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => moveColumn(col, 1)} disabled={idx === columnOrder.length - 1}
                      className="p-1 text-gray-500 hover:text-white disabled:opacity-20 disabled:cursor-not-allowed rounded transition"
                      title="Move down">
                      <ChevronDown className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => toggleColumn(col)}
                      className={`p-1 rounded transition ${isHidden ? "text-gray-600 hover:text-gray-300" : "text-sky-400 hover:text-sky-300"}`}
                      title={isHidden ? "Show column" : "Hide column"}>
                      {isHidden ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                );
              })}
            </div>
            <div className="px-4 py-3 border-t border-white/10 flex-shrink-0">
              <p className="text-[0.65em] text-gray-600">Drag column edges to resize · Changes are saved automatically</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
