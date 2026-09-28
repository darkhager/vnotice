"use client";
import React, { useEffect, useMemo, useState } from "react";
import { getApiBase } from "../lib/api";

// Settings → Threat Summary Management (admin only): pick the sources, and
// optionally specific products under each (same tree as the Threat Stream
// filter), whose CVEs get details extracted + an AI summary/verification.
// Results live in the cve_insights table, linked to cves by CVE number.
type Sel = Record<string, "all" | string[]>;
type Stats = { in_scope: number; extracted: number; ai_checked: number; ai_errors: number; ai_configured: boolean; backfill_days: number };

export default function ThreatSummarySettings() {
  const [catalog, setCatalog] = useState<{ source: string; product: string; count: number }[]>([]);
  const [sel, setSel] = useState<Sel>({});
  const [enabled, setEnabled] = useState(true);
  const [stats, setStats] = useState<Stats | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const apply = (d: any) => { setSel(d.sources || {}); setEnabled(d.enabled || !Object.keys(d.sources || {}).length); setStats(d.stats); };
  const load = () => {
    fetch(`${getApiBase()}/cves/products`).then((r) => r.json()).then(setCatalog).catch(() => {});
    fetch(`${getApiBase()}/settings/threat-summary`).then((r) => r.json()).then(apply)
      .catch(() => setMsg("✗ Could not load settings."));
  };
  useEffect(load, []);

  // source → [{product, count}], sources sorted by volume
  const tree = useMemo(() => {
    const m = new Map<string, { product: string; count: number }[]>();
    catalog.forEach((r) => { if (!m.has(r.source)) m.set(r.source, []); m.get(r.source)!.push({ product: r.product, count: r.count }); });
    return Array.from(m.entries())
      .map(([source, prods]) => ({ source, prods: prods.sort((a, b) => b.count - a.count), total: prods.reduce((n, p) => n + p.count, 0) }))
      .sort((a, b) => b.total - a.total);
  }, [catalog]);

  const toggleSource = (src: string) =>
    setSel((prev) => { const n = { ...prev }; if (n[src]) delete n[src]; else n[src] = "all"; return n; });

  const toggleProduct = (src: string, prod: string, all: string[]) =>
    setSel((prev) => {
      const n = { ...prev };
      const cur = n[src] === "all" ? all : (n[src] as string[] | undefined) || [];
      const next = cur.includes(prod) ? cur.filter((p) => p !== prod) : [...cur, prod];
      if (next.length === 0) delete n[src];
      else n[src] = next.length === all.length ? "all" : next;
      return n;
    });

  const call = async (method: string, path: string, body?: object) => {
    setBusy(true);
    setMsg("");
    try {
      const r = await fetch(`${getApiBase()}${path}`, {
        method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined,
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof d.detail === "string" ? d.detail : `HTTP ${r.status}`);
      return d;
    } catch (e) {
      setMsg(`✗ ${e instanceof Error ? e.message : "request failed"}`);
      return null;
    } finally {
      setBusy(false);
    }
  };

  const btn = "px-3 py-2 text-xs font-bold rounded-lg transition disabled:opacity-50";
  const picked = Object.keys(sel).length;
  return (
    <div className="p-6 space-y-6">
      <div className="border-b border-white/10 pb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">🧠 Threat Summary Management</h2>
        <p className="text-xs text-gray-400 mt-1">
          Choose which sources and products get automatic detail extraction (affected / fixed versions, conditions,
          mitigation, remediation, IOCs) plus an AI summary and AI check. Runs every 10 minutes, newest CVEs first,
          covering CVEs from the last {stats?.backfill_days ?? 30} days and every new one.
        </p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-2xl">
          {[["In scope", stats.in_scope], ["Extracted", stats.extracted], ["AI checked", stats.ai_checked], ["AI failed", stats.ai_errors]].map(([l, n]) => (
            <div key={l as string} className="bg-black/20 border border-white/5 rounded-xl p-3">
              <div className="text-[10px] text-gray-500 uppercase tracking-wider">{l}</div>
              <div className="text-lg font-bold text-white">{n as number}</div>
            </div>
          ))}
        </div>
      )}
      {stats && !stats.ai_configured && (
        <p className="text-[11px] text-yellow-400">No AI key registered — details are extracted, but no AI summary/check until one is set in Settings → 🤖 AI Verification.</p>
      )}

      <div className="bg-black/10 p-5 rounded-xl border border-white/5 max-w-2xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Sources &amp; products ({picked} source{picked === 1 ? "" : "s"} selected)</div>
          <div className="flex gap-3 text-[11px]">
            <button className="text-sky-400 hover:underline" onClick={() => setSel(Object.fromEntries(tree.map((t) => [t.source, "all" as const])))}>Select all</button>
            <button className="text-sky-400 hover:underline" onClick={() => setSel({})}>Deselect all</button>
          </div>
        </div>
        <div className="max-h-[420px] overflow-y-auto pr-1 space-y-1">
          {tree.map(({ source, prods, total }) => {
            const s = sel[source];
            const all = prods.map((p) => p.product);
            const partial = Array.isArray(s);
            return (
              <div key={source}>
                <div className="flex items-center gap-2 text-xs text-gray-200 py-1">
                  <button className="w-4 text-gray-500 hover:text-white" onClick={() => setOpen((o) => ({ ...o, [source]: !o[source] }))}>
                    {open[source] ? "▼" : "▶"}
                  </button>
                  <input type="checkbox" className="accent-sky-500" checked={!!s}
                    ref={(el) => { if (el) el.indeterminate = partial; }} onChange={() => toggleSource(source)} />
                  <span className="flex-1 cursor-pointer select-none" onClick={() => toggleSource(source)}>{source}</span>
                  <span className="text-[10px] text-gray-500">{partial ? `${(s as string[]).length}/${all.length} products · ` : ""}{total}</span>
                </div>
                {open[source] && (
                  <div className="pl-10 pb-1 space-y-0.5">
                    {prods.map(({ product, count }) => (
                      <label key={product} className="flex items-center gap-2 text-[11px] text-gray-300 cursor-pointer select-none">
                        <input type="checkbox" className="accent-sky-500"
                          checked={s === "all" || (partial && (s as string[]).includes(product))}
                          onChange={() => toggleProduct(source, product, all)} />
                        <span className="flex-1">{product}</span>
                        <span className="text-[10px] text-gray-500">{count}</span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          {tree.length === 0 && <div className="text-xs text-gray-500">Loading sources…</div>}
        </div>

        <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer select-none pt-2 border-t border-white/5">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="accent-sky-500" />
          Run the Threat Summary job
        </label>
        <div className="flex flex-wrap gap-2">
          <button disabled={busy} className={`${btn} bg-sky-500 hover:bg-sky-600 text-white`}
            onClick={async () => {
              const d = await call("PUT", "/settings/threat-summary", { enabled, sources: sel });
              if (d) { apply(d); setMsg("✓ Saved."); }
            }}>Save</button>
          <button disabled={busy || !picked} className={`${btn} glass-panel border border-white/10 text-gray-300 hover:text-white`}
            onClick={async () => { const d = await call("POST", "/settings/threat-summary/run"); if (d) setMsg(`✓ ${d.result}`); }}>
            Run a batch now
          </button>
          {!!stats?.ai_errors && (
            <button disabled={busy} className={`${btn} glass-panel border border-white/10 text-gray-300 hover:text-white`}
              onClick={async () => { const d = await call("POST", "/settings/threat-summary/run?retry_failed=true"); if (d) setMsg(`✓ ${d.result}`); }}>
              Retry failed
            </button>
          )}
          <button disabled={busy} className={`${btn} text-gray-400 hover:text-white`} onClick={load}>↻ Refresh counts</button>
        </div>
        {msg && <p className="text-[11px] text-gray-300">{msg}</p>}
      </div>
    </div>
  );
}
