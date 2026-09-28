"use client";
import React, { useEffect, useState } from "react";
import { getApiBase } from "../lib/api";

// Settings → Admin Summary: Teams webhook(s) that get ONE card every 10 minutes
// listing every new CVE across all feeds. The server never returns the URLs,
// only their last 6 characters.
export default function AdminDigestSettings() {
  const [saved, setSaved] = useState<{ enabled: boolean; webhooks: string[] } | null>(null);
  const [urls, setUrls] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const load = () =>
    fetch(`${getApiBase()}/settings/admin-digest`).then((r) => r.json())
      .then((d) => { setSaved(d); if (d.webhooks.length) setEnabled(d.enabled); })
      .catch(() => setMsg("✗ Could not load settings."));
  useEffect(() => { load(); }, []);

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
  return (
    <div className="p-6 space-y-6">
      <div className="border-b border-white/10 pb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">📋 Admin Summary</h2>
        <p className="text-xs text-gray-400 mt-1">
          Every 10 minutes, one Microsoft Teams card listing every new CVE from every feed (sorted by severity).
          Skipped when nothing is new. Individual users keep their own per-CVE alerts.
        </p>
      </div>
      {saved && (
        <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5 max-w-2xl">
          <div className="text-xs text-gray-400">
            Status:{" "}
            {saved.webhooks.length
              ? <span className={saved.enabled ? "text-green-400 font-bold" : "text-yellow-400 font-bold"}>
                  {saved.enabled ? "On" : "Paused"} · {saved.webhooks.length} webhook(s) ({saved.webhooks.join(", ")})
                </span>
              : <span className="text-yellow-400 font-bold">No webhook saved</span>}
          </div>
          <div className="space-y-1">
            <label className="block text-[10px] font-semibold text-gray-400 uppercase tracking-wider">
              Teams webhook URL(s), one per line
            </label>
            <textarea value={urls} onChange={(e) => setUrls(e.target.value)} rows={3}
              placeholder={saved.webhooks.length ? "Leave blank to keep the saved webhook(s)" : "https://...logic.azure.com/workflows/..."}
              className="w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-xs font-mono" />
            <p className="text-[10px] text-gray-500">Stored encrypted on the server. Create one in Teams: channel → ··· → Workflows → “Post to a channel when a webhook request is received”.</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer select-none">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="accent-sky-500" />
            Send the 10-minute summary
          </label>
          <div className="flex flex-wrap gap-2">
            <button disabled={busy} className={`${btn} bg-sky-500 hover:bg-sky-600 text-white`}
              onClick={async () => {
                const list = urls.split("\n").map((u) => u.trim()).filter(Boolean);
                const d = await call("PUT", "/settings/admin-digest", { webhooks: list, enabled, keep_existing: list.length === 0 });
                if (d) { setSaved(d); setUrls(""); setMsg("✓ Saved."); }
              }}>Save</button>
            <button disabled={busy || !saved.webhooks.length} className={`${btn} glass-panel border border-white/10 text-gray-300 hover:text-white`}
              onClick={async () => {
                const d = await call("POST", "/settings/admin-digest/test");
                if (d) setMsg(`✓ ${d.result}`);
              }}>{busy ? "Working…" : "Send test card"}</button>
          </div>
          {msg && <p className="text-[11px] text-gray-300">{msg}</p>}
        </div>
      )}
    </div>
  );
}
