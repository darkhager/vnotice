"use client";
import React, { useEffect, useState } from "react";
import { getApiBase } from "../lib/api";

// Settings → AI Verification. Same contract as Sabler's Settings page: the
// server never returns the key, only whether one is saved and its last 4 chars.
type Provider = { id: string; label: string; model: string; verify_model: string; models: string[] };
type LlmSettings = {
  providers: Provider[]; provider: string; model: string; verify_model: string;
  configured: boolean; key_hint: string;
};

export default function AiSettings() {
  const [s, setS] = useState<LlmSettings | null>(null);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [verifyModel, setVerifyModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const apply = (d: LlmSettings) => {
    setS(d);
    const p = d.provider || d.providers[0]?.id || "";
    const def = d.providers.find((x) => x.id === p);
    setProvider(p);
    setModel(d.model || def?.model || "");
    setVerifyModel(d.verify_model || def?.verify_model || "");
  };

  useEffect(() => {
    fetch(`${getApiBase()}/settings/llm`).then((r) => r.json()).then(apply).catch(() => setMsg("✗ Could not load AI settings."));
  }, []);

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

  const onProvider = (id: string) => {
    setProvider(id);
    const def = s?.providers.find((x) => x.id === id);
    setModel(def?.model || "");
    setVerifyModel(def?.verify_model || "");
  };

  const models = s?.providers.find((x) => x.id === provider)?.models || [];
  const input = "w-full bg-black/35 border border-white/10 rounded-lg p-2.5 text-white focus:border-sky-400 focus:outline-none text-xs transition";
  const label = "block text-[10px] font-semibold text-gray-400 uppercase tracking-wider";
  const btn = "px-3 py-2 text-xs font-bold rounded-lg transition disabled:opacity-50";

  return (
    <div className="p-6 space-y-6">
      <div className="border-b border-white/10 pb-4">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">🤖 AI Verification</h2>
        <p className="text-xs text-gray-400 mt-1">
          An AI model double-checks the vulnerability details extracted from each CVE record (affected versions,
          conditions, fix, mitigation, IOCs) against the vendor&apos;s own text, and flags anything wrong or missing.
          Same provider setup as Sabler.
        </p>
      </div>

      {s && (
        <div className="space-y-4 bg-black/10 p-5 rounded-xl border border-white/5 max-w-2xl">
          <div className="text-xs text-gray-400">
            Status:{" "}
            {s.configured
              ? <span className="text-green-400 font-bold">Key saved ({s.key_hint}) · {s.provider}</span>
              : <span className="text-yellow-400 font-bold">No key registered</span>}
          </div>
          <div className="space-y-1">
            <label className={label}>Provider</label>
            <select value={provider} onChange={(e) => onProvider(e.target.value)} className={input}>
              {s.providers.map((p) => <option key={p.id} value={p.id} className="bg-slate-900">{p.label}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className={label}>Model</label>
              <input list="ai-models" value={model} onChange={(e) => setModel(e.target.value)} className={input} />
            </div>
            <div className="space-y-1">
              <label className={label}>Verifier model (does the checking)</label>
              <input list="ai-models" value={verifyModel} onChange={(e) => setVerifyModel(e.target.value)} className={input} />
            </div>
            <datalist id="ai-models">{models.map((m) => <option key={m} value={m} />)}</datalist>
          </div>
          <div className="space-y-1">
            <label className={label}>API key</label>
            <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} autoComplete="off"
              placeholder={s.configured ? "Leave blank to keep the saved key" : "Paste the provider's API key"} className={input} />
            <p className="text-[10px] text-gray-500">Stored encrypted on the server; never shown again or sent to the browser.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button disabled={busy} className={`${btn} bg-sky-500 hover:bg-sky-600 text-white`}
              onClick={async () => {
                const d = await call("PUT", "/settings/llm", { provider, model, verify_model: verifyModel, api_key: apiKey });
                if (d) { apply(d); setApiKey(""); setMsg("✓ Saved."); }
              }}>Save</button>
            <button disabled={busy || !s.configured} className={`${btn} glass-panel border border-white/10 text-gray-300 hover:text-white`}
              onClick={async () => {
                const d = await call("POST", "/settings/llm/test");
                if (d) setMsg(`✓ Both models answered: ${d.reply}`);
              }}>{busy ? "Working…" : "Test"}</button>
            <button disabled={busy || !s.configured} className={`${btn} glass-panel border border-red-500/20 text-red-400 hover:bg-red-500/10`}
              onClick={async () => {
                if (!window.confirm("Remove the saved AI key?")) return;
                const d = await call("DELETE", "/settings/llm");
                if (d) { apply(d); setMsg("✓ Key removed."); }
              }}>Remove key</button>
          </div>
          {msg && <p className="text-[11px] text-gray-300">{msg}</p>}
        </div>
      )}
    </div>
  );
}
