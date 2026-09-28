// Mirrors the frontend's profile + settings bundle (the `vnotice_*` localStorage
// keys) to the backend so profiles survive a browser cache-clear / new browser
// and are captured by server-side DB backups. No login required.
//
// Every browser shares ONE server bundle, so a blind "upload my copy" let a
// browser holding an old copy (just by loading the page) wipe edits made in
// another browser -- e.g. the Admin profile's Teams webhook. Sync is therefore
// three-way: `base` is what this browser last got from / gave to the server;
// only values that differ from `base` are local edits and go up. Everything
// else is taken from the server as it is now.
import { getApiBase } from "./api";

const BUNDLE_KEY = "profiles_v1";
// Derived/large caches, and per-browser state (which profile is signed in HERE).
const EXCLUDE = new Set(["vnotice_vulnerabilities", "vnotice_currentUser_id", "vnotice_deleted_profiles"]);
const PROFILES = "vnotice_profiles";

type Bundle = Record<string, string>;

export function collectBundle(): Bundle {
  const out: Bundle = {};
  if (typeof localStorage === "undefined") return out;
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && k.startsWith("vnotice_") && !EXCLUDE.has(k)) {
      out[k] = localStorage.getItem(k) ?? "";
    }
  }
  return out;
}

let base: Bundle = {};          // last state agreed with the server
let lastServer: Bundle = {};    // last server copy seen (for the unload beacon)
let lastPushed = "";

const byId = (raw: string | undefined): Map<string, any> => {
  const m = new Map<string, any>();
  try { const v = JSON.parse(raw || "[]"); if (Array.isArray(v)) v.forEach((p) => p?.id && m.set(p.id, p)); } catch { /* ignore */ }
  return m;
};

// Profiles merge per profile, so two browsers editing different profiles both win.
function mergeProfiles(server?: string, baseRaw?: string, local?: string): string | undefined {
  const S = byId(server), B = byId(baseRaw), L = byId(local);
  const out = new Map(S);
  L.forEach((p, id) => { if (JSON.stringify(p) !== JSON.stringify(B.get(id))) out.set(id, p); });  // edited / created here
  B.forEach((_, id) => { if (!L.has(id)) out.delete(id); });                                       // deleted here
  return out.size ? JSON.stringify(Array.from(out.values())) : server;
}

export function mergeBundles(server: Bundle, local: Bundle): Bundle {
  const out: Bundle = { ...server };
  for (const [k, v] of Object.entries(local)) {
    if (!(k in server) || v !== base[k]) out[k] = v;   // new key, or edited here
  }
  for (const k of Object.keys(base)) if (!(k in local)) delete out[k];   // removed here
  const p = mergeProfiles(server[PROFILES], base[PROFILES], local[PROFILES]);
  if (p !== undefined) out[PROFILES] = p;
  return out;
}

async function fetchServerBundle(): Promise<Bundle | null> {
  const res = await fetch(`${getApiBase()}/appstate/${BUNDLE_KEY}`);
  if (!res.ok) return null;
  const v = (await res.json())?.value;
  if (!v || typeof v !== "object") return {};
  return Object.fromEntries(Object.entries(v as Bundle).filter(([k]) => !EXCLUDE.has(k)));
}

// Upload this browser's edits merged into the server's current bundle.
export async function pushState(): Promise<void> {
  try {
    const local = collectBundle();
    if (Object.keys(local).length === 0) return;
    const serialized = JSON.stringify(local);
    if (serialized === lastPushed) return;
    const server = await fetchServerBundle();
    if (server === null) return;
    const merged = mergeBundles(server, local);
    const res = await fetch(`${getApiBase()}/appstate/${BUNDLE_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: merged }),
    });
    if (res.ok) {
      lastPushed = serialized;
      lastServer = merged;
      // Our edits are now agreed. Keys we did NOT edit keep their old base, so a
      // stale in-memory copy written back later still isn't mistaken for an edit.
      for (const [k, v] of Object.entries(local)) if (v !== base[k]) base[k] = v;
      for (const k of Object.keys(base)) if (!(k in local)) delete base[k];
      base[PROFILES] = local[PROFILES];
    }
  } catch {
    /* offline / backend down — try again next tick */
  }
}

// Best-effort push on tab close (survives unload where fetch may not).
export function pushBeacon(): void {
  try {
    const local = collectBundle();
    if (Object.keys(local).length === 0 || JSON.stringify(local) === lastPushed) return;
    const blob = new Blob([JSON.stringify({ value: mergeBundles(lastServer, local) })], { type: "application/json" });
    navigator.sendBeacon(`${getApiBase()}/appstate/${BUNDLE_KEY}`, blob);
  } catch {
    /* ignore */
  }
}

// On page load the server copy is the truth: it overwrites this browser's
// vnotice_* keys (keys only this browser has are kept and pushed up later).
export async function hydrateState(): Promise<void> {
  try {
    if (typeof localStorage === "undefined") return;
    const server = await fetchServerBundle();
    if (!server) { base = collectBundle(); return; }
    for (const [k, v] of Object.entries(server)) if (typeof v === "string") localStorage.setItem(k, v);
    lastServer = server;
    base = { ...server };
  } catch {
    /* offline / backend down — fall back to local-only */
  }
}
