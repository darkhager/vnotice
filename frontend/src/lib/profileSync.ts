// Mirrors the frontend's profile + settings bundle (the `vnotice_*` localStorage
// keys) to the backend so profiles survive a browser cache-clear / new browser
// and are captured by server-side DB backups. No login required.
import { getApiBase } from "./api";

const BUNDLE_KEY = "profiles_v1";
// Derived/large caches that don't belong in the profile bundle.
const EXCLUDE = new Set(["vnotice_vulnerabilities"]);

export function collectBundle(): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof localStorage === "undefined") return out;
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && k.startsWith("vnotice_") && !EXCLUDE.has(k)) {
      out[k] = localStorage.getItem(k) ?? "";
    }
  }
  return out;
}

let _lastPushed = "";

// Upload the current bundle (skips redundant pushes when nothing changed).
export async function pushState(): Promise<void> {
  try {
    const bundle = collectBundle();
    if (Object.keys(bundle).length === 0) return;
    const serialized = JSON.stringify(bundle);
    if (serialized === _lastPushed) return;
    const res = await fetch(`${getApiBase()}/appstate/${BUNDLE_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: bundle }),
    });
    if (res.ok) _lastPushed = serialized;
  } catch {
    /* offline / backend down — try again next tick */
  }
}

// Best-effort push on tab close (survives unload where fetch may not).
export function pushBeacon(): void {
  try {
    const bundle = collectBundle();
    if (Object.keys(bundle).length === 0) return;
    const blob = new Blob([JSON.stringify({ value: bundle })], { type: "application/json" });
    navigator.sendBeacon(`${getApiBase()}/appstate/${BUNDLE_KEY}`, blob);
  } catch {
    /* ignore */
  }
}

// Pull the server bundle into localStorage. Only seeds a browser that has no
// local profiles yet, so an existing browser's data is never clobbered on load.
export async function hydrateState(): Promise<void> {
  try {
    if (typeof localStorage === "undefined") return;
    const hasLocalProfiles = !!localStorage.getItem("vnotice_profiles");
    if (hasLocalProfiles) return;
    const res = await fetch(`${getApiBase()}/appstate/${BUNDLE_KEY}`);
    if (!res.ok) return;
    const data = await res.json();
    const bundle = data?.value;
    if (!bundle || typeof bundle !== "object") return;
    for (const [k, v] of Object.entries(bundle)) {
      if (typeof v === "string") localStorage.setItem(k, v);
    }
  } catch {
    /* offline / backend down — fall back to local-only */
  }
}
