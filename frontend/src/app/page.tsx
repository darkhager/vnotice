"use client";
import { useEffect, useState } from "react";
import Dashboard from "@/components/Dashboard";
import { hydrateState } from "@/lib/profileSync";

export default function Home() {
  // Pull any server-saved profile/settings bundle into localStorage BEFORE the
  // Dashboard reads it, so a fresh browser restores the saved profiles.
  const [ready, setReady] = useState(false);
  useEffect(() => {
    hydrateState().finally(() => setReady(true));
  }, []);

  if (!ready) {
    return (
      <main className="min-h-screen p-4 md:p-8 flex items-center justify-center">
        <div className="text-slate-400 text-sm animate-pulse">Loading profiles…</div>
      </main>
    );
  }

  return (
    <main className="min-h-screen p-4 md:p-8">
      <Dashboard />
    </main>
  );
}
