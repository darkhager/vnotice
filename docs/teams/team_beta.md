# Team Beta — Frontend Experience

**Scope:** All Next.js/React source in `frontend/src/`

## Files Owned
`frontend/src/` — all components, hooks, lib, types  
`frontend/package.json` · `frontend/tsconfig.json` · `frontend/tailwind.config.ts`

## Current Sprint Focus (P4)
1. Extract `useCveData`, `useSyncState`, `useAlertRules` hooks from Dashboard.tsx
2. Move `mapApiCve()` + `inferVendorProduct()` to `frontend/src/lib/cveUtils.ts`
3. Extract `<AlertsPanel>` component
4. Target: Dashboard.tsx < 500 lines, same behaviour, TypeScript strict passes

## Standards
- TypeScript strict mode always on. No `as any`, no `// @ts-ignore`.
- All API calls through `frontend/src/lib/api.ts` — no inline `fetch()` in components.
- When a new backend endpoint is added (by Alpha), wire it into `api.ts` in the same PR.
- Manual browser test required before merge (golden path + edge cases).
