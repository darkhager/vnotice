# Onboarding — Vnotice

New here? Do these in order.

## 1. Get access
- Clone the repo: `git clone https://github.com/darkhager/vnotice.git`
- Ask the team for the SSH login to the production server (`vnotice@10.4.150.57`). Never put that password in a file — keep it in your own password manager.
- On Windows, install [PuTTY](https://www.putty.org/) — deployment uses its `plink`/`pscp` tools (see step 4), not OpenSSH.

## 2. Run it locally
```powershell
# Backend (SQLite, no Docker)
cd backend
.\setup_local.ps1        # creates venv, installs deps, writes .env, starts uvicorn
# API: http://localhost:8000  Swagger: http://localhost:8000/docs

# Frontend (separate terminal)
cd frontend
npm install
npm run dev               # http://localhost:3000
```
If a run fails with `table user_configs has no column named ...`, delete `backend/cvedb.sqlite` and restart — the dev DB gets recreated with the current schema.

## 3. Read the map before touching code
- `CLAUDE.md` — architecture, routes, schema, what's built vs. missing.
- `backend/main.py` — every API route. `backend/rss_parser.py` — feed/NVD fetchers. `frontend/src/components/Dashboard.tsx` — nearly the whole UI (it's a big single file, see CLAUDE.md's P4 for the planned split).

## 4. Know the production layout
Bare-metal on `10.4.150.57` (no Docker, no root — the `vnotice` user isn't a sudoer):

| Service | Port | Unit |
|---|---|---|
| Backend (uvicorn, plain HTTP) | 8080 | `vnotice-backend.service` |
| Frontend (Next.js, `next start`, plain HTTP) | 4000 | `vnotice-frontend.service` |

Both are `systemd --user` services (lingering enabled, so they survive logout/reboot without a login session). Both serve plain HTTP (no TLS) -- open `http://10.4.150.57:4000`.

## 5. Ship a change
There's no CI/CD yet — deploys are manual, from Windows via PuTTY's CLI tools (`git bash` recommended):

**Backend:**
```bash
# 1. Syntax-check locally first
py -c "import ast; ast.parse(open('backend/main.py', encoding='utf-8').read())"

# 2. Upload
"/c/Program Files/PuTTY/pscp.exe" -batch -pw '<password>' backend/main.py vnotice@10.4.150.57:/home/vnotice/vnotice/backend/

# 3. Restart (MSYS_NO_PATHCONV=1 stops git-bash from mangling the /run/user/... path)
MSYS_NO_PATHCONV=1 "/c/Program Files/PuTTY/plink.exe" -ssh -batch -pw '<password>' vnotice@10.4.150.57 \
  "XDG_RUNTIME_DIR=/run/user/\$(id -u) systemctl --user restart vnotice-backend"

# 4. Verify
curl -s http://10.4.150.57:8080/health/
```

**Frontend:** same upload step, then on the server: `npm run build` (needs `nvm use 20` first) before restarting `vnotice-frontend` — Next.js needs a rebuild, unlike the backend which just re-executes the `.py` file.

**Gotcha:** never `pkill -f 'uvicorn main:app'` over SSH — the pattern matches the SSH shell's own command line and kills your connection (exit 128). Use `systemctl --user stop/restart` instead.

## 6. Commit
Nothing auto-commits. Stage, commit, and push yourself when a change is ready — ask before pushing if you're unsure it's wanted yet.
