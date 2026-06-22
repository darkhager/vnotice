# Team Delta — DevOps & Packaging

**Scope:** Docker, CI/CD, environment configuration

## Files Owned
`docker-compose.yml` · `backend/Dockerfile` · `frontend/Dockerfile` · `.github/workflows/ci.yml`

## Current State
- Docker Compose works: PostgreSQL + backend + frontend in three containers.
- CI pipeline lints (flake8 + ESLint) but **does not run pytest** — this is a known gap (P6).

## Immediate Fix Needed
Add pytest to CI:
```yaml
# In .github/workflows/ci.yml, backend-test job:
- name: Run tests
  run: |
    cd backend
    pip install -r requirements.txt
    pytest tests/ -v
```

## Environment Variables (backend)
| Variable | Dev default | Production requirement |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./cvedb.sqlite` | PostgreSQL URL |
| `SECRET_KEY` | `changeme-...` | **Must be changed — 32+ random chars** |
| `ALGORITHM` | `HS256` | Keep |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Adjust per policy |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Set to actual frontend domain |

## Standards
- Never commit real credentials to docker-compose.yml — use `.env` file or secrets manager.
- Any new system dependency added by Alpha (e.g. `twilio`, `aiosmtplib`) must be added to `backend/Dockerfile` and `requirements.txt` simultaneously.
- CI must pass before any merge to main.
