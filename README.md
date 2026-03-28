# QRoulette
For the description: QRoulette — Consumer financial fraud prevention tool that analyzes QR code destinations in real-time, blocking malicious links before they reach the user.

## Backend Contract (Team Integration)

Backend lives in `backend/` and currently exposes a stable `1.0.0` contract for teammates to build against.

### Run locally

From `backend/`:

- `py -m venv .venv`
- `.venv\Scripts\activate`
- `py -m pip install -r requirements.txt`
- `py -m uvicorn main:app --reload`

Open docs at `http://127.0.0.1:8000/docs`.

### Endpoints

- `GET /health`
  - Returns: `{ "status": "ok" }`

- `GET /contract`
  - Returns active contract version and route registry.

- `POST /scan`
  - Request body:
    - `url` (string, required)
    - `qr_code_id` (string, optional)
  - Response:
    - `allowed` (boolean)
    - `destination` (string, resolved final URL after redirects)
    - `reason` (string)
    - `analysis` object:
      - `risk_score` (0-100)
      - `risk_level` (`safe` | `suspicious` | `danger`)
      - `flagged_safe_browsing` (boolean)
      - `flagged_threat_intel` (boolean)
      - `typosquatting_detected` (boolean)
      - `domain_age_days` (integer or null)
      - `redirect_hops` (integer, based on the observed redirect chain)
      - `ssl_valid` (boolean)
      - `ai_summary` (string)

- `GET /go?url=...&qr_code_id=...`
  - Logs scan attempt to Supabase.
  - If safe: returns `307` redirect to the resolved final destination.
  - If danger: returns `403` with same decision payload shape as `POST /scan`.

- `GET /dashboard/summary`
  - Returns counters:
    - `safe`, `suspicious`, `danger`, `total`

- `GET /dashboard/recent?limit=25`
  - Returns recent scan records from Supabase `scans` table.
  - `limit` range: `1` to `100`.

### Supabase notes

- Table used: `scans`
- Public inserts are allowed for scanner flow.
- Reads should come from backend using service role key.
- `.env` must include:
  - `SUPABASE_URL`
  - `SUPABASE_KEY`

### Current implementation status

- Contract and logging are stable.
- `backend/services/analyzer.py` now calls shared service modules and maps their outputs into the same `RiskAnalysis` contract.

### Service integration interfaces

Keep these function signatures stable so teammate internals can evolve without breaking routes:

- `backend/services/safe_browsing.py`
  - `check_safe_browsing(url: str) -> dict`
  - Returns keys: `matched` (bool), `threat_types` (list[str]), `error` (str | None)

- `backend/services/whoisxml.py`
  - `get_domain_age_days(hostname: str) -> int | None`

- `backend/services/typosquatting.py`
  - `detect_typosquatting(target: str) -> bool`

- `backend/services/extensions.py`
  - `get_suspicious_extension(url: str) -> str | None`

- `backend/services/gemini.py`
  - `summarize_risk(url: str, risk_level: str, reasons: list[str]) -> str`

### Security service env vars

- `GOOGLE_SAFE_BROWSING_API_KEY` (preferred)
- `GOOGLE_SAFE_API_KEY` (legacy fallback, supported)
- `WHOIS_MOCK_AGES` (optional local/demo mapping, format: `host:days,host2:days`)
- `WHOIS_CREATED_AT` (optional ISO timestamp fallback for local testing)

## Deploy On Vercel

This repo is now prepared for a two-project Vercel setup:

- `frontend/` as a Next.js project
- `backend/` as a FastAPI project

### Frontend project

In Vercel, create a project with:

- Root Directory: `frontend`
- Framework Preset: `Next.js`

Required environment variables:

- `NEXT_PUBLIC_API_URL=https://<your-backend>.vercel.app`

### Backend project

In Vercel, create a second project with:

- Root Directory: `backend`
- Framework Preset: `Other`

The backend now includes `backend/pyproject.toml`, which declares runtime dependencies and exposes the FastAPI app entrypoint as `main:app` for Vercel.

Recommended environment variables:

- `CORS_ORIGINS=https://<your-frontend>.vercel.app`
- `SUPABASE_URL`
- `SUPABASE_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`
- Any other provider keys used by your deployment

### Notes

- Root Directory is a Vercel project setting, so it cannot be fully committed in the repo.
- The frontend defaults to `http://localhost:8000` for local development and should use `NEXT_PUBLIC_API_URL` in Vercel.
- If you want preview frontend deployments to call the backend, add the relevant preview domain(s) to `CORS_ORIGINS` or use a shared custom domain strategy.
