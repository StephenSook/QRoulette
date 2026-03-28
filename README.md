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
    - `destination` (string)
    - `reason` (string)
    - `analysis` object:
      - `risk_score` (0-100)
      - `risk_level` (`safe` | `suspicious` | `danger`)
      - `flagged_safe_browsing` (boolean)
      - `flagged_threat_intel` (boolean)
      - `typosquatting_detected` (boolean)
      - `domain_age_days` (integer or null)
      - `redirect_hops` (integer)
      - `ssl_valid` (boolean)
      - `ai_summary` (string)

- `GET /go?url=...&qr_code_id=...`
  - Logs scan attempt to Supabase.
  - If safe: returns `307` redirect to destination.
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
- Risk analysis currently uses fallback logic in `backend/services/analyzer.py`.
- Teammate integrations (Safe Browsing, threat intel, redirect checker, Gemini) should plug into the analyzer while preserving the same response shape.
