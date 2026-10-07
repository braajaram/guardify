# Guardify

Evidence-first URL, file, and email security analysis. The current vertical slice never invents threat intelligence: until VirusTotal/Gemini/Redis/Supabase credentials and adapters are configured, scans return `UNKNOWN` with an explicit unavailable-evidence explanation.

## Run locally

```powershell
cd apps/api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
pytest
```

In another terminal:

```powershell
cd apps/web
npm install
npm run dev
```

Copy `.env.example` to environment-specific secret stores. Never expose `SUPABASE_SERVICE_ROLE_KEY` or provider keys to the browser. Deploy `apps/api` as a Render web service and `apps/web` as a Vercel project; set `NEXT_PUBLIC_API_URL` to the Render URL and `CORS_ORIGINS` to the Vercel URL.

## Current scope and limitations

Implemented and tested: URL scheme/credential/SSRF validation, bounded file reads, SHA-256 hashing, strict email schema, request IDs, security headers, structured response shape, graceful `UNKNOWN` state, and a functional web flow. Provider integrations, authentication/RLS, Redis caching/rate limiting, persistent history, and full analyst telemetry require the configured Supabase, Upstash, VirusTotal, and Gemini adapters before production launch. No scan is presented as safe without evidence.
