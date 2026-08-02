# 1ai-osint Frontend

Single-page React app (React 19 + TypeScript + Vite 8) for the 1ai-osint OSINT & identity-correlation platform. It submits a scan target (name, username, email, or domain), polls the backend job status, and renders the resulting findings dashboard.

## Dev

```bash
npm install
npm run dev      # Vite dev server (default http://localhost:5173)
```

In dev, API requests (`/api/*`) are proxied to the FastAPI backend at `http://127.0.0.1:8000` (see `vite.config.ts`), so no CORS or environment setup is required.

## Build & verify

```bash
npm run build    # tsc -b && vite build
npm run lint     # eslint .
npm run preview  # serve the production build locally
```

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_BASE_URL` | unset (same-origin `/api`) | Base URL of the 1ai-osint backend. Leave unset in dev to use the Vite proxy. Set it (e.g. `http://127.0.0.1:8000`) to talk directly to a backend served elsewhere, such as a production build or a remote host. Trailing slashes are stripped. |

Copy `frontend/.env.example` to `frontend/.env` if you need to override the backend URL.

## API contract

- `POST {base}/api/scan` — body `{ target, fast: true, max_iterations: 3 }` → `{ job_id, status }`
- `GET {base}/api/scan/{job_id}` — polled every 2 s until `completed` or `failed`, capped at 90 attempts or 5 consecutive failures so a stuck job cannot poll forever.

## Layout

- `src/App.tsx` — scan form, job polling, results dashboard
- `src/main.tsx` — React entry point
- `src/index.css` — global styles
- `public/favicon.svg` — site icon
