---
scope: frontend
depends_on: [src/api/app.py, src/core/models.py, src/modules/deep_scan/__init__.py]
status: complete
---

# AGENTS.md — frontend

## Tujuan Folder Ini
React 19 + Vite 8 + TypeScript SPA untuk UX deep-scan (identity correlation / OSINT dashboard). Entry: `index.html` → `src/main.tsx` → `src/App.tsx`.

## Ekspor / Interface Utama
- `src/main.tsx` — entry; `createRoot(document.getElementById('root')!)` + `<StrictMode>` renders `App`
- `src/App.tsx` — default export `App`; single-page scan UI (submit scan, poll job status, render dossier & findings)
- API contract consumed (backend FastAPI): `POST /api/scan` body `{target, fast, max_iterations}` → `{job_id, status, target}`; `GET /api/scan/{job_id}` → job dict berisi `status` dan `result`
- Scripts (`package.json`): `npm run dev | build | lint | preview`; `build` = `tsc -b && vite build`

## Dependensi Internal
- Depends on: backend FastAPI `src/api/app.py:346,363` (`/api/scan`, `/api/scan/{job_id}`); shape response dari `DeepScanResult.to_dict()` (`src/modules/deep_scan/__init__.py:104-134`); model `Finding`/`ScanResult` (`src/core/models.py:20,68`)
- Depended by: none — frontend adalah leaf consumer, dijalankan standalone via Vite dev/preview (backend `src/api/app.py` juga punya UI sendiri via `/` dan `/ui`)

## Issue Spesifik
- [Low] `<title>frontend</title>` masih default template — `index.html:7`
- [Low] Aset tak terpakai: `public/icons.svg`, `src/assets/react.svg`, `src/assets/vite.svg`, `src/assets/hero.png` (tidak dirujuk di source; hanya `public/favicon.svg` dipakai — `index.html:5`)
- [Info] Tidak ada Vite proxy (`vite.config.ts` hanya plugin react) — dev memerlukan `VITE_API_BASE_URL` (`src/App.tsx:8`, lihat `.env.example`) atau backend harus mengizinkan origin dev via CORS (`src/api/app.py:28`)
- [Info] `frontend/README.md` masih template Vite default; belum mendokumentasikan kontrak API frontend↔backend

## Rekomendasi Perbaikan Scoped
- Kosmetik/opsional; bug-bug kode spesifik ada di `src/AGENTS.md`.

> Last updated: onboarding docs — AGENTS.md pertama untuk folder frontend (commit 8fa2bbf)
