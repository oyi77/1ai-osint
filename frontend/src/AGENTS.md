---
scope: frontend/src
depends_on: [../AGENTS.md, ../../src/api/app.py, ../../src/modules/deep_scan/__init__.py]
status: complete
---

# AGENTS.md — frontend/src

## Tujuan Folder Ini
Semua source React/TypeScript SPA: komponen utama (`App.tsx`), entry (`main.tsx`), styling global (`index.css`), aset statis (`assets/`).

## Ekspor / Interface Utama
- `App` (default export, `App.tsx:209`) — komponen single-page; state `target | status | jobId | result`
- `startScan` (`App.tsx:30`) — `POST ${API_BASE}/api/scan` dengan body `{target, fast: true, max_iterations: 3}`; sukses → `setJobId(data.job_id)`
- Polling effect (`App.tsx:55`) — `setInterval` 2000 ms `GET /api/scan/{jobId}`; `status === 'completed'` → `setResult(data.result)`, `'failed'` → stop
- Types: `ScanStatus` (`App.tsx:6`), `Finding` (`App.tsx:10`), `ScanResult` (`App.tsx:18`)
- `main.tsx` — entry, StrictMode
- `index.css` — CSS custom properties (dark glassmorphism theme), 334 baris

## Dependensi Internal
- Depends on: backend `POST /api/scan` / `GET /api/scan/{job_id}` (`src/api/app.py:346,363`); shape result dari `DeepScanResult.to_dict()` (`src/modules/deep_scan/__init__.py:104-134`) — keys yang dipakai frontend (`target`, `finding_count`, `findings[].{id,module,title,description,raw_data}`) cocok
- Depended by: `index.html` (memuat `/src/main.tsx`)

## Issue Spesifik
- [Medium] Polling tanpa timeout/batas — `App.tsx:58-79`; jika job stuck di `queued`/`running` (backend), interval 2 s berjalan tanpa batas selama komponen mounted; trace: `App.tsx:61` fetch → `src/api/app.py:363` (job dict tanpa TTL/expiry yang terlihat di jalur API ini)
- [Low] `Finding.raw_data: any` — `App.tsx:15`; `raw_data?.verified` dan `raw_data?.url` (`App.tsx:176,183`) dibaca tanpa validasi schema
- [Low] Error detail dibuang — catch hanya `console.error` (`App.tsx:45-52,75-78`); UI kegagalan generik "Check backend logs" (`App.tsx:198-203`), padahal backend menyediakan `detail` (mis. 422) dan job `error`/`last_error`
- [Low] `key={i}` untuk daftar findings — `App.tsx:173` (aman selama list statis; debt jika list direorder/difilter)
- [Low] `raw_data.url` dirender langsung sebagai `href` (`App.tsx:183-187`) — React 19 memblokir `javascript:` scheme; skema URL lain tidak divalidasi di frontend [hipotesis — perlu verifikasi manual bahwa modul backend menjamin isi `raw_data.url`]
- [Low] `as unknown as number` cast pada `setInterval` — `App.tsx:79` (kosmetik workaround tipe)

## Rekomendasi Perbaikan Scoped
```tsx
// Before — App.tsx:58-79: polling tanpa batas
if (status === 'running' && jobId) {
  interval = setInterval(async () => {
    // ... fetch ...
  }, 2000);
}

// After — cap jumlah poll + laporkan timeout
const MAX_POLLS = 150; // ~5 menit pada 2 s
let polls = 0;
interval = setInterval(async () => {
  if (++polls > MAX_POLLS) {
    setStatus('failed');
    clearInterval(interval);
    return;
  }
  // ... fetch ...
}, 2000);
```

```tsx
// Before — App.tsx:15: raw_data untyped
raw_data: any;

// After — schema minimal untuk field yang benar-benar dibaca UI
raw_data?: { verified?: boolean; url?: string } & Record<string, unknown>;
```

> Last updated: onboarding docs — AGENTS.md pertama untuk folder src (commit 8fa2bbf)
