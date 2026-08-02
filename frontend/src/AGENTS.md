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
- [RESOLVED-Medium] Polling tanpa timeout/batas — `App.tsx:58-79`; jika job stuck di `queued`/`running` (backend), interval 2 s berjalan tanpa batas selama komponen mounted; trace: `App.tsx:61` fetch → `src/api/app.py:363` (job dict tanpa TTL/expiry yang terlihat di jalur API ini). Sudah dibatasi: `MAX_POLL_ATTEMPTS=90` (~3 menit pada 2 s) dan `MAX_CONSECUTIVE_POLL_FAILURES=5` (`App.tsx:8-10`); saat batas terlampaui, status `failed` + pesan job mungkin stuck (`App.tsx:119-133`).
- [RESOLVED-Low] `Finding.raw_data: any` — dulu `App.tsx:15`; kini `raw_data: Record<string, unknown>` (`App.tsx:24`), dan akses `raw_data.verified`/`raw_data.url` dilakukan lewat guard tipe di render (`App.tsx:233-236`)
- [RESOLVED-Low] Error detail dibuang — kini state `errorMessage` (`App.tsx:49`) menampung `data.detail` dari respon non-OK (`App.tsx:68`) dan `data.error` dari job gagal (`App.tsx:107-109`); dirender di UI (`App.tsx:267-268`) dengan fallback generik hanya bila kosong (`App.tsx:270`)
- [RESOLVED-Low] `key={i}` untuk daftar findings — dulu `App.tsx:173`; kini `key={f.id || \`${f.module}-${i}\`}` (`App.tsx:238`) — id finding dipakai sebagai key stabil, fallback index hanya jika id kosong
- [RESOLVED-Low] `raw_data.url` dirender langsung sebagai `href` — kini lewat guard `isSafeHttpUrl` (`App.tsx:34-42`): hanya URL absolut http/https yang dipakai (`App.tsx:235-236`) dan dirender sebagai link (`App.tsx:248-252`); skema lain (mis. `javascript:`) difilter
- [RESOLVED-Low] `as unknown as number` cast pada `setInterval` — dulu `App.tsx:79`; polling kini pakai `setTimeout` rekursif dengan `let timeout: number | undefined` (`App.tsx:85`) + `window.setTimeout` (`App.tsx:135,138`), jadi cast tidak diperlukan lagi

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
> Last updated: fix pass — polling dibatasi (MAX_POLL_ATTEMPTS=90, MAX_CONSECUTIVE_POLL_FAILURES=5, App.tsx:8-10), raw_data: Record<string, unknown> (:24), errorMessage disurface (:49/:267-268), key stabil (:238), isSafeHttpUrl untuk URL (:34-42), cast setInterval dihapus
