# POWER PLAN — Membuat 1ai-osint Powerful

> Status: current state 2665 tests, 60+ modules, deep_scan engine, ZKIT identity
> graph, AI orchestration (OmniRoute), local intel DB (phone_intel, just built),
> gc-lookup integration. This plan turns a broad-but-fragmented tool into a
> **correlated intelligence platform**: every entity (phone, email, username,
> domain, crypto) feeds one local DB, cross-links, and produces actionable
> dossiers — not isolated findings.

## Vision

Dari "kumpulan module OSINT" menjadi **satu platform intelijen yang:
(1) menyimpan semua temuan di satu DB lokal yang bisa di-query, (2) menghubungkan
entitas lintas-module (correlation), (3) otomatis memonitor perubahan, dan
(4) menghasilkan dossier terpadu + alert** — semua tanpa bocorkan raw PII (ZKIT).

---

## P0 — Data & Correlation Foundation (tertinggi, unlock semua yang lain)

### P0.1 Unified Entity Intel DB (entitas → DB tunggal)
- Perluas `phone_intel/db.py` → `entity_intel.db`: tabel per tipe entitas
  (`phone`, `email`, `username`, `domain`, `crypto_address`) + satu tabel
  `observations(entity, source, data, confidence, fetched_at, expires_at)`.
- Semua module menulis ke DB ini (phone_finder, email_osint, people_finder,
  domain_recon, data_leaks, crypto) — bukan hanya phone_intel.
- CLI: `1ai-osint intel <entity>` = query DB → tampilkan semua sumber + umur.
- **Acceptance**: `1ai-osint intel +628...` dan `1ai-osint intel fikri@x.com`
  menampilkan semua observasi lintas-module dari DB, tanpa memanggil API bila fresh.

### P0.2 Correlation Engine (entity linking)
- Modul `correlation/`: dari satu anchor (mis. phone) → GetContact profile →
  nama/email → search email_osint + data_leaks + people_finder → graph entitas
  (phone ↔ email ↔ username ↔ domain) dengan confidence score.
- Reuse ZKIT graph (`identity_tracking/zkit_engine.py`) — hubungkan node via hash.
- Output: `CorrelationResult` = daftar entitas terhubung + skor + sumber.
- **Acceptance**: anchor phone +628... menghasilkan graph {phone, email,
  username, domain} dengan confidence, semua dari DB + fetch yang fresh saja.

### P0.3 Full Dossier Generator
- Dari CorrelationResult → `report_engine` menghasilkan dossier JSON/SARIF/PDF
  yang menggabungkan semua sumber + korelasi, bukan report per-module.
- Opsional AI summary (P3.1) via OmniRoute.
- **Acceptance**: `1ai-osint dossier <entity>` menghasilkan satu file terpadu.

---

## P1 — Source Expansion (lebih banyak data)

### P1.1 Breach & Intel Sources
- [DONE] Hudson Rock infostealer (free API).
- Tambah: `h8mail` aggregator (sudah ada sebagian), `leak-lookup` (gratis,
  batch), `dehashed/leakcheck` (berbayar, sudah ada di SOURCE_MODULES).
- **Acceptance**: data_leaks mencakup >= 16 sumber, semua terdedup + severity.

### P1.2 Business / Lead Intel (Google Maps)
- Port ringkas dari omkarcloud/gosom google-maps-scraper: cari bisnis by
  category/area → name, phone, address, website, reviews.
- Source baru `business_intel/` → menulis ke entity_intel.db (phone bisnis).
- **Acceptance**: query "coffee shop Jombang" → daftar bisnis JSON + phone,
  tersimpan di DB.

### P1.3 Social Platform Intel (TikTok / IG / FB)
- Port pattern dari HackUnderway (TokIntel, InstaCrawler, meta_scan):
  profile TikTok, partial-email Instagram, Facebook Pages scraper.
- Semua gated (butuh rate-limit / respek ToS), output → entity_intel.db.
- **Acceptance**: username → profil TikTok/IG terstruktur bila target publik.

### P1.4 Phone Directory Expansion
- gc-lookup (GetContact) ✅ + web search ✅ + carrier ✅ + Truecaller (gated) ✅.
- Tambah: sync kontak (Google) lookup opsional, `whatslookup`-style WhatsApp
  bisnis profile.
- **Acceptance**: phone_intel mencakup >= 6 sumber dengan fallback yang jelas.

---

## P2 — Automation & Proactive Intel

### P2.1 Scheduled Deep Scans
- `scheduler/` (cron/systemd user service): `1ai-osint scan --schedule daily
  <entity-list>`; simpan history scan di DB; dedup dengan fingerprint.
- **Acceptance**: daftar entitas di-scan tiap 24h, hasil baru terdeteksi.

### P2.2 Watchlists + Change Detection
- Wire `monitoring/` (sudah ada watchlist.py, change_detector.py) ke DB:
  watchlist entitas; deteksi perubahan (email baru, tag baru, status breach
  baru); simpan delta.
- **Acceptance**: entitas di watchlist → perubahan terekam + laporan delta.

### P2.3 Alerts (Telegram / webhook)
- `alerter.py` → kirim alert ke Telegram (bot) / webhook n8n saat perubahan
  severity MENINGKAT (mis. entitas baru muncul di breach, tag baru di GetContact).
- **Acceptance**: perubahan severity → alert Telegram terkirim (E2E via bot).

---

## P3 — AI Orchestration Depth

### P3.1 Auto-Dossier & Summary
- AI (OmniRoute) generate ringkasan investigasi dari CorrelationResult:
  "siapa Fikri?" — profiling, temuan kunci, saran langkah berikut.
- **Acceptance**: dossier + summary bahasa Indonesia/Inggris, grounded di findings.

### P3.2 Risk Scoring / Anomaly
- Risk scorer: skor entitas dari jumlah sumber terhubung, freshness, severity
  breach, tag kontroversial. Naik/turun otomatis.
- **Acceptance**: entitas dengan banyak breach + fresh → skor tinggi.

### P3.3 False-Positive Filtering
- AI filter hasil module (mirip gitleaks false-positive). Terapkan ke
  people_finder/social dorks (banyak FP saat ini).
- **Acceptance**: hasil module melewati AI gate, FP berkurang terukur.

---

## P4 — Reliability & Scale

### P4.1 Rate Limiter + Retry Universal
- Pastikan SEMUA panggilan eksternal lewat `rate_limiter.py` + retry/backoff
  (sudah ada rate_limiter.py — audit modul yang belum pakai).
- **Acceptance**: audit menunjukkan 100% source memakai rate limiter.

### P4.2 Caching Universal
- Perluas pola cache (phone_intel / gc-lookup) ke semua module: hasil API
  di-cache di DB dengan TTL, tidak memanggil ulang bila fresh.
- **Acceptance**: scan ulang entitas sama dalam TTL → 0 panggilan eksternal.

### P4.3 Observability
- `state/` log per scan, metric (durasi, source hit/miss, error rate),
  health endpoint.
- **Acceptance**: dashboard/metrik menunjukkan health tiap source.

---

## P5 — UX & Surfaces

### P5.1 CLI Parity & Streaming
- Semua module bisa `scan`, `intel` (query DB), `dossier` (report gabungan).
- Progress streaming (sudah ada di deep_scan) konsisten di semua.

### P5.2 Web Dashboard
- Frontend React (sudah ada) tampilkan: entity search → dossier + graph
  korelasi (sigma.js), watchlist, alert feed, DB stats.
- **Acceptance**: search entity di web → graph korelasi + dossier render.

### P5.3 API + MCP
- REST: `POST /api/intel/{entity}`, `GET /api/dossier/{entity}`,
  `GET /api/watchlist`.
- MCP: expose intel/dossier/watchlist sebagai tools (sudah ada MCP bridge).
- **Acceptance**: curl + MCP tool mengembalikan data DB yang sama.

---

## P6 — Integration with 1ai-ecosystem

### P6.1 1ai-hub Brain
- Hasil scan penting → brain_remember (concept per entity); query via brain
  search dari module lain.
- **Acceptance**: entity yang di-scan bisa di-recall lewat brain.

### P6.2 Telegram Bot
- Bot: `/osint <entity>` → jalankan scan → balas dossier ringkas; `/watch <e>`;
  alert push.
- **Acceptance**: perintah bot E2E via Telethon.

### P6.3 n8n / Workflow
- Step plugin (1ai-hub) membungkus scan; trigger berkala; feed ke workflow
  revenue/alerts.
- **Acceptance**: workflow 1ai-hub memanggil scan 1ai-osint.

---

## P7 — Ethics & Compliance

### P7.1 ZKIT Privacy
- Pastikan raw PII tidak pernah dipersist ke disk (hanya hash + bukti).
- **Acceptance**: audit menyatakan 0 raw PII di state/output.

### P7.2 Source Governance
- Setiap source tercatat: TOS-compliance, rate limit, legal-use-only.
  Mark Truecaller/WhatsApp-web sebagai unofficial/fragile.
- **Acceptance**: `compliance.py` mencakup semua source baru.

---

## Prioritas & Urutan Eksekusi

| Fase | Isi | Nilai | Effort |
|------|-----|-------|--------|
| **P0.1** | Unified entity DB | ⭐⭐⭐ (unlock semua) | S |
| **P0.2** | Correlation engine | ⭐⭐⭐ | M |
| **P0.3** | Dossier generator | ⭐⭐⭐ | M |
| **P1.1** | +breach sources | ⭐⭐ | S |
| **P2.2/2.3** | Watchlist + alerts | ⭐⭐⭐ | M |
| **P3.1** | AI summary | ⭐⭐ | S |
| **P4.2** | Universal caching | ⭐⭐⭐ | M |
| **P1.2** | Google Maps business | ⭐⭐ | L |
| **P1.3** | Social scrapers | ⭐⭐ | L |
| **P2.1** | Scheduled scans | ⭐⭐ | S |
| **P5.2** | Web dashboard | ⭐⭐ | L |
| **P6.2** | Telegram bot | ⭐⭐ | M |
| **P3.2/3.3** | Risk scoring + FP filter | ⭐ | M |
| **P4.3** | Observability | ⭐ | S |

**Rekomendasi urutan**: P0.1 → P0.2 → P0.3 (fondasi intelijen) → P4.2
(caching, hemat kuota) → P2.2/2.3 (proaktif) → P3.1 (AI summary) → lalu sisanya
berdasarkan kebutuhan.

## Definition of Done (platform powerful)
- [ ] Satu DB lokal berisi observasi semua entitas, queryable via CLI/API/web
- [ ] Correlation engine menghubungkan phone↔email↔username↔domain dengan confidence
- [ ] Dossier terpadu (JSON/SARIF/PDF) per entitas
- [ ] Watchlist + change detection + alert Telegram
- [ ] Scan ulang dalam TTL = 0 panggilan eksternal (caching universal)
- [ ] 100% source pakai rate limiter + retry
- [ ] 0 raw PII persist (ZKIT)
- [ ] Seluruh suite tetap green (2665+ tests, coverage naik)
