# 1ai-osint — Blueprint Lengkap: Menuju OSINT Engine Terbaik di Dunia
> Disusun Agustus 2026 · BerkahKarya · File mandiri (self-contained), taruh di `docs/1ai-osint-Blueprint.md`

---

## 0. Definisi "Terbaik di Dunia"

"Terbaik" di kategori OSINT diukur di 5 sumbu — bukan cuma jumlah source:

| Sumbu | Pemenang saat ini | Kenapa mereka menang |
|---|---|---|
| **Breadth (jumlah & keragaman sumber)** | SpiderFoot (200+ modul), Maltego (80+ transform) | Coverage luas = jarang "kosong" saat investigasi |
| **Correlation & reasoning** | espectrosint, NiamonX, Sherlockeye | AI cross-reference otomatis antar temuan → hemat waktu analis |
| **Visual/UX investigasi** | Maltego (graph), Aleph | Non-technical analyst bisa pivot cepat tanpa command line |
| **Automation/Agentic** | OpenOSINT (MCP-native, REPL, agent decides tool chain) | Arah paling baru 2026 — agent yang mikir & pivot sendiri, bukan cuma klik tombol |
| **Trust & compliance** | HIBP (lawful, transparan), OSINT Industries | Data handling jelas, retention policy jelas, defensible saat diaudit |

**Insight kunci:** tidak ada satu pemain pun unggul di 5 sumbu sekaligus. Maltego kuat visual tapi mahal & manual. SpiderFoot luas tapi UX kasar & reasoning minim. espectrosint/NiamonX kuat reasoning tapi closed-source & data source-nya lemah di luar US/EU. **Celah ini peluang `1ai-osint`.**

---

## 1. Strategi Diferensiasi

### 1.1 Local Data Superiority (Indonesia/SEA)
Semua pemain besar dioptimasi untuk sumber US/EU. Mereka lemah di: data registrasi bisnis Indonesia (OSS/NIB, AHU Kemenkumham), pola nomor HP & operator lokal, platform marketplace lokal (Tokopedia/Shopee seller footprint — cek ToS dulu), NLP Bahasa Indonesia untuk entity extraction (nama/alamat/gelar), nuance domain `.id`/`.co.id` (PANDI WHOIS beda format dari ICANN generic). Ini **moat structural** — kompetitor global tidak akan prioritaskan ini karena fokus market mereka global/enterprise.

### 1.2 Agentic-First Architecture
Ikuti pola OpenOSINT (MCP-native, agent memutuskan tool chain sendiri) daripada pola SpiderFoot (klik tombol, tunggu). Agent yang: terima 1 input (nama/email/domain/nomor HP) → reasoning sendiri entity relevan untuk dipivot → self-correct kalau satu sumber gagal/rate-limited → generate laporan naratif, bukan cuma tabel raw data.

### 1.3 Compliance-by-Design sebagai Fitur Jual
UU PDP (Law 27/2022) full enforced sejak Okt 2024. Kompetitor yang scraping tanpa legal basis jelas jadi liability buat penggunanya. Jual **"audit trail & lawful-basis-aware OSINT"** sebagai fitur premium: tiap query dicatat (sumber, tujuan/legal basis, waktu, requester), built-in reminder skip/flag sumber yang butuh consent eksplisit (data spesifik Pasal 4.2: kesehatan, biometrik, data anak, dll), retention policy otomatis (auto-purge setelah N hari).

---

## 2. Arsitektur Referensi (5 Layer)

```
┌─────────────────────────────────────────────────────────┐
│ LAYER 5 — Output & Reporting                             │
│ Narrative report, graph export, PDF/JSON, API webhook     │
├─────────────────────────────────────────────────────────┤
│ LAYER 4 — AI Reasoning & Correlation                      │
│ Entity resolution, pivot decision, confidence scoring,    │
│ cross-source dedup, hypothesis generation                 │
├─────────────────────────────────────────────────────────┤
│ LAYER 3 — Access Control & Compliance                     │
│ Audit log, legal-basis tagging, retention policy,          │
│ rate-limit/ToS guard per source, RBAC per user tier        │
├─────────────────────────────────────────────────────────┤
│ LAYER 2 — Source Adapter / Tool Layer (MCP-based)          │
│ Setiap sumber data = 1 adapter dengan interface seragam     │
├─────────────────────────────────────────────────────────┤
│ LAYER 1 — Data Sources                                     │
│ Global feeds + Local (ID/SEA) feeds — lihat matriks §3      │
└─────────────────────────────────────────────────────────┘
```

**Prinsip desain:**
- Layer 2 MCP-native dari awal — supaya `1ai-osint` bisa dipanggil langsung dari Claude Code/Desktop atau agent lain di ekosistem `1ai-hub` tanpa reimplement.
- Layer 3 di tengah arsitektur (bukan afterthought di ujung) — supaya tiap adapter baru otomatis "lewat" compliance gate.
- Layer 4 pakai pola planner-large/executor-small yang sudah diterapkan di `1ai-auto-bounty`: model besar (Claude) untuk reasoning/pivot decision, model kecil/rule-based untuk parsing raw response tiap adapter (hemat cost & latency).

---

## 3. Adoption Matrix — Tool Konkret per Kategori

Gunakan 3 cara adopsi berbeda, jangan disamaratakan:
- 🔌 **INTEGRATE** — wrap jadi adapter/tool call langsung, agent panggil real-time
- 📖 **STUDY** — bukan dipakai langsung, source code/arsitekturnya dipelajari & diadaptasi jadi kode sendiri
- ⛔ **SKIP** — closed-source/komersial/butuh legal review dulu

### 🔌 INTEGRATE langsung (adapter Layer 2)
| Tool | Fungsi | Prioritas Fase |
|---|---|---|
| theHarvester | Email/subdomain/host recon | Fase 1 |
| Sherlock | Username enum (400+ situs) | Fase 1 |
| Maigret | Username enum (3,000+ situs, lebih luas dari Sherlock) | Fase 1 |
| Holehe | Email → platform registration check | Fase 1 |
| HIBP API | Breach/leak check (lawful, gold standard) | Fase 1 |
| Amass | Subdomain/attack-surface mapping | Fase 1 |
| Subfinder, httpx, dnsx | Recon toolkit pendukung | Fase 1 |
| GHunt | Investigasi akun Google spesifik | Fase 2 |
| bbot | Correlation engine — bisa jadi orchestrator recon langsung | Fase 2 |
| Shodan / Censys API | Infrastructure exposure (berbayar) | Fase 4 — tier premium |

### 📖 STUDY (arsitektur/pola)
| Repo | Yang dipelajari |
|---|---|
| [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) | Pola MCP-native adapter interface + REPL agent tool-selection — **blueprint arsitektur utama Layer 2-4** |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Struktur modul untuk breadth referensi (cek LICENSE sebelum adaptasi kode); pola "1 modul = 1 sumber + normalisasi output" worth ditiru |
| MISP / OpenCTI | Skema data model entity-relationship untuk storage/graph layer |
| Maltego (Transform Hub) | UX pattern graph-pivot (bukan open source, referensi desain interaksi saja) |

### ⛔ SKIP dulu (legal review / komersial)
| Item | Alasan |
|---|---|
| DeHashed, Intelligence X | Breach DB berbayar — butuh legal review basis hukum sebelum integrasi |
| Data spesifik Pasal 4.2 UU PDP (kesehatan, biometrik, dll) | Jangan bangun adapter sama sekali tanpa legal review eksplisit |
| Scraping marketplace (Tokopedia/Shopee seller) | Cek ToS platform dulu sebelum bikin adapter otomatis |

### 3.1 Sumber Data Lokal Indonesia/SEA (Moat §1.1 — riset lanjutan)
- **AHU Online (Kemenkumham)** — data legalitas badan usaha
- **OSS/NIB registry** — perizinan usaha
- **PANDI WHOIS (.id domain)** — format beda dari WHOIS generic
- **BPS/data.go.id open data** — demografi & statistik resmi (legal basis kuat: data pemerintah terbuka)
- Nomor HP → operator prefix mapping (Telkomsel/XL/Indosat/Tri/Smartfren) — untuk validasi/enrichment, bukan reverse-lookup identitas (rawan UU PDP tanpa legal basis)

---

## 4. Legal & Compliance Checklist (Prasyarat, Bukan Opsional)

Berdasarkan UU PDP (Law 27/2022, full enforced Okt 2024):

1. **Legal basis per sumber** — dokumentasikan dasar hukum tiap adapter (consent, kepentingan sah, data terbuka pemerintah, dll). Sumber pemerintah terbuka = legal basis paling aman untuk mulai.
2. **Data spesifik (Pasal 4.2)** — kesehatan, biometrik, data anak, orientasi seksual, dll butuh consent eksplisit. Jangan build adapter ke kategori ini sampai ada legal review.
3. **Audit trail wajib** — siapa query apa, kapan, tujuan apa (juga jadi fitur jual §1.3).
4. **ToS per platform sumber** — scraping marketplace/sosmed harus dicek ToS masing-masing; API resmi (mis. Meta Graph API) lebih aman daripada scraping langsung.
5. **Retention & purge policy** — default mis. 30 hari (standar kompetitor Sherlockeye) + opsi extend dengan justifikasi.
6. **Rate-limit & attribution guard** — jangan sampai `1ai-osint` sendiri "ninggalin jejak" mencurigakan ke target — pakai proxy rotation yang etis untuk automated scanning, bukan untuk menyamarkan identitas dari otoritas.

---

## 5. Roadmap Bertahap

**Fase 1 — Foundation (MCP-native core + compliance gate)**
- Bangun Layer 2 dengan interface seragam, mulai 5-8 sumber global paling matang (theHarvester, Sherlock/Maigret, HIBP, Amass)
- Bangun Layer 3 (audit log + legal-basis tagging) dari awal, bukan ditambah belakangan
- Validasi arsitektur agentic sederhana: 1 input → agent pilih adapter relevan → output terstruktur

**Fase 2 — Reasoning Layer**
- Tambah Layer 4: entity resolution, dedup, confidence scoring
- Adopsi pola planner-large/executor-small dari `1ai-auto-bounty`
- Narrative report generation

**Fase 3 — Local Data Moat**
- Riset & bangun adapter data Indonesia (§3.1) — mulai dari legal basis paling jelas (data pemerintah terbuka)
- Bangun NLP/entity extraction aware format nama & alamat Indonesia

**Fase 4 — Scale & Differentiate**
- Graph visualization (evaluasi Neo4j CE atau alternatif ringan)
- Tier premium: breach DB berbayar (dengan legal review), infrastructure intel (Shodan/Censys)
- Benchmark head-to-head vs SpiderFoot/OpenOSINT di skenario investigasi nyata

---

## 6. PROMPT LENGKAP — Tempel Langsung ke Claude Code di Repo `1ai-osint`

```
Kamu bertindak sebagai lead architect untuk menjadikan `1ai-osint` sebagai
OSINT engine kelas dunia. Baca dulu README, docs/, dan catatan audit
ekosistem BerkahKarya (jika ada di repo/notes) untuk memahami state
`1ai-osint` saat ini — termasuk catatan bahwa repo ini butuh dokumentasi
tool licensing & access control.

Dokumen ini (1ai-osint-Blueprint.md) adalah referensi utama strategi.
Rujuk §0-§5 untuk konteks lengkap sebelum mulai.

TAHAP 1 — AUDIT STATE SAAT INI:
1. Inventarisir adapter/integrasi sumber data yang sudah ada. Untuk
   masing-masing catat: sumber apa, legal basis apa (kalau belum ada,
   tandai "UNDOCUMENTED"), rate-limit/ToS constraint apa.
2. Cek apakah sudah ada audit-log/access-control layer (Layer 3). Kalau
   belum, ini prioritas #1 sebelum nambah fitur apapun.
3. Bandingkan arsitektur saat ini dengan referensi arsitektur 5-layer di
   §2 — layer mana yang belum ada sama sekali.

TAHAP 2 — EKSPLORASI REFERENSI (clone ke /tmp/research, jangan tulis kode
dulu):
1. Clone dan baca source code OpenOSINT (github.com/OpenOSINT/OpenOSINT) —
   fokus ke desain MCP-native adapter interface dan agent tool-selection
   logic (REPL decides which tool to run).
2. Clone dan baca beberapa modul SpiderFoot (github.com/smicallef/spiderfoot)
   — fokus struktur modul untuk breadth referensi, bukan untuk disalin
   utuh (cek LICENSE dulu).
3. Baca skema data model MISP atau OpenCTI untuk pola normalisasi entity
   (person/domain/email/organization + relationship) yang bisa
   diadaptasi ke storage layer 1ai-osint.

TAHAP 3 — EKSEKUSI ADOPSI TOOL (§3 matrix):
1. List semua tool di kategori 🔌 INTEGRATE Fase 1 (theHarvester, Sherlock,
   Maigret, Holehe, HIBP API, Amass, Subfinder/httpx/dnsx). Untuk
   masing-masing cek: sudah terpasang/terintegrasi? Kalau belum, apa
   langkah instalasi/dependency-nya (binary, API key)?
2. Buat 1 adapter/wrapper module per tool dengan interface SERAGAM (input
   target, output JSON terstruktur) — jangan biarkan format output beda
   per tool.
3. Untuk kategori 📖 STUDY, buat ringkasan 1 paragraf per repo: pola
   arsitektur apa yang mau diadopsi ke kode sendiri, dan di file/module
   mana pola itu diterapkan.
4. Kalau ada tool yang overlap dengan `1ai-auto-bounty` (recon tools:
   subfinder/httpx/dnsx/amass), tandai sebagai kandidat shared library
   (`1ai-recon-core`) daripada diimplementasi ulang di masing-masing repo.

TAHAP 4 — GAP ANALYSIS & PRIORITAS:
Buat tabel: [fitur/layer dibutuhkan] | [ada di 1ai-osint?] | [ada
referensi/adapter siap?] | [prioritas P0/P1/P2] | [effort estimate].
Prioritaskan sesuai roadmap §5: compliance gate dulu (Fase 1), reasoning
layer (Fase 2), baru local-data moat (Fase 3).

TAHAP 5 — IMPLEMENTATION PLAN (bukan kode penuh dulu):
Untuk 3-5 item prioritas P0, tulis: interface/kontrak modul, dependency
baru dibutuhkan, test plan (termasuk test compliance: setiap adapter baru
wajib isi field legal-basis sebelum bisa dipanggil). Laporkan sebagai
checklist bertahap. Tunggu konfirmasi sebelum menulis implementasi penuh.

BATASAN PENTING:
- Prioritaskan compliance (Layer 3) SEBELUM breadth sumber data baru —
  jangan tambah adapter yang scraping data pribadi tanpa legal-basis
  tagging yang jelas.
- Untuk kategori data spesifik (kesehatan, biometrik, data anak, orientasi
  seksual/politik) sesuai Pasal 4.2 UU PDP — JANGAN bangun adapter ke
  kategori ini tanpa legal review eksplisit dari saya terlebih dahulu.
- Saat mempelajari source code repo referensi, jangan copy-paste verbatim
  kalau lisensi tidak mengizinkan — pelajari pola arsitekturnya dan
  implementasikan versi sendiri.
- Semua data source yang diintegrasikan harus untuk investigasi/riset yang
  authorized dan sesuai hukum — bukan untuk surveillance individu tanpa
  dasar hukum yang sah.
```

### Cara Pakai
1. Simpan file ini utuh sebagai `docs/1ai-osint-Blueprint.md` di repo `1ai-osint`.
2. Buka Claude Code di repo tersebut, paste prompt §6 sebagai instruksi awal.
3. Hasil Tahap 1 (audit) akan langsung kasih tahu seberapa jauh gap compliance saat ini — paling urgent dibereskan sebelum nambah breadth.
4. Review checklist Tahap 5 sebelum lanjut eksekusi kode penuh.
