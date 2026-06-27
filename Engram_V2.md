# Engram — Blueprint Arsitektur v2
## (Versi Updated: Per-Case Relative Scoring + Multi-Signal Fusion + XAI)

> Tim: Bastion Seize — WRECK-IT 7.0
> Subtema: Autonomous Defense & AI-Driven Threat Hunting

---

## 1. Latar Belakang Perubahan Arsitektur

Versi awal Engram menggunakan model Isolation Forest yang dilatih dari
dataset publik CIC-MalMem2022, dengan pendekatan **case-level scoring**
(satu dump dibandingkan langsung ke seluruh distribusi dataset).

Melalui serangkaian pengujian empiris terhadap dump dari sistem Windows
modern (termasuk dump dari VM yang sengaja dibuat minimal/vanilla untuk
kontrol eksperimen), ditemukan bahwa pendekatan ini menghasilkan **false
positive yang konsisten dan signifikan**. Investigasi mendalam
(normalisasi fitur, normalisasi rasio, kalibrasi threshold, kategorisasi
fitur artifact vs environment-scale) mengonfirmasi bahwa akar masalahnya
adalah **domain mismatch**: dataset training dibangun dari environment
Windows generasi lama dengan karakteristik sistem (jumlah service,
arsitektur prosesor, pola loading DLL) yang berbeda signifikan dari
sistem produksi modern — terlepas dari seberapa minimal konfigurasi
sistem yang diuji.

**Keputusan desain:** daripada membuang kapasitas ML atau mengecilkan
perannya jadi sekadar pelengkap kosmetik, Engram v2 mengubah CARA model
ML digunakan — dari *absolute cross-dataset comparison* menjadi
***per-case relative anomaly detection***. Pendekatan ini membuat ML
tetap menjadi komponen inti yang reliable, karena domain perbandingannya
menjadi adil (proses dibandingkan dengan proses lain di sistem yang
sama, bukan dengan dataset dari tahun yang berbeda).

---

## 2. Filosofi Inti

> *"Sebuah proses tidak dinilai aneh karena beda dari sistem orang lain
> di tahun yang berbeda — ia dinilai aneh karena beda dari
> tetangga-tetangganya sendiri, di sistem yang sama, pada saat yang
> sama."*

Ini sejalan dengan prinsip **zero-day detection** yang sesungguhnya:
malware baru tidak punya signature, tapi ia hampir selalu punya
**perilaku struktural yang menyimpang** dari proses-proses legitimate
di sekitarnya — entah itu thread count yang tidak wajar, DLL yang
hidden, atau region memori dengan proteksi mencurigakan.

---

## 3. Arsitektur Sistem (High-Level)

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE (React)                   │
│   New Case → Progress → Dashboard (per-process risk table)  │
└────────────────────────┬──────────────────────────────────┘
                         │ HTTP / REST API
┌────────────────────────▼──────────────────────────────────┐
│                  BACKEND (FastAPI)                         │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │  STAGE 1 — Volatility 3 Pipeline                    │    │
│  │  9 plugin: pslist, dlllist, handles, ldrmodules,    │    │
│  │  malfind, modules, svcscan, callbacks, psscan       │    │
│  └───────────────────┬──────────────────────────────────┘    │
│                      ↓                                       │
│  ┌────────────────────────────────────────────────────┐    │
│  │  STAGE 2 — Per-Process Feature Extraction           │    │
│  │  Output: DataFrame, 1 row = 1 proses                │    │
│  │  Kolom: pid, name, n_threads, n_dlls, n_handles,    │    │
│  │  malfind_hits, is_hidden, dll_hidden_ratio, dst     │    │
│  └───────────────────┬──────────────────────────────────┘    │
│                      ↓                                       │
│  ┌─────────────┬─────────────────┬─────────────────────┐   │
│  │  SIGNAL 1   │   SIGNAL 2      │    SIGNAL 3          │   │
│  │  Rule-Based │   ML Isolation  │    VirusTotal        │   │
│  │  Scorer     │   Forest        │    IOC Reputation    │   │
│  │  (forensik  │   (PER-CASE     │    (independen dari  │   │
│  │  klasik per │   RELATIVE —    │    OS/environment)   │   │
│  │  proses)    │   fit() ke      │                       │   │
│  │             │   proses dalam  │                       │   │
│  │             │   case yg sama) │                       │   │
│  └──────┬──────┴────────┬────────┴──────────┬────────────┘   │
│         └───────────────┼───────────────────┘                │
│                         ↓                                    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  STAGE 3 — Weighted Fusion Engine                   │    │
│  │  final_score = w1*rule + w2*ml + w3*vt              │    │
│  │  + Whitelist mechanism (known-AV false positive)    │    │
│  └───────────────────┬──────────────────────────────────┘    │
│                      ↓                                       │
│  ┌────────────────────────────────────────────────────┐    │
│  │  STAGE 4 — XAI Explainer                            │    │
│  │  "Kenapa proses ini di-flag?" → breakdown per sinyal│    │
│  └────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Detail Tiap Stage

### Stage 1 — Volatility 3 Pipeline (TIDAK BERUBAH dari v1)

Plugin yang dijalankan terhadap memory dump:

| Plugin | Fungsi |
|---|---|
| `windows.pslist` | Daftar proses, PID/PPID, thread count |
| `windows.dlllist` | DLL yang di-load tiap proses |
| `windows.handles` | Handle yang dibuka tiap proses |
| `windows.ldrmodules` | Deteksi DLL hidden (process hollowing indicator) |
| `windows.malfind` | Deteksi region memori RWX mencurigakan (code injection) |
| `windows.modules` | Kernel modules/drivers |
| `windows.svcscan` | Windows services |
| `windows.callbacks` | Kernel callback routines (rootkit hook indicator) |
| `windows.psscan` | Pool scan — pengganti psxview (deprecated), cross-check hidden process |

### Stage 2 — Per-Process Feature Extraction (BARU)

Berbeda dari v1 yang menghasilkan 55 fitur **per case**, Stage 2 versi
baru menghasilkan tabel fitur **per proses**:

```
| pid  | name         | n_threads | n_dlls | n_handles | malfind_hits | is_hidden | dll_not_in_load | ... |
|------|--------------|-----------|--------|-----------|--------------|-----------|-----------------|-----|
| 4    | System       | 105       | 12     | 80        | 0            | False     | 0               | ... |
| 5120 | rundll32.exe | 2         | 8      | 15        | 3            | True      | 5               | ... |
| 692  | services.exe | 8         | 45     | 200       | 0            | False     | 1               | ... |
```

Sumber tiap kolom dipetakan dari output Volatility 3 yang sudah
divalidasi sebelumnya (lihat `feature_extractor.py` v1 sebagai
referensi logika ekstraksi yang sudah established).

### Stage 3 — Tiga Sinyal Independen

**Sinyal 1: Rule-Based Scorer**
Forensik klasik per proses, logika eksplisit dan dapat dijelaskan
langsung tanpa perlu model statistik:
- Malfind hit dengan proteksi RWX → skor tinggi
- DLL hidden ratio tinggi (ldrmodules anomaly) → skor tinggi
- Proses ada di psscan tapi tidak di pslist → skor tinggi
- Proses tanpa path di disk (fileless indicator) → skor tinggi
- **Whitelist mechanism**: proses yang dikenal sering false-positive
  (contoh: `MsMpEng.exe` — Windows Defender) di-discount skornya secara
  eksplisit dengan justifikasi yang didokumentasikan

**Sinyal 2: ML Isolation Forest — PER-CASE RELATIVE (perubahan inti v2)**
- Model di-`fit()` ulang setiap kali case baru dianalisis, terhadap
  seluruh proses **di dalam case itu sendiri** — bukan terhadap dataset
  eksternal
- Mendeteksi proses yang "outlier" relatif terhadap kebiasaan sistem
  itu sendiri (misal: proses dengan thread count jauh di atas rata-rata
  proses lain di sistem yang sama)
- Model dari dataset CIC-MalMem2022 (v1) tetap disimpan sebagai
  **referensi sekunder/opsional**, bukan penentu utama — bisa
  ditampilkan sebagai informasi tambahan dengan disclaimer keterbatasan
  generalisasi yang sudah didokumentasikan

**Sinyal 3: VirusTotal IOC Reputation**
- Independen dari karakteristik OS — IP/domain/hash yang diekstrak
  dari proses dicocokkan ke reputasi global
- Tidak terpengaruh isu domain mismatch yang dialami Sinyal 2

### Stage 4 — Weighted Fusion

```python
final_score = (
    w_rule * rule_based_score +
    w_ml   * ml_relative_score +
    w_vt   * virustotal_score
)
```

Bobot (`w_rule`, `w_ml`, `w_vt`) ditentukan berdasarkan reliabilitas
empiris tiap sinyal — didokumentasikan secara transparan di laporan
teknis, termasuk eksperimen yang mendasari keputusan bobot tersebut.

### Stage 5 — XAI Explainer

Untuk setiap proses dengan severity tinggi, sistem menghasilkan
penjelasan terstruktur:

```
Proses: rundll32.exe (PID 5120)
Severity: CRITICAL

Breakdown kontribusi:
  • Rule-based (60%): malfind hit RWX terdeteksi, DLL hidden ratio 45%
    di atas rata-rata proses lain di sistem ini
  • ML relative (30%): thread count dan handle count proses ini
    3.2σ lebih ekstrem dibanding 104 proses lain di case ini
  • VirusTotal (10%): tidak ada IOC terkait, tidak mempengaruhi skor
```

---

## 5. Perbandingan v1 vs v2

| Aspek | v1 (sebelumnya) | v2 (updated) |
|---|---|---|
| Level analisis ML | Case-level (1 dump = 1 angka) | Per-process (tiap proses dinilai) |
| Domain perbandingan ML | Dataset eksternal (2022) | Proses lain dalam case yang sama |
| Resiko domain mismatch | Tinggi (terbukti dari eksperimen) | Rendah (perbandingan adil, sama waktu & sistem) |
| Peran ML dalam keputusan final | Dominan/tunggal | Salah satu dari 3 sinyal independen |
| Penjelasan ke user | Skor probabilitas global | Breakdown per proses, per sinyal |
| Ketergantungan ke 1 dataset | Tinggi | Rendah (dataset jadi referensi sekunder) |

---

## 6. Justifikasi untuk Presentasi ke Juri

> *"Engram v2 mendeteksi anomali tidak dengan membandingkan sistem
> Anda ke database malware tahun lalu, tetapi dengan mempelajari
> 'kebiasaan' sistem Anda sendiri secara real-time, lalu mencari
> proses yang menyimpang dari kebiasaan itu. Pendekatan ini secara
> inheren lebih tahan terhadap evolusi sistem operasi dan lebih dekat
> dengan filosofi zero-day detection sesungguhnya — mendeteksi pola
> mencurigakan tanpa harus mengenalnya terlebih dahulu."*

Poin kunci yang bisa disampaikan bila ditanya juri:
1. **Kenapa tidak pakai ML sebagai penentu tunggal?** — defense-in-depth,
   prinsip keamanan industri standar, bukan kompromi teknis
2. **Kenapa per-case relative, bukan absolute?** — hasil dari pengujian
   empiris yang menemukan domain mismatch, didokumentasikan sebagai
   bagian dari proses riset yang jujur
3. **Bagaimana validasi dilakukan?** — pengujian terhadap dump real-world
   dan dump VM kontrol, dengan dokumentasi lengkap proses debugging

---

## 7. Komponen yang Perlu Dibangun (Roadmap Teknis)

- [ ] `extract_per_process_features()` — fungsi ekstraksi fitur per-PID
- [ ] `score_processes_relative()` — Isolation Forest fit per-case
- [ ] `rule_based_scorer.py` — update untuk output per-proses + whitelist
- [ ] `combined_scorer.py` — weighted fusion 3 sinyal
- [ ] `xai_explainer.py` — update untuk breakdown per-proses per-sinyal
- [ ] Update Dashboard React — tabel proses dengan severity + tombol
      "lihat alasan" yang menampilkan breakdown XAI
- [ ] Dokumentasi teknis: catatan eksperimen domain mismatch sebagai
      bagian dari laporan/proposal (menunjukkan rigor riset)
