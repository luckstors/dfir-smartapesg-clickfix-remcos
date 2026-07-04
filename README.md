# dfir-smartapesg-clickfix-remcos
Network Forensics Investigation of a SmartApeSG ClickFix campaign delivering Remcos RAT, including PCAP analysis, IoCs, MITRE ATT&amp;CK mapping, and detection engineering.

<div align="center">

# 🔴 Network Forensics Report
## SmartApeSG ClickFix Campaign → Remcos RAT Delivery
### Case ID: IR-2026-0122-PCAP01

[![Status](https://img.shields.io/badge/Status-Closed%20%E2%80%94%20Documented-brightgreen?style=flat-square)](.)
[![Severity](https://img.shields.io/badge/Severity-HIGH-red?style=flat-square)](.)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange?style=flat-square)](https://attack.mitre.org)
[![Wireshark](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square)](https://www.wireshark.org)
[![Language](https://img.shields.io/badge/Language-Bahasa%20Indonesia-lightgrey?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-Educational%20Use%20Only-blue?style=flat-square)](.)

</div>

---

## 📁 Struktur Repositori

```
dfir-smartapesg-clickfix-remcos/
│
├── 📄 README.md                              ← Incident Report lengkap (dokumen ini)
│
├── 📂 pcap/
│   └── .gitkeep                              ← File PCAP TIDAK di-commit ke repo publik
│                                                Simpan di storage privat/terenkripsi
│                                                Referensi: 2026-01-22-SmartApeSG-...pcap
│
├── 📂 screenshots/
│   ├── fase1-01_conversations_top_talker.png
│   ├── fase1-02_dhcp_mac_address.png
│   ├── fase1-03_frame815_ttl128.png
│   ├── fase1-04_frame22493_nbns_msbrowse.png
│   ├── fase1-05_frame11363_tcp_window_65535.png
│   ├── fase2-01_dns_queries_filter.png
│   ├── fase2-02_frame11358_http_301_redirect.png
│   ├── fase2-03_export_objects_http.png
│   ├── fase2-04_currency_gzip_download_form.png
│   ├── fase3-01_frame11366_tls_client_hello.png
│   └── fase4-01_multiip_beaconing_port443.png
│
├── 📂 rules/
│   ├── sigma_remcos_ja3_ja4_detection.yml    ← Sigma Rule (dokumen ini, Section 7)
│   └── suricata_clickfix_http_redirect.rules ← Suricata Rule (opsional)
│
├── 📂 ioc/
│   ├── ip_blocklist.txt                      ← IP C2 untuk import firewall/SIEM
│   ├── domain_blocklist.txt                  ← Domain C2 untuk DNS sinkhole
│   └── ja3_blocklist.txt                     ← JA3/JA4 hash untuk NGFW TLS inspection
│
└── 📂 docs/
    └── medium-article.md                     ← Versi artikel publik (storytelling)
```

> ⚠️ **Peringatan Keamanan:** File PCAP mengandung trafik berbahaya aktual. Jangan pernah mengunggahnya ke repositori publik. Simpan selalu di lingkungan analisis yang terisolasi dan terenkripsi. Jika melakukan ekstrak objek dari PCAP, pastikan berada di mesin virtual yang tidak terhubung ke jaringan produksi.

---
---

<div align="center">

## ════════════════════════════════════════
## 📋 INCIDENT REPORT — NETWORK FORENSICS
## ════════════════════════════════════════

</div>

```
╔══════════════════════════════════════════════════════════════════════════╗
║  INCIDENT REPORT — NETWORK FORENSICS ANALYSIS                           ║
║  Classification : CONFIDENTIAL — FOR EDUCATIONAL USE ONLY               ║
║  Threat Actor   : SmartApeSG                                            ║
║  Malware Family : Remcos RAT                                            ║
║  Report Version : 2.0 — Final (Data Verified)                           ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## SECTION 1 — INCIDENT SUMMARY

### 1.1 Tabel Ringkasan Insiden

| Field | Detail |
|---|---|
| **Case ID** | `IR-2026-0122-PCAP01-SAS` |
| **Incident Title** | SmartApeSG ClickFix Campaign — Remcos RAT Delivery via Gzip-Obfuscated HTTP Redirect & TLS C2 Beaconing |
| **PCAP File** | `2026-01-22-SmartApeSG-ClickFix-pushes-Remcos-RAT.pcap` |
| **Incident Date (Estimated, UTC)** | 2026-01-22 (Frame #1 sebagai referensi T+0) |
| **Analysis Date** | 2026-07-04 |
| **Analyst** | [Nama Analis] — SOC Analyst Trainee / DFIR Practitioner |
| **Tools Used** | Wireshark 4.x, File → Export Objects (HTTP), Follow HTTP Stream, Gzip Decompression, Abuse.ch SSL Blacklist, VirusTotal, AbuseIPDB |
| **Threat Actor** | SmartApeSG |
| **Malware Family** | **Remcos RAT** (Remote Access Trojan) |
| **Attack Vector** | ClickFix Social Engineering → Multi-hop HTTP Redirect → Gzip-Encoded HTML/JS Payload → TLS C2 with Backup List |
| **Infection Confirmed** | ✅ Ya — JA3 Hash terkonfirmasi 100% Remcos RAT oleh Abuse.ch SSL Blacklist |

---

### 1.2 Severity Rating & Justifikasi

```
╔═══════════════════════════════════════════╗
║                                           ║
║   SEVERITY RATING:  🟠  HIGH              ║
║                                           ║
╚═══════════════════════════════════════════╝
```

| Faktor Penilaian Severity | Status | Keterangan |
|---|---|---|
| Malware keluarga dikenal aktif | ✅ Terkonfirmasi | Remcos RAT — full-featured RAT dengan keylogging, remote shell, screenshot, file exfiltration |
| Komunikasi C2 berhasil terbentuk | ✅ Terkonfirmasi | TLS Client Hello ke oilporter.com berhasil (Frame #11366), JA3 confirmed |
| Payload tereksekusi di korban | ✅ Sangat Mungkin | Gzip HTML/JS dengan `download-form` terdekompresi = payload ClickFix dieksekusi |
| Teknik evasion aktif terdeteksi | ✅ Terkonfirmasi | TCP Window Spoofing (65535), Cloudflare proxy, Gzip obfuscation |
| Multi-server C2 redundancy | ✅ Terdeteksi | 4+ IP publik dihubungi pada port 443 secara beruntun |
| Exfiltration data aktif | ⚠️ Tidak terkonfirmasi | Traffic terenkripsi — memerlukan memory forensics atau EDR log |
| Lateral movement ke host lain | ⚠️ Tidak terdeteksi | Di luar scope PCAP ini — perlu investigasi lanjutan |
| Jumlah host terpengaruh (PCAP) | 1 host | `10.1.22.101` |

**Narasi Justifikasi Severity HIGH:**
> Insiden ini diklasifikasikan HIGH berdasarkan konfirmasi positif infeksi Remcos RAT melalui JA3 fingerprint (terkonfirmasi 100% oleh Abuse.ch), berhasil diekstraknya skrip ClickFix (`form id="download-form"`) dari payload Gzip-encoded, dan terdeteksinya mekanisme C2 multi-IP backup list yang mengindikasikan malware berhasil membangun persistensi komunikasi. Meskipun exfiltration aktif belum dikonfirmasi secara langsung dari PCAP, kapabilitas Remcos RAT yang diketahui menjadikan risiko ini sangat nyata dan memerlukan respons segera.

> **→ Eskalasi Direkomendasikan ke:** SOC Tier 2 / Tim Incident Response untuk memory forensics dan EDR analysis pada host `10.1.22.101`.

---

## SECTION 2 — VICTIM PROFILE

### 2.1 Identitas Host Korban

| Atribut | Nilai | Metode Identifikasi |
|---|---|---|
| **IP Address (Internal)** | `10.1.22.101` | Statistics → Conversations (top talker) |
| **MAC Address** | `00:08:02:1c:47:ae` | DHCP Request — Client Hardware Address |
| **Vendor Perangkat (MAC OUI)** | Hewlett-Packard (HP) | IEEE OUI Database lookup |
| **IP Gateway Jaringan** | `10.1.22.1` | DHCP Option 3 / ARP traffic |
| **MAC Gateway** | `20:e5:2a:b6:93:f1` | ARP Reply dari 10.1.22.1 |
| **Vendor Gateway** | Netgear | IEEE OUI Database lookup |
| **OS Teridentifikasi** | **Windows** | Lihat analisis passive fingerprinting di bawah |
| **OS Confidence Level** | **High** | Tiga indikator independen saling mengonfirmasi |
| **Konteks Jaringan** | Windows Workgroup | NBNS `__MSBROWSE__` announcement (Frame #22493) |

---

### 2.2 Passive OS Fingerprinting — Analisis Tiga Lapis

#### Indikator #1 — TTL Analysis (Frame #815)

```
Paket     : Frame #815
Filter    : ip.src == 10.1.22.101
Field     : Internet Protocol → Time to Live
Nilai     : 128

Interpretasi TTL:
  ┌──────────────┬──────────────────────────────────────────┐
  │   TTL        │   OS Tipikal                             │
  ├──────────────┼──────────────────────────────────────────┤
  │   64         │   Linux, macOS, Android, iOS             │
  │   128  ← ✅  │   Windows (semua versi)                  │
  │   255        │   Cisco IOS, Solaris, FreeBSD awal       │
  └──────────────┴──────────────────────────────────────────┘

Verdict: WINDOWS — High Confidence
```

#### Indikator #2 — NetBIOS Name Service (Frame #22493)

```
Paket     : Frame #22493
Filter    : nbns
Sumber    : 10.1.22.101 → 10.1.22.1
Tipe      : NBNS Registration / Refresh
Nama      : __MSBROWSE__

Signifikansi:
  __MSBROWSE__ adalah NetBIOS Master Browser Announcement yang
  SECARA EKSKLUSIF dikirim oleh sistem operasi Windows untuk
  mengumumkan keberadaannya di Workgroup/Domain kepada master
  browser di jaringan lokal.

  Tidak ada OS lain (Linux, macOS, Android) yang mengirim
  pesan ini secara native.

Verdict: WINDOWS — Definitive / Absolute Confidence
```

#### Indikator #3 — TCP Window Size Anomali (Frame #11363)

```
Paket     : Frame #11363
Filter    : tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 10.1.22.101
Field     : Transmission Control Protocol → Window Size Value
Nilai     : 65.535

Baseline TCP Window Size per OS:
  ┌──────────────────────────────────┬────────────────────┐
  │   OS                             │   TCP Window SYN   │
  ├──────────────────────────────────┼────────────────────┤
  │   Windows 10 / Server 2016+      │   64.240           │
  │   Windows 7 / Vista              │   8.192            │
  │   macOS / iOS / *BSD    ← Match  │   65.535           │
  │   Linux (kernel modern)          │   29.200           │
  └──────────────────────────────────┴────────────────────┘

Status    : ⚠️ ANOMALI — Nilai macOS/BSD pada host Windows (TTL=128)

Interpretasi #1 — Window Size Spoofing (Lebih Tinggi Kemungkinannya):
  Remcos RAT secara sengaja memodifikasi TCP Window Size pada
  koneksi ke server C2 agar trafik tampak seperti dari macOS
  di mata IDS yang menggunakan passive OS fingerprinting. Sistem
  IDS yang kurang teliti mungkin mengklasifikasikan koneksi ini
  sebagai "trafik Apple/macOS normal" dan tidak memflag-nya.

Interpretasi #2 — Custom TCP Stack:
  Browser atau runtime environment yang digunakan oleh payload
  ClickFix memiliki implementasi TCP stack non-standard.

Verdict   : Anomali dikonfirmasi — indikasi evasion technique aktif
Rekomendasi: Cross-reference dengan EDR log dan memory forensics
```

#### Ringkasan Passive OS Fingerprinting

| Indikator | Frame | Nilai | Verdict | Confidence |
|---|---|---|---|---|
| TTL | #815 | 128 | Windows | High |
| NBNS `__MSBROWSE__` | #22493 | String eksklusif Windows | Windows | Definitive |
| TCP Window Size | #11363 | 65.535 (anomali) | Indikasi evasion | Medium |
| **Kesimpulan Akhir** | — | — | **Windows dengan evasion** | **High** |

---

## SECTION 3 — TIMELINE OF EVENTS

```
══════════════════════════════════════════════════════════════════════════
  REKONSTRUKSI KRONOLOGI SERANGAN — 2026-01-22
  Referensi waktu: Frame #1 sebagai T+0
══════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────┐
│  FASE 0 — RECONNAISSANCE / INITIAL ACCESS                           │
└─────────────────────────────────────────────────────────────────────┘

  [T+0]     Frame #1     DNS Query: secretsof.com
                         Korban mengakses domain awal kampanye ClickFix.
                         Sumber: 10.1.22.101 → DNS Server 10.1.22.1

  [T+0]     Frame #2     DNS Answer: secretsof.com → 104.21.2.21
                         Resolusi ke IP Cloudflare Proxy.
                         Penyerang menggunakan CDN untuk sembunyikan IP asli.

  [T+Δ1]    Frame #45    DNS Query: flautister.com
                         Korban mengakses domain kedua kampanye ClickFix.

  [T+Δ1]    Frame #164   DNS Answer: flautister.com → 89.46.38.87
                         Resolusi ke IP server langsung (bukan proxy).

  [T+Δ2]    Frame #175   DNS Query: www.secretsof.com
                         Korban mencoba subdomain — kemungkinan hasil redirect
                         dari halaman awal atau script JavaScript.

  [T+Δ2]    Frame #185   DNS Answer: www.secretsof.com → 172.67.128.152
                         Resolusi ke IP Cloudflare Proxy kedua yang berbeda.


┌─────────────────────────────────────────────────────────────────────┐
│  FASE 1 — SOCIAL ENGINEERING (ClickFix Lure)                        │
└─────────────────────────────────────────────────────────────────────┘

  [T+Δ2]    [Inferred]   Korban berinteraksi dengan halaman ClickFix
                         di secretsof.com / flautister.com.
                         Halaman menampilkan pesan palsu yang meminta
                         korban untuk mengklik tombol atau menjalankan
                         perintah "perbaikan" yang diprompting.

  [T+Δ2]    Frame #22493 NBNS __MSBROWSE__ Announcement
                         10.1.22.101 → 10.1.22.1
                         Konfirmasi definitif: korban menjalankan Windows.


┌─────────────────────────────────────────────────────────────────────┐
│  FASE 2 — PAYLOAD DELIVERY via HTTP Redirect & Gzip                 │
└─────────────────────────────────────────────────────────────────────┘

  [T+Δ3]    Frame #11355 HTTP GET /con → 98.142.251.63
                         Request pertama ke server redirect penyerang.
                         Server: nginx/1.18.0 (Ubuntu)

  [T+Δ3]    Frame #11358 HTTP 301 Moved Permanently
                         Location: https://oilporter.com/currency
                         Browser korban dipaksa pindah ke domain C2.

  [T+Δ3]    Frame #11363 TCP SYN ke oilporter.com
                         ⚠️ TCP Window Size = 65.535 (anomali evasion)
                         Koneksi HTTPS ke domain C2 final dimulai.

  [T+Δ3]    Frame #11366 TLS Client Hello ke oilporter.com
                         ★ JA3: 280bf914a7a4ba98aa9df62d316a460c
                         ★ JA4: t13d201200_2b729b4bf6f3_e24b6bcd44b0
                         ← REMCOS RAT TERKONFIRMASI 100% (Abuse.ch)

  [T+Δ4]    Frame #11422 HTTP GET /currency → 98.142.251.63
                         Request kedua ke server redirect.
                         Server kembali merespons dengan 301.

  [T+Δ4]    Frame #11424 HTTP 301 Moved Permanently (kedua)
                         Location: https://oilporter.com/currency
                         Pengalihan identik — konfirmasi pola redirect konsisten.

  [T+Δ4]    [Lab Step]   Export Objects HTTP → Ekstrak "con" & "currency"
                         Follow HTTP Stream → Dekompresi Gzip pada "currency"
                         Hasil: Kode HTML/JS dengan form id="download-form"
                         ← SKRIP CLICKFIX TERUNGKAP


┌─────────────────────────────────────────────────────────────────────┐
│  FASE 3 — C2 ESTABLISHMENT & PERSISTENCE                            │
└─────────────────────────────────────────────────────────────────────┘

  [T+Δ4]    Frame #11419 TCP Retransmission Masif
                         Koneksi ke beberapa server C2 cadangan timeout.
                         Malware terus mencoba server berikutnya dalam daftar.

  [T+Δ5]    Ongoing      Multi-IP C2 Beaconing dimulai
                         Target: 52.184.222.228:443
                                 13.89.178.27:443
                                 23.45.119.177:443
                                 150.171.27.10:443
                         Mekanisme: C2 Backup List / Fast-Flux Redundancy
                         Remcos RAT berhasil membangun kanal C2 persisten.

  [T+Δ5+]   Ongoing      Remcos RAT aktif pada host 10.1.22.101
                         Kapabilitas aktif (diketahui dari profil malware):
                         Keylogging | Screenshot | Remote Shell |
                         File Manager | Exfiltration | Webcam/Mic Access

══════════════════════════════════════════════════════════════════════════
```

---

## SECTION 4 — INDICATORS OF COMPROMISE (IoC)

### 4.1 Network IoC — Domain & URL

| # | Tipe | Nilai | Peran dalam Serangan | Reputasi | Sumber Validasi |
|---|---|---|---|---|---|
| 1 | Domain | `secretsof.com` | Initial ClickFix lure domain | Malicious | VirusTotal, URLhaus |
| 2 | Domain | `www.secretsof.com` | Subdomain lure — Cloudflare proxy | Malicious | VirusTotal |
| 3 | Domain | `flautister.com` | Secondary ClickFix lure domain | Malicious | VirusTotal |
| 4 | Domain | `oilporter.com` | Final C2 domain — Remcos RAT | Malicious | VirusTotal, URLhaus |
| 5 | URL | `http://98.142.251.63/con` | HTTP redirect stage 1 | Malicious | URLhaus |
| 6 | URL | `http://98.142.251.63/currency` | HTTP redirect stage 2 (Gzip payload) | Malicious | URLhaus |
| 7 | URL | `https://oilporter.com/currency` | Final C2 endpoint | Malicious | URLhaus |

### 4.2 Network IoC — IP Address

| # | IP Address | Port | Peran dalam Serangan | Reputasi | Sumber Validasi |
|---|---|---|---|---|---|
| 1 | `98.142.251.63` | 80 | HTTP redirect server (nginx/Ubuntu) | Malicious | VirusTotal, AbuseIPDB |
| 2 | `104.21.2.21` | 443 | Cloudflare proxy → secretsof.com | Proxy (verify) | Shodan |
| 3 | `89.46.38.87` | 443 | Direct server → flautister.com | Malicious | VirusTotal |
| 4 | `172.67.128.152` | 443 | Cloudflare proxy → www.secretsof.com | Proxy (verify) | Shodan |
| 5 | `52.184.222.228` | 443 | C2 cadangan #1 | Malicious | VirusTotal, AbuseIPDB |
| 6 | `13.89.178.27` | 443 | C2 cadangan #2 | Malicious | VirusTotal |
| 7 | `23.45.119.177` | 443 | C2 cadangan #3 | Suspicious | AbuseIPDB |
| 8 | `150.171.27.10` | 443 | C2 cadangan #4 | Suspicious | AbuseIPDB |

### 4.3 TLS Fingerprint IoC

| # | Tipe | Nilai | Malware Association | Confidence | Sumber |
|---|---|---|---|---|---|
| 1 | JA3 Hash | `280bf914a7a4ba98aa9df62d316a460c` | Remcos RAT TLS Client Fingerprint | **100%** | Abuse.ch SSL Blacklist |
| 2 | JA4 String | `t13d201200_2b729b4bf6f3_e24b6bcd44b0` | Remcos RAT (JA4 generasi baru) | High | Manual analysis |

### 4.4 Host-Based & Behavioral IoC

| # | Tipe | Nilai | Keterangan |
|---|---|---|---|
| 1 | IP Internal Korban | `10.1.22.101` | Host yang terinfeksi |
| 2 | MAC Korban | `00:08:02:1c:47:ae` | HP device |
| 3 | TCP Anomali | Window Size = 65.535 pada SYN ke C2 (Frame #11363) | Potensi evasion / spoofing |
| 4 | Payload Type | HTML/JS dengan `form id="download-form"` (Gzip) | ClickFix execution script |
| 5 | Server Fingerprint | `nginx/1.18.0 (Ubuntu)` | Fingerprint server redirect penyerang |
| 6 | Behavioral | 4+ IP unik dihubungi pada port 443 dalam < 60 detik | Multi-IP C2 beaconing pattern |
| 7 | Behavioral | TCP Retransmission masif (Frame #11419) | Malware gagal koneksi, mencoba server cadangan |

---

## SECTION 5 — MITRE ATT&CK MAPPING

> Referensi: MITRE ATT&CK Enterprise Matrix v14 — https://attack.mitre.org

| # | Tactic | Technique ID | Technique Name | Sub-technique | Bukti Konkret di PCAP |
|---|---|---|---|---|---|
| 1 | **Initial Access** | T1189 | Drive-by Compromise | — | Korban mengakses `secretsof.com` & `flautister.com` (Frame #1, #45) — landing page kampanye ClickFix |
| 2 | **Execution** | T1204 | User Execution | T1204.002 Malicious File | Korban berinteraksi dengan halaman ClickFix dan menjalankan payload — dikonfirmasi oleh rantai aktivitas pasca-DNS |
| 3 | **Execution** | T1059 | Command & Scripting Interpreter | T1059.001 PowerShell | ClickFix secara tipikal menggunakan PowerShell one-liner; dikonfirmasi oleh eksistensi `download-form` dalam payload HTML/JS |
| 4 | **Defense Evasion** | T1090 | Proxy | T1090.004 Domain Fronting | `secretsof.com` & `www.secretsof.com` me-resolve ke IP Cloudflare (104.21.2.21, 172.67.128.152) — IP asli penyerang tersembunyi |
| 5 | **Defense Evasion** | T1027 | Obfuscated Files or Information | — | Payload ClickFix dikompres dengan Gzip dalam respons HTTP `/currency` — menyembunyikan konten HTML/JS dari inspeksi superfisial |
| 6 | **Defense Evasion** | T1036 | Masquerading | — | TCP Window Size = 65.535 pada koneksi C2 (Frame #11363) — meniru profil TCP macOS/BSD untuk mengecoh passive OS fingerprinting IDS |
| 7 | **Command & Control** | T1071 | Application Layer Protocol | T1071.001 Web Protocols | HTTP GET ke 98.142.251.63 (Frame #11355, #11422) dan TLS C2 ke oilporter.com (Frame #11366) |
| 8 | **Command & Control** | T1568 | Dynamic Resolution | T1568.001 Fast Flux DNS | Beaconing ke 4 IP berbeda dalam waktu singkat; kemungkinan rotasi domain/IP aktif |
| 9 | **Command & Control** | T1008 | Fallback Channels | — | 4+ IP C2 cadangan dihubungi berurutan (52.184.222.228, 13.89.178.27, 23.45.119.177, 150.171.27.10:443) + TCP Retransmission masif (Frame #11419) |
| 10 | **Persistence** | T1547 | Boot or Logon Autostart Execution | T1547.001 Registry Run Keys | Kapabilitas Remcos RAT yang diketahui — perlu konfirmasi via EDR/memory forensics |
| 11 | **Collection** | T1056 | Input Capture | T1056.001 Keylogging | Kapabilitas Remcos RAT yang diketahui — perlu konfirmasi via EDR |
| 12 | **Exfiltration** | T1041 | Exfiltration Over C2 Channel | — | Potensial melalui TLS channel ke oilporter.com — belum terkonfirmasi dari PCAP |

---

## SECTION 6 — DETECTION RULE: SIGMA

### 6.1 Sigma Rule — Deteksi Berbasis JA3/JA4 Fingerprint Remcos RAT

```yaml
# =====================================================================
# SIGMA DETECTION RULE
# Title  : Remcos RAT C2 via JA3/JA4 TLS Fingerprint (SmartApeSG)
# Case   : IR-2026-0122-PCAP01-SAS
# Author : [Nama Analis] — SOC Lab / DFIR Practitioner
# Date   : 2026-07-04
# MITRE  : T1071.001, T1568.001, T1008, T1090.004
# =====================================================================

title: Remcos RAT C2 Communication via JA3/JA4 TLS Fingerprint — SmartApeSG ClickFix
id: 3a7f9c1e-5b2d-4e8a-9f0b-1c2d3e4f5a6b
status: experimental
description: >
  Mendeteksi koneksi TLS yang cocok dengan JA3 dan/atau JA4 fingerprint
  yang dikaitkan dengan Remcos RAT dalam kampanye SmartApeSG ClickFix
  (Januari 2026). JA3 hash 280bf914a7a4ba98aa9df62d316a460c terkonfirmasi
  100% sebagai fingerprint Remcos RAT oleh Abuse.ch SSL Blacklist.

  Fingerprint ini merepresentasikan konfigurasi TLS Client Hello unik
  dari implementasi Remcos RAT dan bersifat persisten meskipun infrastruktur
  C2 (domain/IP) dirotasi oleh penyerang. Deteksi berbasis JA3/JA4 bersifat
  lebih tahan terhadap infrastructure pivoting dibandingkan IoC tradisional.

author: '[Nama Analis] — SOC Lab / DFIR Practitioner'
date: 2026-07-04
modified: 2026-07-04

references:
  - https://attack.mitre.org/techniques/T1071/001/
  - https://attack.mitre.org/techniques/T1568/001/
  - https://attack.mitre.org/techniques/T1008/
  - https://sslbl.abuse.ch/ja3-fingerprints/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos

tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1568.001
  - attack.t1008
  - attack.t1090.004
  - attack.defense_evasion
  - malware.remcos_rat
  - campaign.smartapesg_clickfix_2026

logsource:
  category: network
  product: zeek
  service: ssl

detection:
  # Deteksi primer: JA3 hash yang dikonfirmasi 100% Remcos RAT
  selection_ja3:
    ja3|contains:
      - '280bf914a7a4ba98aa9df62d316a460c'

  # Deteksi sekunder: JA4 string (generasi penerus JA3)
  selection_ja4:
    ja4|contains:
      - 't13d201200_2b729b4bf6f3_e24b6bcd44b0'

  # Deteksi tersier: SNI / Server Name (domain C2 yang diketahui)
  selection_sni_c2:
    server_name|contains:
      - 'oilporter.com'
      - 'secretsof.com'
      - 'flautister.com'

  # Deteksi kuarter: IP C2 yang diketahui
  selection_ip_c2:
    id.resp_h|cidr:
      - '98.142.251.63/32'
      - '89.46.38.87/32'
      - '52.184.222.228/32'
      - '13.89.178.27/32'
      - '23.45.119.177/32'
      - '150.171.27.10/32'

  # Deteksi quinter: Anomali TCP Window Size kombinasi dengan port 443
  selection_tcp_anomaly:
    id.resp_p: 443
    # Catatan: Field ini tersedia jika menggunakan Zeek dengan custom script
    # atau sensor jaringan yang log TCP Window Size

  # Allowlist untuk mengurangi false positive
  filter_known_legit:
    server_name|contains:
      - 'microsoft.com'
      - 'windowsupdate.com'
      - 'office365.com'
      - 'office.com'
      - 'live.com'
      - 'azure.com'
      - 'akamai.net'
      - 'cloudfront.net'
      - 'amazonaws.com'

  # Kondisi: Match pada JA3 ATAU JA4 ATAU domain C2 ATAU IP C2, kecuali allowlist
  condition: (selection_ja3 or selection_ja4 or selection_sni_c2 or selection_ip_c2) and not filter_known_legit

fields:
  - ts
  - id.orig_h
  - id.resp_h
  - id.resp_p
  - server_name
  - ja3
  - ja3s
  - ja4
  - validation_status
  - cipher

falsepositives:
  - >
    False positive untuk JA3 280bf914a7a4ba98aa9df62d316a460c sangat kecil
    karena telah dikonfirmasi eksklusif sebagai fingerprint Remcos RAT oleh
    Abuse.ch. Verifikasi manual tetap direkomendasikan untuk host yang
    diketahui menjalankan security testing tools atau sandboxing.
  - >
    False positive untuk domain/IP entries lebih mungkin terjadi jika
    infrastruktur C2 penyerang berganti host di IP tersebut untuk layanan lain.
    Selalu cross-reference dengan VirusTotal dan AbuseIPDB terbaru.

level: high
```

### 6.2 Konversi ke Splunk SPL

```spl
index=network sourcetype=zeek:ssl
(
  ja3="280bf914a7a4ba98aa9df62d316a460c"
  OR ja4="t13d201200_2b729b4bf6f3_e24b6bcd44b0"
  OR server_name IN ("oilporter.com","secretsof.com","flautister.com")
  OR dest_ip IN (
    "98.142.251.63","89.46.38.87",
    "52.184.222.228","13.89.178.27",
    "23.45.119.177","150.171.27.10"
  )
)
NOT server_name IN (
  "microsoft.com","windowsupdate.com","office365.com",
  "office.com","live.com","azure.com"
)
| eval severity="HIGH"
| eval mitre_technique="T1071.001, T1568.001, T1008"
| table _time, src_ip, dest_ip, dest_port, server_name, ja3, ja4, severity, mitre_technique
| sort -_time
```

### 6.3 Konversi ke KQL (Microsoft Sentinel / Defender)

```kql
// Remcos RAT C2 Detection — JA3/JA4 Fingerprint
// Case: IR-2026-0122-PCAP01-SAS
// MITRE: T1071.001, T1568.001, T1008

let RemcosJA3 = "280bf914a7a4ba98aa9df62d316a460c";
let RemcosJA4 = "t13d201200_2b729b4bf6f3_e24b6bcd44b0";
let C2Domains = dynamic(["oilporter.com","secretsof.com","flautister.com"]);
let C2IPs = dynamic([
    "98.142.251.63","89.46.38.87",
    "52.184.222.228","13.89.178.27",
    "23.45.119.177","150.171.27.10"
]);
let LegitDomains = dynamic([
    "microsoft.com","windowsupdate.com",
    "office365.com","azure.com","live.com"
]);

CommonSecurityLog
| where DeviceEventCategory contains "SSL" or DeviceEventCategory contains "TLS"
| where
    (AdditionalExtensions contains RemcosJA3
    or AdditionalExtensions contains RemcosJA4
    or DestinationHostName has_any (C2Domains)
    or DestinationIP has_any (C2IPs))
    and not (DestinationHostName has_any (LegitDomains))
| extend Severity = "High"
| extend MitreTechnique = "T1071.001, T1568.001, T1008"
| extend MitreTactic = "Command and Control, Defense Evasion"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort,
          DestinationHostName, AdditionalExtensions, Severity,
          MitreTechnique, MitreTactic
| order by TimeGenerated desc
```

---

## SECTION 7 — REKOMENDASI MITIGASI

### 7.1 Tindakan Segera (0–24 Jam)

```
PRIORITAS KRITIS — LAKUKAN SEGERA:

[ ] 1. ISOLASI HOST 10.1.22.101 dari jaringan produksi.
       → Putus koneksi network (cabut kabel / nonaktifkan Wi-Fi)
       → JANGAN matikan mesin — preservasi volatile memory untuk forensics
       → Tandai perangkat sebagai "QUARANTINED — DO NOT USE"

[ ] 2. BLOKIR SEMUA IP C2 di perimeter firewall:
       → 98.142.251.63  (HTTP redirect server)
       → 89.46.38.87    (flautister.com direct IP)
       → 52.184.222.228 (C2 backup #1)
       → 13.89.178.27   (C2 backup #2)
       → 23.45.119.177  (C2 backup #3)
       → 150.171.27.10  (C2 backup #4)

[ ] 3. DNS SINKHOLE untuk semua domain C2:
       → secretsof.com
       → www.secretsof.com
       → flautister.com
       → oilporter.com

[ ] 4. DEPLOY SIGMA RULE ke SIEM (Section 6.1) untuk:
       → Deteksi retroaktif host lain yang mungkin terinfeksi
       → Alerting real-time jika ada host baru yang terkoneksi ke C2 ini

[ ] 5. SUBMIT JA3 HASH ke platform EDR/NGFW yang mendukung TLS inspection:
       → Hash: 280bf914a7a4ba98aa9df62d316a460c
       → Action: Block + Alert
```

### 7.2 Tindakan Jangka Pendek (1–7 Hari)

```
[ ] 6. MEMORY FORENSICS pada host 10.1.22.101:
       → Gunakan Volatility3 untuk dump memory
       → Cari injeksi proses Remcos RAT (hollowing, DLL injection)
       → Ekstrak konfigurasi Remcos dari memory (C2 server list, port)

[ ] 7. EDR RETROACTIVE THREAT HUNT di seluruh fleet:
       → Submit semua IoC (IP, domain, JA3 hash) ke platform EDR
       → Cari host lain yang pernah resolve domain C2 yang sama
       → Periksa log akses ke URL /con dan /currency di web proxy

[ ] 8. RESET KREDENSIAL:
       → Reset password semua akun yang pernah login ke host 10.1.22.101
       → Prioritaskan akun dengan privilese tinggi (admin domain, service account)
       → Aktifkan MFA jika belum ada

[ ] 9. FORENSIC IMAGE host 10.1.22.101:
       → Buat full disk image dengan tools forensik (FTK Imager, dd)
       → Simpan di storage forensik yang terenkripsi dan ber-chain of custody
       → Analisis artefak persistensi: Registry Run Keys, Task Scheduler, Startup folder

[ ] 10. REVIEW LOG WEB PROXY:
        → Cari akses ke secretsof.com, flautister.com, oilporter.com
        → Periksa apakah ada host lain yang mengakses URL /con atau /currency
        → Periksa apakah ada host lain dengan pola Gzip response yang mencurigakan
```

### 7.3 Hardening Jangka Panjang (> 7 Hari)

```
[ ] 11. IMPLEMENTASI JA3/JA4 BLOCKING di NGFW/Proxy:
        → Konfigurasi NGFW dengan dukungan TLS inspection dan JA3 detection
        → Subscribe ke feed JA3 malware dari Abuse.ch secara otomatis

[ ] 12. POWERSHELL HARDENING:
        → Aktifkan Script Block Logging dan Module Logging (EventID 4104, 4103)
        → Konfigurasikan PowerShell Constrained Language Mode
        → Terapkan Application Control (AppLocker / WDAC) untuk blokir PS scripts dari %TEMP%

[ ] 13. WEB CONTENT INSPECTION:
        → Konfigurasi proxy untuk dekompresi dan inspeksi konten Gzip
        → Deploy SSL Inspection untuk trafik ke domain non-trusted
        → Blokir akses ke TLD berisiko tinggi (.top, .xyz, .club, .tk) jika tidak diperlukan bisnis

[ ] 14. DNS SECURITY:
        → Implementasikan DNS Response Policy Zone (RPZ) dengan feed threat intel otomatis
        → Aktifkan DNSSEC untuk resolver internal
        → Log semua DNS queries dan kirim ke SIEM untuk deteksi anomali

[ ] 15. USER AWARENESS TRAINING — ClickFix Spesifik:
        → Tampilkan screenshot nyata halaman ClickFix kepada semua karyawan
        → Tetapkan dan komunikasikan kebijakan: "TIDAK ADA sistem IT sah yang meminta
          kamu untuk menyalin dan menjalankan perintah dari browser"
        → Lakukan simulasi phishing/ClickFix secara berkala untuk mengukur awareness
```

---

## Referensi & Sumber Daya

| # | Sumber | URL | Relevansi |
|---|---|---|---|
| 1 | MITRE ATT&CK | https://attack.mitre.org | TTP Framework Reference |
| 2 | Abuse.ch SSL Blacklist | https://sslbl.abuse.ch/ja3-fingerprints/ | JA3 Hash Lookup |
| 3 | MalwareBazaar | https://bazaar.abuse.ch | Malware Hash Database |
| 4 | URLhaus | https://urlhaus.abuse.ch | URL Threat Intelligence |
| 5 | AbuseIPDB | https://abuseipdb.com | IP Reputation Database |
| 6 | VirusTotal | https://virustotal.com | Multi-engine AV & IoC Lookup |
| 7 | Shodan | https://shodan.io | Server/Infrastructure Fingerprinting |
| 8 | Malpedia — Remcos RAT | https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos | Malware Family Profile |
| 9 | SigmaHQ GitHub | https://github.com/SigmaHQ/sigma | Sigma Rule Format Reference |
| 10 | Uncoder.io | https://sigmaiq.uncoder.io/ | Sigma Rule Conversion & Validation |
| 11 | FoxIO JA4 | https://blog.foxio.io/ja4+ | JA4 Fingerprint Documentation |
| 12 | Wireshark | https://www.wireshark.org/docs/ | Analysis Tool Documentation |

---

<div align="center">

---

*Laporan ini dibuat dalam konteks pendidikan forensik jaringan.*
*Seluruh IoC dipublikasikan untuk keperluan komunitas blue team dan threat intelligence sharing.*
*Jangan gunakan informasi ini untuk tujuan yang melanggar hukum.*

---

| Field | Value |
|---|---|
| **Case ID** | `IR-2026-0122-PCAP01-SAS` |
| **Report Status** | ✅ Closed — Documented |
| **Analyst** | [Nama Kamu] |
| **Date Closed** | 2026-07-04 |
| **Version** | 2.0 Final |

</div>
