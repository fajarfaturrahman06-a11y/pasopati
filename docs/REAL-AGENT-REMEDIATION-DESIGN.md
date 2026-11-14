# Rancangan Arsitektur: Remediasi Agent Nyata (PASOPATI)

Dokumen ini adalah desain teknis untuk **remediasi agent nyata** — mengubah konfigurasi
sistem operasi host target secara langsung melalui agent, dengan persetujuan eksplisit per-tindakan
dan verifikasi terbaca ulang. Ini **bukan** simulasi status di dashboard.

> **Status:** Fase A–E **selesai 06 Nov 2026**. Dokumen ini adalah desain awal (Fase A); daftar final 10 alias ada di `pasopati_audit.py` `ALLOWLIST_ANALISA`. Tabel §5 hanya contoh desain awal.

## 1. Prinsip keamanan (non-negotiable)

1. **Default read-only** — agent tanpa approval hanya boleh membaca/mengaudit.
2. **Persetujuan eksplisit per-plan** — setiap perubahan harus disetujui operator dengan konteksnya.
3. **Allowlist, bukan raw command** — dashboard hanya memilih *alias tindakan* dari daftar terdaftar di
   agent; agent menerjemahkan alias → perintah nyata. Dashboard tidak boleh mengirim string shell mentah.
4. **Backup sebelum ubah** — konfigurasi lama disimpan terpisah di host.
5. **Verifikasi sesudah ubah** — nilai akhir dibaca ulang dari sistem, bukan diasumsikan.
6. **Rollback = restore dari backup**, bukan mengganti teks deskripsi.
7. **Fail-safe** — kegagalan di langkah apa pun menghentikan alur (stop-on-failure), tidak lanjut.

## 2. Komponen

```
┌──────────────┐   (1) Audit        ┌──────────────┐
│  Dashboard   │ ─────────────────▶ │   Agent      │
│  (Puskodal)  │                    │  (pasopati_    │
│              │ ◀───────────────── │   agent.py)  │
│  - runbook   │   (2) Evidence     │              │
│  - approval  │                    │  - allowlist │
│  - verify UI │                    │  - backup    │
└──────┬───────┘                    │  - executor  │
       │                            └──────▲───────┘
       │ (3) plan/approve/verify           │ (4) perintah terdaftar
┌──────▼───────────────────────┐           │
│        Server (control)      │──── TLS/mTLS ────
│  - state machine             │     + HMAC per-pesan
│  - audit store (/api/audit-logs, /api/ingest)
└──────────────────────────────┘
```

### A. Dashboard (Puskodal UI)
- Menampilkan runbook: daftar temuan + rencana tindakan per temuan (perintah sesungguhnya yang akan dijalankan,
  risiko, reversibility).
- Operator **approve/reject per item**, bukan blanket approve.
- Menampilkan status verifikasi nyata (dibaca ulang dari host), label dibedakan:
  **`SIMULASI`** vs **`TERVERIFIKASI NYATA`**.

### B. Server (control plane, `server.ts`)
- Endpoint baru:
  - `POST /api/remediation-plan` — operator/dashboard meminta rencana perbaikan.
  - `POST /api/remediation-approve` — persetujuan per-plan menghasilkan **nonce + expiry 10 menit + HMAC plan signature**. Token boleh diterbitkan ulang setelah kedaluwarsa; batas kirim evidence 60 menit.
  - `GET/POST /api/remediation-verify` — menampung hasil verifikasi dari agent.
- State machine per plan:
  ```
  PLANNED → APPROVED → EXECUTING → VERIFIED
                                          ↘ (gagal di langkah i)
                                            ROLLED_BACK / FAILED
  ```
- Menyimpan approval & evidence; memperluas skema audit log agar menyimpan `evidence`
  (perintah, exit code, output hash, timestamp).

### C. Agent (host target)
- Tetap **read-only** secara default.
- Mode `remediate` hanya aktif dengan **token persetujuan + plan signature** yang terverifikasi.
- Verifikasi sebelum eksekusi: signature-valid, nonce-belum-dipakai, belum-expired, OS/versi cocok, allowlist.
- Allowlist wajib punya handler `rollback` nyata (bukan sekadar mencetak pesan); rollback memakai pre-state snapshot.
- Backup lokal (direktori backup per-host, versi bernomor, retensi terbatas).
- Executor menjalankan alias terdaftar → verify → evidence HMAC → kirim per-langkah.

### D. Backup store
- Lokasi: di host target (direktori khusus, mis. `%PROGRAMDATA%\PASOPATI\backups` Linux: `/var/lib/pasopati/backups`).
- Format: snapshot konfigurasi yang diubah + metadata (timestamp, plan_id, pre_state, post_state_expected).
- Retensi: dibatasi (mis. 10 terakhir per host) untuk menghindari pemenuhan disk.

## 3. Alur kerja end-to-end

1. **Audit** — agent mengirim temuan (FAIL/WARNING) via `/api/ingest` (sudah ada).
2. **Runbook** — dashboard (AI) menyusun rencana per-temuan: `alias tindakan`, risiko, reversibility.
3. **Approval** — operator memilih item yang disetujui. Server membuat token (nonce + HMAC + expiry).
4. **Transit** — server meneruskan plan+token ke agent via kanal aman (TLS + mTLS).
5. **Agent verify** — signature/nonce/expiry/allowlist/prasyarat OS.
6. **Backup** — snapshot konfigurasi target.
7. **Eksekusi + verifikasi per langkah** — bukti (output, exit code) di-HMAC dan dikirim real-time.
8. **Hasil akhir**:
   - Semua verify PASS → `VERIFIED`.
   - Ada gagal → stop → tawaran otomatis **rollback dari backup** → verify ulang → `ROLLED_BACK`
     (atau `FAILED` bila rollback gagal, + alert operator).
9. **UI** menampilkan nilai terverifikasi yang dibaca dari host; audit terdokumentasi permanen.

## 4. Skema data

```text
remediation_plan = {
  plan_id, device_id, created_by, created_at,
  items: [ { finding_id, alias, risk, reversible,
             pre_state, post_state_expected } ],
  approved_by, approved_at, nonce, expires_at
}
evidence = {
  plan_id, step_index, alias, exit_code,
  output_hash, verified: bool, timestamp
}
```

## 5. Allowlist awal (alias → perintah)

| OS | Alias contoh | Efek nyata | Verifikasi |
|---|---|---|---|
| Linux | `fw-enable-ufw` | `ufw enable`, default deny incoming | `ufw status` |
| Linux | `ssh-disable-root` | `PermitRootLogin no` di sshd_config | `sshd -T \| grep PermitRootLogin` |
| Windows | `fw-enable-defender` | `Set-NetFirewallProfile -Enabled True` | `Get-NetFirewallProfile` |
| Windows | `guest-account-disable` | `Disable-LocalUser -Name Guest` | `Get-LocalUser Guest` |
| Windows | `usb-storage-block` | registry `USBSTOR Start=4` | `reg query ...\USBSTOR` |

Alias **terdaftar di agent** — dashboard hanya memilih dari daftar, tidak mengirim string perintah.

## 6. Keamanan kanal & eksekusi

- **TLS + mTLS** server↔agent.
- **HMAC-SHA256 per pesan** (reuse pola `/api/ingest` yang sudah ada).
- **Nonce anti-replay + expiry pendek**.
- Agent berjalan dengan **hak istimewa minimum** — sudoers sangat sempit hanya untuk alias allowlist,
  atau tanpa root dengan capability spesifik bila memungkinkan.
- Approval terpisah dari request (minimal role-based; idealnya four-eyes untuk item berisiko tinggi).

## 7. Fail-safe

- Tanpa approval → agent menolak perubahan.
- Koneksi putus di tengah langkah → agent stop; status dianggap `UNKNOWN` → perlu reconciliation sebelum lanjut.
- Verify gagal → rollback otomatis dari backup.
- Rollback gagal → status `FAILED` + alert operator, tidak dipalsukan.
- Rate limit + semua upaya tercatat.

## 8. Mode operasional

| Mode | Deskripsi |
|---|---|
| **A. READ-ONLY** | default; audit saja |
| **B. ASSISTED** | setiap plan perlu approval per-item (mode untuk implementasi awal) |
| **C. FULL-AUTO terbatas** | hanya item reversibel + risiko rendah; *tidak direkomendasikan untuk fase awal* |

## 9. Roadmap implementasi

| Fase | Isi |
|---|---|
| **A** | Arsitektur + skema + allowlist *(dokumen ini)* |
| **B** | Server: endpoint plan/approve/verify + state machine + skema evidence |
| **C** | Agent: mode remediate (1 OS dulu, mis. Linux), backup/verify/rollback, evidence HMAC |
| **D** | UI: runbook persetujuan per-item, display verifikasi nyata, rollback dari host |
| **E** | Pilot di host non-kritis → perluasan OS & alias |

## 10. Risiko & mitigasi

| Risiko | Mitigasi |
|---|---|
| RCE via command injection | alias allowlist; tidak ada raw shell dari luar |
| Perubahan destruktif | backup + cek reversibility + stop-on-failure |
| Eskalasi hak | sudoers sempit, least-privilege |
| Replay attack | nonce + expiry + HMAC |
| "Teater keamanan" berulang | label UI dibedakan: `SIMULASI` vs `TERVERIFIKASI NYATA` |

## 11. Kriteria selesai (acceptance)

- [ ] Tanpa approval, agent **tidak mengubah apa pun** (teruji).
- [ ] Setiap perubahan memiliki backup + hasil verifikasi terbaca ulang.
- [ ] Rollback mengembalikan nilai yang dibaca ulang dari host (bukan teks).
- [ ] Audit evidence terverifikasi independen via HMAC.
