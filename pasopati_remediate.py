#!/usr/bin/env python3
"""
================================================================================
 PASOPATI SCRIPT PERBAIKAN (REMEDIATION) v2.6
================================================================================
Dipakai untuk MENJALANKAN perbaikan dari plan yang disetujui server, atau
mode DEMO. Mesin pemeriksaannya ada di pasopati_audit.py (harus berada di folder
yang sama).

Contoh:
  python pasopati_remediate.py --server http://192.168.1.10:3000 \
      --plan-id PLAN-... --remediate-api-key <KEY> --hmac-key <HMAC>
  python pasopati_remediate.py --remediate-plan plan.json --remediate-token <n>.<s> ...
  python pasopati_remediate.py --demo --no-exec

Tanpa token valid, host tidak diubah (read-only).
================================================================================
"""
import os
import sys

try:
    import pasopati_audit as core
except ImportError:
    print("[!] pasopati_audit.py tidak ditemukan di folder yang sama dengan script ini.")
    print("    Unduh juga: /api/download/pasopati_audit.py")
    sys.exit(1)

MODES = ("--plan-id", "--remediate-plan", "--demo", "--quarantine", "--quarantine-release", "--deadman-rollback", "--watch", "--verify-manifest", "--list-aliases")


def main():
    argv = sys.argv[1:]
    if not any(flag in argv for flag in MODES) and not any(a in ("-h", "--help") for a in argv):
        print("PASOPATI - script perbaikan. Butuh salah satu mode:")
        print("  --plan-id <ID> --server <URL>   ambil plan yang sudah disetujui")
        print("  --remediate-plan <file>         pakai plan.json lokal")
        print("  --demo                          susun plan otomatis dari audit")
        print("  --quarantine [--quarantine-release]")
        print("  --list-aliases                  tampilkan alias per OS (windows/linux)")
        print("Tambahkan --no-exec untuk uji aman tanpa perubahan.")
        return 2
    core.main(argv, entry_script=os.path.abspath(__file__))
    return 0


if __name__ == "__main__":
    sys.exit(main())
