#!/usr/bin/env python3
"""Uji generator runbook app.py (Field Console): semua temuan agent harus
menghasilkan aksi + rollback, dan skrip bash harus lolos `bash -n`.

Jalankan: python3 tests/test_app_scripts.py
"""
import io
import os
import subprocess
import zipfile
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import app  # noqa: E402


def mk_check(i, param, detail, status="FAIL"):
    return {"param": param, "cat": "Uji", "cis": "CIS-X", "status": status, "detail": detail}


LINUX_PARAMS = [
    ("Network & Dangerous Ports Filtering", "Port 445 / 23 / 21 / 4444 terbuka"),
    ("Host-Based Local Firewall Active", "UFW inactive"),
    ("SSH Root Login & Auth", "PermitRootLogin yes"),
    ("USB Mass Storage Restriction", "usb-storage tidak diblacklist"),
    ("Auditd Daemon Security Logging", "auditd tidak aktif"),
    ("Kernel Module Integrity & Rootkit Scan", "modul diamorphine terdeteksi"),
    ("Bootloader GRUB Configuration Hardening", "grub.cfg mode 644"),
    ("Full Disk Encryption (LUKS)", "belum dienkripsi LUKS"),
    ("Sudoers Privilege Boundary & NOPASSWD", "ada NOPASSWD"),
    ("SUID Binary Escalation Vector Scan", "SUID pada /bin/bash"),
]
WINDOWS_PARAMS = [
    ("Network & Dangerous Ports Filtering", "Port 445 / 3389 / 4444 terbuka"),
    ("Host-Based Local Firewall Active", "satu profil firewall OFF"),
    ("Guest Account Lockdown", "akun Guest aktif"),
    ("USB Storage Device Control", "USB belum dibatasi"),
    ("Windows Event Log & Auditing", "audit process creation mati"),
    ("UEFI Secure Boot & Driver Enforcement", "Secure Boot mati"),
    ("BitLocker Drive Encryption (FDE)", "BitLocker tidak aktif"),
    ("Local Administrators Group Membership", "terlalu banyak admin"),
    ("UAC (EnableLUA)", "UAC tidak aktif"),
]


def device(os_name, params, ports):
    return {
        "os": os_name,
        "role": "Server Uji",
        "checks": [mk_check(i, p, d) for i, (p, d) in enumerate(params)],
        "open_ports": ports,
    }


class AppScriptTests(unittest.TestCase):
    def test_linux_covers_every_finding_and_is_valid_bash(self):
        hard, roll, ext = app.generate_dynamic_scripts("DEV-UJI", device("Ubuntu 22.04", LINUX_PARAMS, [21, 23, 445, 4444]))
        self.assertEqual(ext, "bash")
        for token in [
            "--dport 4444", "--dport 445", "--dport 23", "--dport 21",
            "ufw --force enable", "PermitRootLogin no", "pasopati-usb-lock.conf",
            "systemctl enable auditd", "/boot/grub/grub.cfg", "NOPASSWD:", "chmod u-s",
            "LUKS", "rootkit",
        ]:
            self.assertIn(token, hard, f"hardening tidak memuat {token}")
        for token in ["--dport 4444", "ufw disable", "sshd_config.pasopati.bak", "pasopati-grub.list", "pasopati-suid.list", "RESTORED"]:
            self.assertIn(token, roll, f"rollback tidak memuat {token}")
        self.assertIn("TEMUAN BELUM DIPETAKAN", hard)
        self.assertIn("exec sudo -E bash", hard)
        self.assertIn("PASOPATI_ELEVATED", hard)
        self.assertIn("exec sudo -E bash", roll)
        self.assertIn("(tidak ada - semua temuan sudah ditangani di atas)", hard)

        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(hard)
            path = f.name
        try:
            subprocess.run(["bash", "-n", path], check=True, capture_output=True)
        finally:
            os.unlink(path)

    def test_windows_covers_every_finding(self):
        hard, roll, ext = app.generate_dynamic_scripts("DEV-WIN", device("Windows 11 Pro", WINDOWS_PARAMS, [3389, 445, 4444]))
        self.assertEqual(ext, "powershell")
        for token in [
            "PASOPATI-Block-4444", "Set-NetFirewallProfile", "Disable-LocalUser", "USBSTOR",
            "auditpol /set", "Confirm-SecureBootUEFI", "manage-bde -on", "EnableLUA", "Get-LocalGroupMember",
        ]:
            self.assertIn(token, hard, f"hardening tidak memuat {token}")
        self.assertIn("Remove-NetFirewallRule", roll)
        self.assertIn("(tidak ada - semua temuan sudah ditangani di atas)", hard)
        self.assertIn("-Verb RunAs", hard)
        self.assertIn("-Elevated", hard)

    def test_unknown_finding_is_not_dropped(self):
        hard, _roll, _ext = app.generate_dynamic_scripts("DEV-UJI", device("Ubuntu 22.04", [("Parameter Baru Tanpa Alias", "detail khusus")], []))
        self.assertIn("Parameter Baru Tanpa Alias", hard)
        self.assertIn("detail khusus", hard)

    def test_rootkit_does_not_trigger_ssh_step(self):
        hard, _roll, _ext = app.generate_dynamic_scripts(
            "DEV-UJI", device("Ubuntu 22.04", [("Kernel Module Integrity & Rootkit Scan", "modul diamorphine")], [])
        )
        self.assertNotIn("PermitRootLogin", hard)


class ProjectZipTests(unittest.TestCase):
    def test_zip_mengecualikan_rahasia_dan_template_tetap_ada(self):
        names = zipfile.ZipFile(io.BytesIO(app.create_project_zip_bytes())).namelist()
        self.assertIn('.env.example', names)
        for secret in ('.env', 'opencode.json', 'reapprove.ps1', 'token.txt'):
            self.assertNotIn(secret, names)
        self.assertFalse(any(n.startswith('bitlocker-recovery-') for n in names))
        self.assertIn('app.py', names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
