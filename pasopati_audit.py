#!/usr/bin/env python3
"""
================================================================================
 PASOPATI ENDPOINT AUDIT AGENT (CLI) v2.6 — SCRIPT PEMERIKSAAN
 System Audit, Threat Remediation & Intelligence Architecture Guard
 Defense Cyber Operations & Deep Core Infrastructure Inspection
================================================================================
 Standards: CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443 compliance
 Capabilities:
  1. Deep Endpoint Audit (Kernel & Boot Integrity, LUKS/BitLocker FDE, SUID/Sudo)
  2. Idempotent & Deterministic Hardening Generator
  3. Pre-Execution Dry-Run & Automated Post-Remediation Re-Audit Loop
  4. Cryptographic HMAC-SHA256 Telemetry Authentication
  5. Emergency Network Quarantine Vector (Kill-Switch)

 Catatan: modul ini adalah MESIN PEMERIKSAAN. Script perbaikan terpisah ada di
 pasopati_remediate.py dan memakai modul ini sebagai pustaka.
================================================================================
"""

import os
import sys
import json
import socket
import platform
import subprocess
import datetime
import argparse
import glob
import uuid
import tempfile
import atexit
import shutil
import hmac
import hashlib
import re
import secrets
import ssl
import time
import errno
import urllib.request
import urllib.error
import urllib.parse

# Optional psutil integration
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# HMAC shared secret MUST be supplied per-deployment (--hmac-key or env HMAC_SECRET).
# There is intentionally NO hardcoded fallback.

CRITICAL_PORTS = {
    445: {"service": "SMB/Active Directory", "risk": "CRITICAL", "desc": "Rentan EternalBlue, SMB Relay, dan Lateral Movement."},
    3389: {"service": "RDP (Remote Desktop)", "risk": "HIGH", "desc": "Rawan Brute-Force BlueKeep jika tidak dibatasi via VPN/IP Whitelist."},
    23: {"service": "Telnet", "risk": "CRITICAL", "desc": "Protokol plaintext tanpa enkripsi; kredensial komando mudah disadap."},
    21: {"service": "FTP Plaintext", "risk": "HIGH", "desc": "Transmisi file dan firmware plaintext rawan MITM."},
    4444: {"service": "Metasploit / C2 Backdoor", "risk": "EMERGENCY", "desc": "Port default reverse shell Metasploit payload."},
    22: {"service": "SSH Secure Shell", "risk": "MEDIUM", "desc": "Perlu dipastikan root login & password auth dinonaktifkan."}
}

def get_current_user():
    try:
        return os.getlogin()
    except Exception:
        pass
    for var in ['USER', 'USERNAME', 'LOGNAME']:
        if var in os.environ and os.environ[var]:
            return os.environ[var]
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        pass
    return "operator"

def get_mac_address():
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
        return mac.upper()
    except Exception:
        return "00:00:00:00:00:00"

def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def _dedupe_ports(entries):
    seen = set()
    result = []
    for entry in entries:
        port = entry.get("port")
        if port in seen:
            continue
        seen.add(port)
        result.append(entry)
    return result

def scan_listening_ports():
    open_ports = []
    if HAS_PSUTIL:
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    port = conn.laddr.port
                    ip = conn.laddr.ip
                    pid = conn.pid
                    proc_name = "Unknown"
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except Exception:
                            proc_name = "System/Protected"
                    
                    is_crit = port in CRITICAL_PORTS and port != 22
                    crit_meta = CRITICAL_PORTS.get(port, {})
                    open_ports.append({
                        "port": port,
                        "ip": ip,
                        "process": proc_name,
                        "pid": pid,
                        "is_critical": is_crit,
                        "service": crit_meta.get("service", proc_name),
                        "risk_level": crit_meta.get("risk", "INFO"),
                        "threat_desc": crit_meta.get("desc", "Layanan listening aktif.")
                    })
            return _dedupe_ports(open_ports)
        except Exception:
            pass

    # Standard library fallback
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 502, 1433, 1521, 3306, 3389, 4444, 5432, 8080]
    hosts = ['127.0.0.1']
    try:
        primary = get_primary_ip()
        if primary and primary not in hosts:
            hosts.append(primary)
    except Exception:
        pass
    seen_ports = set()
    for port in target_ports:
        reachable = False
        for host in hosts:
            if reachable:
                break
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.15)
            result = sock.connect_ex((host, port))
            if result == 0:
                reachable = True
            sock.close()
        if not reachable:
            continue
        if port in seen_ports:
            continue
        seen_ports.add(port)
        is_crit = port in CRITICAL_PORTS and port != 22
        crit_meta = CRITICAL_PORTS.get(port, {})
        open_ports.append({
            "port": port,
            "ip": "127.0.0.1",
            "process": crit_meta.get("service", "TCP Service"),
            "pid": None,
            "is_critical": is_crit,
            "service": crit_meta.get("service", "Active Service"),
            "risk_level": crit_meta.get("risk", "INFO"),
            "threat_desc": crit_meta.get("desc", "Layanan terdeteksi merespons pada socket lokal.")
        })
    return _dedupe_ports(open_ports)

# ==============================================================================
# MODULE 1: KERNEL & BOOT INTEGRITY (CIS 1.1 / DISA STIG KRN-001)
# ==============================================================================
def audit_kernel_boot_integrity():
    current_os = platform.system().lower()
    findings = []
    
    if 'linux' in current_os:
        # Check loaded modules for rootkits/hooks
        untrusted_modules = []
        try:
            with open('/proc/modules', 'r') as f:
                loaded = [line.split()[0] for line in f.readlines()]
            suspicious = ['diamorphine', 'suterusu', 'reptile', 'adore_ng', 'kbeast']
            untrusted_modules = [m for m in suspicious if m in loaded]
        except Exception:
            pass
        
        status_mod = "FAIL" if untrusted_modules else "PASS"
        desc_mod = f"Terdeteksi kernel hook/rootkit mencurigakan: {untrusted_modules}!" if untrusted_modules else "Kernel modules terverifikasi bersih dari signature rootkit publik."
        findings.append({
            "parameter": "Kernel Module Integrity & Rootkit Scan",
            "category": "Kernel & Boot",
            "cis_id": "CIS 1.1.1 / DISA STIG V-214800",
            "status": status_mod,
            "details": desc_mod
        })

        # GRUB boot config permissions
        grub_paths = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
        grub_found = False
        grub_secure = False
        for gp in grub_paths:
            if os.path.exists(gp):
                grub_found = True
                st = os.stat(gp)
                mode = oct(st.st_mode)[-3:]
                if mode in ['400', '600', '000']:
                    grub_secure = True
                break
        
        is_wsl = False
        try:
            if os.path.exists('/proc/version'):
                with open('/proc/version', 'r') as f:
                    v = f.read().lower()
                    if 'microsoft' in v or 'wsl' in v:
                        is_wsl = True
        except Exception:
            pass
        if (not grub_found) and is_wsl:
            findings.append({
                "parameter": "Bootloader GRUB Configuration Hardening",
                "category": "Kernel & Boot",
                "cis_id": "CIS 1.4.1 / DISA STIG V-214810",
                "status": "N/A",
                "details": "N/A di WSL: tidak ada GRUB bootloader (boot via kernel WSL); kontrol ini hanya berlaku di baremetal."
            })
        else:
            findings.append({
                "parameter": "Bootloader GRUB Configuration Hardening",
                "category": "Kernel & Boot",
                "cis_id": "CIS 1.4.1 / DISA STIG V-214810",
                "status": "PASS" if (grub_found and grub_secure) else "FAIL",
                "details": "Izin file grub.cfg dikunci (0600/0400 root-only)." if (grub_found and grub_secure) else ("File GRUB bootloader ditemukan tanpa batas izin yang cukup ketat (potensi manipulasi boot kernel)." if grub_found else "GRUB bootloader configuration tidak ditemukan pada sistem.")
            })

    elif 'windows' in current_os:
        # Secure Boot verification
        sb_status = "PASS"
        sb_details = "UEFI Secure Boot aktif memverifikasi integritas bootloader."
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"], capture_output=True, text=True, timeout=4)
            if "True" in res.stdout:
                sb_status = "PASS"
            elif "False" in res.stdout:
                sb_status = "FAIL"
                sb_details = "UEFI Secure Boot DINONAKTIFKAN! Rawan manipulasi rootkit boot (BootHole/BlackLotus)."
        except Exception:
            sb_status = "WARNING"
            sb_details = "Query Secure Boot memerlukan elevated PowerShell privilege."

        findings.append({
            "parameter": "UEFI Secure Boot & Driver Enforcement",
            "category": "Kernel & Boot",
            "cis_id": "DISA STIG WN11-00-000005",
            "status": sb_status,
            "details": sb_details
        })

    return findings

# ==============================================================================
# MODULE 2: CRYPTOGRAPHIC POSTURE & STORAGE ENCRYPTION (FDE)
# ==============================================================================
def audit_crypto_storage():
    current_os = platform.system().lower()
    findings = []

    if 'linux' in current_os:
        # Check if running in WSL virtualized environment
        is_wsl = False
        try:
            if os.path.exists('/proc/version'):
                with open('/proc/version', 'r') as f:
                    v = f.read().lower()
                    if 'microsoft' in v or 'wsl' in v:
                        is_wsl = True
        except Exception:
            pass

        luks_active = False
        try:
            res = subprocess.run(["lsblk", "-f"], capture_output=True, text=True, timeout=3)
            if "crypto_LUKS" in res.stdout:
                luks_active = True
        except Exception:
            pass

        if luks_active:
            status_luks = "PASS"
            details_luks = "Partisi data operasional terenkripsi menggunakan modul LUKS."
        elif is_wsl:
            status_luks = "N/A"
            details_luks = "N/A di WSL: disk virtual VHDX ext4; LUKS hanya berlaku di penyimpanan baremetal."
        else:
            status_luks = "FAIL"
            details_luks = "Penyimpanan data militer belum dienkripsi LUKS (risiko ekstraksi offline jika perangkat hilang)."

        findings.append({
            "parameter": "Full Disk Encryption (LUKS)",
            "category": "Cryptographic Posture",
            "cis_id": "CIS 1.1.2 / DISA STIG V-214820",
            "status": status_luks,
            "details": details_luks
        })

    elif 'windows' in current_os:
        bitlocker_active = False
        bitlocker_in_progress = False
        bitlocker_query_ok = True
        bitlocker_pct = 0
        try:
            _bl = _win_bitlocker_state()
            bitlocker_pct = _bl.get("encryptionPercentage") or 0
            bitlocker_active = bool(_bl.get("protectionOn")) or bool(_bl.get("encrypted"))
            # Enkripsi yang masih berjalan bukan kegagalan: protector sudah ada,
            # proteksi menyala setelah konversi selesai/reboot.
            bitlocker_in_progress = (not bitlocker_active) and _win_bitlocker_ok(_bl)
        except Exception:
            bitlocker_query_ok = False

        if bitlocker_active:
            bl_status = "PASS"
            bl_details = "Volume sistem C: terproteksi BitLocker XTS-AES 256-bit."
        elif bitlocker_in_progress:
            bl_status = "WARNING"
            bl_details = (f"Enkripsi BitLocker sedang berjalan ({bitlocker_pct}%); "
                          "proteksi aktif setelah enkripsi selesai/reboot.")
        elif bitlocker_query_ok:
            bl_status = "FAIL"
            bl_details = "Volume C: tidak terenkripsi BitLocker! Data taktis berisiko dicuri via physical extraction."
        else:
            bl_status = "WARNING"
            bl_details = "Status BitLocker tidak terbaca (butuh Administrator); verifikasi manual."

        findings.append({
            "parameter": "BitLocker Drive Encryption (FDE)",
            "category": "Cryptographic Posture",
            "cis_id": "DISA STIG WN11-00-000025",
            "status": bl_status,
            "details": bl_details
        })

    return findings

# ==============================================================================
# MODULE 3: ADVANCED PRIVILEGE BOUNDARY (SUID / SUDO / LOCAL GROUPS)
# ==============================================================================
def audit_privilege_boundaries():
    current_os = platform.system().lower()
    findings = []

    if 'linux' in current_os:
        # Check /etc/sudoers for NOPASSWD (parse per-line, skip comments)
        nopasswd_found = False
        sudoers_error = False
        try:
            sudoers_paths = ['/etc/sudoers']
            if os.path.exists('/etc/sudoers.d'):
                sudoers_paths.extend([os.path.join('/etc/sudoers.d', f) for f in os.listdir('/etc/sudoers.d')])
            for sp in sudoers_paths:
                if os.path.isfile(sp):
                    found_nopasswd = False
                    try:
                        with open(sp, 'r', errors='ignore') as f:
                            for line in f:
                                stripped = line.strip()
                                if not stripped or stripped.startswith('#'):
                                    continue
                                if "NOPASSWD:" in stripped:
                                    found_nopasswd = True
                                    break
                    except Exception:
                        sudoers_error = True
                    if found_nopasswd:
                        nopasswd_found = True
                        break
        except Exception:
            pass

        if nopasswd_found:
            sudo_status = "FAIL"
            sudo_details = "Ditemukan aturan eskalasi privilege sudo NOPASSWD tanpa otentikasi!"
        elif sudoers_error:
            sudo_status = "WARNING"
            sudo_details = "Verifikasi konfigurasi sudoers tidak dapat dilakukan (akses baca ditolak)."
        else:
            sudo_status = "PASS"
            sudo_details = "Tidak ditemukan aturan sudo NOPASSWD; batas privilege sudoers wajar."
        findings.append({
            "parameter": "Sudoers Privilege Boundary & NOPASSWD",
            "category": "Privilege Boundary",
            "cis_id": "CIS 5.3.4 / DISA STIG V-214885",
            "status": sudo_status,
            "details": sudo_details
        })

        # Check SUID binaries on critical utilities
        risky_suid = []
        for test_bin in ['/bin/bash', '/bin/sh', '/usr/bin/python3', '/usr/bin/perl', '/bin/netcat', '/usr/bin/find']:
            if os.path.exists(test_bin):
                st = os.stat(test_bin)
                if st.st_mode & 0o4000:
                    risky_suid.append(test_bin)

        findings.append({
            "parameter": "SUID Binary Escalation Vector Scan",
            "category": "Privilege Boundary",
            "cis_id": "CIS 1.1.21 / DISA STIG V-214830",
            "status": "FAIL" if risky_suid else "PASS",
            "details": f"PERINGATAN! Binari kritis memiliki bit SUID aktif: {risky_suid} (rawan eskalasi root seketika)!" if risky_suid else "Tidak ditemukan bit SUID liar pada shell atau scripting interpreter."
        })

    elif 'windows' in current_os:
        # Check local admin membership
        unauthorized_admins = False
        try:
            res = subprocess.run(["net", "localgroup", "Administrators"], capture_output=True, text=True, timeout=3)
            # Flag if multiple unexpected accounts found
            lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
            if len(lines) > 8:
                unauthorized_admins = True
        except Exception:
            pass

        findings.append({
            "parameter": "Local Administrators Group Membership",
            "category": "Privilege Boundary",
            "cis_id": "DISA STIG WN11-00-000015",
            "status": "WARNING" if unauthorized_admins else "PASS",
            "details": "Jumlah akun administrator lokal melebihi kuota minimal hak istimewa STIG." if unauthorized_admins else "Keanggotaan grup Administrators lokal terbatasi sesuai baseline tugas operasional."
        })

    return findings

# ==============================================================================
# EXISTING MODULES: FIREWALL, ACCESS CONTROL, ENDPOINT PROTECTION, LOGGING
# ==============================================================================
def audit_firewall():
    current_os = platform.system().lower()
    if 'linux' in current_os:
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
            if "Status: active" in res.stdout:
                return {"status": "PASS", "details": "UFW Firewall aktif dan mengisolasi port inbound."}
        except Exception:
            pass
        try:
            res = subprocess.run(["iptables", "-S"], capture_output=True, text=True, timeout=3)
            if res.returncode != 0:
                return {"status": "WARNING", "details": "Tidak dapat membaca aturan iptables (izin tidak cukup)."}
            lines = [l.strip() for l in (res.stdout or '').splitlines() if l.strip()]
            has_filter_rules = any(l.startswith('-A ') or l.startswith('-N ') for l in lines)
            has_restrictive_policy = any(
                l.startswith('-P ') and (' DROP' in l or ' REJECT' in l) for l in lines
            )
            if has_filter_rules or has_restrictive_policy:
                return {"status": "PASS", "details": "Aturan filtering iptables terdeteksi aktif."}
        except Exception:
            pass
        return {"status": "FAIL", "details": "Firewall lokal (UFW/Iptables) dinonaktifkan atau belum terkonfigurasi."}
    elif 'windows' in current_os:
        try:
            res = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=4)
            states = [
                line.split()[-1].upper()
                for line in (res.stdout or '').splitlines()
                if line.strip().lower().startswith('state') and len(line.split()) >= 2
            ]
            if res.returncode != 0 or not states:
                return {"status": "WARNING", "details": "Tidak dapat membaca status seluruh profil Windows Firewall."}
            if all(state == 'ON' for state in states):
                return {"status": "PASS", "details": "Windows Defender Firewall aktif di seluruh profil."}
            return {"status": "FAIL", "details": "Windows Defender Firewall mati pada satu atau lebih profil jaringan."}
        except Exception:
            return {"status": "WARNING", "details": "Izin tidak cukup untuk membaca konfigurasi Windows Firewall."}
    return {"status": "WARNING", "details": f"OS {platform.system()} memerlukan modul verifikasi manual."}

def audit_access_control():
    current_os = platform.system().lower()
    findings = []
    if 'linux' in current_os:
        # Baca konfigurasi efektif (sshd -T) termasuk Include sshd_config.d/*.
        value, source = _sshd_effective_value()
        if value in ('no', 'prohibit-password'):
            ssh_status = "PASS"
            ssh_details = "Root login langsung via SSH dibatasi (nilai efektif PermitRootLogin=%s, sumber: %s)." % (value, source)
        elif value is None:
            ssh_status = "WARNING"
            ssh_details = "PermitRootLogin tidak dapat diverifikasi otomatis (sshd -T dan config tidak terbaca)."
        else:
            ssh_status = "FAIL"
            ssh_details = "PermitRootLogin efektif '%s' (sumber: %s) — memungkinkan brute-force root." % (value, source)

        findings.append({
            "parameter": "SSH Root Login & Auth",
            "category": "Access Control",
            "cis_id": "CIS 5.2 SSH Server (mapped heuristic) / DISA STIG V-214878",
            "status": ssh_status,
            "details": ssh_details
        })
    elif 'windows' in current_os:
        try:
            res = subprocess.run(["net", "user", "Guest"], capture_output=True, text=True, timeout=3)
            if "Account active               No" in res.stdout or "Akun aktif                   Tidak" in res.stdout:
                guest_status = "PASS"
                details = "Akun bawaan Guest telah dinonaktifkan sesuai STIG."
            else:
                guest_status = "FAIL"
                details = "Akun Guest terdeteksi AKTIF di sistem operasi."
        except Exception:
            guest_status = "WARNING"
            details = "Perlu hak akses administrator untuk query net user Guest."
            
        findings.append({
            "parameter": "Guest Account Lockdown",
            "category": "Access Control",
            "cis_id": "DISA STIG WN11-00-000010",
            "status": guest_status,
            "details": details
        })
    return findings

def audit_endpoint_protection():
    current_os = platform.system().lower()
    if 'linux' in current_os:
        usb_blocked = False
        candidates = [
            "/etc/modprobe.d/blacklist.conf",
            "/etc/modprobe.d/storage.conf",
            _USB_MODPROBE_PATH,
        ]
        try:
            import glob as _glob
            candidates.extend(_glob.glob("/etc/modprobe.d/*.conf"))
        except Exception:
            pass
        for _p in dict.fromkeys(candidates):
            if not _p or not os.path.exists(_p):
                continue
            try:
                with open(_p, "r", errors="ignore") as _f:
                    _content = _f.read()
                if "install usb-storage /bin/true" in _content or "blacklist usb-storage" in _content:
                    usb_blocked = True
                    break
            except Exception:
                pass
        return {
            "parameter": "USB Mass Storage Restriction",
            "category": "Endpoint Protection",
            "cis_id": "CIS 1.1.23 / DISA STIG V-214840",
            "status": "PASS" if usb_blocked else "WARNING",
            "details": "Driver modul USB mass storage dibatasi untuk proteksi data taktis." if usb_blocked else "USB Mass Storage tidak dibatasi (potensi eksfiltrasi data via removable media)."
        }
    elif 'windows' in current_os:
        # Satu sumber pembacaan dengan langkah remediasi (usb-storage-block),
        # supaya hasil audit ulang tidak berbeda dari pre-state/verify.
        st = _win_usbstor_state()
        start = st.get("start")
        if start is not None:
            blocked = start == 4
            return {
                "parameter": "USB Storage Device Control",
                "category": "Endpoint Protection",
                "cis_id": "DISA STIG WN11-CC-000180",
                "status": "PASS" if blocked else "WARNING",
                "details": "Driver USBSTOR dinonaktifkan via registry (Start=4)." if blocked else "USB Mass Storage masih aktif (Start!=4)."
            }
        return {
            "parameter": "USB Storage Device Control",
            "category": "Endpoint Protection",
            "cis_id": "DISA STIG WN11-CC-000180",
            "status": "WARNING",
            "details": "Kunci registry USBSTOR tidak terbaca; verifikasi manual diperlukan."
        }
    return {
        "parameter": "Peripheral Storage Isolation",
        "category": "Endpoint Protection",
        "cis_id": "CIS 1.1",
        "status": "WARNING",
        "details": "OS tidak didukung untuk deteksi otomatis periferal (perlu verifikasi manual)."
    }

def audit_system_logging():
    current_os = platform.system().lower()
    if 'linux' in current_os:
        is_wsl = False
        try:
            if os.path.exists('/proc/version'):
                with open('/proc/version', 'r') as f:
                    v = f.read().lower()
                    if 'microsoft' in v or 'wsl' in v:
                        is_wsl = True
        except Exception:
            pass

        try:
            res = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True, timeout=3)
            is_active = res.stdout.strip() == "active"
            if is_active:
                return {
                    "parameter": "Auditd Daemon Security Logging",
                    "category": "System Logging",
                    "cis_id": "CIS 4.1.1.1 / DISA STIG V-214875",
                    "status": "PASS",
                    "details": "Service auditd aktif merekam security audit kernel."
                }
            elif is_wsl:
                return {
                    "parameter": "Auditd Daemon Security Logging",
                    "category": "System Logging",
                    "cis_id": "CIS 4.1.1.1 / DISA STIG V-214875",
                    "status": "N/A",
                    "details": "N/A di WSL: auditd tidak berjalan by default; kontrol ini hanya berlaku di Linux baremetal."
                }
            else:
                return {
                    "parameter": "Auditd Daemon Security Logging",
                    "category": "System Logging",
                    "cis_id": "CIS 4.1.1.1 / DISA STIG V-214875",
                    "status": "FAIL",
                    "details": "Service auditd TIDAK aktif! Aktivitas eskalasi hak istimewa tidak tercatat."
                }
        except Exception:
            if is_wsl:
                return {
                    "parameter": "Auditd Daemon Security Logging",
                    "category": "System Logging",
                    "cis_id": "CIS 4.1.1.1 / DISA STIG V-214875",
                    "status": "N/A",
                    "details": "N/A di WSL: auditd tidak berjalan by default; kontrol ini hanya berlaku di Linux baremetal."
                }
            return {
                "parameter": "Auditd Daemon Security Logging",
                "category": "System Logging",
                "cis_id": "CIS 4.1.1.1",
                "status": "WARNING",
                "details": "Tidak dapat memeriksa auditd (systemctl tidak tersedia di container/WSL)."
            }
    elif 'windows' in current_os:
        ev_status = "WARNING"
        ev_details = "Query Windows Event Log memerlukan hak akses administrator."
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-WinEvent -LogName Security -MaxEvents 1"], capture_output=True, text=True, timeout=4)
            if res.returncode == 0:
                ev_status = "PASS"
                ev_details = "Windows Event Log Security dapat diakses dan berjalan normal."
            else:
                ev_status = "WARNING"
                stderr = (res.stderr or "").lower()
                if "access" in stderr or "akses" in stderr:
                    ev_details = "Event Log Security butuh hak Administrator untuk dibaca (WARNING, bukan FAIL)."
                else:
                    ev_details = "Windows Event Log Security tidak dapat di-query; verifikasi manual."
        except Exception:
            ev_status = "WARNING"
            ev_details = "Query Windows Event Log memerlukan hak akses administrator."
        return {
            "parameter": "Windows Event Log & Auditing",
            "category": "System Logging",
            "cis_id": "DISA STIG WN11-AU-000050",
            "status": ev_status,
            "details": ev_details
        }
    return {
        "parameter": "Central Security Event Logging",
        "category": "System Logging",
        "cis_id": "CIS 4.1",
        "status": "WARNING",
        "details": "OS tidak didukung untuk deteksi otomatis logging (perlu verifikasi manual)."
    }

# ==============================================================================
# MODULE 4: HARDENING BASELINE TAMBAHAN (Windows 11 / CIS / STIG)
# ==============================================================================
# Semua pembacaan read-only. Nilai tidak terbaca → WARNING (bukan FAIL palsu),
# kecuali konfigurasi terbaca dan jelas melanggar.
_WIN_SMB_SRV = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
_WIN_DEFENDER_RTP = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
_WIN_DNS_POLICY = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
_WIN_EXPLORER_POLICY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

def _reg_dword(path, name):
    rc, out = _run_no_shell(["reg", "query", path, "/v", name], 5)
    if rc != 0:
        return None
    m = re.search(re.escape(name) + r"\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", out or "")
    return int(m.group(1), 0) if m else None

def _reg_string(path, name):
    rc, out = _run_no_shell(["reg", "query", path, "/v", name], 5)
    if rc != 0:
        return None
    m = re.search(re.escape(name) + r"\s+REG_\w+\s+(.+)", out or "")
    return m.group(1).strip() if m else None

def _win_service_state(name):
    rc, out = _run_no_shell(["sc", "qc", name], 5)
    if rc != 0:
        return None
    low = (out or "").upper()
    if "DISABLED" in low:
        return "disabled"
    return "configured"

def _net_accounts_value(label_en, label_id):
    rc, out = _run_no_shell(["net", "accounts"], 5)
    if rc != 0:
        return None
    for line in (out or "").splitlines():
        low = line.lower()
        if label_en.lower() in low or label_id.lower() in low:
            nums = re.findall(r"-?\d+", line.replace(":", " "))
            # "Never"/"Tidak pernah" → 0, jangan dianggap tidak terbaca.
            return int(nums[-1]) if nums else 0
    return None

def audit_windows_hardening():
    findings = []
    def add(parameter, cis, status, details):
        findings.append({
            "parameter": parameter, "category": "Access Control",
            "cis_id": cis, "status": status, "details": details
        })

    lua = _reg_dword(_WIN_UAC_KEY if "_WIN_UAC_KEY" in globals() else r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    add("User Account Control (UAC) Enforcement", "DISA STIG WN11-SO-000250",
        "WARNING" if lua is None else ("PASS" if lua == 1 else "FAIL"),
        "UAC tidak terbaca." if lua is None else ("UAC aktif (EnableLUA=1)." if lua == 1 else "UAC DINONAKTIFKAN (EnableLUA=0)."))

    nla = _reg_dword(r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    add("RDP Network Level Authentication (NLA)", "DISA STIG WN11-CC-000040",
        "WARNING" if nla is None else ("PASS" if nla == 1 else "FAIL"),
        "Status NLA tidak terbaca." if nla is None else ("NLA wajib (UserAuthentication=1)." if nla == 1 else "NLA tidak diwajibkan pada RDP."))

    smb1 = _reg_dword(_WIN_SMB_SRV, "SMB1")
    add("SMBv1 Protocol", "CIS 2.3.9 / DISA STIG WN11-00-000165",
        "PASS" if smb1 in (None, 0) else "FAIL",
        "SMB1 tidak diset (default modern nonaktif)." if smb1 is None else ("SMBv1 nonaktif." if smb1 == 0 else "SMBv1 AKTIF."))

    signing = _reg_dword(_WIN_SMB_SRV, "RequireSecuritySignature")
    add("SMB Signing Required", "CIS 2.3.8 / DISA STIG WN11-00-000170",
        "WARNING" if signing is None else ("PASS" if signing == 1 else "FAIL"),
        "Nilai SMB signing tidak terbaca." if signing is None else ("SMB signing diwajibkan." if signing == 1 else "SMB signing tidak diwajibkan."))

    rtp = _reg_dword(_WIN_DEFENDER_RTP, "DisableRealtimeMonitoring")
    add("Microsoft Defender Real-Time Protection", "DISA STIG WN11-00-000045",
        "PASS" if rtp in (None, 0) else "FAIL",
        "Real-time protection aktif (kunci tidak dimatikan)." if rtp is None else ("Real-time protection aktif." if rtp == 0 else "Real-time protection DIMATIKAN."))

    llmnr = _reg_dword(_WIN_DNS_POLICY, "EnableMulticast")
    add("LLMNR Resolution Disabled", "CIS 18.5.4.2",
        "WARNING" if llmnr is None else ("PASS" if llmnr == 0 else "FAIL"),
        "Kebijakan LLMNR belum diset." if llmnr is None else ("LLMNR nonaktif." if llmnr == 0 else "LLMNR aktif (rawan poisoning)."))

    autorun = _reg_dword(_WIN_EXPLORER_POLICY, "NoDriveTypeAutoRun")
    add("Autorun/Autoplay Restriction", "CIS 18.9.14.1",
        "WARNING" if autorun is None else ("PASS" if autorun == 255 else "FAIL"),
        "Kebijakan autoplay belum diset." if autorun is None else ("Autoplay dimatikan untuk semua drive." if autorun == 255 else f"Autoplay masih aktif (0x{autorun:X})."))

    policy = _reg_string(r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy")
    add("PowerShell Execution Policy", "DISA STIG WN11-CC-000225",
        "WARNING" if not policy else ("PASS" if policy.lower() in ("remotesigned", "allsigned", "restricted") else "FAIL"),
        "ExecutionPolicy tidak terbaca." if not policy else f"ExecutionPolicy={policy}.")

    winrm = _win_service_state("WinRM")
    add("WinRM Service Exposure", "DISA STIG WN11-CC-000340",
        "WARNING" if winrm is None else ("WARNING" if winrm != "disabled" else "PASS"),
        "Status layanan WinRM tidak terbaca." if winrm is None else ("WinRM aktif (pastikan memang dipakai)." if winrm != "disabled" else "WinRM nonaktif."))

    rc, out = _run_no_shell(["net", "user", "Administrator"], 5)
    disabled = ("Account active               No" in (out or "")) or ("Akun aktif                   Tidak" in (out or ""))
    add("Built-in Administrator Account", "CIS 2.3.1.2",
        "PASS" if disabled else "WARNING",
        "Akun Administrator bawaan nonaktif." if disabled else "Akun Administrator bawaan aktif — tinjau pemakaiannya.")

    minlen = _net_accounts_value("Minimum password length", "Panjang sandi minimum")
    add("Password Policy: Minimum Length", "CIS 1.1.4 / DISA STIG WN11-AC-000005",
        "WARNING" if minlen is None else ("PASS" if minlen >= 14 else "FAIL"),
        "Kebijakan panjang sandi tidak terbaca." if minlen is None else f"Panjang minimum sandi={minlen} (baseline 14).")

    lockout = _net_accounts_value("Lockout threshold", "Ambang penguncian")
    add("Account Lockout Threshold", "CIS 1.2.2 / DISA STIG WN11-AC-000010",
        "WARNING" if lockout is None else ("PASS" if 0 < lockout <= 5 else "FAIL"),
        "Ambang penguncian tidak terbaca." if lockout is None else f"Ambang penguncian={lockout} (baseline 1-5).")

    auditpol = _win_auditpol_state() if "_win_auditpol_state" in globals() else {"readable": False}
    add("Audit Process Creation Policy", "DISA STIG WN11-AU-000050",
        "WARNING" if not auditpol.get("readable") else ("PASS" if auditpol.get("success") else "FAIL"),
        "Kebijakan audit process creation tidak terbaca." if not auditpol.get("readable") else
        ("Process creation diaudit (success)." if auditpol.get("success") else "Process creation TIDAK diaudit."))

    wuauserv = _win_service_state("wuauserv")
    add("Windows Update Service", "CIS 18.9.102.1",
        "WARNING" if wuauserv is None else ("PASS" if wuauserv == "configured" else "FAIL"),
        "Layanan wuauserv tidak terbaca." if wuauserv is None else ("Layanan update aktif." if wuauserv == "configured" else "Layanan update dinonaktifkan."))
    return findings

# ==============================================================================
# MODULE 5: HARDENING BASELINE TAMBAHAN (Linux / CIS / STIG)
# ==============================================================================
def _sshd_effective(name):
    rc, out = _run_no_shell(["sshd", "-T"], 10)
    if rc != 0:
        return None
    for line in (out or "").splitlines():
        if line.lower().startswith(name.lower() + " "):
            return line.split(None, 1)[1].strip().lower().strip('"')
    return None

def _sysctl_value(name):
    text = _read_text("/proc/sys/" + name.replace(".", "/"))
    return (text or "").strip() if text is not None else None

def _mode_of(path):
    try:
        return oct(os.stat(path).st_mode)[-3:]
    except Exception:
        return None

def _login_defs_value(key):
    for line in (_read_text("/etc/login.defs") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() == key:
            return parts[1]
    return None

def audit_linux_hardening():
    findings = []
    def add(parameter, cis, status, details):
        findings.append({
            "parameter": parameter, "category": "Access Control",
            "cis_id": cis, "status": status, "details": details
        })

    pwauth = _sshd_effective("passwordauthentication")
    add("SSH Password Authentication", "CIS 5.2.4 / DISA STIG V-238208",
        "WARNING" if pwauth is None else ("PASS" if pwauth == "no" else "WARNING"),
        "Nilai efektif tidak terbaca." if pwauth is None else f"PasswordAuthentication={pwauth}.")

    empty = _sshd_effective("permitemptypasswords")
    add("SSH Empty Password Rejection", "CIS 5.2.5",
        "WARNING" if empty is None else ("PASS" if empty == "no" else "FAIL"),
        "Nilai efektif tidak terbaca." if empty is None else f"PermitEmptyPasswords={empty}.")

    maxauth = _sshd_effective("maxauthtries")
    add("SSH MaxAuthTries", "CIS 5.2.6",
        "WARNING" if maxauth is None else ("PASS" if maxauth.isdigit() and int(maxauth) <= 4 else "FAIL"),
        "Nilai efektif tidak terbaca." if maxauth is None else f"MaxAuthTries={maxauth} (baseline <=4).")

    umask = _login_defs_value("UMASK")
    add("Default UMASK", "CIS 5.4.3",
        "WARNING" if umask is None else ("PASS" if umask in ("027", "077") else "FAIL"),
        "UMASK tidak ditemukan di login.defs." if umask is None else f"UMASK={umask}.")

    limits = (_read_text("/etc/security/limits.conf") or "") + (_read_text("/etc/security/limits.d/99-pasopati.conf") or "")
    core = re.search(r"^\s*\*\s+(soft|hard)\s+core\s+0", limits, re.MULTILINE)
    add("Core Dump Restriction", "CIS 1.5.1",
        "PASS" if core else "WARNING",
        "Core dump dibatasi 0." if core else "Batas core file tidak ditemukan di limits.conf.")

    aslr = _sysctl_value("kernel.randomize_va_space")
    add("Kernel ASLR", "CIS 1.5.3",
        "WARNING" if aslr is None else ("PASS" if aslr == "2" else "FAIL"),
        "Tidak terbaca." if aslr is None else f"randomize_va_space={aslr} (baseline 2).")

    fwd = _sysctl_value("net.ipv4.ip_forward")
    add("IPv4 Forwarding", "CIS 3.1.1",
        "WARNING" if fwd is None else ("PASS" if fwd == "0" else "WARNING"),
        "Tidak terbaca." if fwd is None else f"ip_forward={fwd} (0 = host, 1 = router).")

    redir = _sysctl_value("net.ipv4.conf.all.accept_redirects")
    add("ICMP Redirect Acceptance", "CIS 3.2.2",
        "WARNING" if redir is None else ("PASS" if redir == "0" else "FAIL"),
        "Tidak terbaca." if redir is None else f"accept_redirects={redir}.")

    for path, cis, label in (
        ("/etc/passwd", "CIS 6.1.2", "max 644"),
        ("/etc/shadow", "CIS 6.1.3", "max 640"),
        ("/etc/group", "CIS 6.1.4", "max 644"),
        ("/etc/crontab", "CIS 5.1.2", "max 600"),
    ):
        mode = _mode_of(path)
        limit = int(label.split()[-1])
        ok = mode is not None and int(mode, 8) <= int(str(limit), 8)
        add(f"{path} Permissions", cis,
            "WARNING" if mode is None else ("PASS" if ok else "FAIL"),
            "Tidak ada / tidak terbaca." if mode is None else f"Mode {mode} (baseline {label}).")

    world = []
    try:
        for name in os.listdir("/etc"):
            full = os.path.join("/etc", name)
            if os.path.isfile(full) and not os.path.islink(full):
                m = os.stat(full).st_mode
                if m & 0o002:
                    world.append(name)
    except Exception:
        pass
    add("World-Writable Files in /etc", "CIS 6.1.10",
        "PASS" if not world else "FAIL",
        "Tidak ada berkas world-writable di /etc." if not world else f"World-writable: {', '.join(sorted(world)[:8])}.")

    timesync = None
    for svc in ("systemd-timesyncd", "chronyd", "ntp"):
        rc, out = _run_no_shell(["systemctl", "is-active", svc], 5)
        if (out or "").strip() == "active":
            timesync = svc
            break
    add("Time Synchronization Service", "CIS 2.2.1.1",
        "PASS" if timesync else "WARNING",
        f"Layanan sinkronisasi waktu aktif ({timesync})." if timesync else "Tidak ada layanan sinkronisasi waktu aktif.")

    aide = shutil.which("aide")
    add("File Integrity Monitoring (AIDE)", "CIS 1.3.1",
        "PASS" if aide else "WARNING",
        "AIDE terpasang." if aide else "AIDE tidak terpasang (verifikasi manual).")

    rules = "/etc/audit/rules.d/audit.rules"
    has_rules = bool((_read_text(rules) or "").strip())
    add("Auditd Rules Present", "CIS 4.1.2",
        "PASS" if has_rules else "WARNING",
        "Berkas aturan audit tersedia." if has_rules else "Aturan auditd tidak ditemukan.")

    pwq = None
    for pam in ("/etc/security/pwquality.conf", "/etc/pam.d/common-password"):
        text = _read_text(pam) or ""
        m = re.search(r"minlen\s*=?\s*(\d+)", text)
        if m:
            pwq = int(m.group(1))
            break
    add("PAM Password Quality (minlen)", "CIS 5.4.1",
        "WARNING" if pwq is None else ("PASS" if pwq >= 14 else "FAIL"),
        "minlen tidak ditemukan." if pwq is None else f"minlen={pwq} (baseline 14).")

    sudo_ts = None
    text = _read_text("/etc/sudoers") or ""
    m = re.search(r"timestamp_timeout\s*=\s*(\d+)", text)
    if m:
        sudo_ts = int(m.group(1))
    add("Sudo Timestamp Timeout", "CIS 5.3.2",
        "WARNING" if sudo_ts is None else ("PASS" if 0 < sudo_ts <= 15 else "FAIL"),
        "timestamp_timeout tidak diset (default 5 menit)." if sudo_ts is None else f"timestamp_timeout={sudo_ts}.")

    journal = "/var/log/journal"
    add("Journald Persistent Storage", "CIS 4.2.1.1",
        "PASS" if os.path.isdir(journal) else "WARNING",
        "Journal persisten aktif." if os.path.isdir(journal) else "Journal belum persisten (log hilang saat reboot).")
    return findings

# ==============================================================================
# MODULE 6: PROFIL KONTROL DEKLARATIF
# ==============================================================================# Profil adalah dokumen YAML (isinya JSON — JSON adalah subset YAML, jadi tidak
# butuh dependensi parser). Satu kontrol = satu objek dengan `check` bertipe.
# Tipe check: registry, command, sysctl, file_mode, file_content, service,
# exists, sshd. `na_if`: wsl | missing:<path> | program_missing:<cmd>.
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_PROFILE = "standard"
_PROFILE_CACHE = {}

def _is_wsl():
    try:
        text = (_read_text("/proc/version") or "").lower()
        return "microsoft" in text or "wsl" in text
    except Exception:
        return False

def _load_profile(name):
    if name in _PROFILE_CACHE:
        return _PROFILE_CACHE[name]
    path = os.path.join(ROOT_DIR, "profiles", f"{name}.yaml")
    controls = []
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("controls"), list):
                controls = [c for c in data["controls"] if isinstance(c, dict) and c.get("parameter")]
        except Exception as exc:
            print(f"[!] Profil {path} gagal dibaca: {exc}")
    _PROFILE_CACHE[name] = controls
    return controls

def _profile_na(cond):
    if not cond:
        return False
    kind, _, arg = str(cond).partition(":")
    if kind == "wsl":
        return _is_wsl()
    if kind == "missing":
        return not os.path.exists(arg)
    if kind == "program_missing":
        return shutil.which(arg) is None
    return False

def _eval_check(check):
    """Kembalikan (ok, details). Exception → (None, pesan)."""
    ctype = check.get("type")
    if ctype == "registry":
        got = _reg_dword(check["path"], check["name"]) if check.get("dword") else _reg_string(check["path"], check["name"])
        if got is None:
            return None, "nilai registry tidak terbaca/tidak ada"
        expect = check.get("expect")
        expected = expect if isinstance(expect, list) else [expect]
        return got in expected, f"nilai={got!r} (harap {expected!r})"
    if ctype == "command":
        rc, out = _run_no_shell([str(x) for x in check["argv"]], int(check.get("timeout", 10)))
        text = (out or "").strip()
        if check.get("min") is not None or check.get("max") is not None:
            numbers = re.findall(r"-?\d+", text)
            if not numbers:
                return None, "angka tidak ditemukan pada keluaran"
            value = int(numbers[-1] if check.get("last") else numbers[0])
            low = check.get("min")
            high = check.get("max")
            ok = (low is None or value >= int(low)) and (high is None or value <= int(high))
            return ok, f"nilai={value} (rentang {low}..{high})"
        if check.get("output"):
            hit = re.search(check["output"], text, re.IGNORECASE | re.MULTILINE) is not None
            if check.get("mode") == "nomatch":
                hit = not hit
            return hit, (text[:180] or f"exit {rc}")
        return rc == int(check.get("expect_exit", 0)), (text[:180] or f"exit {rc}")
    if ctype == "sysctl":
        got = _sysctl_value(check["path"])
        if got is None:
            return None, "tidak terbaca"
        expect = check.get("expect")
        expected = expect if isinstance(expect, list) else [expect]
        return str(got) in [str(x) for x in expected], f"nilai={got} (harap {expected})"
    if ctype == "file_mode":
        mode = _mode_of(check["path"])
        if mode is None:
            return None, "berkas tidak ada"
        return int(mode, 8) <= int(str(check["max"]), 8), f"mode {mode} (maks {check['max']})"
    if ctype == "file_content":
        text = _read_text(check["path"])
        if text is None:
            return None, "berkas tidak terbaca"
        problems = []
        for pattern in check.get("require", []):
            if not re.search(pattern, text, re.MULTILINE):
                problems.append(f"tidak ada /{pattern}/")
        for pattern in check.get("forbid", []):
            if re.search(pattern, text, re.MULTILINE):
                problems.append(f"masih ada /{pattern}/")
        return not problems, ("; ".join(problems) or "sesuai")
    if ctype == "service":
        expect = check.get("expect")
        if platform.system().lower() == "windows":
            rc, out = _run_no_shell(["sc", "qc", str(check["name"])], 5)
            if rc != 0:
                return None, "layanan tidak ada"
            disabled = "DISABLED" in (out or "").upper()
            return (expect == "disabled") == disabled, ("disabled" if disabled else "configured")
        rc, out = _run_no_shell(["systemctl", "is-active", str(check["name"])], 5)
        active = (out or "").strip() == "active"
        enabled_rc, _ = _run_no_shell(["systemctl", "is-enabled", str(check["name"])], 5)
        if expect == "running":
            return active, "active" if active else "inactive"
        if expect == "stopped":
            return not active, "active" if active else "inactive"
        if expect == "disabled":
            return not active and enabled_rc != 0, f"active={active} enabled_rc={enabled_rc}"
        return active and enabled_rc == 0, f"active={active} enabled_rc={enabled_rc}"
    if ctype == "exists":
        return os.path.exists(check["path"]) == bool(check.get("want", True)), check["path"]
    if ctype == "sshd":
        got = _sshd_effective(str(check["directive"]))
        if got is None:
            return None, "nilai efektif tidak terbaca"
        return got == str(check.get("expect")).lower(), f"{check['directive']}={got}"
    return None, f"tipe check tidak dikenal: {ctype}"

def audit_profile(profile_name):
    if not profile_name or profile_name == "none":
        return []
    os_name = "windows" if "windows" in platform.system().lower() else "linux"
    findings = []
    for control in _load_profile(os_name):
        if _profile_na(control.get("na_if")):
            findings.append({
                "parameter": control["parameter"],
                "category": control.get("category", "Hardening Baseline"),
                "cis_id": control.get("cis_id", ""),
                "status": "N/A",
                "details": f"N/A: {control.get('na_reason', control.get('na_if'))}"
            })
            continue
        try:
            ok, detail = _eval_check(control.get("check") or {})
        except Exception as exc:
            ok, detail = None, f"gagal dievaluasi: {exc}"
        if ok is None:
            status = "WARNING"
        elif ok:
            status = "PASS"
        else:
            status = "FAIL" if str(control.get("severity", "medium")).lower() in ("high", "medium") else "WARNING"
        findings.append({
            "parameter": control["parameter"],
            "category": control.get("category", "Hardening Baseline"),
            "cis_id": " / ".join(filter(None, [control.get("cis_id"), control.get("stig")])),
            "status": status,
            "details": f"{detail}. {control.get('mitigation', '')}".strip()
        })
    return findings



# ==============================================================================
# MAIN FULL AUDIT ORCHESTRATOR
# ==============================================================================
def run_full_audit(unit_name="PASOPATI-LOCAL-NODE"):
    print(f"[*] Menjalankan audit taktis PASOPATI v2.6 pada {unit_name}...")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_ports = scan_listening_ports()
    
    fw = audit_firewall()
    ac = audit_access_control()
    ep = audit_endpoint_protection()
    lg = audit_system_logging()
    kb = audit_kernel_boot_integrity()
    cs = audit_crypto_storage()
    pb = audit_privilege_boundaries()
    extra = audit_windows_hardening() if 'windows' in platform.system().lower() else audit_linux_hardening()
    
    crit_open = [p for p in open_ports if p.get('is_critical')]
    exposed = []
    blocked_now = []
    for p in crit_open:
        if _port_effectively_blocked(p['port']):
            blocked_now.append(p['port'])
        else:
            exposed.append(p)
    if any(p['port'] in [4444, 23] for p in exposed):
        port_status = "FAIL"
        port_details = f"Ditemukan port ancaman darurat terekspos: {[p['port'] for p in exposed]}!"
    elif exposed:
        port_status = "WARNING"
        desc_list = [f"Port {p['port']} ({p.get('service', 'Service')})" for p in exposed]
        port_details = f"Layanan kritis/obfuscated terekspos: {', '.join(desc_list)}. Wajib diisolasi via whitelist firewall."
    else:
        port_status = "PASS"
        if blocked_now:
            port_details = f"Tidak ada port kritis terekspos (diblokir firewall: {sorted(set(blocked_now))})."
        else:
            port_details = "Tidak ditemukan port liar berisiko tinggi terbuka secara publik."

    audit_matrix = [
        {
            "parameter": "Network & Dangerous Ports Filtering",
            "category": "Network & Port",
            "cis_id": "CIS 3.4 / DISA STIG NET-001",
            "status": port_status,
            "details": port_details
        },
        {
            "parameter": "Host-Based Local Firewall Active",
            "category": "Endpoint Protection",
            "cis_id": "CIS 3.5.1 / DISA STIG V-214870",
            "status": fw["status"],
            "details": fw["details"]
        }
    ]
    
    audit_matrix.extend(ac)
    audit_matrix.append(ep)
    audit_matrix.append(lg)
    audit_matrix.extend(kb)
    audit_matrix.extend(cs)
    audit_matrix.extend(pb)
    audit_matrix.extend(extra)
    audit_matrix.extend(audit_profile(AUDIT_PROFILE))
    
    for item in audit_matrix:
        detail_val = item.get("details") or item.get("detail", "")
        item["detail"] = detail_val
        item["details"] = detail_val

    total_items = len(audit_matrix)
    pass_items = sum(1 for item in audit_matrix if item["status"] == "PASS")
    warn_items = sum(1 for item in audit_matrix if item["status"] == "WARNING")
    fail_items = sum(1 for item in audit_matrix if item["status"] == "FAIL")
    na_items = sum(1 for item in audit_matrix if str(item.get("status", "")).upper() in ("N/A", "SKIPPED"))
    applicable_items = max(total_items - na_items, 1)
    raw_score = int(((pass_items * 100) + (warn_items * 50)) / applicable_items)
    
    audit_result = {
        "metadata": {
            "scanner": "PASOPATI Autonomous Deep Agent v2.7",
            "timestamp": timestamp,
            "tactical_unit": unit_name,
            "machine_id": get_machine_id(),
            "standard_baseline": "CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443 Deep Baseline",
            "audit_version": "2.7",
            "profile": {
                "name": AUDIT_PROFILE,
                "checks_total": total_items,
                "applicable": applicable_items,
                "not_applicable": na_items
            },
            "quarantine_status": "NORMAL"
        },
        "device_info": {
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "platform_type": "Linux Server" if "linux" in platform.system().lower() else "Windows Workstation",
            "primary_ip": get_primary_ip(),
            "mac_address": get_mac_address(),
            "active_user": get_current_user(),
            "listening_ports_count": len(open_ports),
            "critical_ports_detected": len(crit_open),
            "ports_list": [p['port'] for p in open_ports]
        },
        "scoring": {
            "cyber_readiness_score": raw_score,
            "passed_checks": pass_items,
            "warning_checks": warn_items,
            "failed_checks": fail_items,
            "total_checks": total_items,
            "applicable_checks": applicable_items,
            "na_checks": na_items
        },
        "compliance_matrix": audit_matrix
    }
    
    return audit_result

# ==============================================================================
# CRYPTOGRAPHIC TELEMETRY PUSH (HMAC-SHA256 SIGNED)
# ==============================================================================
def push_telemetry(payload, url, secret_key=None):
    if not secret_key:
        print("[!] Telemetri tidak terkirim: kunci HMAC (--hmac-key / env HMAC_SECRET) tidak diset.")
        return False
    print(f"[*] Menghubungi endpoint telemetri aman Puskodal: {url} ...")
    try:
        # ensure_ascii=False keeps non-ASCII characters as raw UTF-8, matching
        # exactly the bytes that are transmitted and signed (no \uXXXX drift).
        data_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

        # Calculate HMAC-SHA256 signature over the exact transmitted bytes
        signature = hmac.new(secret_key.encode("utf-8"), data_bytes, hashlib.sha256).hexdigest()
        req_timestamp = str(int(time.time()))
        
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PASOPATI-Agent/2.6",
                "X-Pasopati-Signature": signature,
                "X-Pasopati-Timestamp": req_timestamp,
                "X-Pasopati-Unit": payload.get("metadata", {}).get("tactical_unit", "UNKNOWN")
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            status_code = response.getcode()
            resp_body = response.read().decode("utf-8", errors="ignore")
            if 200 <= status_code < 300:
                print(f"[+] [SUKSES TELEMETRI] Berhasil diunggah ke Puskodal dengan tanda tangan kriptografi (HTTP {status_code})!")
                return True
            else:
                print(f"[!] Server merespons HTTP {status_code}: {resp_body}")
                return False
    except urllib.error.HTTPError as e:
        print(f"[!] Gagal mengirim telemetri (HTTP Error {e.code}): {e.reason}")
        return False
    except Exception as e:
        print(f"[!] Kesalahan pengiriman telemetri: {str(e)}. Hasil audit tetap aman tersimpan di lokal.")
        return False

# ==============================================================================
# REAL AGENT REMEDIATION — Mode remediate terkendali persetujuan
# ==============================================================================
# Prinsip (lihat docs/REAL-AGENT-REMEDIATION-DESIGN.md):
#  - Default read-only: agent tanpa token persetujuan TIDAK mengubah apa pun.
#  - Hanya alias tindakan dari ALLOWLIST_ANALISA yang diperbolehkan.
#  - Setiap perubahan: baca pre-state → backup → apply → verifikasi (baca ulang).
#  - Rollback = restore dari snapshot backup, bukan mengubah teks.
#  - Stop-on-failure; evidence (exit code + hash keluaran) dikirim ke server.
# ==============================================================================

import hashlib as _hashlib
import re as _re

# Direktori backup lokal untuk snapshot pra-perubahan di host.
def _remediation_backup_dir():
    root = os.path.join(os.path.expanduser("~"), ".pasopati")
    path = os.path.join(root, "backups")
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    except Exception:
        pass
    # os.chmod 0o700 tidak membentuk ACL di Windows; pastikan pemilik sesi
    # benar-benar bisa membaca file kunci BitLocker setelah proses elevated.
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        if user:
            for d in (root, path):
                try:
                    _run_no_shell(["icacls", d, "/grant", user + ":(OI)(CI)F", "/C", "/Q"], 15)
                except Exception:
                    pass
    return path

def _comparable_state(state):
    """Buang field berisik (raw/output/error) agar pre-state bisa dibandingkan."""
    if not isinstance(state, dict):
        return state
    return {k: v for k, v in state.items() if k not in ("raw", "output", "error")}

def _hash_state(value):
    return "sha256:" + _hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()

def _backup_snapshot(plan_id, alias, pre_state):
    d = _remediation_backup_dir()
    os.makedirs(d, exist_ok=True)
    unique = uuid.uuid4().hex[:8]
    path = os.path.join(d, f"{plan_id}_{alias}_{int(time.time())}_{unique}.json")
    with open(path, "w") as f:
        json.dump({"planId": plan_id, "alias": alias, "at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"), "preState": pre_state}, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return path

def _restore_from_snapshot(path):
    with open(path, "r") as f:
        meta = json.load(f)
    return meta.get("preState")

def _run_no_shell(argv, timeout=10):
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return res.returncode, (res.stdout or "") + (res.stderr or "")
    except Exception as e:
        return -1, str(e)

# --- Preflight jalur akses: cegah operator terkunci di luar host ---
_ACCESS_RISK_NOTES = {
    "ports-block-windows": "memblokir RDP 3389 inbound — sesi remote BARU tidak bisa masuk sampai rule dihapus",
    "ports-block-linux": "memblokir port 21/23/445/4444 via iptables (22 tetap terbuka)",
    "ssh-disable-root": "root tidak bisa login SSH langsung pada sesi baru",
    "fw-enable-ufw": "UFW default deny incoming; port 22 diizinkan lebih dulu, tetap sediakan konsol",
    "fw-enable-defender": "Windows Firewall dinyalakan di semua profil; sesi remote bisa terputus",
}

def _session_is_remote():
    if platform.system().lower() == "windows":
        return str(os.environ.get("SESSIONNAME", "")).upper().startswith("RDP")
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))

def _access_preflight(items):
    """Kembalikan (blocking, catatan). blocking=True bila sesi ini remote dan plan
    memblokir kanal yang sedang dipakai, sehingga eksekusi butuh konfirmasi."""
    notes = []
    blocking = False
    aliases = {i.get("alias") for i in items if isinstance(i, dict)}
    remote = _session_is_remote()
    for alias in sorted(a for a in aliases if a in _ACCESS_RISK_NOTES):
        notes.append(f"{alias}: {_ACCESS_RISK_NOTES[alias]}")
        if remote and alias in ("ports-block-windows", "fw-enable-defender"):
            blocking = True
    if blocking:
        notes.append("sesi ini terdeteksi REMOTE — siapkan konsol/KVM atau rollback sebelum lanjut")
    return blocking, notes

# --- Dead-man timer: rollback otomatis bila operator terputus dan tak konfirmasi ---
# Dijalankan sebagai proses/jadwal terpisah supaya tetap hidup walau sesi SSH/RDP mati.
DEFAULT_DEADMAN_SECONDS = 600
DEADMAN_ENV = "PASOPATI_DEADMAN_SECONDS"

def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except Exception:
        return default

def _deadman_confirm_path(plan_id):
    return os.path.join(_remediation_backup_dir(), f"{plan_id}.confirmed")

def _deadman_task_name(plan_id):
    return "PASOPATI-DEADMAN-" + str(plan_id)[:60]

def _deadman_shell_script(seconds, confirm, plan_id, backup_dir):
    python = os.path.abspath(sys.executable or "python3")
    entry = os.path.abspath(sys.argv[0] or "pasopati_remediate.py")
    return (
        "#!/bin/sh\n"
        f"# Watchdog PASOPATI: rollback otomatis bila tak dikonfirmasi dalam {int(seconds)} detik.\n"
        f"sleep {int(seconds)}\n"
        f'if [ -f "{confirm}" ]; then rm -f "{confirm}"; exit 0; fi\n'
        f'exec "{python}" "{entry}" --deadman-rollback "{plan_id}" "{backup_dir}"\n'
    )

def _deadman_ps_script(seconds, confirm, plan_id, backup_dir, log_path):
    python = os.path.abspath(sys.executable or "python")
    entry = os.path.abspath(sys.argv[0] or "pasopati_remediate.py")
    def q(value):
        return "'" + str(value).replace("'", "''") + "'"
    return (
        f"Start-Sleep -Seconds {int(seconds)}\n"
        f"if (Test-Path -LiteralPath {q(confirm)}) {{ Remove-Item -LiteralPath {q(confirm)} -Force; exit 0 }}\n"
        f"& {q(python)} {q(entry)} --deadman-rollback {q(plan_id)} {q(backup_dir)} *>> {q(log_path)}\n"
    )

def _deadman_arm(plan_id, seconds):
    """Pasang watchdog. Kembalikan deskripsi target (path/task) untuk log."""
    if seconds <= 0:
        return ""
    backup_dir = _remediation_backup_dir()
    confirm = _deadman_confirm_path(plan_id)
    try:
        os.remove(confirm)
    except Exception:
        pass
    if platform.system().lower() == "windows":
        ps = os.path.join(backup_dir, f"{plan_id}_deadman.ps1")
        log_path = os.path.join(backup_dir, f"{plan_id}_deadman.log")
        with open(ps, "w") as f:
            f.write(_deadman_ps_script(seconds, confirm, plan_id, backup_dir, log_path))
        target = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
        rc, out = _run_no_shell([
            "schtasks", "/create", "/f", "/tn", _deadman_task_name(plan_id),
            "/sc", "once", "/st", target.strftime("%H:%M"), "/sd", target.strftime("%m/%d/%Y"),
            "/ru", "SYSTEM", "/rl", "HIGHEST",
            "/tr", f'powershell -NoProfile -ExecutionPolicy Bypass -File "{ps}"'
        ], 30)
        if rc != 0:
            raise RuntimeError((out or "").strip()[:200] or "schtasks gagal")
        return "task " + _deadman_task_name(plan_id)
    script = os.path.join(backup_dir, f"{plan_id}_deadman.sh")
    with open(script, "w") as f:
        f.write(_deadman_shell_script(seconds, confirm, plan_id, backup_dir))
    try:
        os.chmod(script, 0o700)
    except Exception:
        pass
    subprocess.Popen(
        ["/bin/sh", script],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return script

def _deadman_disarm(plan_id):
    """Batalkan watchdog (tulis file konfirmasi + hapus task Windows)."""
    try:
        with open(_deadman_confirm_path(plan_id), "w") as f:
            f.write(datetime.datetime.now().isoformat() + "\n")
    except Exception:
        pass
    if platform.system().lower() == "windows":
        _run_no_shell(["schtasks", "/delete", "/f", "/tn", _deadman_task_name(plan_id)], 20)

def run_deadman_rollback(plan_id, backup_dir):
    """Mode watchdog: pulihkan seluruh snapshot plan tanpa server/token."""
    print(f"[DEADMAN] Tidak ada konfirmasi — memulihkan plan {plan_id} dari {backup_dir}")
    snapshots = sorted(glob.glob(os.path.join(backup_dir, f"{plan_id}_*.json")))
    failures = 0
    restored = 0
    for snap in reversed(snapshots):
        try:
            with open(snap, "r") as f:
                meta = json.load(f)
        except Exception as exc:
            print(f"[!] Snapshot tidak terbaca: {snap}: {exc}")
            failures += 1
            continue
        alias = meta.get("alias")
        entry = ALLOWLIST_ANALISA.get(alias) or {}
        if "rollback" not in entry:
            print(f"    lewati {alias} (tanpa handler rollback)")
            continue
        pre_state = meta.get("preState")
        try:
            entry["rollback"](pre_state)
            match = _comparable_state(entry["read"]()) == _comparable_state(pre_state)
        except Exception as exc:
            print(f"    rollback {alias} gagal: {exc}")
            match = False
        restored += 1
        if not match:
            failures += 1
            print(f"    [!] {alias}: state belum kembali ke pre-state")
        else:
            print(f"    [OK] {alias} dipulihkan")
    result = {
        "planId": plan_id,
        "at": datetime.datetime.now().isoformat(timespec="seconds"),
        "snapshots": len(snapshots),
        "restored": restored,
        "failures": failures,
        "status": "ROLLED_BACK" if failures == 0 else "PARTIAL",
    }
    try:
        with open(os.path.join(backup_dir, f"deadman-result-{plan_id}.json"), "w") as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass
    print(f"[DEADMAN] Selesai: {restored} langkah dipulihkan, {failures} gagal.")
    return result

# --- Escrow kunci BitLocker ke server (redundansi selain file lokal) ---
_ESCROW_BASE = ""
_ESCROW_KEY = ""
_ESCROW_DEVICE = ""
# Kredensial host ter-enrol + opsi TLS agent.
_HOST_KEY = ""
_CA_CERT = ""
_INSECURE = False

def _urlopen(req, timeout=8):
    context = None
    if _INSECURE:
        context = ssl._create_unverified_context()
    elif _CA_CERT:
        context = ssl.create_default_context(cafile=_CA_CERT)
    return urllib.request.urlopen(req, timeout=timeout, context=context)

def _auth_headers():
    headers = {}
    if _HOST_KEY:
        headers["X-Pasopati-Host-Key"] = _HOST_KEY
    return headers

def _escrow_push(kind, value):
    if not (_ESCROW_BASE and (_ESCROW_KEY or _HOST_KEY) and value):
        return False
    try:
        body = json.dumps({"deviceId": _ESCROW_DEVICE, "kind": kind, "value": value}).encode("utf-8")
        headers = {"Content-Type": "application/json", **_auth_headers()}
        if _ESCROW_KEY:
            headers["X-Pasopati-API-Key"] = _ESCROW_KEY
        req = urllib.request.Request(_ESCROW_BASE + "/api/escrow", data=body, headers=headers, method="POST")
        with _urlopen(req, 8) as resp:
            return 200 <= resp.getcode() < 300
    except Exception as exc:
        print(f"    [!] Escrow ke server gagal ({kind}): {exc}")
        return False

# --- Persistensi firewall (rule harus bertahan setelah reboot) ---
def _firewall_persist_supported():
    if shutil.which("netfilter-persistent"):
        return True
    return bool(shutil.which("iptables-save")) and os.path.isdir("/etc/iptables")

def _firewall_persist():
    if shutil.which("netfilter-persistent"):
        rc, out = _run_no_shell(["netfilter-persistent", "save"], 20)
        return rc == 0, (out or "").strip()[:200]
    if shutil.which("iptables-save") and os.path.isdir("/etc/iptables"):
        rc, out = _run_no_shell(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"], 20)
        return rc == 0, (out or "").strip()[:200]
    return False, "netfilter-persistent/iptables-save tidak tersedia"

def _firewall_persisted(ports):
    if not ports:
        return True
    text = _read_text("/etc/iptables/rules.v4") or ""
    if not text:
        return False
    return all(f"--dport {p} -j DROP" in text for p in ports)

# --- Windows: Windows Defender Firewall ---
_FW_ON = ("ON", "AKTIF", "AAN")
_FW_OFF = ("OFF", "NONAKTIF", "UIT")
def _win_fw_state():
    rc, out = _run_no_shell(["netsh", "advfirewall", "show", "allprofiles", "state"], 10)
    if rc != 0:
        return {"state": "unknown", "activeCount": 0, "offCount": 0, "raw": out}
    on = off = 0
    for line in (out or "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].upper() in ("STATE", "STATUS"):
            value = parts[-1].upper()
            if value in _FW_ON:
                on += 1
            elif value in _FW_OFF:
                off += 1
    return {"activeCount": on, "offCount": off, "raw": out[:400]}
def _win_fw_apply():
    # `state on` yang menyalakan firewall; `firewallpolicy` hanya mengatur arah default.
    rc, out = _run_no_shell(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], 15)
    if rc == 0:
        _run_no_shell(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], 15)
    return {"exitCode": rc, "output": out}
def _win_fw_verify():
    s = _win_fw_state()
    return s.get("offCount") == 0 and s.get("activeCount", 0) > 0
def _win_fw_rollback(pre):
    # Kembalikan hanya bila sebelumnya memang ada profil yang mati.
    if isinstance(pre, dict) and pre.get("offCount", 0) == 0:
        return {"exitCode": 0, "output": "firewall sudah aktif sebelum remediasi; dibiarkan aktif"}
    rc, out = _run_no_shell(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], 15)
    return {"exitCode": rc, "output": out}

def _win_guest_state():
    rc, out = _run_no_shell(["net", "user", "Guest"], 10)
    active = ("Akun aktif                   Ya" in out) or ("Account active               Yes" in out)
    disabled = ("Account active               No" in out) or ("Akun aktif                   Tidak" in out)
    return {"active": bool(active) and not bool(disabled), "disabled": bool(disabled), "raw": out[:500]}
def _win_guest_apply():
    rc, out = _run_no_shell(["net", "user", "Guest", "/active:no"], 10)
    return {"exitCode": rc, "output": out}
def _win_guest_verify():
    return _win_guest_state().get("disabled") is True
def _win_guest_rollback(pre):
    if isinstance(pre, dict) and pre.get("active") is True:
        rc, out = _run_no_shell(["net", "user", "Guest", "/active:yes"], 10)
        return {"exitCode": rc, "output": out}
    return {"exitCode": 0, "output": "Guest sudah nonaktif sebelum remediasi; dibiarkan nonaktif"}

# --- Windows: registry USBSTOR start=4 (block) / 3 (normal) ---
_USBSTOR_KEY = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR"
def _win_usbstor_state():
    rc, out = _run_no_shell(["reg", "query", _USBSTOR_KEY, "/v", "Start"], 10)
    m = _re.search(r"Start\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", out)
    return {"raw": out[:300], "start": int(m.group(1), 0) if m else None}
def _win_usbstor_apply():
    rc, out = _run_no_shell(["reg", "add", _USBSTOR_KEY, "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"], 10)
    return {"exitCode": rc, "output": out}
def _win_usbstor_restore(pre):
    val = 4 if pre.get("start") == 4 else 3
    rc, out = _run_no_shell(["reg", "add", _USBSTOR_KEY, "/v", "Start", "/t", "REG_DWORD", "/d", str(val), "/f"], 10)
    return {"exitCode": rc, "output": out}
def _win_usbstor_verify():
    return _win_usbstor_state().get("start") == 4

# --- Linux: UFW (default deny + izin SSH sebelum enable agar tidak terkunci) ---
_UFW_SSH_PORT = "22/tcp"
def _linux_ufw_state():
    rc, out = _run_no_shell(["ufw", "status", "verbose"], 5)
    match = re.search(r"Default:\s*(\w+)\s*\(incoming\)", out or "", re.IGNORECASE)
    return {
        "active": "Status: active" in (out or ""),
        "defaultIncoming": match.group(1).lower() if match else None,
        "sshAllowed": (_UFW_SSH_PORT in (out or "")) or ("OpenSSH" in (out or "")),
        "raw": (out or "")[:400],
    }
def _linux_ufw_apply():
    st = _linux_ufw_state()
    errors = []
    if st.get("defaultIncoming") != "deny":
        rc, out = _run_no_shell(["ufw", "default", "deny", "incoming"], 10)
        if rc != 0:
            errors.append("default deny incoming: " + out[:120])
    rc, out = _run_no_shell(["ufw", "default", "allow", "outgoing"], 10)
    if rc != 0:
        errors.append("default allow outgoing: " + out[:120])
    if not st.get("sshAllowed"):
        rc, out = _run_no_shell(["ufw", "allow", _UFW_SSH_PORT], 10)
        if rc != 0:
            errors.append("allow 22/tcp: " + out[:120])
    if not st.get("active"):
        rc, out = _run_no_shell(["ufw", "--force", "enable"], 15)
        if rc != 0:
            errors.append("enable: " + out[:120])
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "UFW aktif: default deny incoming, SSH diizinkan"}
def _linux_ufw_verify():
    st = _linux_ufw_state()
    return st.get("active") is True and st.get("defaultIncoming") == "deny" and st.get("sshAllowed") is True
def _linux_ufw_rollback(pre):
    if not isinstance(pre, dict):
        return {"exitCode": -1, "output": "snapshot UFW tidak tersedia"}
    if pre.get("defaultIncoming"):
        _run_no_shell(["ufw", "default", str(pre["defaultIncoming"]), "incoming"], 10)
    if "sshAllowed" in pre and not pre.get("sshAllowed"):
        _run_no_shell(["ufw", "delete", "allow", _UFW_SSH_PORT], 10)
    if pre.get("active") is True:
        return {"exitCode": 0, "output": "UFW sudah aktif sebelumnya; default/rule dipulihkan, tetap aktif"}
    rc, out = _run_no_shell(["ufw", "--force", "disable"], 15)
    return {"exitCode": rc, "output": out or "UFW dikembalikan ke nonaktif"}

# --- Linux: SSH root login (perhatikan Include sshd_config.d + validasi sshd -t) ---
_SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
_SSHD_INCLUDE_DIR = "/etc/ssh/sshd_config.d"
_SSHD_DROPIN = os.path.join(_SSHD_INCLUDE_DIR, "99-pasopati-root-login.conf")

def _read_text(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return None

def _write_text_atomic(path, text):
    tmp = path + ".pasopati.tmp"
    mode = 0o644
    try:
        mode = os.stat(path).st_mode & 0o777
    except Exception:
        pass
    with open(tmp, "w") as f:
        f.write(text)
    try:
        os.chmod(tmp, mode)
    except Exception:
        pass
    _atomic_replace(tmp, path)

def _sshd_config_files():
    files = []
    if os.path.exists(_SSHD_CONFIG_PATH):
        files.append(_SSHD_CONFIG_PATH)
    if os.path.isdir(_SSHD_INCLUDE_DIR):
        for name in sorted(os.listdir(_SSHD_INCLUDE_DIR)):
            if name.endswith(".conf"):
                files.append(os.path.join(_SSHD_INCLUDE_DIR, name))
    return files

def _sshd_include_active():
    content = _read_text(_SSHD_CONFIG_PATH) or ""
    for line in content.splitlines():
        parts = line.strip().split()
        if parts and parts[0].lower() == "include" and _SSHD_INCLUDE_DIR in " ".join(parts[1:]):
            return True
    return False

def _sshd_main_has_directive():
    content = _read_text(_SSHD_CONFIG_PATH) or ""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.split()[0].lower() == "permitrootlogin":
            return True
    return False

def _sshd_effective_value():
    """Nilai efektif PermitRootLogin: utamakan `sshd -T`, fallback baca config (main + drop-in)."""
    rc, out = _run_no_shell(["sshd", "-T"], 10)
    if rc == 0 and isinstance(out, str):
        for line in out.splitlines():
            if line.lower().startswith("permitrootlogin "):
                return line.split(None, 1)[1].strip().lower().strip('"'), "sshd -T"
    value = None
    for path in _sshd_config_files():
        content = _read_text(path)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and stripped.split()[0].lower() == "permitrootlogin":
                # First-match-wins: jangan lanjut ke file Include bila main sudah menetapkan nilai.
                return (stripped.split(None, 1)[1].strip().lower() if len(stripped.split()) > 1 else value), "config"
    return value, "config"

def _sshd_service_active():
    for service in ("ssh", "sshd"):
        rc, out = _run_no_shell(["systemctl", "is-active", service], 5)
        if rc == 0 or (out or "").strip() == "active":
            return True
    return False

def _sshd_validate():
    rc, out = _run_no_shell(["sshd", "-t"], 10)
    return rc == 0, (out or "")

def _sshd_restart():
    rc, out = _run_no_shell(["systemctl", "restart", "sshd"], 10)
    if rc != 0:
        rc, out2 = _run_no_shell(["systemctl", "restart", "ssh"], 10)
        out = (out or "") + (out2 or "")
    return rc, (out or "")

def _linux_ssh_read_config():
    content = _read_text(_SSHD_CONFIG_PATH)
    return {"exists": os.path.exists(_SSHD_CONFIG_PATH), "content": content}

def _linux_ssh_state():
    value, source = _sshd_effective_value()
    dropin_content = _read_text(_SSHD_DROPIN)
    return {
        "exists": os.path.exists(_SSHD_CONFIG_PATH),
        "content": _read_text(_SSHD_CONFIG_PATH),
        "dropinExists": os.path.exists(_SSHD_DROPIN),
        "dropinContent": dropin_content,
        "effective": value,
        "source": source,
        "active": _sshd_service_active(),
    }

def _linux_ssh_apply():
    st = _linux_ssh_state()
    use_dropin = os.path.isdir(_SSHD_INCLUDE_DIR) and _sshd_include_active() and not _sshd_main_has_directive()
    try:
        if use_dropin:
            _write_text_atomic(_SSHD_DROPIN, "PermitRootLogin no\n")
        else:
            content = st.get("content")
            if content is None:
                return {"exitCode": -1, "output": "sshd_config tidak ditemukan / tidak dapat dibaca"}
            lines = content.splitlines()
            replaced = False
            out_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped and stripped.split() and stripped.split()[0].lower() == "permitrootlogin":
                    out_lines.append("PermitRootLogin no")
                    replaced = True
                elif stripped.startswith("#") and "PermitRootLogin" in stripped:
                    out_lines.append("PermitRootLogin no")
                    replaced = True
                else:
                    out_lines.append(line)
            if not replaced:
                out_lines.append("PermitRootLogin no")
            _write_text_atomic(_SSHD_CONFIG_PATH, "\n".join(out_lines) + "\n")
    except Exception as e:
        return {"exitCode": -1, "output": "gagal menulis konfigurasi SSH: " + str(e)[:300]}

    ok, out = _sshd_validate()
    if not ok:
        # Kembalikan snapshot agar konfigurasi tidak tertinggal rusak.
        _linux_ssh_rollback(st)
        return {"exitCode": -1, "output": "sshd -t menolak konfigurasi; dipulihkan. " + out[:250]}

    rc, out = _sshd_restart()
    target = "drop-in " + _SSHD_DROPIN if use_dropin else _SSHD_CONFIG_PATH
    return {"exitCode": rc, "output": "PermitRootLogin no ditulis ke %s; restart ssh rc=%s %s" % (target, rc, out[:200])}

def _linux_ssh_verify():
    value, _source = _sshd_effective_value()
    return value == "no" and _sshd_service_active() is True

def _linux_ssh_rollback(pre):
    if not isinstance(pre, dict):
        return {"exitCode": -1, "output": "snapshot SSH tidak tersedia untuk rollback"}
    try:
        if pre.get("dropinExists") is False and os.path.exists(_SSHD_DROPIN):
            os.remove(_SSHD_DROPIN)
        elif isinstance(pre.get("dropinContent"), str):
            _write_text_atomic(_SSHD_DROPIN, pre["dropinContent"])
        if isinstance(pre.get("content"), str):
            _write_text_atomic(_SSHD_CONFIG_PATH, pre["content"])
    except Exception as e:
        return {"exitCode": -1, "output": "rollback SSH gagal: " + str(e)[:300]}
    ok, out = _sshd_validate()
    if not ok:
        return {"exitCode": -1, "output": "rollback menulis snapshot tetapi sshd -t gagal: " + out[:200]}
    rc, out = _sshd_restart()
    return {"exitCode": rc, "output": "konfigurasi SSH dipulihkan dari snapshot; restart rc=%s" % rc}

# --- Linux: auditd ---
def _linux_auditd_state():
    rc_a, out_a = _run_no_shell(["systemctl", "is-active", "auditd"], 5)
    rc_e, out_e = _run_no_shell(["systemctl", "is-enabled", "auditd"], 5)
    return {"active": out_a.strip() == "active", "enabled": out_e.strip() == "enabled", "raw": (out_a + out_e)[:300]}
def _linux_auditd_apply():
    rc, out = _run_no_shell(["systemctl", "enable", "--now", "auditd"], 15)
    return {"exitCode": rc, "output": out}
def _linux_auditd_verify():
    return _linux_auditd_state().get("active") is True
def _linux_auditd_rollback(pre):
    # Hanya matikan bila auditd memang mati sebelum remediasi.
    if isinstance(pre, dict) and pre.get("active") is True:
        return {"exitCode": 0, "output": "auditd sudah aktif sebelum remediasi; dibiarkan aktif"}
    rc, out = _run_no_shell(["systemctl", "disable", "--now", "auditd"], 15)
    return {"exitCode": rc, "output": out}

# --- Linux: USB mass storage block (modprobe blacklist) ---
_USB_MODPROBE_PATH = "/etc/modprobe.d/pasopati-usb-lock.conf"
_USB_MODPROBE_CONTENT = "install usb-storage /bin/true\nblacklist usb-storage\n"
def _linux_usb_state():
    if not os.path.exists(_USB_MODPROBE_PATH):
        return {"exists": False, "blocked": False, "content": None}
    try:
        with open(_USB_MODPROBE_PATH, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return {"exists": True, "blocked": False, "content": None, "error": str(e)[:200]}
    return {"exists": True, "blocked": ("install usb-storage /bin/true" in content), "content": content}
def _linux_usb_apply():
    try:
        os.makedirs(os.path.dirname(_USB_MODPROBE_PATH), exist_ok=True)
        with open(_USB_MODPROBE_PATH, "w") as f:
            f.write(_USB_MODPROBE_CONTENT)
    except Exception as e:
        return {"exitCode": -1, "output": "gagal menulis " + _USB_MODPROBE_PATH + ": " + str(e)[:300]}
    return {"exitCode": 0, "output": "usb-storage diblokir via modprobe blacklist"}
def _linux_usb_verify():
    return _linux_usb_state().get("blocked") is True
def _linux_usb_rollback(pre):
    prev = pre.get("content") if isinstance(pre, dict) else None
    try:
        if prev is None:
            if os.path.exists(_USB_MODPROBE_PATH):
                os.remove(_USB_MODPROBE_PATH)
            return {"exitCode": 0, "output": "file modprobe dihapus (kembali ke pre-state tidak ada)"}
        with open(_USB_MODPROBE_PATH, "w") as f:
            f.write(prev)
        return {"exitCode": 0, "output": "file modprobe dipulihkan dari snapshot"}
    except Exception as e:
        return {"exitCode": -1, "output": "rollback usb modprobe gagal: " + str(e)[:300]}

# --- Windows: RDP NLA (UserAuthentication = 1) ---
_WIN_RDP_KEY = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
def _win_rdp_state():
    rc, out = _run_no_shell(["reg", "query", _WIN_RDP_KEY, "/v", "UserAuthentication"], 10)
    m = _re.search(r"UserAuthentication\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", out)
    return {"raw": out[:300], "userAuthentication": int(m.group(1), 0) if m else None}
def _win_rdp_apply():
    rc, out = _run_no_shell(["reg", "add", _WIN_RDP_KEY, "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f"], 10)
    return {"exitCode": rc, "output": out}
def _win_rdp_verify():
    return _win_rdp_state().get("userAuthentication") == 1
def _win_rdp_rollback(pre):
    val = pre.get("userAuthentication") if isinstance(pre, dict) and isinstance(pre.get("userAuthentication"), int) else 0
    rc, out = _run_no_shell(["reg", "add", _WIN_RDP_KEY, "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", str(val), "/f"], 10)
    return {"exitCode": rc, "output": out}

# --- Windows: UAC (EnableLUA = 1) ---
_WIN_UAC_KEY = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
def _win_uac_state():
    rc, out = _run_no_shell(["reg", "query", _WIN_UAC_KEY, "/v", "EnableLUA"], 10)
    m = _re.search(r"EnableLUA\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", out)
    return {"raw": out[:300], "enableLUA": int(m.group(1), 0) if m else None}
def _win_uac_apply():
    rc, out = _run_no_shell(["reg", "add", _WIN_UAC_KEY, "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"], 10)
    return {"exitCode": rc, "output": out}
def _win_uac_verify():
    return _win_uac_state().get("enableLUA") == 1
def _win_uac_rollback(pre):
    val = pre.get("enableLUA") if isinstance(pre, dict) and isinstance(pre.get("enableLUA"), int) else 0
    rc, out = _run_no_shell(["reg", "add", _WIN_UAC_KEY, "/v", "EnableLUA", "/t", "REG_DWORD", "/d", str(val), "/f"], 10)
    return {"exitCode": rc, "output": out}

# --- Windows: BitLocker (protector + on) ---
def _win_ps(cmd, timeout=20):
    return _run_no_shell(["powershell", "-NoProfile", "-Command", cmd], timeout)

# Windows menolak BitLocker pada volume OS tanpa TPM (0x8028400F) kecuali policy
# ini mengizinkannya. Nilai ini yang dipasang gpedit "Require additional
# authentication at startup" + "Allow BitLocker without a compatible TPM".
# Keempat opsi TPM harus "Allow" (2): kombinasi "Do not allow" semuanya
# memicu 0x8031005B (policy startup options in conflict).
_FVE_POLICY_KEY = r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE"
_FVE_NO_TPM_VALUES = {
    "EnableBdeWithNoTPM": 1,
    "UseAdvancedStartup": 1,
    "UseTPM": 2,
    "UseTPMPIN": 2,
    "UseTPMKey": 2,
    "UseTPMKeyPIN": 2,
}

def _fve_policy_state():
    """Snapshot nilai policy FVE yang kita ubah; None berarti belum ada."""
    rc, out = _run_no_shell(["reg", "query", _FVE_POLICY_KEY], 10)
    text = out or ""
    state = {}
    for name in _FVE_NO_TPM_VALUES:
        m = _re.search(r"\b" + name + r"\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", text)
        state[name] = int(m.group(1), 0) if m else None
    return state

def _fve_policy_apply_no_tpm():
    prev = _fve_policy_state()
    for name, val in _FVE_NO_TPM_VALUES.items():
        _run_no_shell(["reg", "add", _FVE_POLICY_KEY, "/v", name, "/t", "REG_DWORD", "/d", str(val), "/f"], 10)
    return prev

def _fve_policy_restore(prev):
    if not isinstance(prev, dict):
        return
    for name, old in prev.items():
        if name not in _FVE_NO_TPM_VALUES:
            continue
        if old is None:
            _run_no_shell(["reg", "delete", _FVE_POLICY_KEY, "/v", name, "/f"], 10)
        else:
            _run_no_shell(["reg", "add", _FVE_POLICY_KEY, "/v", name, "/t", "REG_DWORD", "/d", str(old), "/f"], 10)

def _win_bitlocker_state():
    """Baca status via PowerShell (JSON stabil, tidak bergantung lokalisasi/manage-bde)."""
    cmd = (
        "$v=Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop; "
        "@{p=[string]$v.ProtectionStatus; e=[int]$v.EncryptionPercentage; "
        "s=[string]$v.VolumeStatus; "
        "k=@($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }); "
        "r=@($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | "
        "ForEach-Object { [string]$_.RecoveryPassword })} | ConvertTo-Json -Compress"
    )
    rc, out = _win_ps(cmd, 15)
    try:
        data = json.loads((out or "").strip().splitlines()[-1])
        protection = str(data.get("p", "")).strip().lower()
        pct = int(data.get("e", 0) or 0)
        return {
            "protectionOn": protection in ("on", "1", "true"),
            "protectionStatus": str(data.get("p", "")),
            "volumeStatus": str(data.get("s", "")),
            "encrypted": pct >= 100,
            "encryptionPercentage": pct,
            "protectors": list(data.get("k") or []),
            "recoveryKeys": [k for k in (data.get("r") or []) if k],
            "fve": _fve_policy_state(),
        }
    except Exception:
        rc2, raw = _run_no_shell(["manage-bde", "-status", "C:"], 10)
        low = raw or ""
        m = _re.search(r"Percentage Encrypted:\s*([0-9.]+)%", low)
        return {
            "protectionOn": ("Protection On" in low) or ("Perlindungan Aktif" in low),
            "protectionStatus": "On" if ("Protection On" in low or "Perlindungan Aktif" in low) else "Off",
            "volumeStatus": "FullyEncrypted" if "Fully Encrypted" in low else (
                "EncryptionInProgress" if "Encryption In Progress" in low else "FullyDecrypted"),
            "encrypted": "100.0%" in low,
            "encryptionPercentage": float(m.group(1)) if m else 0.0,
            "protectors": [],
            "recoveryKeys": [],
            "raw": low[:300],
            "fve": _fve_policy_state(),
        }

def _win_tpm_ready():
    rc, out = _win_ps(
        "try { $t=Get-Tpm; if ($t.TpmPresent -and $t.TpmReady) { 'yes' } else { 'no' } } catch { 'no' }", 15)
    return "yes" in (out or "").lower()

def _win_bitlocker_boot_password(length=20):
    """Password boot BitLocker harus ANGKA saja.

    Layar pre-boot memakai layout keyboard dasar; karakter seperti '_' atau '-'
    (hasil token_urlsafe) sering tidak bisa diketik dan membuat volume tidak
    bisa dibuka. Kasus lapangan 2026-11-14: password berisi '_' ditolak di
    layar "Enter the password to unlock this drive".
    """
    return "".join(secrets.choice("0123456789") for _ in range(length))

def _win_bitlocker_add_protector(kind, timeout=20):
    if kind == "recovery":
        return _win_ps("Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector | Out-Null", timeout)
    if kind == "tpm":
        return _win_ps("Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector | Out-Null", timeout)
    pw = _win_bitlocker_boot_password()
    rc, out = _win_ps(
        "$p=ConvertTo-SecureString '" + pw + "' -AsPlainText -Force; "
        "Add-BitLockerKeyProtector -MountPoint 'C:' -PasswordProtector -Password $p | Out-Null", timeout)
    return rc, out, pw

def _win_bitlocker_ok(st):
    """Enkripsi dianggap berhasil bila proteksi On, atau enkripsi sudah berjalan
    dengan protector aman. Proteksi bisa tetap Off selama konversi berlangsung
    dan baru On setelah enkripsi selesai/reboot."""
    if not isinstance(st, dict):
        return False
    if st.get("protectionOn") or st.get("encrypted"):
        return True
    status = str(st.get("volumeStatus") or "").lower()
    if "decryption" in status:
        return False
    pct = st.get("encryptionPercentage") or 0
    secure = any(p in ("Password", "RecoveryPassword", "Tpm", "TpmPin", "StartupKey")
                 for p in (st.get("protectors") or []))
    return pct > 0 and secure

def _win_bitlocker_apply():
    st = _win_bitlocker_state()
    if st.get("protectionOn"):
        return {"exitCode": 0, "output": "BitLocker sudah aktif (idempoten)", "recoveryKey": ""}

    pct = st.get("encryptionPercentage") or 0
    status = str(st.get("volumeStatus") or "").lower()
    if "decryption" in status:
        return {"exitCode": 1,
                "output": ("dekripsi BitLocker masih berjalan; tunggu sampai "
                           "Fully Decrypted sebelum mengaktifkan ulang"),
                "recoveryKey": ""}
    if pct > 0 and not st.get("encrypted"):
        # Enkripsi sudah berjalan (lanjutan run sebelumnya). Jangan menerbitkan
        # password baru; cukup nyalakan proteksi dan laporkan state sebenarnya.
        _win_ps("Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop | Out-Null", 20)
        st = _win_bitlocker_wait_ready(30)
        keys = st.get("recoveryKeys") or []
        return {"exitCode": 0 if _win_bitlocker_ok(st) else 1,
                "output": (f"enkripsi BitLocker sudah berjalan ({pct}%); "
                           "proteksi menyala setelah enkripsi/reboot"),
                "recoveryKey": keys[-1] if keys else ""}

    protectors = st.get("protectors") or []
    tpm_ready = _win_tpm_ready()
    boot_pw = None

    if "RecoveryPassword" not in protectors:
        _win_bitlocker_add_protector("recovery")

    if st.get("encrypted"):
        # Volume sudah terenkripsi → pastikan ada protector yang bisa membuka, lalu resume.
        if not tpm_ready and "Password" not in protectors:
            _fve_policy_apply_no_tpm()
            rc_pw, _out_pw, boot_pw = _win_bitlocker_add_protector("password")
            if rc_pw != 0:
                boot_pw = None
        if tpm_ready and "Tpm" not in protectors:
            _win_bitlocker_add_protector("tpm")
        rc, out = _win_ps("Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop | Out-Null", 20)
        if rc != 0:
            rc2, out2 = _win_ps("manage-bde -protectors -enable C:", 20)
            if rc2 != 0:
                return {"exitCode": 1, "output": ("resume gagal: " + out[:150] + " | " + out2[:150]), "recoveryKey": ""}
    else:
        # Belum terenkripsi. Tanpa TPM: PasswordProtector (satu-satunya set yang valid).
        if tpm_ready:
            rc, out = _win_ps(
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 "
                "-TpmProtector -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null", 30)
        else:
            # Volume OS tanpa TPM ditolak Windows (0x8028400F) kecuali policy
            # "Allow BitLocker without a compatible TPM" dipasang lebih dulu.
            _fve_policy_apply_no_tpm()
            boot_pw = _win_bitlocker_boot_password()
            enable_cmd = (
                "$p=ConvertTo-SecureString '" + boot_pw + "' -AsPlainText -Force; "
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 "
                "-PasswordProtector -Password $p -SkipHardwareTest -ErrorAction Stop | Out-Null")
            rc, out = _win_ps(enable_cmd, 30)
            if rc != 0 and ("0x8028400F" in (out or "") or "0x8031005B" in (out or "") or "TPM" in (out or "")):
                # Policy baru kadang belum terbaca sampai Group Policy refresh.
                _win_ps("gpupdate /target:computer /force | Out-Null", 120)
                rc, out = _win_ps(enable_cmd, 30)
            if rc == 0:
                _win_bitlocker_add_protector("recovery")
        if rc != 0:
            keys = (_win_bitlocker_state().get("recoveryKeys") or [])
            res = {"exitCode": 1, "output": "enable gagal: " + (out or "")[:300],
                   "recoveryKey": keys[-1] if keys else ""}
            if boot_pw:
                # Password sudah dipasang ke volume: jangan pernah hilangkan.
                res["bootPassword"] = boot_pw
            return res

    st = _win_bitlocker_wait_ready()
    if not st.get("protectionOn") and not st.get("encrypted"):
        # Enkripsi bisa berjalan dengan proteksi masih tersuspend.
        rc_r, _out_r = _win_ps("Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop | Out-Null", 20)
        if rc_r != 0:
            _win_ps("manage-bde -protectors -enable C:", 20)
        st = _win_bitlocker_wait_ready(30)
    if not _win_bitlocker_ok(st):
        pct = st.get("encryptionPercentage")
        keys = st.get("recoveryKeys") or []
        res = {"exitCode": 1,
               "output": ("proteksi/enkripsi tidak aktif setelah perintah "
                          f"(pct={pct}, status={st.get('protectionStatus')}, "
                          f"volume={st.get('volumeStatus')}, "
                          f"protectors={st.get('protectors')})"),
               "recoveryKey": keys[-1] if keys else ""}
        if boot_pw:
            res["bootPassword"] = boot_pw
        return res
    keys = st.get("recoveryKeys") or []
    pct = st.get("encryptionPercentage") or 0
    res = {
        "exitCode": 0,
        "output": ("proteksi BitLocker aktif" if st.get("protectionOn") else
                   f"enkripsi BitLocker berjalan ({pct}%); proteksi menyala setelah enkripsi/reboot"),
        "recoveryKey": keys[-1] if keys else "",
    }
    if boot_pw:
        res["bootPassword"] = boot_pw
    return res

def _win_bitlocker_verify():
    return _win_bitlocker_ok(_win_bitlocker_state())

def _win_bitlocker_wait_ready(timeout=45, interval=4):
    """Enable-BitLocker kembali sebelum status volume ter-update; tunggu sampai
    proteksi On atau enkripsi mulai berjalan."""
    deadline = time.time() + timeout
    st = _win_bitlocker_state()
    while time.time() < deadline:
        if st.get("protectionOn") or st.get("encrypted") or (st.get("encryptionPercentage") or 0) > 0:
            return st
        time.sleep(interval)
        st = _win_bitlocker_state()
    return st

def _win_bitlocker_rollback_state():
    # Dekripsi berjalan di background: cukup bandingkan status proteksi, bukan
    # persentase enkripsi, agar rollback tidak selalu dilaporkan gagal.
    return {"protectionOn": _win_bitlocker_state().get("protectionOn")}

def _win_bitlocker_rollback(pre):
    def _restore_policy(res):
        if isinstance(pre, dict):
            _fve_policy_restore(pre.get("fve"))
        return res
    # Aktif sebelum remediasi → biarkan aktif.
    if isinstance(pre, dict) and pre.get("protectionOn") is True:
        return _restore_policy({"exitCode": 0, "output": "BitLocker sudah aktif sebelum remediasi; dibiarkan aktif"})
    # Sudah terenkripsi tapi proteksi mati → suspend, jangan dekripsi (lama).
    if isinstance(pre, dict) and pre.get("encrypted") is True:
        rc, out = _win_ps("Suspend-BitLocker -MountPoint 'C:' -Force | Out-Null", 20)
        return _restore_policy({"exitCode": rc, "output": ("proteksi disuspend (tetap terenkripsi). " + out[:150]) if rc == 0 else out})
    rc, out = _run_no_shell(["manage-bde", "-off", "C:"], 120)
    # Password acak yang dibuat remediasi tidak diketahui operator; hapus agar
    # tidak tertinggal sebagai protector yang tak bisa dipakai. RecoveryPassword
    # (kunci yang sudah di-escrow) sengaja dibiarkan sampai dekripsi selesai.
    if isinstance(pre, dict) and "Password" not in (pre.get("protectors") or []):
        _run_no_shell(["manage-bde", "-protectors", "-delete", "C:", "-type", "Password"], 30)
    return _restore_policy({"exitCode": rc, "output": (out or "")[:300] + " (dekripsi dapat berjalan di background)"})

# --- Linux: GRUB config permissions (CIS 1.4.1) ---
_GRUB_PATHS = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
def _linux_grub_state():
    found = {}
    for gp in _GRUB_PATHS:
        if os.path.exists(gp):
            found[gp] = oct(os.stat(gp).st_mode)[-3:]
    return {"found": found, "secure": bool(found) and all(m in ('400', '600', '000') for m in found.values())}
def _linux_grub_apply():
    st = _linux_grub_state()
    if not st["found"]:
        return {"exitCode": -1, "output": "grub.cfg tidak ditemukan"}
    errors = []
    for gp in st["found"]:
        try:
            os.chmod(gp, 0o600)
        except Exception as e:
            errors.append(f"{gp}: {e}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "izin grub.cfg diset 0600"}
def _linux_grub_verify():
    return _linux_grub_state()["secure"] is True
def _linux_grub_rollback(pre):
    modes = pre.get("found") if isinstance(pre, dict) else None
    if not modes:
        return {"exitCode": -1, "output": "snapshot izin grub tidak tersedia"}
    errors = []
    for gp, mode in modes.items():
        try:
            os.chmod(gp, int(mode, 8))
        except Exception as e:
            errors.append(f"{gp}: {e}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "izin grub dipulihkan"}

# --- Linux: sudoers NOPASSWD (CIS 5.3.4) ---
# Aturan keamanan jalur ini:
#  1. Validasi sintaks `visudo -c -f` pada salinan sementara SEBELUM mengganti
#     berkas asli (berkas sudoers rusak = sudo mati).
#  2. Tulis atomik (tmp + os.replace) agar tidak pernah setengah jadi.
#  3. Berkas cloud-init (`90-cloud-init-users`) tidak dicabut bila user-nya
#     belum punya password — pada image cloud, mencabut NOPASSWD membuat sudo
#     langsung tidak terpakai.
def _sudoers_files():
    files = ['/etc/sudoers']
    d = '/etc/sudoers.d'
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isfile(p) and not name.endswith(('~', '.bak', '.tmp', '.pasopati.tmp')):
                files.append(p)
    return [p for p in files if os.path.isfile(p)]

_CLOUD_INIT_SUDOERS = '90-cloud-init-users'

def _sudoers_validate(path):
    """Validasi sintaks sudoers. True bila valid atau visudo tidak tersedia."""
    rc, out = _run_no_shell(["visudo", "-c", "-f", path], 15)
    if rc == -1:
        return True, "visudo tidak tersedia (validasi dilewati)"
    return rc == 0, (out or "").strip()[:300]

def _sudoers_write(path, content, mode, force=False):
    """Tulis atomik + validasi. force=True tetap mengganti walau visudo menolak (rollback)."""
    tmp = path + ".pasopati.tmp"
    with open(tmp, "w") as f:
        f.write(content)
    try:
        os.chmod(tmp, mode)
    except Exception:
        pass
    ok, msg = _sudoers_validate(tmp)
    if not ok and not force:
        try:
            os.remove(tmp)
        except Exception:
            pass
        return False, msg
    # Windows menolak replace bila target read-only (sudoers 0440/0444) — buka dulu.
    try:
        if os.path.exists(path):
            os.chmod(path, 0o600)
    except Exception:
        pass
    _atomic_replace(tmp, path)
    try:
        os.chmod(path, mode)
    except Exception:
        pass
    return ok, msg

def _account_has_no_password(spec):
    """True bila subjek sudoers (user/grup) ada dan belum punya password."""
    name = spec.lstrip('%+')
    if not name or name.startswith('#'):
        return False
    rc, out = _run_no_shell(["passwd", "-S", name], 5)
    if rc != 0:
        return False
    parts = (out or "").split()
    return len(parts) >= 2 and parts[1] in ("L", "NP", "*L")

def _sudoers_cloud_init_exempt(path, content):
    """Subjek pada berkas cloud-init yang belum punya password (aman dipertahankan)."""
    if os.path.basename(path) != _CLOUD_INIT_SUDOERS:
        return []
    exempt = []
    for line in (content or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or 'NOPASSWD:' not in stripped:
            continue
        subject = stripped.split()[0]
        if _account_has_no_password(subject):
            exempt.append(subject)
    return exempt
def _linux_sudoers_state():
    entries = {}
    for p in _sudoers_files():
        try:
            with open(p, 'r', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        if 'NOPASSWD:' in content:
            entries[p] = {"content": content, "mode": oct(os.stat(p).st_mode)[-3:]}
    return {"files": entries, "clean": not entries}
def _linux_sudoers_apply():
    st = _linux_sudoers_state()
    if st["clean"]:
        return {"exitCode": 0, "output": "tidak ada NOPASSWD; tidak ada perubahan"}
    replaced, notes, errors = [], [], []
    for p, meta in st["files"].items():
        content = meta.get("content", "")
        exempt = _sudoers_cloud_init_exempt(p, content)
        if exempt:
            notes.append("%s: NOPASSWD dipertahankan untuk %s (belum punya password)" % (p, ", ".join(exempt)))
            continue
        new_content = "\n".join(
            line.replace("NOPASSWD:", "") if not line.strip().startswith('#') else line
            for line in content.splitlines()
        ) + "\n"
        try:
            mode = int(meta.get("mode") or "440", 8)
            ok, msg = _sudoers_write(p, new_content, mode)
        except Exception as e:
            ok, msg = False, str(e)
        if ok:
            replaced.append({"path": p, "content": content, "mode": meta.get("mode")})
        else:
            errors.append("%s: %s" % (p, msg))
    if errors:
        # Satu berkas gagal divalidasi → kembalikan yang sudah diganti, jangan separuh jalan.
        for item in reversed(replaced):
            try:
                _sudoers_write(item["path"], item["content"], int(item["mode"] or "440", 8), force=True)
            except Exception:
                pass
        return {"exitCode": -1, "output": "visudo menolak; seluruh perubahan dibatalkan. " + "; ".join(errors)[:400]}
    output = "NOPASSWD dihapus dari %d berkas" % len(replaced) if replaced else "tidak ada berkas yang diubah"
    if notes:
        output += " | " + "; ".join(notes)
    return {"exitCode": 0, "output": output[:600]}

def _linux_sudoers_verify():
    for p, meta in _linux_sudoers_state()["files"].items():
        if not _sudoers_cloud_init_exempt(p, meta.get("content", "")):
            return False
    return True

def _linux_sudoers_rollback(pre):
    files = pre.get("files") if isinstance(pre, dict) else None
    if not files:
        return {"exitCode": 0, "output": "tidak ada perubahan sudoers untuk dipulihkan"}
    errors = []
    for p, meta in files.items():
        try:
            _sudoers_write(p, meta.get("content", ""), int(meta.get("mode") or "440", 8), force=True)
        except Exception as e:
            errors.append("%s: %s" % (p, e))
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "sudoers dipulihkan dari snapshot"}

# --- Linux: SUID pada binari kritis (CIS 1.1.21) ---
_SUID_CANDIDATES = ['/bin/bash', '/bin/sh', '/usr/bin/python3', '/usr/bin/perl', '/bin/netcat', '/usr/bin/find']
def _linux_suid_state():
    set_bits = {}
    for p in _SUID_CANDIDATES:
        if os.path.exists(p):
            mode = os.stat(p).st_mode
            if mode & 0o4000:
                set_bits[p] = oct(mode)[-4:]
    return {"suid": set_bits, "clean": not set_bits}
def _linux_suid_apply():
    st = _linux_suid_state()
    if st["clean"]:
        return {"exitCode": 0, "output": "tidak ada SUID liar; tidak ada perubahan"}
    errors = []
    for p in st["suid"]:
        try:
            os.chmod(p, os.stat(p).st_mode & ~0o4000)
        except Exception as e:
            errors.append(f"{p}: {e}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "bit SUID dihapus"}
def _linux_suid_verify():
    return _linux_suid_state()["clean"] is True
def _linux_suid_rollback(pre):
    suid = pre.get("suid") if isinstance(pre, dict) else None
    if not suid:
        return {"exitCode": 0, "output": "tidak ada bit SUID untuk dipulihkan"}
    errors = []
    for p in suid:
        try:
            os.chmod(p, os.stat(p).st_mode | 0o4000)
        except Exception as e:
            errors.append(f"{p}: {e}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "bit SUID dipulihkan"}

# --- Windows: audit policy Process Creation (DISA STIG WN10-AU-000050) ---
# Pakai GUID subcategory agar tidak bergantung bahasa OS (Windows ID/EN/dll).
_AUDITPOL_SUBCAT_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"
def _auditpol_parse_setting(out, guid):
    """Ambil kolom numerik `Setting Value` dari laporan CSV auditpol (0-3)."""
    for line in (out or "").splitlines():
        if guid.lower() not in line.lower():
            continue
        parts = [part.strip().strip('"') for part in line.split(",")]
        if parts and parts[-1].isdigit():
            return int(parts[-1])
    return None
_AUDITPOL_SUBCAT_NAMES = ("process creation", "pembuatan proses")
def _win_auditpol_state():
    rc, out = _run_no_shell(["auditpol", "/get", f"/subcategory:{_AUDITPOL_SUBCAT_GUID}", "/r"], 10)
    if rc != 0:
        return {"readable": False, "success": False, "failure": False, "raw": (out or "")[:400]}
    value = _auditpol_parse_setting(out, _AUDITPOL_SUBCAT_GUID)
    if value is not None:
        return {"readable": True, "success": bool(value & 1), "failure": bool(value & 2), "raw": (out or "")[:400]}
    # Fallback: keluaran teks lama (bukan CSV) dalam bahasa Inggris/Indonesia.
    for line in (out or "").splitlines():
        low = line.lower()
        if any(name in low for name in _AUDITPOL_SUBCAT_NAMES):
            both = ("success and failure" in low) or ("keberhasilan dan kegagalan" in low)
            success = both or ("success" in low) or ("keberhasilan" in low)
            failure = both or ("failure" in low) or ("kegagalan" in low)
            return {"readable": True, "success": success, "failure": failure, "raw": (out or "")[:400]}
    return {"readable": False, "success": False, "failure": False, "raw": (out or "")[:400]}
def _win_auditpol_apply():
    rc, out = _run_no_shell(["auditpol", "/set", f"/subcategory:{_AUDITPOL_SUBCAT_GUID}", "/success:enable", "/failure:enable"], 10)
    return {"exitCode": rc, "output": out}
def _win_auditpol_verify():
    s = _win_auditpol_state()
    return s.get("readable") is True and s.get("success") is True and s.get("failure") is True
def _win_auditpol_rollback(pre):
    if not isinstance(pre, dict) or not pre.get("readable"):
        return {"exitCode": 0, "output": "pre-state auditpol tidak terbaca; dibiarkan"}
    succ = "enable" if pre.get("success") else "disable"
    fail = "enable" if pre.get("failure") else "disable"
    rc, out = _run_no_shell(["auditpol", "/set", f"/subcategory:{_AUDITPOL_SUBCAT_GUID}", f"/success:{succ}", f"/failure:{fail}"], 10)
    return {"exitCode": rc, "output": out}

# --- Port berbahaya: blokir listener kritis (enforce) ---
_LINUX_CRIT_PORTS = [(4444, "C2 Backdoor"), (445, "SMB"), (23, "Telnet"), (21, "FTP")]
_WIN_CRIT_PORTS = [(4444, "C2 Backdoor"), (445, "SMB"), (23, "Telnet"), (21, "FTP"), (3389, "RDP")]

def _linux_port_rule_exists(port):
    try:
        return subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            capture_output=True
        ).returncode == 0
    except Exception:
        return False

def _linux_ports_state():
    rc, out = _run_no_shell(["ss", "-tuln"], 5)
    listening = []
    for port, _label in _LINUX_CRIT_PORTS:
        if f":{port} " in out or f":{port}\n" in out:
            listening.append(port)
    blocked = [p for p, _l in _LINUX_CRIT_PORTS if _linux_port_rule_exists(p)]
    supported = _firewall_persist_supported()
    return {
        "listening": listening,
        "blocked": blocked,
        "open": [p for p in listening if p not in blocked],
        "persistSupported": supported,
        "persisted": _firewall_persisted(blocked) if supported else None,
    }

def _linux_ports_apply():
    st = _linux_ports_state()
    errors = []
    for port in st["open"]:
        if not _linux_port_rule_exists(port):
            rc, out = _run_no_shell(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], 10)
            if rc != 0:
                errors.append(f"{port}: {out[:120]}")
    notes = []
    if st["open"] and st.get("persistSupported"):
        ok, msg = _firewall_persist()
        if ok:
            notes.append("rule dipersistenkan")
        else:
            notes.append(f"PERSISTENSI GAGAL: {msg}")
    elif st["open"]:
        notes.append("persistensi firewall tidak tersedia — rule hilang setelah reboot")
    summary = "; ".join(notes)
    return {"exitCode": 0 if not errors else -1, "output": ("; ".join(errors) + " | " if errors else "") + summary or f"port diblokir: {st['open']}"}

def _linux_ports_verify():
    st = _linux_ports_state()
    if not all(p in st["blocked"] for p in st["listening"]):
        return False
    # Bila mekanisme persistensi ada, rule wajib ikut tersimpan.
    return st.get("persisted") is not False

def _linux_ports_rollback(pre):
    ports = pre.get("open") if isinstance(pre, dict) else None
    if not ports:
        return {"exitCode": 0, "output": "tidak ada rule yang perlu dihapus"}
    errors = []
    for port in ports:
        rc, out = _run_no_shell(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], 10)
        if rc != 0:
            errors.append(f"{port}: {out[:120]}")
    if _firewall_persist_supported():
        ok, msg = _firewall_persist()
        if not ok:
            errors.append(f"persistensi: {msg}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "rule blokir dihapus & dipersistenkan"}

def _win_port_rule_exists(port):
    rc, _out = _win_ps(
        f"if (Get-NetFirewallRule -DisplayName 'PASOPATI-Block-{port}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}", 10)
    return rc == 0

def _port_effectively_blocked(port):
    if platform.system().lower() == "windows":
        return _win_port_rule_exists(port)
    return _linux_port_rule_exists(port)

def _win_ports_state():
    rc, out = _run_no_shell(["powershell", "-NoProfile", "-Command",
                             "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort"], 15)
    listening = sorted({int(x) for x in (out or "").split() if x.strip().isdigit()})
    crit = [p for p, _l in _WIN_CRIT_PORTS if p in listening]
    blocked = []
    for port in crit:
        rc2, _ = _run_no_shell(["powershell", "-NoProfile", "-Command",
                                f"if (Get-NetFirewallRule -DisplayName 'PASOPATI-Block-{port}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"], 10)
        if rc2 == 0:
            blocked.append(port)
    return {"listening": crit, "blocked": blocked, "open": [p for p in crit if p not in blocked]}

def _win_ports_apply():
    st = _win_ports_state()
    errors = []
    for port in st["open"]:
        rc, out = _run_no_shell(["powershell", "-NoProfile", "-Command",
                                 f"New-NetFirewallRule -DisplayName 'PASOPATI-Block-{port}' -Direction Inbound -LocalPort {port} -Protocol TCP -Action Block | Out-Null"], 15)
        if rc != 0:
            errors.append(f"{port}: {out[:120]}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or f"port diblokir: {st['open']}"}

def _win_ports_verify():
    st = _win_ports_state()
    return all(p in st["blocked"] for p in st["listening"])

def _win_ports_rollback(pre):
    ports = pre.get("open") if isinstance(pre, dict) else None
    if not ports:
        return {"exitCode": 0, "output": "tidak ada rule yang perlu dihapus"}
    errors = []
    for port in ports:
        rc, out = _run_no_shell(["powershell", "-NoProfile", "-Command",
                                 f"Remove-NetFirewallRule -DisplayName 'PASOPATI-Block-{port}' -ErrorAction SilentlyContinue"], 10)
        if rc != 0:
            errors.append(f"{port}: {out[:120]}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "rule blokir dihapus"}

# --- Advisory (read-only, tidak memblokir plan) ---
def _fde_state():
    if platform.system().lower() == "windows":
        rc, out = _run_no_shell(["manage-bde", "-status", "C:"], 10)
        on = ("Protection On" in out) or ("Perlindungan Aktif" in out)
        return {"encrypted": on, "engine": "BitLocker", "raw": out[:300]}
    rc, out = _run_no_shell(["lsblk", "-f"], 5)
    return {"encrypted": "crypto_LUKS" in out, "engine": "LUKS", "raw": out[:300]}

def _fde_verify():
    return _fde_state().get("encrypted") is True

def _rootkit_state():
    suspicious = ["diamorphine", "suterusu", "reptile", "adore_ng", "kbeast"]
    found = []
    try:
        with open("/proc/modules", "r") as f:
            loaded = [line.split()[0] for line in f.readlines() if line.strip()]
        found = [m for m in suspicious if m in loaded]
    except Exception:
        pass
    return {"suspicious": found}

def _rootkit_verify():
    return not _rootkit_state().get("suspicious")

def _secureboot_state():
    rc, out = _run_no_shell(["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"], 10)
    return {"enabled": "True" in out, "raw": out[:200]}

def _secureboot_verify():
    return _secureboot_state().get("enabled") is True

def _admins_state():
    rc, out = _run_no_shell(["net", "localgroup", "Administrators"], 10)
    members = [l.strip() for l in (out or "").splitlines() if l.strip() and not l.strip().startswith(("Alias", "Comment", "Members", "---", "The command", "Perintah"))]
    return {"count": len(members), "members": members[:20]}

def _admins_verify():
    return _admins_state().get("count", 99) <= 8

ADVISORY_ALIASES = {"advisory-fde", "advisory-rootkit", "advisory-secureboot", "advisory-admins"}

ALLOWLIST_ANALISA = {
    "fw-enable-defender": {
        "os": "windows", "risk": "MEDIUM", "reversible": True,
        "read": _win_fw_state, "apply": _win_fw_apply, "verify": _win_fw_verify,
        "rollback": _win_fw_rollback
    },
    "guest-account-disable": {
        "os": "windows", "risk": "MEDIUM", "reversible": True,
        "read": _win_guest_state, "apply": _win_guest_apply, "verify": _win_guest_verify,
        "rollback": _win_guest_rollback
    },
    "usb-storage-block": {
        "os": "windows", "risk": "MEDIUM", "reversible": True,
        "read": _win_usbstor_state, "apply": _win_usbstor_apply, "verify": _win_usbstor_verify,
        "rollback": _win_usbstor_restore
    },
    "fw-enable-ufw": {
        "os": "linux", "risk": "MEDIUM", "reversible": True,
        "read": _linux_ufw_state, "apply": _linux_ufw_apply, "verify": _linux_ufw_verify,
        "rollback": _linux_ufw_rollback
    },
    "ssh-disable-root": {
        "os": "linux", "risk": "HIGH", "reversible": True,
        "read": _linux_ssh_read_config, "apply": _linux_ssh_apply, "verify": _linux_ssh_verify,
        "rollback": _linux_ssh_rollback
    },
    "auditd-enable": {
        "os": "linux", "risk": "LOW", "reversible": True,
        "read": _linux_auditd_state, "apply": _linux_auditd_apply, "verify": _linux_auditd_verify,
        "rollback": _linux_auditd_rollback
    },
    "usb-block-linux": {
        "os": "linux", "risk": "MEDIUM", "reversible": True,
        "read": _linux_usb_state, "apply": _linux_usb_apply, "verify": _linux_usb_verify,
        "rollback": _linux_usb_rollback
    },
    "rdp-nla-enable": {
        "os": "windows", "risk": "MEDIUM", "reversible": True,
        "read": _win_rdp_state, "apply": _win_rdp_apply, "verify": _win_rdp_verify,
        "rollback": _win_rdp_rollback
    },
    "uac-enable": {
        "os": "windows", "risk": "MEDIUM", "reversible": True,
        "read": _win_uac_state, "apply": _win_uac_apply, "verify": _win_uac_verify,
        "rollback": _win_uac_rollback
    },
    "bitlocker-enable": {
        "os": "windows", "risk": "HIGH", "reversible": True,
        "read": _win_bitlocker_state, "apply": _win_bitlocker_apply, "verify": _win_bitlocker_verify,
        "rollback": _win_bitlocker_rollback, "rollback_state": _win_bitlocker_rollback_state
    },
    "grub-config-perms": {
        "os": "linux", "risk": "LOW", "reversible": True,
        "read": _linux_grub_state, "apply": _linux_grub_apply, "verify": _linux_grub_verify,
        "rollback": _linux_grub_rollback
    },
    "sudoers-remove-nopasswd": {
        "os": "linux", "risk": "MEDIUM", "reversible": True,
        "read": _linux_sudoers_state, "apply": _linux_sudoers_apply, "verify": _linux_sudoers_verify,
        "rollback": _linux_sudoers_rollback
    },
    "suid-strip-critical": {
        "os": "linux", "risk": "MEDIUM", "reversible": True,
        "read": _linux_suid_state, "apply": _linux_suid_apply, "verify": _linux_suid_verify,
        "rollback": _linux_suid_rollback
    },
    "win-auditpol-process": {
        "os": "windows", "risk": "LOW", "reversible": True,
        "read": _win_auditpol_state, "apply": _win_auditpol_apply, "verify": _win_auditpol_verify,
        "rollback": _win_auditpol_rollback
    },
    "ports-block-linux": {
        "os": "linux", "risk": "HIGH", "reversible": True,
        "read": _linux_ports_state, "apply": _linux_ports_apply, "verify": _linux_ports_verify,
        "rollback": _linux_ports_rollback
    },
    "ports-block-windows": {
        "os": "windows", "risk": "HIGH", "reversible": True,
        "read": _win_ports_state, "apply": _win_ports_apply, "verify": _win_ports_verify,
        "rollback": _win_ports_rollback
    },
    "advisory-fde": {
        "os": "any", "risk": "LOW", "reversible": False,
        "read": _fde_state, "verify": _fde_verify, "advisory": True
    },
    "advisory-rootkit": {
        "os": "any", "risk": "LOW", "reversible": False,
        "read": _rootkit_state, "verify": _rootkit_verify, "advisory": True
    },
    "advisory-secureboot": {
        "os": "any", "risk": "LOW", "reversible": False,
        "read": _secureboot_state, "verify": _secureboot_verify, "advisory": True
    },
    "advisory-admins": {
        "os": "any", "risk": "LOW", "reversible": False,
        "read": _admins_state, "verify": _admins_verify, "advisory": True
    }
}

def print_aliases_by_os():
    """Cetak alias remediasi dipisah per OS (sumber tunggal: ALLOWLIST_ANALISA)."""
    order = ("windows", "linux", "any")
    groups = {name: [] for name in order}
    for alias, entry in ALLOWLIST_ANALISA.items():
        groups.setdefault(entry.get("os", "any"), []).append(alias)
    for name in order:
        names = sorted(groups.get(name, []))
        print(f"[{name}] {len(names)} alias")
        for alias in names:
            risk = ALLOWLIST_ANALISA[alias].get("risk", "-")
            tag = " advisory" if alias in ADVISORY_ALIASES else ""
            print(f"  - {alias} ({risk}{tag})")
        print()
    print("[i] Plan hanya boleh berisi alias satu OS (+ alias 'any').")
    print("[i] Alias Linux ditolak agent Windows dan sebaliknya.")

# ==============================================================================
# RUN REMEDIATION — validasi token → backup → apply → verifikasi → evidence
# ==============================================================================
def _validate_remediation_token(plan, token, hmac_secret):
    """Tirukan validasi server: nonce cocok, signature HMAC valid, belum expired."""
    if not token or "." not in token:
        return False, "Token persetujuan belum diberikan / format tidak valid."
    nonce, _, signature = token.partition(".")
    if nonce != plan.get("nonce", ""):
        return False, "Nonce tidak cocok dengan rencana."
    expires_at = plan.get("expiresAt")
    if isinstance(expires_at, (int, float)) and time.time() * 1000 > expires_at:
        return False, "Token persetujuan kedaluwarsa."
    canonical = json.dumps({
        "planId": plan.get("planId"),
        "deviceId": plan.get("deviceId"),
        "items": plan.get("items"),
        "approvedBy": plan.get("approvedBy"),
        "nonce": plan.get("nonce"),
        "expiresAt": plan.get("expiresAt")
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    expected = hmac.new((hmac_secret or "").encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.lower(), (signature or "").lower()):
        return False, "Signature rencana tidak valid."
    return True, "Token valid."

def _fetch_remediation_plan(server_url, plan_id, api_key):
    """Ambil plan LENGKAP (nonce+signature) dari server agar target hanya butuh agent."""
    base = (server_url or "").rstrip("/")
    if not base:
        raise RuntimeError("--server wajib diisi untuk mengambil plan.")
    url = f"{base}/api/remediation-plans/{urllib.parse.quote(plan_id, safe='')}/agent"
    headers = {"User-Agent": "PASOPATI-Agent/2.5", **_auth_headers()}
    if api_key:
        headers["X-Pasopati-API-Key"] = api_key
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _urlopen(req, 10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        # Tampilkan alasan dari server (mis. 409 plan belum disetujui / sudah terminal).
        detail = exc.read().decode("utf-8", errors="ignore")
        try:
            detail = json.loads(detail).get("reason") or detail
        except Exception:
            pass
        raise RuntimeError(f"HTTP {exc.code}: {str(detail)[:300]}")
    plan = data.get("plan") or {}
    token = data.get("token") or ""
    if not plan.get("items"):
        raise RuntimeError("Plan dari server tidak memiliki items.")
    return plan, token


def _push_remediation_evidence(server_url, api_key, plan_id, nonce, to_status, evidence, hmac_key=None, post_audit=None):
    payload = {"planId": plan_id, "nonce": nonce, "toStatus": to_status, "evidence": evidence}
    if post_audit:
        payload["postAudit"] = post_audit
    url = server_url.rstrip("/") + "/api/remediation-verify"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PASOPATI-Agent/2.6",
        **({"X-Pasopati-API-Key": api_key} if api_key else {}),
        **_auth_headers()
    }
    if hmac_key:
        # Evidence ditandatangani HMAC atas raw body, sama seperti telemetri ingest.
        headers["X-Pasopati-Signature"] = hmac.new(
            hmac_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-Pasopati-Timestamp"] = str(int(time.time()))
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with _urlopen(req, 8) as response:
        return response.getcode()

def _is_elevated():
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return False
    except Exception:
        return False

def _notify_admin_needed():
    """Tampilkan notifikasi agar user menjalankan sebagai admin/root."""
    msg = "PASOPATI butuh hak Administrator (Windows) / root (Linux)."
    try:
        if platform.system().lower() == "windows":
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, msg + " Jalankan PowerShell sebagai Administrator.", "PASOPATI", 0x40)
        else:
            for tool, args in (("notify-send", ["notify-send", "PASOPATI", msg]), ("zenity", ["zenity", "--error", "--text", msg])):
                try:
                    subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                except Exception:
                    pass
    except Exception:
        pass

ELEVATED_ENV = "PASOPATI_ELEVATED"
ELEVATION_METHOD_ENV = "PASOPATI_ELEVATION_METHOD"

def _elevation_method():
    if _is_elevated():
        return os.environ.get(ELEVATION_METHOD_ENV) or "already-root"
    return "none"


def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def _windows_elevation_command(script, argv, log_path):
    """Bangun perintah PowerShell: elevasi UAC, cwd dipertahankan, output ke log, tunggu selesai."""
    inner = (
        "Set-Location -LiteralPath " + _ps_quote(os.getcwd()) + "; "
        + "& " + " ".join([_ps_quote(sys.executable), _ps_quote(script)] + [_ps_quote(a) for a in argv])
        + " *> " + _ps_quote(log_path) + "; exit $LASTEXITCODE"
    )
    return (
        "Start-Process powershell -Verb RunAs -Wait -ArgumentList "
        "'-NoProfile','-ExecutionPolicy','Bypass','-Command'," + _ps_quote(inner)
    )

def _elevate_windows(script, argv):
    log_dir = os.path.join(tempfile.gettempdir(), "pasopati")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        pass
    log_path = os.path.join(log_dir, f"run-{int(time.time())}-{os.getpid()}.log")
    child_argv = list(argv) + ["--elevated"]

    print("[*] Jendela Administrator akan dibuka (UAC). Konfirmasi dengan 'Yes'.")
    print(f"[*] Output lengkap juga ditulis ke: {log_path}")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             _windows_elevation_command(script, child_argv, log_path)],
            capture_output=True, text=True, timeout=1800
        )
    except Exception as exc:
        print(f"[!] Gagal meminta UAC: {exc}")
        print("[i] Alternatif: buka PowerShell sebagai Administrator lalu jalankan perintah yang sama.")
        sys.exit(1)

    if proc.returncode != 0 and proc.stderr:
        print(proc.stderr.strip()[:600])

    # Tampilkan hasil dari log elevated (jendela anak bisa saja sudah tertutup).
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as lf:
            lines = lf.read().splitlines()
        print("\n===== HASIL EKSEKUSI ELEVATED =====")
        print("\n".join(lines[-40:]) if lines else "(log kosong — kemungkinan UAC dibatalkan)")
        print("===== AKHIR HASIL =====")
    except Exception:
        print(f"[i] Log tidak terbaca. Periksa manual: {log_path}")
    sys.exit(0 if proc.returncode == 0 else 1)

def _elevated_finish():
    """Tahan jendela elevated agar hasil bisa dibaca sebelum tertutup."""
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    try:
        if sys.stdin and sys.stdin.isatty():
            input("\nTekan Enter untuk menutup jendela ini...")
    except Exception:
        pass

def ensure_elevated(argv, entry_script=None):
    """Minta hak root/Administrator lalu jalankan ulang perintah yang sama.

    Dipakai untuk audit DAN remediasi agar kontrol yang butuh root
    (/etc/sudoers, iptables, auditd, LUKS, registry, BitLocker) terbaca/berjalan.
    """
    if os.environ.get(ELEVATED_ENV) == "1" or _is_elevated() or "--no-elevate" in argv:
        return

    print("[*] Mengelevasi hak akses (root/Administrator) agar kontrol terbaca maksimal...")
    script = os.path.abspath(entry_script or __file__)

    if platform.system().lower() == "windows":
        return _elevate_windows(script, argv)

    env = dict(os.environ)
    env[ELEVATED_ENV] = "1"
    env[ELEVATION_METHOD_ENV] = "sudo"

    import shutil as _shutil
    interactive = False
    try:
        interactive = bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        interactive = False

    if _shutil.which("sudo"):
        try:
            if interactive:
                os.execvpe("sudo", ["sudo", "-E", sys.executable, script] + list(argv), env)
            else:
                # Tanpa TTY (cron/CI/server) `sudo -E` mati diam-diam karena tidak bisa
                # meminta sandi. Coba `sudo -n`; bila gagal, lanjut dengan hak saat ini.
                proc = subprocess.run(
                    ["sudo", "-n", sys.executable, script] + list(argv), env=env
                )
                if proc.returncode == 0:
                    sys.exit(0)
                print("[!] sudo tanpa TTY tidak dapat meminta sandi — melanjutkan dengan hak saat ini.")
                print("    Untuk kontrol penuh: jalankan ulang dengan sudo atau sediakan cache sudo.")
        except Exception as exc:
            print(f"[!] Elevasi sudo gagal: {exc}")
    if _shutil.which("pkexec"):
        try:
            env[ELEVATION_METHOD_ENV] = "pkexec"
            prefix = ["pkexec", "env", ELEVATED_ENV + "=1", ELEVATION_METHOD_ENV + "=pkexec"]
            for key in ("HMAC_SECRET", "PASOPATI_API_KEY"):
                if os.environ.get(key):
                    prefix.append(f"{key}={os.environ[key]}")
            os.execvpe("pkexec", prefix + [sys.executable, script] + list(argv), env)
        except Exception:
            pass

    _notify_admin_needed()
    print("[!] sudo/pkexec tidak tersedia atau gagal. Jalankan manual: sudo python3 pasopati_audit.py ...")

# ------------------------------------------------------------------------------
# RIWAYAT EKSEKUSI (dibawa ke audit.json agar run berikutnya punya konteks)
# ------------------------------------------------------------------------------
def _state_folder():
    if platform.system().lower() == "windows":
        base = os.environ.get("PROGRAMDATA") if _is_elevated() else os.path.expanduser("~")
        folder = os.path.join(base or os.path.expanduser("~"), "PASOPATI")
    else:
        folder = "/var/lib/pasopati" if _is_elevated() else os.path.join(os.path.expanduser("~"), ".pasopati")
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        probe = os.path.join(folder, ".write-test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
        return folder
    except Exception:
        fallback = os.path.join(os.path.expanduser("~"), ".pasopati")
        os.makedirs(fallback, mode=0o700, exist_ok=True)
        return fallback

def _history_path():
    return os.path.join(_state_folder(), "history.json")

_MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

def _atomic_replace(source, target, attempts=6, base_delay=0.025, deadline=2.0):
    """Ganti file via rename dengan retry singkat untuk EPERM/EACCES/EBUSY (Windows).

    Error permanen (ENOENT, ENOSPC, dst.) langsung dilempar. File tujuan tidak
    dihapus lebih dulu sehingga atomicity tidak rusak.
    """
    retryable = {errno.EPERM, errno.EACCES, errno.EBUSY}
    started = time.time()
    for attempt in range(1, attempts + 1):
        try:
            os.replace(source, target)
            return
        except OSError as error:
            if getattr(error, "errno", None) not in retryable:
                raise
            remaining = deadline - (time.time() - started)
            if attempt >= attempts or remaining <= 0:
                raise
            time.sleep(min(base_delay * (2 ** (attempt - 1)), 0.4, remaining))

def get_machine_id():
    """UUID mesin yang dibuat sekali dan dipakai ulang (identitas endpoint stabil).

    Disimpan lokal dengan mode 0600. Nilai ini ikut di dalam payload yang
    ditandatangani HMAC, jadi bukan sekadar klaim yang mudah dipalsukan.
    """
    path = os.path.join(_state_folder(), "machine-id")
    try:
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read().strip()
        if _MACHINE_ID_RE.match(existing):
            return existing
    except Exception:
        pass
    fresh = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(fresh)
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        _atomic_replace(tmp, path)
    except Exception:
        pass
    return fresh

def read_history(path=None):
    path = path or _history_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def append_history(entry):
    """Simpan riwayat (maks 100 entri) dan kembalikan (riwayat_lengkap, path)."""
    path = _history_path()
    history = read_history(path)[-99:]
    history.append(entry)
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        _atomic_replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception as exc:
        print(f"[!] Riwayat tidak dapat ditulis: {exc}")
    return history, path


def _demo_auto_plan():
    """Mode DEMO: bangun plan otomatis dari hasil audit (FAIL/WARNING)."""
    try:
        result = run_full_audit("DEMO-NODE")
        matrix = result.get("compliance_matrix", [])
    except Exception:
        matrix = []
    current_os = platform.system().lower()
    mapping = []
    if current_os == "windows":
        mapping = [
            ("dangerous port", "ports-block-windows"),
            ("firewall", "fw-enable-defender"),
            ("guest", "guest-account-disable"),
            ("rdp", "rdp-nla-enable"),
            ("3389", "rdp-nla-enable"),
            ("uac", "uac-enable"),
            ("bitlocker", "bitlocker-enable"),
            ("usb", "usb-storage-block"),
            ("event log", "win-auditpol-process"),
            ("auditing", "win-auditpol-process"),
            ("secure boot", "advisory-secureboot"),
            ("administrator", "advisory-admins"),
        ]
    else:
        mapping = [
            ("dangerous port", "ports-block-linux"),
            ("firewall", "fw-enable-ufw"),
            ("permitrootlogin", "ssh-disable-root"),
            ("ssh root", "ssh-disable-root"),
            ("audit", "auditd-enable"),
            ("usb", "usb-block-linux"),
            ("grub", "grub-config-perms"),
            ("sudoers", "sudoers-remove-nopasswd"),
            ("nopasswd", "sudoers-remove-nopasswd"),
            ("suid", "suid-strip-critical"),
            ("luks", "advisory-fde"),
            ("full disk encryption", "advisory-fde"),
            ("rootkit", "advisory-rootkit"),
        ]
    items = []
    seen = set()
    for check in matrix:
        if check.get("status") not in ("FAIL", "WARNING"):
            continue
        hay = (check.get("parameter", "") + " " + check.get("details", "")).lower()
        for kw, alias in mapping:
            if kw in hay and alias not in seen:
                entry = ALLOWLIST_ANALISA.get(alias)
                if entry and entry.get("os") == current_os:
                    items.append({"alias": alias})
                    seen.add(alias)
                break
    # Saring aksi yang tak berlaku di lingkungan ini agar demo mulus (tetap transparan).
    filtered = []
    for it in items:
        alias = it["alias"]
        if current_os != "windows":
            if alias == "ssh-disable-root" and not os.path.exists(_SSHD_CONFIG_PATH) and not os.path.isdir(_SSHD_INCLUDE_DIR):
                continue
            if alias == "grub-config-perms" and not any(os.path.exists(p) for p in _GRUB_PATHS):
                continue
            if alias == "sudoers-remove-nopasswd" and not os.path.exists("/etc/sudoers"):
                continue
            if alias in ("advisory-secureboot", "advisory-admins"):
                continue
        filtered.append(it)
    return {"planId": "DEMO-AUTO", "deviceId": "DEMO-NODE", "items": filtered}

def run_remediation(args):
    global _ESCROW_BASE, _ESCROW_KEY, _ESCROW_DEVICE, _HOST_KEY, _CA_CERT, _INSECURE
    _ESCROW_BASE = (getattr(args, "push_url", None) or "").rstrip("/")
    if _ESCROW_BASE.endswith("/api/ingest"):
        _ESCROW_BASE = _ESCROW_BASE[: -len("/api/ingest")]
    _ESCROW_KEY = getattr(args, "remediate_api_key", "") or ""
    _HOST_KEY = getattr(args, "host_key", "") or os.environ.get("PASOPATI_HOST_KEY", "")
    _CA_CERT = getattr(args, "ca_cert", "") or ""
    _INSECURE = bool(getattr(args, "insecure", False))
    if _HOST_KEY:
        print("[*] Kredensial host ter-enrol dipakai (X-Pasopati-Host-Key).")
        if _ESCROW_BASE.startswith("http://"):
            print("[i] Koneksi masih plaintext http:// — host key terlihat di jaringan.")
    if _INSECURE:
        print("[i] Verifikasi TLS dimatikan (--insecure).")
    plan_path = args.remediate_plan
    if getattr(args, "plan_id", None) and not plan_path:
        try:
            print(f"[*] Mengambil plan {args.plan_id} dari server {args.server} ...")
            plan, token = _fetch_remediation_plan(args.server, args.plan_id, args.remediate_api_key)
        except Exception as exc:
            print(f"[!] Gagal mengambil plan dari server: {exc}")
            return
        fd, plan_path = tempfile.mkstemp(prefix="pasopati-plan-", suffix=".json")
        with os.fdopen(fd, "w") as pf:
            json.dump(plan, pf, indent=2)
        if not args.remediate_token:
            args.remediate_token = token
        print(f"[+] Plan diterima & disimpan sementara: {plan_path}")
    if getattr(args, "demo", False) and not plan_path:
        plan = _demo_auto_plan()
        plan_id = plan.get("planId", "DEMO-AUTO")
        items = plan.get("items", [])
        if not items:
            print("[*] Mode DEMO: tidak ada temuan FAIL/WARNING yang bisa diperbaiki otomatis.")
            return
        print(f"[*] Mode DEMO: plan otomatis {plan_id} ({len(items)} tindakan).")
    else:
        if not plan_path or not os.path.exists(plan_path):
            print("[!] File rencana remediasi tidak ditemukan.")
            return
        with open(plan_path, "r") as f:
            plan = json.load(f)
        if isinstance(plan, dict) and "plan" in plan and isinstance(plan["plan"], dict):
            plan = plan["plan"]
        plan_id = plan.get("planId", "UNKNOWN")
        items = plan.get("items", [])
        if not items:
            print("[!] Rencana tidak memiliki items.")
            return

    # Allowlist check: semua alias harus terdaftar; OS cocok.
    current_os = platform.system().lower()
    for item in items:
        alias = item.get("alias", "")
        entry = ALLOWLIST_ANALISA.get(alias)
        if not entry:
            print(f"[!] Alias '{alias}' TIDAK ada di allowlist agent — ditolak.")
            return
        if entry["os"] not in (current_os, "any"):
            print(f"[!] Alias '{alias}' hanya untuk OS {entry['os']} — host ini {current_os}.")
            return

    access_blocking, access_notes = _access_preflight(items)
    if access_notes:
        print("[!] ==================== PERINGATAN JALUR AKSES ====================")
        for note in access_notes:
            print(f"    - {note}")
        print("[!] ===============================================================")

    if getattr(args, "demo", False):
        print("[*] Mode DEMO: melewati validasi token (hanya untuk presentasi/demo).")
        if not args.no_exec and not _is_elevated():
            print("[!] DEMO butuh admin/root. Jalankan sebagai Administrator (Windows) atau sudo (Linux).")
            _notify_admin_needed()
            return
    else:
        if not args.hmac_key:
            print("[!] --hmac-key (HMAC_SECRET) wajib diisi untuk memverifikasi signature plan.")
            print("    Salin nilai HMAC_SECRET dari .env server, contoh:")
            print("    --hmac-key \"<HMAC_SECRET>\"")
            return
        ok, msg = _validate_remediation_token(plan, args.remediate_token, args.hmac_key)
        print(f"[*] Validasi token persetujuan: {msg}")
        if not ok:
            print("[!] Remediasi DIBATALKAN. Agent tetap read-only.")
            return
        if not args.no_exec and not _is_elevated():
            print("[!] Eksekusi butuh admin/root. Jalankan sebagai Administrator (Windows) atau sudo (Linux).")
            _notify_admin_needed()
            return

    # Tanpa URL push, evidence tidak akan pernah sampai dan plan menggantung.
    if not args.no_exec and not args.push_url and not getattr(args, "demo", False):
        print("[!] --push-url wajib untuk eksekusi nyata (evidence harus dikirim ke server).")
        print("    Contoh: --push-url http://<server>:3000")
        return
    if not args.no_exec and not args.push_url and getattr(args, "demo", False):
        print("[*] Mode DEMO tanpa --push-url: evidence hanya dicetak di terminal (tidak dikirim).")

    if access_blocking and not args.no_exec and not getattr(args, "force_access_risk", False):
        print("[!] Eksekusi DITAHAN: plan memblokir akses remote yang sedang dipakai.")
        print("    Punya konsol/KVM/IPMI? Ulangi dengan --force-access-risk.")
        print("    Ingin meninjau dulu tanpa perubahan? Tambahkan --no-exec.")
        return

    print(f"[*] Rencana {plan_id}: {len(items)} tindakan. Mode: {'--no-exec (tanpa perubahan)' if args.no_exec else 'EKSEKUSI AKTUAL'}")

    _ESCROW_DEVICE = str(plan.get("deviceId") or "UNKNOWN")
    if getattr(args, "host_id", None):
        print(f"[*] Host ID: {args.host_id}")

    deadman_seconds = int(getattr(args, "deadman_seconds", 0) or 0)
    if not args.no_exec and deadman_seconds > 0 and any(
        not ALLOWLIST_ANALISA[i["alias"]].get("advisory") for i in items
    ):
        try:
            target = _deadman_arm(plan_id, deadman_seconds)
            print(f"[*] DEAD-MAN AKTIF: rollback otomatis dalam {deadman_seconds} dtk bila tidak dikonfirmasi.")
            print(f"    target: {target}")
        except Exception as exc:
            print(f"[!] Dead-man gagal dipasang: {exc}")

    backup_meta = []
    evidence = []
    evidence_by_step = {}
    to_status = "VERIFIED"

    # --resume: lanjutkan plan EXECUTING yang terputus tanpa mengulang langkah
    # yang sudah terverifikasi. Bukti lama ikut dibawa agar cakupan tetap lengkap.
    resume = bool(getattr(args, "resume", False))
    if resume:
        aliases_in_plan = {i.get("alias") for i in items}
        for prior in (plan.get("evidence") or []):
            if not isinstance(prior, dict) or prior.get("alias") not in aliases_in_plan:
                continue
            if int(prior.get("exitCode") or 0) == 0 and (prior.get("verified") is True or prior.get("advisory") is True):
                evidence.append(prior)
        if evidence:
            print(f"[*] RESUME: {len(evidence)} langkah sudah terverifikasi, dilewati.")
    done_aliases = {e.get("alias") for e in evidence}

    for idx, item in enumerate(items):
        alias = item["alias"]
        entry = ALLOWLIST_ANALISA[alias]
        if resume and alias in done_aliases:
            print(f"  [{idx+1}/{len(items)}] {alias} | dilewati (sudah terverifikasi)")
            continue
        pre_state = entry["read"]()
        print(f"  [{idx+1}/{len(items)}] {alias} | pre-state: {json.dumps(pre_state)[:160]}")
        if args.no_exec:
            continue
        if alias in ADVISORY_ALIASES:
            # Langkah advisory: read-only, tidak memicu rollback plan.
            try:
                adv_ok = bool(entry["verify"]())
            except Exception:
                adv_ok = False
            ev_entry = {
                "stepIndex": idx,
                "alias": alias,
                "exitCode": 0,
                "outputHash": _hash_state(pre_state),
                "preStateHash": _hash_state(pre_state),
                "verified": adv_ok,
                "advisory": True,
            }
            evidence.append(ev_entry)
            evidence_by_step[alias] = ev_entry
            print(f"    advisory: {'SESUAI' if adv_ok else 'PERLU TINDAKAN MANUAL'} (tidak memblokir plan)")
            continue
        backup_path = _backup_snapshot(plan_id, alias, pre_state)
        backup_meta.append({"alias": alias, "path": backup_path, "preState": pre_state})
        res = entry["apply"]()
        exit_code = res.get("exitCode", 0) if isinstance(res, dict) else 0
        if isinstance(res, dict) and res.get("recoveryKey"):
            # Kunci pemulihan BitLocker WAJIB disimpan: tanpa ini volume bisa terkunci permanen.
            key_path = os.path.join(_remediation_backup_dir(), f"{plan_id}_bitlocker-recovery.txt")
            try:
                os.makedirs(_remediation_backup_dir(), exist_ok=True)
                with open(key_path, "w") as kf:
                    kf.write(res["recoveryKey"] + "\n")
                try:
                    os.chmod(key_path, 0o600)
                except Exception:
                    pass
                print(f"    [!] RECOVERY KEY BitLocker: {res['recoveryKey']}")
                print(f"        disimpan di: {key_path}")
            except Exception as exc:
                print(f"    [!] Simpan recovery key GAGAL: {exc}. Salin manual: {res['recoveryKey']}")
        if isinstance(res, dict) and res.get("bootPassword"):
            pw_path = os.path.join(_remediation_backup_dir(), f"{plan_id}_bitlocker-boot-password.txt")
            try:
                with open(pw_path, "w") as pf:
                    pf.write(res["bootPassword"] + "\n")
                try:
                    os.chmod(pw_path, 0o600)
                except Exception:
                    pass
                print(f"    [!] PASSWORD BOOT BitLocker: {res['bootPassword']}")
                print(f"        disimpan di: {pw_path}")
            except Exception as exc:
                print(f"    [!] Simpan password boot GAGAL: {exc}. Salin manual: {res['bootPassword']}")
        if isinstance(res, dict) and (res.get("recoveryKey") or res.get("bootPassword")):
            # Escrow server: redundansi bila host terkunci / file lokal hilang.
            if res.get("recoveryKey"):
                ok = _escrow_push("recovery", res["recoveryKey"])
                print("    escrow recovery key ke server: " + ("OK" if ok else "GAGAL (file lokal tetap ada)"))
            if res.get("bootPassword"):
                ok = _escrow_push("bootpw", res["bootPassword"])
                print("    escrow password boot ke server: " + ("OK" if ok else "GAGAL (file lokal tetap ada)"))
        verified = False
        try:
            verified = bool(entry["verify"]())
        except Exception:
            verified = False
        post_state = {}
        try:
            post_state = entry["read"]()
        except Exception:
            post_state = {"error": "post-state tidak terbaca"}
        ev_entry = {
            "stepIndex": idx,
            "alias": alias,
            "exitCode": int(exit_code) if isinstance(exit_code, (int, float)) else 0,
            # Hash menggambarkan output nyata: pre-state, hasil apply, dan post-state.
            "outputHash": _hash_state({"pre": pre_state, "apply": res, "post": post_state}),
            "preStateHash": _hash_state(pre_state),
            "output": str(res.get("output", ""))[:400] if isinstance(res, dict) else "",
            "verified": verified
        }
        evidence.append(ev_entry)
        evidence_by_step[alias] = ev_entry
        if not verified:
            if ev_entry.get("output"):
                print(f"    output: {ev_entry['output'][:400].replace(chr(10), ' ')}")
            print(f"[!] Verifikasi gagal pada langkah {alias}. Menghentikan eksekusi (stop-on-failure).")
            rollback_failures = 0
            for meta in reversed(backup_meta):
                ralias = meta["alias"]
                bp = meta["path"]
                entry_rb = ALLOWLIST_ANALISA.get(ralias, {})
                try:
                    pre = _restore_from_snapshot(bp)
                    if "rollback" in entry_rb:
                        rb_res = entry_rb["rollback"](pre)
                        rb_rc = rb_res.get("exitCode") if isinstance(rb_res, dict) else 0
                        rb_out = rb_res.get("output", "") if isinstance(rb_res, dict) else ""
                        rb_verified = False
                        state_matched = False
                        try:
                            if "rollback_state" in entry_rb:
                                now_state = entry_rb["rollback_state"]()
                                keys = set(now_state) if isinstance(now_state, dict) else set()
                                state_matched = _comparable_state(now_state) == _comparable_state(
                                    {k: pre.get(k) for k in keys} if isinstance(pre, dict) else {}
                                )
                            else:
                                state_matched = _comparable_state(entry_rb["read"]()) == _comparable_state(pre)
                        except Exception:
                            state_matched = False
                        rb_verified = state_matched
                        if not state_matched and isinstance(rb_res, dict) and rb_res.get("output"):
                            print(f"    output rollback: {str(rb_res['output'])[:200]}")
                        print(f"    rollback {ralias} dari snapshot {os.path.basename(bp)} -> exitCode {rb_rc}")
                        if ralias in evidence_by_step:
                            evidence_by_step[ralias]["rollback"] = {
                                "exitCode": int(rb_rc) if isinstance(rb_rc, (int, float)) else 0,
                                "verified": rb_verified,
                                "outputHash": _hash_state({"pre": pre, "apply": rb_res, "output": rb_out})
                            }
                        if not state_matched:
                            rollback_failures += 1
                    else:
                        print(f"    rollback snapshot: {os.path.basename(bp)} (tidak ada handler rollback untuk {ralias}; pulihkan manual dari snapshot)")
                        rollback_failures += 1
                except Exception as e:
                    print(f"    rollback {ralias} gagal: {e}")
                    rollback_failures += 1
            to_status = "ROLLED_BACK"
            if rollback_failures:
                print(f"[!] {rollback_failures} langkah rollback tidak bersih — periksa backup di {_remediation_backup_dir()}")
            break

    if not args.no_exec and to_status in ("VERIFIED", "ROLLED_BACK"):
        _deadman_disarm(plan_id)
        print("[*] Dead-man dibatalkan (hasil sudah final).")

    if args.no_exec:
        append_history({
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "unit": plan.get("deviceId", "UNKNOWN"),
            "hostname": platform.node(),
            "operator": get_current_user(),
            "mode": "remediation-noexec",
            "planId": plan_id,
            "status": "NO_EXEC",
            "steps": len(items),
            "elevated": _is_elevated(),
            "elevation_method": _elevation_method(),
            "score": None, "pass": None, "warn": None, "fail": None,
        })
        print("[+] Mode --no-exec selesai: tidak ada perubahan sistem. Agent tetap read-only.")
        return

    append_history({
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "unit": plan.get("deviceId", "UNKNOWN"),
        "hostname": platform.node(),
        "operator": get_current_user(),
        "mode": "remediation",
        "planId": plan_id,
        "status": to_status,
        "steps": len(evidence),
        "elevated": _is_elevated(),
        "elevation_method": _elevation_method(),
        "score": None, "pass": None, "warn": None, "fail": None,
    })

    demo_plan = str(plan_id).startswith("DEMO")
    post_audit = None
    if to_status == "VERIFIED" and not demo_plan:
        try:
            print("[*] Audit ulang pasca-remediasi (bukti perubahan nyata)...")
            fresh = run_full_audit(plan.get("deviceId", "UNKNOWN"))
            post_audit = {"scoring": fresh.get("scoring"), "compliance_matrix": fresh.get("compliance_matrix")}
            score = (fresh.get("scoring") or {}).get("cyber_readiness_score")
            print(f"    skor pasca-remediasi: {score}/100")
        except Exception as exc:
            print(f"[!] Audit ulang gagal ({exc}); server akan menolak VERIFIED.")
    if args.push_url and not demo_plan:
        try:
            rc = _push_remediation_evidence(
                args.push_url, args.remediate_api_key, plan_id, plan.get("nonce", ""),
                to_status, evidence, args.hmac_key, post_audit
            )
            print(f"[+] Evidence terkirim ke server ({rc}).")
        except Exception as e:
            print(f"[!] Gagal mengirim evidence: {e}")
            print(f"    Evidence lokal tetap tercatat; backup ada di {_remediation_backup_dir()}")
    elif demo_plan:
        print("[*] Plan DEMO tidak terdaftar di server; evidence hanya dicetak (tanpa push).")
        print(f"    Status akhir: {to_status} | {len(evidence)} langkah | backup: {_remediation_backup_dir()}")
# -------------------------------------------------
# EMERGENCY NETWORK QUARANTINE SWITCH (KILL-SWITCH)
# ==============================================================================
def verify_agent_manifest(args):
    """Bandingkan hash agen lokal dengan manifest server. True bila cocok."""
    base = (getattr(args, "server", None) or "").rstrip("/")
    if not base:
        print("[!] --verify-manifest butuh --server.")
        return False
    req = urllib.request.Request(base + "/api/agent/manifest", headers={"User-Agent": "PASOPATI-Agent/2.7"}, method="GET")
    try:
        with _urlopen(req, 10) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception as exc:
        print(f"[!] Manifest tidak dapat diambil: {exc}")
        return False
    problems = []
    for entry in data.get("files") or []:
        name = entry.get("name")
        remote = entry.get("sha256")
        local_path = os.path.join(ROOT_DIR, str(name))
        if not remote:
            problems.append(f"{name}: server tidak punya hash")
            continue
        try:
            with open(local_path, "rb") as f:
                local = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            problems.append(f"{name}: berkas lokal tidak ada")
            continue
        if local != remote:
            problems.append(f"{name}: hash beda ({local[:12]} != {str(remote)[:12]})")
    signature = data.get("signature")
    key = getattr(args, "manifest_key", "") or os.environ.get("AGENT_SIGNING_KEY", "")
    if signature and key:
        canonical = json.dumps(data.get("files") or [], sort_keys=True, separators=(",", ":"))
        expected = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(signature)):
            problems.append("tanda tangan manifest tidak valid")
    elif signature:
        print("[i] Manifest bertanda tangan, tetapi --manifest-key/AGENT_SIGNING_KEY tidak diset.")
    if problems:
        print("[!] Manifest TIDAK cocok:")
        for problem in problems:
            print(f"    - {problem}")
        return False
    print(f"[+] Manifest agen cocok (versi {data.get('version')}, {len(data.get('files') or [])} berkas).")
    return True

def _fetch_pending_plans(args):
    base = (getattr(args, "server", None) or "").rstrip("/")
    if not base:
        raise RuntimeError("--server wajib diisi untuk --watch")
    req = urllib.request.Request(
        base + "/api/hosts/me/plans",
        headers={"User-Agent": "PASOPATI-Agent/2.7", **_auth_headers()},
        method="GET",
    )
    with _urlopen(req, 10) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return [p for p in (data.get("plans") or []) if isinstance(p, dict) and p.get("planId")]


def run_watch(args):
    global _HOST_KEY, _CA_CERT, _INSECURE
    _HOST_KEY = getattr(args, "host_key", "") or os.environ.get("PASOPATI_HOST_KEY", "")
    _CA_CERT = getattr(args, "ca_cert", "") or ""
    _INSECURE = bool(getattr(args, "insecure", False))
    if not _HOST_KEY:
        print("[!] --watch butuh --host-key (host ter-enrol) atau env PASOPATI_HOST_KEY.")
        return
    interval = max(int(getattr(args, "interval", 60) or 60), 10)
    attempted = {}
    print(f"[*] Watch mode aktif. Polling tiap {interval} dtk (Ctrl+C untuk berhenti).")
    while True:
        try:
            pending = _fetch_pending_plans(args)
        except Exception as exc:
            print(f"[!] Polling gagal: {exc}")
            pending = []
        for plan in pending:
            plan_id = plan["planId"]
            last = attempted.get(plan_id)
            if last and time.time() - last < interval * 5:
                continue
            attempted[plan_id] = time.time()
            print(f"[*] Plan {plan_id} ({plan.get('items')} langkah) dijalankan otomatis.")
            child = argparse.Namespace(**vars(args))
            child.plan_id = plan_id
            child.remediate_plan = None
            child.remediate_token = None
            child.demo = False
            child.force_access_risk = True  # unattended: preflight hanya peringatan
            try:
                run_remediation(child)
            except Exception as exc:
                print(f"[!] Plan {plan_id} gagal: {exc}")
        time.sleep(interval)


def _iptables_ensure(args):
    """Tambahkan rule iptables hanya bila belum ada (idempoten)."""
    if subprocess.run(["iptables", "-C"] + args, capture_output=True).returncode == 0:
        return
    subprocess.run(["iptables", "-A"] + args, check=False)


def trigger_emergency_quarantine(dry_run=False, release=False):
    current_os = platform.system().lower()
    action = "RELEASE (KEMBALI KE PERIMETER NORMAL)" if release else "KILL-SWITCH DEFCON 1"
    print("\n[!] ================================================================")
    print(f"[!] {action}...")
    print("[!] ================================================================")

    if dry_run:
        print("[DRY-RUN] Perintah isolasi firewall akan dievaluasi tanpa diterapkan.")
        if 'linux' in current_os:
            if release:
                print("  [DRY-RUN] iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT + hapus rule PASOPATI")
            else:
                print("  [DRY-RUN] iptables -P INPUT DROP && iptables -P FORWARD DROP")
                print("  [DRY-RUN] izinkan loopback + koneksi ESTABLISHED/RELATED")
        else:
            policy = "blockinbound,allowoutbound" if release else "blockinbound,blockoutbound"
            print(f"  [DRY-RUN] netsh advfirewall set allprofiles firewallpolicy {policy}")
        return True

    try:
        if 'linux' in current_os:
            if release:
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=False)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
                subprocess.run(["iptables", "-D", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=False)
                subprocess.run(["iptables", "-D", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=False)
                print("[+] [PERIMETER NORMAL] Policy dikembalikan ke ACCEPT dan rule karantina dihapus.")
            else:
                # Drop inbound/forward, tetap izinkan loopback + sesi yang sudah berjalan (SSH/forensik).
                _iptables_ensure(["-i", "lo", "-j", "ACCEPT"])
                _iptables_ensure(["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
                subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=False)
                subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=False)
                print("[+] [TERISOLASI] Inbound/forward di-DROP; loopback & sesi berjalan tetap diizinkan.")
                print("    Lepas dengan: python3 pasopati_remediate.py --quarantine --quarantine-release")
        elif 'windows' in current_os:
            policy = "blockinbound,allowoutbound" if release else "blockinbound,blockoutbound"
            proc = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy],
                capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                print(f"[!] netsh gagal (rc={proc.returncode}): {(proc.stdout or '') + (proc.stderr or '')}".strip()[:300])
                return False
            print("[+] [PERIMETER NORMAL] Windows Firewall kembali ke blockinbound,allowoutbound." if release
                  else "[+] [TERISOLASI] Windows Defender Firewall memblokir inbound+outbound.")
        return True
    except Exception as e:
        print(f"[!] Gagal menerapkan karantina jaringan: {str(e)}")
        return False

def main(argv=None, entry_script=None, parser_only=False):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description="PASOPATI Audit Agent v2.6 (pemeriksaan endpoint)")
    parser.add_argument("-o", "--output", default="audit.json", help="Path file keluaran JSON (default: audit.json)")
    parser.add_argument("-u", "--unit", default="PASOPATI-LOCAL-NODE", help="Kode identitas unit taktis (contoh: SRV-KOMPI-B)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Jalankan tanpa output visual banner")
    parser.add_argument("--push-url", default=None, help="URL endpoint Puskodal/Server untuk telemetry push otomatis")
    parser.add_argument("--hmac-key", default=os.environ.get("HMAC_SECRET"), help="Kunci rahasia pra-bagi untuk tanda tangan HMAC-SHA256 (default: env HMAC_SECRET)")
    parser.add_argument("--dry-run", action="store_true", help="Jalankan dalam mode simulasi/evaluasi kompatibilitas tanpa modifikasi")
    parser.add_argument("--quarantine", action="store_true", help="Picu darurat Kill-Switch isolasi firewall perangkat (DEFCON 1)")
    parser.add_argument("--quarantine-release", action="store_true", help="Lepas karantina: kembalikan policy firewall ke perimeter normal")
    parser.add_argument("--remediate-plan", default=None, help="Path JSON rencana remediasi (dari server /api/remediation-plan)")
    parser.add_argument("--server", default=None, help="Base URL server, mis. http://192.168.1.10:3000 (untuk --plan-id)")
    parser.add_argument("--plan-id", default=None, help="Ambil plan yang sudah disetujui langsung dari server (target tidak perlu plan.json)")
    parser.add_argument("--remediate-token", default=None, help="Token persetujuan dari server (format: nonce.signature)")
    parser.add_argument("--remediate-api-key", default=os.environ.get("PASOPATI_API_KEY"), help="API key Puskodal untuk pengiriman evidence (default: env PASOPATI_API_KEY)")
    parser.add_argument("--no-exec", action="store_true", help="Mode aman: validasi token & tampilkan rencana tanpa melakukan perubahan apa pun")
    parser.add_argument("--demo", action="store_true", help="Mode DEMO sekali-klik: lewati token + buat plan otomatis dari audit. Tetap butuh admin/root untuk eksekusi.")
    parser.add_argument("--no-elevate", action="store_true", help="Jangan meminta root/UAC otomatis (audit jalan dengan hak saat ini)")
    parser.add_argument("--force-access-risk", action="store_true", help="Lanjut walau plan memblokir kanal akses remote (pastikan ada konsol/KVM)")
    parser.add_argument("--deadman-seconds", type=int, default=_env_int(DEADMAN_ENV, DEFAULT_DEADMAN_SECONDS), help="Rollback otomatis bila hasil tak dikonfirmasi dalam N detik (0 = mati)")
    parser.add_argument("--deadman-rollback", nargs=2, metavar=("PLAN_ID", "BACKUP_DIR"), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--resume", action="store_true", help="Lanjutkan plan EXECUTING yang terputus; lewati langkah yang sudah terverifikasi")
    parser.add_argument("--host-key", default=os.environ.get("PASOPATI_HOST_KEY"), help="Kunci host ter-enrol (X-Pasopati-Host-Key); env PASOPATI_HOST_KEY")
    parser.add_argument("--host-id", default=os.environ.get("PASOPATI_HOST_ID"), help="ID host ter-enrol (informasi/log)")
    parser.add_argument("--ca-cert", default=None, help="Path CA PEM untuk memverifikasi server HTTPS (pinning)")
    parser.add_argument("--insecure", action="store_true", help="Matikan verifikasi sertifikat TLS server")
    parser.add_argument("--watch", action="store_true", help="Polling plan terikat milik host lalu jalankan otomatis (butuh --host-key)")
    parser.add_argument("--interval", type=int, default=60, help="Detik antar polling --watch (min 10)")
    parser.add_argument("--profile", choices=("standard", "none"), default="standard", help="Paket profil kontrol deklaratif (default: standard)")
    parser.add_argument("--verify-manifest", action="store_true", help="Bandingkan hash agen lokal dengan manifest server")
    parser.add_argument("--strict-manifest", action="store_true", help="Batal bila manifest tidak cocok/mengandung berkas berbeda")
    parser.add_argument("--manifest-key", default=os.environ.get("AGENT_SIGNING_KEY"), help="Kunci HMAC untuk memverifikasi tanda tangan manifest")
    parser.add_argument("--list-aliases", action="store_true", help="Tampilkan alias remediasi dipisah per OS (windows/linux/any) lalu keluar")
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    if parser_only:
        return parser
    args = parser.parse_args(argv)
    if args.list_aliases:
        print_aliases_by_os()
        return
    global AUDIT_PROFILE
    AUDIT_PROFILE = args.profile

    # Normalisasi path sebelum elevasi agar tidak bergantung cwd jendela Administrator.
    args.output = os.path.abspath(args.output)
    if args.server:
        args.server = args.server.rstrip("/")
    if args.plan_id and not args.push_url and args.server:
        args.push_url = args.server
    if args.remediate_plan:
        args.remediate_plan = os.path.abspath(args.remediate_plan)

    # SEMUA mode meminta hak root/Administrator; tanpa itu banyak kontrol tidak terbaca.
    ensure_elevated(argv, entry_script)
    if getattr(args, "elevated", False):
        atexit.register(_elevated_finish)

    if args.verify_manifest:
        ok = verify_agent_manifest(args)
        if not ok and args.strict_manifest:
            sys.exit(2)
        if not args.remediate_plan and not args.plan_id and not args.demo and not args.watch:
            return

    if args.watch:
        run_watch(args)
        return

    if args.remediate_plan or args.plan_id or args.demo:
        run_remediation(args)
        return

    if args.deadman_rollback:
        run_deadman_rollback(args.deadman_rollback[0], args.deadman_rollback[1])
        return

    # Penting: --quarantine-release juga harus jalan tanpa flag --quarantine.
    if args.quarantine or args.quarantine_release:
        ok_q = trigger_emergency_quarantine(dry_run=args.dry_run, release=args.quarantine_release)
        append_history({
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "unit": args.unit,
            "hostname": platform.node(),
            "operator": get_current_user(),
            "mode": "quarantine-release" if args.quarantine_release else "quarantine",
            "status": "OK" if ok_q else "FAILED",
            "steps": None,
            "elevated": _is_elevated(),
            "elevation_method": _elevation_method(),
            "score": None, "pass": None, "warn": None, "fail": None,
        })
        if not ok_q:
            print("[!] Perubahan kebijakan firewall gagal. Pulihkan manual: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound")
        return

    if not args.quiet:
        print("""
========================================================================
 [!] PASOPATI v2.6: Deep Tactical Cyber & Integrity Auditor
 Baseline: CIS Benchmark v8.0 | DISA STIG | ISA/IEC 62443
========================================================================
        """)
        
    started_at = datetime.datetime.now().isoformat(timespec="seconds")
    history_before = read_history()

    result = run_full_audit(unit_name=args.unit)

    history_entry = {
        "timestamp": started_at,
        "unit": args.unit,
        "hostname": result["device_info"]["hostname"],
        "operator": result["device_info"]["active_user"],
        "mode": "audit",
        "elevated": _is_elevated(),
        "elevation_method": _elevation_method(),
        "score": result["scoring"]["cyber_readiness_score"],
        "pass": result["scoring"]["passed_checks"],
        "warn": result["scoring"]["warning_checks"],
        "fail": result["scoring"]["failed_checks"],
    }
    history, history_path = append_history(history_entry)

    result["metadata"]["audit_version"] = "2.6"
    result["metadata"]["output_file"] = args.output
    result["execution"] = {
        "timestamp": started_at,
        "hostname": result["device_info"]["hostname"],
        "operator": result["device_info"]["active_user"],
        "elevated": _is_elevated(),
        "elevation_method": _elevation_method(),
        "history_file": history_path,
        "history": history,
    }

    # Tulis atomik supaya audit.json tidak pernah setengah jadi.
    tmp_path = args.output + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(result, f, indent=2)
    _atomic_replace(tmp_path, args.output)
    try:
        os.chmod(args.output, 0o600)
    except Exception:
        pass

    print(f"\n[+] Deep Audit Selesai! Skor Kesiapan Siber: {result['scoring']['cyber_readiness_score']}/100")
    print(f"[+] PASS: {result['scoring']['passed_checks']} | WARN: {result['scoring']['warning_checks']} | FAIL: {result['scoring']['failed_checks']}")
    print(f"[+] Total Parameter Terinspeksi: {result['scoring']['total_checks']} parameter")
    print(f"[+] Hasil audit tersimpan rapi di: {os.path.abspath(args.output)}")
    
    if args.push_url:
        push_telemetry(result, args.push_url, secret_key=args.hmac_key)
    else:
        print("[+] Unggah file ini ke Tab Agent & Upload Dashboard PASOPATI untuk analisis & hardening mendalam!")

if __name__ == "__main__":
    main()
