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
import uuid
import tempfile
import atexit
import hmac
import hashlib
import re
import secrets
import time
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
            return open_ports
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
    return open_ports

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
        bitlocker_query_ok = True
        try:
            res = subprocess.run(["manage-bde", "-status", "C:"], capture_output=True, text=True, timeout=4)
            if "Protection On" in res.stdout or "Perlindungan Aktif" in res.stdout or "Percentage Encrypted: 100" in res.stdout:
                bitlocker_active = True
        except Exception:
            bitlocker_query_ok = False

        findings.append({
            "parameter": "BitLocker Drive Encryption (FDE)",
            "category": "Cryptographic Posture",
            "cis_id": "DISA STIG WN11-00-000025",
            "status": "PASS" if bitlocker_active else ("FAIL" if bitlocker_query_ok else "WARNING"),
            "details": "Volume sistem C: terproteksi BitLocker XTS-AES 256-bit." if bitlocker_active else "Volume C: tidak terenkripsi BitLocker! Data taktis berisiko dicuri via physical extraction."
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
        try:
            rc, out = subprocess.run(["reg", "query", _USBSTOR_KEY, "/v", "Start"], capture_output=True, text=True, timeout=4)
            m = __import__("re").search(r"Start\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)", out or "")
            if rc == 0 and m:
                blocked = int(m.group(1), 0) == 4
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
        except Exception:
            return {
                "parameter": "USB Storage Device Control",
                "category": "Endpoint Protection",
                "cis_id": "DISA STIG WN11-CC-000180",
                "status": "WARNING",
                "details": "Verifikasi kebijakan USB Mass Storage memerlukan hak administrator."
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
                ev_status = "FAIL"
                ev_details = "Windows Event Log Security tidak dapat diakses/query."
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
            "scanner": "PASOPATI Autonomous Deep Agent v2.6",
            "timestamp": timestamp,
            "tactical_unit": unit_name,
            "standard_baseline": "CIS Benchmark v8.0, DISA STIG, ISA/IEC 62443 Deep Baseline",
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
    path = os.path.join(os.path.expanduser("~"), ".pasopati", "backups")
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
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
    os.replace(tmp, path)

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

def _win_bitlocker_state():
    """Baca status via PowerShell (JSON stabil, tidak bergantung lokalisasi/manage-bde)."""
    cmd = (
        "$v=Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop; "
        "@{p=[string]$v.ProtectionStatus; e=[int]$v.EncryptionPercentage; "
        "k=@($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }); "
        "r=@($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | "
        "ForEach-Object { [string]$_.RecoveryPassword })} | ConvertTo-Json -Compress"
    )
    rc, out = _win_ps(cmd, 15)
    try:
        data = json.loads((out or "").strip().splitlines()[-1])
        protection = str(data.get("p", "")).strip().lower()
        return {
            "protectionOn": protection in ("on", "1", "true"),
            "encrypted": int(data.get("e", 0)) >= 100,
            "protectors": list(data.get("k") or []),
            "recoveryKeys": [k for k in (data.get("r") or []) if k],
        }
    except Exception:
        rc2, raw = _run_no_shell(["manage-bde", "-status", "C:"], 10)
        low = raw or ""
        return {
            "protectionOn": ("Protection On" in low) or ("Perlindungan Aktif" in low),
            "encrypted": "100.0%" in low,
            "protectors": [],
            "recoveryKeys": [],
            "raw": low[:300],
        }

def _win_tpm_ready():
    rc, out = _win_ps(
        "try { $t=Get-Tpm; if ($t.TpmPresent -and $t.TpmReady) { 'yes' } else { 'no' } } catch { 'no' }", 15)
    return "yes" in (out or "").lower()

def _win_bitlocker_add_protector(kind, timeout=20):
    if kind == "recovery":
        return _win_ps("Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector | Out-Null", timeout)
    if kind == "tpm":
        return _win_ps("Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector | Out-Null", timeout)
    pw = secrets.token_urlsafe(18)
    rc, out = _win_ps(
        "$p=ConvertTo-SecureString '" + pw + "' -AsPlainText -Force; "
        "Add-BitLockerKeyProtector -MountPoint 'C:' -PasswordProtector -Password $p | Out-Null", timeout)
    return rc, out, pw

def _win_bitlocker_apply():
    st = _win_bitlocker_state()
    if st.get("protectionOn"):
        return {"exitCode": 0, "output": "BitLocker sudah aktif (idempoten)", "recoveryKey": ""}

    protectors = st.get("protectors") or []
    tpm_ready = _win_tpm_ready()
    boot_pw = None

    if "RecoveryPassword" not in protectors:
        _win_bitlocker_add_protector("recovery")

    if st.get("encrypted"):
        # Volume sudah terenkripsi → pastikan ada protector yang bisa membuka, lalu resume.
        if not tpm_ready and "Password" not in protectors:
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
            boot_pw = secrets.token_urlsafe(18)
            rc, out = _win_ps(
                "$p=ConvertTo-SecureString '" + boot_pw + "' -AsPlainText -Force; "
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 "
                "-PasswordProtector -Password $p -SkipHardwareTest -ErrorAction Stop | Out-Null", 30)
            if rc == 0:
                _win_bitlocker_add_protector("recovery")
        if rc != 0:
            return {"exitCode": 1, "output": "enable gagal: " + (out or "")[:300], "recoveryKey": ""}

    st = _win_bitlocker_state()
    if not st.get("protectionOn") and not st.get("encrypted"):
        return {"exitCode": 1, "output": "enkripsi tidak terdeteksi aktif setelah perintah", "recoveryKey": ""}
    keys = st.get("recoveryKeys") or []
    res = {
        "exitCode": 0 if st.get("protectionOn") else 1,
        "output": "proteksi BitLocker aktif" if st.get("protectionOn") else "proteksi belum aktif",
        "recoveryKey": keys[-1] if keys else "",
    }
    if boot_pw:
        res["bootPassword"] = boot_pw
    return res

def _win_bitlocker_verify():
    return _win_bitlocker_state().get("protectionOn") is True
def _win_bitlocker_rollback(pre):
    # Aktif sebelum remediasi → biarkan aktif.
    if isinstance(pre, dict) and pre.get("protectionOn") is True:
        return {"exitCode": 0, "output": "BitLocker sudah aktif sebelum remediasi; dibiarkan aktif"}
    # Sudah terenkripsi tapi proteksi mati → suspend, jangan dekripsi (lama).
    if isinstance(pre, dict) and pre.get("encrypted") is True:
        rc, out = _win_ps("Suspend-BitLocker -MountPoint 'C:' -Force | Out-Null", 20)
        return {"exitCode": rc, "output": ("proteksi disuspend (tetap terenkripsi). " + out[:150]) if rc == 0 else out}
    rc, out = _run_no_shell(["manage-bde", "-off", "C:"], 15)
    return {"exitCode": rc, "output": out}

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
def _sudoers_files():
    files = ['/etc/sudoers']
    d = '/etc/sudoers.d'
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isfile(p) and not name.endswith(('~', '.bak', '.tmp')):
                files.append(p)
    return [p for p in files if os.path.isfile(p)]
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
    errors = []
    for p in st["files"]:
        try:
            mode = os.stat(p).st_mode
            os.chmod(p, mode | 0o200)
            with open(p, 'r', errors='ignore') as f:
                content = f.read()
            new_content = "\n".join(
                line.replace("NOPASSWD:", "") if not line.strip().startswith('#') else line
                for line in content.splitlines()
            ) + "\n"
            with open(p, 'w') as f:
                f.write(new_content)
            os.chmod(p, mode)
        except Exception as e:
            errors.append(f"{p}: {e}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "NOPASSWD dihapus dari sudoers"}
def _linux_sudoers_verify():
    return _linux_sudoers_state()["clean"] is True
def _linux_sudoers_rollback(pre):
    files = pre.get("files") if isinstance(pre, dict) else None
    if not files:
        return {"exitCode": 0, "output": "tidak ada perubahan sudoers untuk dipulihkan"}
    errors = []
    for p, meta in files.items():
        try:
            mode = os.stat(p).st_mode
            os.chmod(p, mode | 0o200)
            with open(p, 'w') as f:
                f.write(meta.get("content", ""))
            os.chmod(p, int(meta["mode"], 8) if meta.get("mode") else mode)
        except Exception as e:
            errors.append(f"{p}: {e}")
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
    return {"listening": listening, "blocked": blocked, "open": [p for p in listening if p not in blocked]}

def _linux_ports_apply():
    st = _linux_ports_state()
    errors = []
    for port in st["open"]:
        if not _linux_port_rule_exists(port):
            rc, out = _run_no_shell(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], 10)
            if rc != 0:
                errors.append(f"{port}: {out[:120]}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or f"port diblokir: {st['open']}"}

def _linux_ports_verify():
    st = _linux_ports_state()
    return all(p in st["blocked"] for p in st["listening"])

def _linux_ports_rollback(pre):
    ports = pre.get("open") if isinstance(pre, dict) else None
    if not ports:
        return {"exitCode": 0, "output": "tidak ada rule yang perlu dihapus"}
    errors = []
    for port in ports:
        rc, out = _run_no_shell(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], 10)
        if rc != 0:
            errors.append(f"{port}: {out[:120]}")
    return {"exitCode": 0 if not errors else -1, "output": "; ".join(errors) or "rule blokir dihapus"}

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
        "rollback": _win_bitlocker_rollback
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
    headers = {"User-Agent": "PASOPATI-Agent/2.5"}
    if api_key:
        headers["X-Pasopati-API-Key"] = api_key
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
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


def _push_remediation_evidence(server_url, api_key, plan_id, nonce, to_status, evidence, hmac_key=None):
    url = server_url.rstrip("/") + "/api/remediation-verify"
    body = json.dumps({"planId": plan_id, "nonce": nonce, "toStatus": to_status, "evidence": evidence}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "PASOPATI-Agent/2.6",
        **({"X-Pasopati-API-Key": api_key} if api_key else {})
    }
    if hmac_key:
        # Evidence ditandatangani HMAC atas raw body, sama seperti telemetri ingest.
        headers["X-Pasopati-Signature"] = hmac.new(
            hmac_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-Pasopati-Timestamp"] = str(int(time.time()))
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=8) as response:
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
def _history_path():
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
        return os.path.join(folder, "history.json")
    except Exception:
        fallback = os.path.join(os.path.expanduser("~"), ".pasopati")
        os.makedirs(fallback, mode=0o700, exist_ok=True)
        return os.path.join(fallback, "history.json")

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
        os.replace(tmp, path)
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

    print(f"[*] Rencana {plan_id}: {len(items)} tindakan. Mode: {'--no-exec (tanpa perubahan)' if args.no_exec else 'EKSEKUSI AKTUAL'}")

    backup_meta = []
    evidence = []
    evidence_by_step = {}
    to_status = "VERIFIED"
    for idx, item in enumerate(items):
        alias = item["alias"]
        entry = ALLOWLIST_ANALISA[alias]
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
    if args.push_url and not demo_plan:
        try:
            rc = _push_remediation_evidence(args.push_url, args.remediate_api_key, plan_id, plan.get("nonce", ""), to_status, evidence, args.hmac_key)
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
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    if parser_only:
        return parser
    args = parser.parse_args(argv)

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

    if args.remediate_plan or args.plan_id or args.demo:
        run_remediation(args)
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
    os.replace(tmp_path, args.output)
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
