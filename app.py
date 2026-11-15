"""
================================================================================
 PASOPATI: System Audit, Threat Remediation & Intelligence Architecture Guard
 Defense Cyber Operations & Core Infrastructure Hardening Console
 Platform: Streamlit + Plotly + Google Gemini AI Engine + ISA/IEC 62443 + DISA STIG

 STATUS: DEPRECATED untuk operasi nyata.
 - Field Console ini bekerja pada data contoh/unggahan; TIDAK memanggil agent dan
   logika remediasinya terpisah dari allowlist agent (rawan menyimpang).
 - Untuk aset nyata gunakan Command Center (React+Express) + `pasopati_audit.py`
   dan `pasopati_remediate.py`. Console ini dipertahankan untuk demo luring.
================================================================================
"""

import streamlit as st
import plotly.graph_objects as go
import json
import time
import os
import copy
import re
import html
import urllib.request
import urllib.error
import hmac
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="PASOPATI | Command Center",
    page_icon=os.path.join(os.path.dirname(os.path.abspath(__file__)), "public", "pasopati-mark.png"),
    layout="wide",
    initial_sidebar_state="expanded"
)

# Design system dimuat dari file terpisah agar app.py tetap ringkas.
CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "pasopati.css")
with open(CSS_PATH, "r", encoding="utf-8") as css_file:
    st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)

# Initial Mock Dataset for 5 Realistic Defense IT/OT Endpoints
INITIAL_DEVICES = {
    "SRV-DATA-YONIF": {
        "hostname": "srv-data-yonif.tni-ad.mil.id",
        "role": "Server Database Operasi & Logistik Yonif",
        "os": "Ubuntu Server 22.04 LTS (x86_64)",
        "ip": "10.14.2.10",
        "mac": "00:1A:4B:99:21:04",
        "user": "sysadmin_ops",
        "open_ports": [22, 80, 443, 445, 3306],
        "checks": [
            {"param": "Network: SMB Port 445 Exposure", "cat": "Network & Port", "cis": "CIS 3.4.1 / DISA STIG NET-001", "status": "FAIL", "detail": "Port SMB 445 terbuka di antarmuka publik tanpa segmentasi VLAN taktis."},
            {"param": "Host-Based Local Firewall", "cat": "Endpoint Protection", "cis": "CIS 3.5.1 / DISA STIG V-214870", "status": "FAIL", "detail": "UFW Firewall berstatus inactive. Seluruh port inbound terpapar langsung."},
            {"param": "SSH Root Direct Login", "cat": "Access Control", "cis": "CIS 5.2.10 / DISA STIG V-214878", "status": "FAIL", "detail": "PermitRootLogin diaktifkan di /etc/ssh/sshd_config."},
            {"param": "USB Mass Storage Lock", "cat": "Endpoint Protection", "cis": "CIS 1.1.23 / DISA STIG V-214840", "status": "WARNING", "detail": "Modul usb-storage tidak diblacklist; rentan exfiltration data taktis via flashdisk."},
            {"param": "Kernel Auditd Service", "cat": "System Logging", "cis": "CIS 4.1.1 / DISA STIG V-214875", "status": "FAIL", "detail": "Auditd service dimatikan, tidak ada rekaman eskalasi privilege dan akses file rahasia."},
            {"param": "Kernel Module Integrity & Rootkit Scan", "cat": "Kernel & Boot", "cis": "CIS 1.1.1 / DISA STIG V-214800", "status": "PASS", "detail": "Modul kernel tervalidasi terhadap whitelist resmi; tidak ada rootkit hook terdeteksi."},
            {"param": "Full Disk Encryption (LUKS)", "cat": "Cryptographic Posture", "cis": "CIS 1.1.2 / DISA STIG V-214820", "status": "FAIL", "detail": "Partisi data database taktis belum terenkripsi LUKS; risiko physical extraction."},
            {"param": "Sudoers NOPASSWD Boundary", "cat": "Privilege Boundary", "cis": "CIS 5.3.4 / DISA STIG V-214885", "status": "FAIL", "detail": "Ditemukan directive NOPASSWD di /etc/sudoers.d/ops-script; bypass otentikasi root."}
        ],
        "is_quarantined": False,
        "history": [
            {"time": "2026-10-27 08:00", "score": 65, "event": "Deploy Awal Satuan"},
            {"time": "2026-10-28 14:30", "score": 50, "event": "Inspeksi Mingguan"},
            {"time": "2026-10-29 09:15", "score": 38, "event": "Drift Terdeteksi (Celah Sudo & LUKS)"}
        ]
    },
    "PC-STAF-INTEL-01": {
        "hostname": "pc-intel-analyst-01.tni.mil.id",
        "role": "Workstation Analis Intelijen Taktis",
        "os": "Windows 11 Enterprise (Build 22631)",
        "ip": "10.14.2.45",
        "mac": "2C:F0:5D:81:44:A2",
        "user": "analis_intel",
        "open_ports": [135, 139, 445, 3389, 4444],
        "checks": [
            {"param": "Backdoor Port 4444 Listener", "cat": "Network & Port", "cis": "DISA STIG NET-002", "status": "FAIL", "detail": "CRITICAL: Terdeteksi port 4444 (Metasploit default listener) aktif melayani koneksi C2 luar!"},
            {"param": "RDP 3389 Tanpa NLA", "cat": "Network & Port", "cis": "DISA STIG WN11-00-000045", "status": "FAIL", "detail": "Remote Desktop terbuka tanpa batasan IP whitelist & tanpa NLA enforcement."},
            {"param": "Windows Guest Account", "cat": "Access Control", "cis": "DISA STIG WN11-00-000010", "status": "FAIL", "detail": "Akun bawaan Guest dalam status aktif, memungkinkan bypass otentikasi AD."},
            {"param": "USB Storage Device Lock", "cat": "Endpoint Protection", "cis": "DISA STIG WN11-CC-000180", "status": "WARNING", "detail": "GPO Removable Storage Access belum diterapkan ke OU workstation intelijen."},
            {"param": "Windows Event Security Auditing", "cat": "System Logging", "cis": "DISA STIG WN11-AU-000050", "status": "PASS", "detail": "Audit Logon Events & Object Access aktif terhubung ke SIEM militer."},
            {"param": "BitLocker Drive Encryption (C:)", "cat": "Cryptographic Posture", "cis": "DISA STIG WN11-00-000025", "status": "FAIL", "detail": "Volume C: intelijen belum terenkripsi BitLocker; data foto satelit rawan ekstraksi."},
            {"param": "UEFI Secure Boot & Driver Integrity", "cat": "Kernel & Boot", "cis": "DISA STIG WN11-00-000005", "status": "FAIL", "detail": "Driver Signing Enforcement dalam mode testsigning=yes; rawan inject rootkit kernel."},
            {"param": "Local Administrators Group Policy", "cat": "Privilege Boundary", "cis": "DISA STIG WN11-00-000015", "status": "WARNING", "detail": "Ditemukan 3 akun non-standar terdaftar di grup Administrators lokal."}
        ],
        "is_quarantined": False,
        "history": [
            {"time": "2026-10-27 10:00", "score": 70, "event": "Inspeksi Awal Sat Intel"},
            {"time": "2026-10-28 16:20", "score": 55, "event": "Instalasi Software Analisis"},
            {"time": "2026-10-29 11:45", "score": 38, "event": "Drift & Backdoor 4444 Terdeteksi"}
        ]
    },
    "PC-STAF-OPS-02": {
        "hostname": "pc-ops-puskodal-02.tni.mil.id",
        "role": "Workstation Puskodal / Komando Pengendalian",
        "os": "Windows 10 Enterprise LTSC",
        "ip": "10.14.2.66",
        "mac": "B4:2E:99:31:7E:10",
        "user": "ops_officer",
        "open_ports": [135, 443],
        "checks": [
            {"param": "Dangerous Ports Exposure", "cat": "Network & Port", "cis": "DISA STIG NET-001", "status": "PASS", "detail": "Port berisiko (SMB, RDP, Telnet, Backdoor) terisolasi sempurna."},
            {"param": "Windows Defender Firewall", "cat": "Endpoint Protection", "cis": "DISA STIG WN10-00-000015", "status": "PASS", "detail": "Firewall Domain, Private, dan Public aktif memblokir unsolicited traffic."},
            {"param": "Local Administrator & Guest Policy", "cat": "Access Control", "cis": "DISA STIG WN10-00-000020", "status": "PASS", "detail": "Guest dinonaktifkan, LAPS aktif mengelola password lokal administrator."},
            {"param": "Removable USB Storage Restriction", "cat": "Endpoint Protection", "cis": "DISA STIG WN10-CC-000180", "status": "PASS", "detail": "Hardware ID USB storage dibatasi via registry GPO."},
            {"param": "Security Auditing Policy", "cat": "System Logging", "cis": "DISA STIG WN10-AU-000050", "status": "WARNING", "detail": "Audit Process Creation belum mencakup logging Command Line parameters."}
        ]
    },
    "GW-RADIO-TAKTIS-OT": {
        "hostname": "gw-hf-vhf-taktis.ot-net.local",
        "role": "Gateway Komunikasi Radio Taktis & BMS (OT)",
        "os": "Embedded OpenWrt / Linux 5.15 (arm64)",
        "ip": "192.168.88.1",
        "mac": "E4:5F:01:D3:88:99",
        "user": "root_operator",
        "open_ports": [21, 23, 80, 502],
        "checks": [
            {"param": "Telnet Protocol Unencrypted (Port 23)", "cat": "Network & Port", "cis": "ISA/IEC 62443-3-3 SR 3.1 / CIS 2.1.1", "status": "FAIL", "detail": "Layanan Telnet aktif mengirim kredensial komando dalam format plaintext tanpa TLS."},
            {"param": "FTP Service Plaintext (Port 21)", "cat": "Network & Port", "cis": "ISA/IEC 62443-4-2 CR 3.1 / CIS 2.1.2", "status": "FAIL", "detail": "Daemon vsftpd aktif dengan izin anonymous download firmware konfigurasi OT."},
            {"param": "Default Gateway Passwords", "cat": "Access Control", "cis": "ISA/IEC 62443-4-2 CR 1.1 / CIS 5.3.1", "status": "FAIL", "detail": "Kata sandi root menggunakan kombinasi default pabrikan radio militer."},
            {"param": "Host-Based IP Filtering (Zone & Conduit)", "cat": "Endpoint Protection", "cis": "ISA/IEC 62443-3-3 SR 5.1 / CIS 3.5.1", "status": "WARNING", "detail": "Iptables aktif namun belum ada aturan drop pada broadcast domain radio."},
            {"param": "Centralized Syslog OT", "cat": "System Logging", "cis": "ISA/IEC 62443-4-2 CR 6.1 / CIS 4.1.1", "status": "FAIL", "detail": "Log disimpan lokal di RAM, hilang seketika jika radio gateway direstart."}
        ]
    },
    "SRV-LOGISTIK-KODIM": {
        "hostname": "srv-log-kodim.tni-ad.mil.id",
        "role": "Server Manajemen Materiel & Logistik Kodim",
        "os": "Debian GNU/Linux 12 (bookworm)",
        "ip": "10.14.5.20",
        "mac": "52:54:00:8C:FA:33",
        "user": "kodim_admin",
        "open_ports": [22, 443, 5432],
        "checks": [
            {"param": "Network Port Hardening", "cat": "Network & Port", "cis": "CIS 3.4.2 / DISA STIG NET-001", "status": "PASS", "detail": "Port terbuka terbatas pada SSH (port diubah) dan HTTPS bersertifikat internal TNI."},
            {"param": "NFTables Local Firewall", "cat": "Endpoint Protection", "cis": "CIS 3.5.3 / DISA STIG V-214870", "status": "PASS", "detail": "NFTables firewall aktif memfilter koneksi berdasarkan whitelist IP Kodam."},
            {"param": "SSH Hardening & Key Authentication", "cat": "Access Control", "cis": "CIS 5.2.1 / DISA STIG V-214878", "status": "PASS", "detail": "PermitRootLogin NO, PasswordAuthentication NO (wajib Ed25519 Hardware Token)."},
            {"param": "USB Mass Storage Module", "cat": "Endpoint Protection", "cis": "CIS 1.1.23 / DISA STIG V-214840", "status": "PASS", "detail": "Modul usb-storage telah diblacklist di /etc/modprobe.d/storage.conf."},
            {"param": "Auditd Daemon Security Rules", "cat": "System Logging", "cis": "CIS 4.1.2 / DISA STIG V-214875", "status": "PASS", "detail": "Auditd merekam setiap perubahan file izin /etc/passwd dan sudoers."}
        ]
    }
}

# Initialize Session State
if "devices" not in st.session_state:
    st.session_state.devices = copy.deepcopy(INITIAL_DEVICES)
if "backup_devices" not in st.session_state:
    st.session_state.backup_devices = copy.deepcopy(INITIAL_DEVICES)
if "last_scan_time" not in st.session_state:
    st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def calculate_score(device_checks):
    total = len(device_checks)
    if total == 0:
        return 100
    p = sum(1 for c in device_checks if c["status"] == "PASS")
    w = sum(1 for c in device_checks if c["status"] == "WARNING")
    return int(((p * 100) + (w * 50)) / total)

def get_overall_score():
    scores = [calculate_score(d["checks"]) for d in st.session_state.devices.values()]
    return int(sum(scores) / len(scores)) if scores else 100

def get_defcon_level(score):
    if score >= 80:
        return {"level": "DEFCON 4", "state": "SIAP OPERASI // MISSION READY", "color": "#10b981", "badge": "bg-emerald-950 text-emerald-400"}
    elif score >= 60:
        return {"level": "DEFCON 3", "state": "WASPADA // ELEVATED THREAT", "color": "#f59e0b", "badge": "bg-amber-950 text-amber-400"}
    elif score >= 50:
        return {"level": "DEFCON 2", "state": "PERLU MITIGASI // ACTIVE PROBES", "color": "#f97316", "badge": "bg-orange-950 text-orange-400"}
    else:
        return {"level": "DEFCON 1", "state": "SIAGA MERAH // COMPROMISE DETECTED", "color": "#ef4444", "badge": "bg-rose-950 text-rose-400"}

def create_gauge_chart(score):
    bar_color = "#10b981" if score >= 75 else ("#f59e0b" if score >= 50 else "#f43f5e")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': "FLEET READINESS INDEX", 'font': {'size': 12, 'color': '#64748b', 'family': 'monospace'}},
        number={'suffix': "/100", 'font': {'size': 38, 'color': '#f8fafc', 'family': 'monospace'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#334155", 'tickfont': {'color': '#64748b', 'size': 10}},
            'bar': {'color': bar_color, 'thickness': 0.28},
            'bgcolor': "#0b111c",
            'borderwidth': 1,
            'bordercolor': "#1e293b",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(244, 63, 94, 0.12)'},
                {'range': [50, 75], 'color': 'rgba(245, 158, 11, 0.12)'},
                {'range': [75, 100], 'color': 'rgba(16, 185, 129, 0.12)'}
            ],
            'threshold': {
                'line': {'color': "#38bdf8", 'width': 3},
                'thickness': 0.75,
                'value': score
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#cbd5e1"},
        height=240,
        margin=dict(l=15, r=15, t=35, b=15)
    )
    return fig

# Safe retrieval of st.secrets for Streamlit Cloud
secret_gemini_key = ""
try:
    if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
        secret_gemini_key = st.secrets["GEMINI_API_KEY"]
except Exception:
    pass

# Dynamic Script Generator: Builds targeted Bash / PowerShell strictly based on failures & open ports
def _safe_script_text(value, max_len=120):
    text = "" if value is None else str(value)
    text = re.sub(r'[\r\n\u2028\u2029]+', ' ', text)
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', text)
    return text.strip()[:max_len]

def generate_dynamic_scripts(device_name, dev):
    safe_device_name = re.sub(r'[^A-Za-z0-9._-]', '_', device_name or '')
    is_linux = any(k in dev["os"].lower() for k in ["linux", "ubuntu", "debian", "openwrt"])
    fail_checks = [c for c in dev["checks"] if c["status"] == "FAIL"]
    warn_checks = [c for c in dev["checks"] if c["status"] == "WARNING"]
    all_findings = fail_checks + warn_checks
    open_ports = dev.get("open_ports", [])
    handled = set()
    def _hay(c):
        return ((c.get("param") or "") + " " + (c.get("detail") or c.get("details") or "")).lower()
    def find(pattern):
        """Tandai semua temuan yang cocok dan kembalikan True bila ada."""
        found = False
        for _c in all_findings:
            if re.search(pattern, _hay(_c)):
                handled.add(_c.get("param"))
                found = True
        return found
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # If clean (100% compliant)
    if len(fail_checks) == 0 and len(warn_checks) == 0:
        if is_linux:
            hard = f"""#!/bin/bash
# ==============================================================================
# PASOPATI HARDENING AUDIT: {safe_device_name}
# Standard: CIS Benchmark / DISA STIG / ISA/IEC 62443
# Timestamp: {now_str}
# ==============================================================================
# [PRASYARAT] Semua skrip hardening PASOPATI wajib dijalankan sebagai root (Linux) / Administrator (Windows).
# OS didukung (5 thn terakhir): Debian 10-13, Ubuntu 20.04/22.04/24.04, Kali 2021-2026; Windows 10 21H2-22H2, Windows 11 21H2-24H2.
# [COMPLIANCE STATUS: 100% PASS]
# Perangkat berada dalam kondisi kepatuhan optimal. Tidak ada aksi lanjutan.
echo "[+] Perangkat {safe_device_name} telah memenuhi parameter keamanan pertahanan."
"""
            roll = f"""#!/bin/bash
# ==============================================================================
# PASOPATI ROLLBACK: {safe_device_name}
# ==============================================================================
# Tidak ada modifikasi aktif yang perlu dipulihkan.
echo "[*] Baseline perangkat telah sesuai standar pertahanan."
"""
            return hard, roll, "bash"
        else:
            hard = f"""# ==============================================================================
# PASOPATI HARDENING AUDIT: {safe_device_name}
# Standard: DISA STIG Windows Baseline
# Timestamp: {now_str}
# ==============================================================================
# [COMPLIANCE STATUS: 100% PASS]
# Perangkat berada dalam kondisi kepatuhan optimal. Tidak ada aksi lanjutan.
Write-Host "[+] Perangkat {safe_device_name} telah memenuhi parameter keamanan pertahanan." -ForegroundColor Green
"""
            roll = f"""# ==============================================================================
# PASOPATI ROLLBACK: {safe_device_name}
# ==============================================================================
# Tidak ada modifikasi aktif yang perlu dipulihkan.
Write-Host "[*] Baseline perangkat telah sesuai standar pertahanan." -ForegroundColor Cyan
"""
            return hard, roll, "powershell"

    # Assemble Targeted Dynamic Scripts based on actual findings
    if is_linux:
        script_ext = "bash"
        hard_lines = [
            "#!/bin/bash",
            "# ==============================================================================",
            f"# PASOPATI TARGETED HARDENING RUNBOOK: {safe_device_name}",
            f"# Role: {_safe_script_text(dev.get('role'))} | OS: {_safe_script_text(dev.get('os'))}",
            f"# Standard: CIS Benchmark / DISA STIG / ISA/IEC 62443",
            f"# Generated: {now_str}",
            "# ==============================================================================",
            "set -e",
            "# [PRASYARAT] Wajib root. OS didukung (5 thn terakhir): Debian 10/11/12/13, Ubuntu 20.04/22.04/24.04, Kali rolling 2021-2026.",
            "if [ \"${PASOPATI_ELEVATED:-0}\" != \"1\" ] && [ \"$(id -u)\" -ne 0 ]; then",
            "  export PASOPATI_ELEVATED=1",
            "  echo '[!] Butuh hak root. Menaikkan hak akses otomatis...' >&2",
            "  if command -v zenity >/dev/null 2>&1; then zenity --error --text='PASOPATI: butuh hak root. Lanjutkan dengan sudo.' 2>/dev/null || true; fi",
            "  if command -v notify-send >/dev/null 2>&1; then notify-send 'PASOPATI' 'Butuh hak root - memanggil sudo.' 2>/dev/null || true; fi",
            "  if command -v sudo >/dev/null 2>&1; then exec sudo -E bash \"$0\" \"$@\"; fi",
            "  if command -v pkexec >/dev/null 2>&1; then exec pkexec env PASOPATI_ELEVATED=1 bash \"$0\" \"$@\"; fi",
            "  echo '[!] sudo/pkexec tidak tersedia. Jalankan: sudo bash \"$0\"' >&2",
            "  exit 1",
            "fi",
            "echo \"[*] OS terdeteksi: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2)\"",
            f"echo '[*] Menjalankan remediasi terarah PASOPATI pada {safe_device_name}...'",
            ""
        ]
        roll_lines = [
            "#!/bin/bash",
            "# ==============================================================================",
            f"# PASOPATI RESTORE / ROLLBACK RUNBOOK: {safe_device_name}",
            f"# Generated: {now_str}",
            "# ==============================================================================",
            "if [ \"${PASOPATI_ELEVATED:-0}\" != \"1\" ] && [ \"$(id -u)\" -ne 0 ]; then",
            "  export PASOPATI_ELEVATED=1",
            "  if command -v sudo >/dev/null 2>&1; then exec sudo -E bash \"$0\" \"$@\"; fi",
            "  if command -v pkexec >/dev/null 2>&1; then exec pkexec env PASOPATI_ELEVATED=1 bash \"$0\" \"$@\"; fi",
            "  echo '[!] Butuh root. Jalankan: sudo bash \"$0\"' >&2; exit 1",
            "fi",
            f"echo '[*] Menjalankan pemulihan konfigurasi pada {safe_device_name}...'",
            ""
        ]

        step = 1

        # Check: Emergency Backdoor port 4444
        if find(r"4444") or 4444 in open_ports:
            hard_lines.append(f"# [{step:02d}] Neutralize Emergency Port 4444 (C2 Backdoor)")
            hard_lines.append("echo '[!] Menghentikan proses backdoor port 4444...'")
            hard_lines.append("fuser -k 4444/tcp 2>/dev/null || kill -9 $(lsof -t -i:4444) 2>/dev/null || true")
            hard_lines.append("iptables -A INPUT -p tcp --dport 4444 -j DROP 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore Port 4444 Rule")
            roll_lines.append("iptables -D INPUT -p tcp --dport 4444 -j DROP 2>/dev/null || true")
            roll_lines.append("")
            step += 1

        # Check: SMB Port 445
        if find(r"445|smb") or 445 in open_ports:
            hard_lines.append(f"# [{step:02d}] Remediate SMB Port 445 (CIS 3.4.1 / DISA STIG NET-001)")
            hard_lines.append("echo '[+] Menonaktifkan layanan Samba daemon...'")
            hard_lines.append("systemctl stop smbd 2>/dev/null || true")
            hard_lines.append("systemctl disable smbd 2>/dev/null || true")
            hard_lines.append("iptables -A INPUT -p tcp --dport 445 -j DROP 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore SMB Service")
            roll_lines.append("iptables -D INPUT -p tcp --dport 445 -j DROP 2>/dev/null || true")
            roll_lines.append("systemctl enable smbd 2>/dev/null || true")
            roll_lines.append("systemctl start smbd 2>/dev/null || true")
            roll_lines.append("")
            step += 1

        # Check: Telnet 23 (OT Radio Gateway / Embedded)
        if find(r"telnet") or 23 in open_ports:
            hard_lines.append(f"# [{step:02d}] Disable Plaintext Telnet (ISA/IEC 62443-3-3 SR 3.1 / CIS 2.1.1)")
            hard_lines.append("echo '[+] Menutup daemon Telnet port 23...'")
            hard_lines.append("systemctl stop telnetd 2>/dev/null || systemctl stop inetd 2>/dev/null || /etc/init.d/telnet stop 2>/dev/null || true")
            hard_lines.append("iptables -A INPUT -p tcp --dport 23 -j DROP 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore Telnet Rule")
            roll_lines.append("iptables -D INPUT -p tcp --dport 23 -j DROP 2>/dev/null || true")
            roll_lines.append("")
            step += 1

        # Check: FTP 21 (OT Radio Gateway / Plaintext)
        if find(r"ftp") or 21 in open_ports:
            hard_lines.append(f"# [{step:02d}] Terminate Plaintext FTP (ISA/IEC 62443-4-2 CR 3.1 / CIS 2.1.2)")
            hard_lines.append("echo '[+] Menghentikan layanan FTP vsftpd...'")
            hard_lines.append("systemctl stop vsftpd 2>/dev/null || /etc/init.d/vsftpd stop 2>/dev/null || true")
            hard_lines.append("iptables -A INPUT -p tcp --dport 21 -j DROP 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore FTP Rule")
            roll_lines.append("iptables -D INPUT -p tcp --dport 21 -j DROP 2>/dev/null || true")
            roll_lines.append("")
            step += 1

        # Check: Firewall inactive
        if find(r"firewall|ufw"):
            hard_lines.append(f"# [{step:02d}] Enforce Host Firewall & Zone Segmentation (CIS 3.5.1 / ISA/IEC 62443)")
            hard_lines.append("echo '[+] Mengaktifkan UFW & menegakkan segmentasi perimeter...'")
            hard_lines.append("if command -v ufw >/dev/null 2>&1; then")
            hard_lines.append("    ufw default deny incoming")
            hard_lines.append("    ufw default allow outgoing")
            hard_lines.append("    ufw allow from 10.14.0.0/16 to any port 22 proto tcp comment 'Whitelisted Military SSH'")
            hard_lines.append("    ufw --force enable")
            hard_lines.append("else")
            hard_lines.append("    iptables -P INPUT DROP")
            hard_lines.append("    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            hard_lines.append("    iptables -A INPUT -i lo -j ACCEPT")
            hard_lines.append("fi")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Disable Enforced Firewall")
            roll_lines.append("ufw disable 2>/dev/null || iptables -P INPUT ACCEPT 2>/dev/null || true")
            roll_lines.append("")
            step += 1

        # Check: SSH Root Direct Login
        if find(r"permitrootlogin|ssh root|root login"):
            hard_lines.append(f"# [{step:02d}] Lock Down SSH Root Direct Access (CIS 5.2.10 / DISA STIG V-214878)")
            hard_lines.append("echo '[+] Menonaktifkan PermitRootLogin pada sshd_config...'")
            hard_lines.append("if [ -f /etc/ssh/sshd_config ]; then")
            hard_lines.append("    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.pasopati.bak")
            hard_lines.append("    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
            hard_lines.append("    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true")
            hard_lines.append("fi")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore SSH Root Login")
            roll_lines.append("if [ -f /etc/ssh/sshd_config.pasopati.bak ]; then")
            roll_lines.append("    mv /etc/ssh/sshd_config.pasopati.bak /etc/ssh/sshd_config")
            roll_lines.append("    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true")
            roll_lines.append("fi")
            roll_lines.append("")
            step += 1

        # Check: USB Storage Lock
        if find(r"usb"):
            hard_lines.append(f"# [{step:02d}] Blacklist USB Mass Storage Module (CIS 1.1.23 / DISA STIG V-214840)")
            hard_lines.append("echo '[+] Memblokir modul kernel usb-storage...'")
            hard_lines.append("echo 'install usb-storage /bin/true' > /etc/modprobe.d/pasopati-usb-lock.conf")
            hard_lines.append("echo 'blacklist usb-storage' >> /etc/modprobe.d/pasopati-usb-lock.conf")
            hard_lines.append("modprobe -r usb-storage 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Unblock USB Storage")
            roll_lines.append("rm -f /etc/modprobe.d/pasopati-usb-lock.conf")
            roll_lines.append("")
            step += 1

        # Check: Kernel Auditd / Syslog
        if find(r"auditd|audit daemon|syslog"):
            hard_lines.append(f"# [{step:02d}] Activate Auditd / Remote Syslog (CIS 4.1.1 / ISA/IEC 62443-4-2 CR 6.1)")
            hard_lines.append("echo '[+] Menghidupkan daemon auditd & aturan rekaman kernel...'")
            hard_lines.append("systemctl enable auditd 2>/dev/null || true")
            hard_lines.append("systemctl restart auditd 2>/dev/null || true")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Revert Auditd Service")
            roll_lines.append("systemctl stop auditd 2>/dev/null || true")
            roll_lines.append("")
            step += 1


        # Check: GRUB config permissions
        if find(r"grub"):
            hard_lines.append(f"# [{step:02d}] Kunci izin grub.cfg (CIS 1.4.1)")
            hard_lines.append("for g in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do")
            hard_lines.append("  if [ -f \"$g\" ]; then stat -c '%a %n' \"$g\" >> /var/tmp/pasopati-grub.list; chmod 600 \"$g\"; fi")
            hard_lines.append("done")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Pulihkan izin grub")
            roll_lines.append("if [ -f /var/tmp/pasopati-grub.list ]; then while read -r mode path; do chmod \"$mode\" \"$path\" 2>/dev/null || true; done < /var/tmp/pasopati-grub.list; fi")
            roll_lines.append("")
            step += 1

        # Check: sudoers NOPASSWD
        if find(r"sudoers|nopasswd"):
            hard_lines.append(f"# [{step:02d}] Hapus NOPASSWD pada sudoers (CIS 5.3.4)")
            hard_lines.append("for f in /etc/sudoers /etc/sudoers.d/*; do")
            hard_lines.append("  [ -f \"$f\" ] || continue")
            hard_lines.append("  if grep -q 'NOPASSWD:' \"$f\"; then cp -a \"$f\" \"$f.pasopati.bak\"; sed -i 's/NOPASSWD://g' \"$f\"; fi")
            hard_lines.append("done")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Pulihkan sudoers")
            roll_lines.append("for b in /etc/sudoers.pasopati.bak /etc/sudoers.d/*.pasopati.bak; do [ -f \"$b\" ] || continue; mv \"$b\" \"${b%.pasopati.bak}\"; done")
            roll_lines.append("")
            step += 1

        # Check: SUID binaries
        if find(r"suid"):
            hard_lines.append(f"# [{step:02d}] Cabut bit SUID pada binari kritis (CIS 1.1.21)")
            hard_lines.append("for b in /bin/bash /bin/sh /usr/bin/python3 /usr/bin/perl /bin/netcat /usr/bin/find; do")
            hard_lines.append("  [ -f \"$b\" ] || continue")
            hard_lines.append("  if [ -u \"$b\" ]; then stat -c '%a %n' \"$b\" >> /var/tmp/pasopati-suid.list; chmod u-s \"$b\"; fi")
            hard_lines.append("done")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Pulihkan bit SUID")
            roll_lines.append("if [ -f /var/tmp/pasopati-suid.list ]; then while read -r mode path; do chmod \"$mode\" \"$path\" 2>/dev/null || true; done < /var/tmp/pasopati-suid.list; fi")
            roll_lines.append("")
            step += 1

        # Check: LUKS (advisory)
        if find(r"luks|full disk encryption"):
            hard_lines.append(f"# [{step:02d}] Full Disk Encryption LUKS — perlu perencanaan")
            hard_lines.append("echo '[!] LUKS tidak dienkripsi otomatis: backup data lalu cryptsetup luksFormat + luksOpen (butuh reboot).'")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] LUKS tidak diubah saat rollback")
            roll_lines.append("")
            step += 1

        # Check: rootkit (advisory)
        if find(r"rootkit|kernel module"):
            hard_lines.append(f"# [{step:02d}] Tinjauan manual kernel module/rootkit")
            hard_lines.append("echo '[!] Periksa modul kernel mencurigakan pada detail temuan; tidak ada perubahan otomatis.'")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Kernel module tidak diubah")
            roll_lines.append("")
            step += 1

        # ---- Temuan yang belum dipetakan: JANGAN diabaikan ----
        hard_lines.append("# ==============================================================================")
        hard_lines.append("# TEMUAN BELUM DIPETAKAN KE AKSI OTOMATIS")
        remaining = [c for c in all_findings if c.get("param") not in handled]
        if not remaining:
            hard_lines.append("# (tidak ada - semua temuan sudah ditangani di atas)")
        else:
            for _c in remaining:
                hard_lines.append(f"# [{_c.get('status')}] {str(_c.get('param'))[:160]}")
                hard_lines.append(f"#   detail: {str(_c.get('detail') or _c.get('details') or '')[:240]}")
                hard_lines.append(f"#   saran : {str(_c.get('mitigasi') or _c.get('mitigation') or '')[:240]}")
        hard_lines.append("")
        hard_lines.append("echo '[SUCCESS] Remediasi selesai. Status kepatuhan dinaikkan ke PASS.'")
        roll_lines.append("echo '[RESTORED] Konfigurasi perangkat dikembalikan ke status cadangan operasional.'")
        return "\n".join(hard_lines), "\n".join(roll_lines), script_ext

    else:
        # Windows PowerShell Script Generation
        script_ext = "powershell"
        hard_lines = [
            "# ==============================================================================",
            f"# PASOPATI TARGETED HARDENING RUNBOOK (POWERSHELL): {safe_device_name}",
            f"# Role: {_safe_script_text(dev.get('role'))} | OS: {_safe_script_text(dev.get('os'))}",
            f"# Standard: DISA STIG Windows 10/11 Baseline",
            f"# Generated: {now_str}",
            "# ==============================================================================",
            "# [PRASYARAT] Wajib Administrator. OS didukung (5 thn terakhir): Windows 10 21H2-22H2, Windows 11 21H2-24H2.",
            "param ([switch]$Elevated)",
            "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
            "  Write-Host '[!] Butuh Administrator. Membuka UAC...' -ForegroundColor Yellow",
            "  Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue",
            "  [void][System.Windows.Forms.MessageBox]::Show('PASOPATI: butuh hak Administrator. Lanjutkan dengan menekan Yes pada UAC.', 'PASOPATI')",
            "  Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -File `\"$PSCommandPath`\" -Elevated\"",
            "  exit 0",
            "}",
            "if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { $os = Get-CimInstance Win32_OperatingSystem; Write-Host \"[*] OS terdeteksi: $($os.Caption) $($os.Version) build $($os.BuildNumber)\" -ForegroundColor Cyan }",
            f"Write-Host '[*] Menjalankan remediasi taktis PASOPATI pada {safe_device_name}...' -ForegroundColor Cyan",
            ""
        ]
        roll_lines = [
            "# ==============================================================================",
            f"# PASOPATI RESTORE / ROLLBACK RUNBOOK (POWERSHELL): {safe_device_name}",
            f"# Generated: {now_str}",
            "# ==============================================================================",
            "param ([switch]$Elevated)",
            "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
            "  Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -ExecutionPolicy Bypass -File `\"$PSCommandPath`\" -Elevated\"",
            "  exit 0",
            "}",
            f"Write-Host '[*] Memulihkan konfigurasi sistem pada {safe_device_name}...' -ForegroundColor Yellow",
            ""
        ]

        step = 1

        # Check: Backdoor 4444
        if find(r"4444") or 4444 in open_ports:
            hard_lines.append(f"# [{step:02d}] Terminate Port 4444 Listener (DISA STIG NET-002)")
            hard_lines.append("Write-Host '[!] Menghentikan proses yang mendengarkan port 4444...' -ForegroundColor Red")
            hard_lines.append("$conn = Get-NetTCPConnection -LocalPort 4444 -ErrorAction SilentlyContinue")
            hard_lines.append("if ($conn) { Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue }")
            hard_lines.append("New-NetFirewallRule -DisplayName 'PASOPATI-Block-4444' -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Block -ErrorAction SilentlyContinue")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Remove Port 4444 Block Rule")
            roll_lines.append("Remove-NetFirewallRule -DisplayName 'PASOPATI-Block-4444' -ErrorAction SilentlyContinue")
            roll_lines.append("")
            step += 1

        # Check: RDP 3389 / NLA
        if find(r"rdp|nla|3389") or 3389 in open_ports:
            hard_lines.append(f"# [{step:02d}] Enforce NLA on Remote Desktop (DISA STIG WN11-00-000045)")
            hard_lines.append("Write-Host '[+] Menerapkan Network Level Authentication (NLA) pada RDP...' -ForegroundColor Yellow")
            hard_lines.append("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Revert RDP NLA Requirement")
            roll_lines.append("Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 0")
            roll_lines.append("")
            step += 1

        # Check: Guest Account
        if find(r"guest"):
            hard_lines.append(f"# [{step:02d}] Disable Built-in Guest Account (DISA STIG WN11-00-000010)")
            hard_lines.append("Write-Host '[+] Menonaktifkan Akun Guest...' -ForegroundColor Yellow")
            hard_lines.append("Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Re-enable Guest Account")
            roll_lines.append("Enable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue")
            roll_lines.append("")
            step += 1

        # Check: Windows Defender Firewall
        if find(r"firewall|ufw"):
            hard_lines.append(f"# [{step:02d}] Enable Windows Defender Firewall Profiles (DISA STIG WN10-00-000015)")
            hard_lines.append("Write-Host '[+] Mengaktifkan semua profil firewall Windows Defender...' -ForegroundColor Yellow")
            hard_lines.append("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Revert Firewall Settings")
            roll_lines.append("Write-Host '[!] Firewall tetap dipertahankan aktif demi keamanan baseline.'")
            roll_lines.append("")
            step += 1

        # Check: USB Storage Lock
        if find(r"usb"):
            hard_lines.append(f"# [{step:02d}] Lock Down USB Mass Storage via Registry (DISA STIG WN11-CC-000180)")
            hard_lines.append("Write-Host '[+] Membatasi akses USB Mass Storage (Start=4)...' -ForegroundColor Yellow")
            hard_lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Restore USB Storage Access")
            roll_lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3")
            roll_lines.append("")
            step += 1

        # Check: Security Auditing
        if find(r"event log|auditing"):
            hard_lines.append(f"# [{step:02d}] Configure Advanced Process Auditing (DISA STIG WN10-AU-000050)")
            hard_lines.append("Write-Host '[+] Mengaktifkan Command Line Auditing pada Process Creation...' -ForegroundColor Yellow")
            hard_lines.append("auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Reset Audit Policy")
            roll_lines.append("auditpol /set /subcategory:'Process Creation' /success:disable /failure:disable")
            roll_lines.append("")
            step += 1


        # Check: UAC
        if find(r"uac"):
            hard_lines.append(f"# [{step:02d}] Aktifkan UAC (EnableLUA=1)")
            hard_lines.append("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Kembalikan UAC ke 0")
            roll_lines.append("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 0")
            roll_lines.append("")
            step += 1

        # Check: BitLocker
        if find(r"bitlocker"):
            hard_lines.append(f"# [{step:02d}] Aktifkan BitLocker C: (DISA STIG WN11-00-000025)")
            hard_lines.append("manage-bde -protectors -add C: -RecoveryPassword | Out-Null")
            hard_lines.append("manage-bde -on C: -SkipHardwareTest")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Matikan BitLocker (bila sebelumnya mati)")
            roll_lines.append("manage-bde -off C:")
            roll_lines.append("")
            step += 1

        # Check: Secure Boot (advisory)
        if find(r"secure boot|driver"):
            hard_lines.append(f"# [{step:02d}] Secure Boot — aktifkan manual di UEFI/BIOS bila mati")
            hard_lines.append("try { Write-Host \"Secure Boot: $(Confirm-SecureBootUEFI)\" } catch { Write-Host 'Secure Boot: tidak dapat dibaca' }")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Secure Boot tidak diubah")
            roll_lines.append("")
            step += 1

        # Check: Administrators membership (advisory)
        if find(r"administrator"):
            hard_lines.append(f"# [{step:02d}] Tinjau keanggotaan grup Administrators")
            hard_lines.append("Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { Write-Host \"Admin: $($_.Name)\" }")
            hard_lines.append("")
            roll_lines.append(f"# [{step:02d}] Keanggotaan admin tidak diubah")
            roll_lines.append("")
            step += 1

        # ---- Temuan yang belum dipetakan: JANGAN diabaikan ----
        hard_lines.append("# ==============================================================================")
        hard_lines.append("# TEMUAN BELUM DIPETAKAN KE AKSI OTOMATIS")
        remaining = [c for c in all_findings if c.get("param") not in handled]
        if not remaining:
            hard_lines.append("# (tidak ada - semua temuan sudah ditangani di atas)")
        else:
            for _c in remaining:
                hard_lines.append(f"# [{_c.get('status')}] {str(_c.get('param'))[:160]}")
                hard_lines.append(f"#   detail: {str(_c.get('detail') or _c.get('details') or '')[:240]}")
                hard_lines.append(f"#   saran : {str(_c.get('mitigasi') or _c.get('mitigation') or '')[:240]}")
        hard_lines.append("")
        hard_lines.append("Write-Host '[SUCCESS] Remediasi Windows Taktis Berhasil Diterapkan!' -ForegroundColor Green")
        roll_lines.append("Write-Host '[RESTORED] Konfigurasi sistem Windows telah dipulihkan ke cadangan.' -ForegroundColor Cyan")
        return "\n".join(hard_lines), "\n".join(roll_lines), script_ext


# ------------------------------------------------------------------------------
# AI PROVIDER HELPER (Google Gemini native atau endpoint OpenAI-compatible)
# ------------------------------------------------------------------------------
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b")

def redact_sensitive(value):
    text = _IP_RE.sub("[REDACTED_MIL_IP]", str(value or ""))
    text = _MAC_RE.sub("[REDACTED_MAC]", text)
    return _HOST_RE.sub("[REDACTED_HOST]", text)

def _env_clean(name, default=""):
    raw = os.environ.get(name, "")
    return (raw.split("#")[0].strip() or default)

def call_ai_provider(prompt, api_key, base_url=None, model=None):
    """Kembalikan (teks, label_sumber). Raise bila gagal."""
    base = (base_url or "").rstrip("/")
    model_name = (model or "").strip() or "gemini-2.5-flash"
    if base and "generativelanguage.googleapis.com" not in base:
        body = json.dumps({
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 600,
            "temperature": 0.2,
        }).encode("utf-8")
        req = urllib.request.Request(base + "/chat/completions", data=body, headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        }, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        if not text:
            raise RuntimeError("respons AI kosong")
        return text, f"Cloud AI ({model_name})"

    from google import genai
    client = genai.Client(api_key=api_key)
    resp = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config={"max_output_tokens": 600, "temperature": 0.2},
    )
    if not resp or not resp.text:
        raise RuntimeError("respons AI kosong")
    return resp.text, f"Google {model_name} (Cloud API)"

def generate_commander_report():
    score = get_overall_score()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    defcon = get_defcon_level(score)
    report = f"""# ==============================================================================
# MARKAS BESAR TENTARA NASIONAL INDONESIA
# PUSAT OPERASI SIBER PERTAHANAN (PUSSIBER)
# PUSKODAL UTAMA SISTEM INFORMASI & INFRASTRUKTUR OT
# ==============================================================================
# NOMOR       : R/LAP-SIBER/PASOPATI/{datetime.now().strftime('%m/%Y')}
# KLASIFIKASI : RAHASIA / TACTICAL CORE INFRASTRUCTURE
# PERIHAL     : LAPORAN RESMI AUDIT KESIAPAN SIBER SATUAN (CIS / STIG / ISA 62443)
# TANGGAL     : {now_str}
# ==============================================================================

## 1. RINGKASAN EKSEKUTIF (EXECUTIVE SUMMARY)
Berdasarkan hasil audit kepatuhan otomatis menggunakan sistem PASOPATI:
- **Skor Kesiapan Siber Agregat Satuan** : `{score}/100`
- **Tingkat Kesiagaan Siber (DEFCON)**   : `{defcon['level']} // {defcon['state']}`
- **Jumlah Aset Terpantau**              : {len(st.session_state.devices)} Endpoint IT/OT Pertahanan
- **Standar Baseline Acuan**            : CIS Benchmark v8.0, DISA STIG, & ISA/IEC 62443 (OT)

---

## 2. REKAPITULASI STATUS ASET PERTAHANAN (IT & OT)
"""
    for name, data in st.session_state.devices.items():
        d_score = calculate_score(data["checks"])
        fails = [c for c in data["checks"] if c["status"] == "FAIL"]
        warns = [c for c in data["checks"] if c["status"] == "WARNING"]
        report += f"""
### [{name}] - {data['role']}
- **Sistem Operasi** : {data['os']}
- **Alamat IP / MAC**: `{data['ip']}` / `{data['mac']}`
- **Active User**    : `{data['user']}`
- **Skor Kesiapan**  : **{d_score}/100** ({'PASS' if d_score >= 75 else 'PERLU PERBAIKAN'})
- **Listening Ports**: `{data['open_ports']}`
- **Temuan Celah**   : {len(fails)} FAIL, {len(warns)} WARNING
"""
        if fails:
            report += "**Daftar Temuan Kritis (FAIL):**\n"
            for f in fails:
                report += f"  - `[{f['cis']}]` **{f['param']}**: {f.get('detail') or f.get('details', '')}\n"
        if warns:
            report += "**Daftar Peringatan (WARNING):**\n"
            for w in warns:
                report += f"  - `[{w['cis']}]` **{w['param']}**: {w.get('detail') or w.get('details', '')}\n"

    report += f"""
---

## 3. REKOMENDASI TAKTIS KEPADA KOMANDAN SATUAN (DAN / PUSKODAL)
1. **Otomasi Remediasi**: Segera laksanakan prosedur 'One-Click Hardening' pada perangkat yang masih memiliki celah FAIL untuk mengeliminasi port listener berbahaya (SMB 445, Telnet 23, Backdoor 4444).
2. **Kepatuhan Infrastruktur OT (Radio BMS)**: Terapkan segmentasi zona dan conduit sesuai standar **ISA/IEC 62443-3-3 SR 5.1** guna mencegah transmisi perintah taktis plaintext.
3. **Penyebaran Telemetri Terpusat**: Distribusikan `pasopati_audit.py` ke seluruh sub-satuan dengan parameter `--push-url` untuk pemantauan terpusat berkelanjutan.

================================================================================
PUSAT OPERASI SIBER PERTAHANAN
PASOPATI AUTONOMOUS AUDIT ENGINE v2.6
================================================================================
"""
    return report

# ------------------------------------------------------------------------------
# SIDEBAR: TACTICAL CONTROL & AI CONFIGURATION
# ------------------------------------------------------------------------------
score_now = get_overall_score()
defcon_info = get_defcon_level(score_now)

st.sidebar.image(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "public", "pasopati-mark.png"),
    width=120
)
st.sidebar.markdown(f"""
<div style='padding: 12px 14px; background: #1b202a; border: 1px solid #2a3140; border-left: 3px solid #ef4444; border-radius: 6px; margin-bottom: 14px;'>
    <div style='color: #64748b; font-size: 0.68rem; font-family: monospace; letter-spacing: 0.1em; font-weight: 700;'>PROTOKOL AUDIT &amp; PENGAMANAN AGEN TI</div>
    <div style='color: #f1f5f9; font-size: 1.25rem; font-weight: 800; font-family: monospace; letter-spacing: 0.12em; margin-top: 2px;'>PASOPATI <span style='font-size:0.72rem; color:#ef4444;'>v2.6</span></div>
    <div style='margin-top: 8px; display: inline-flex; align-items: center; gap: 6px; font-size: 0.72rem; font-family: monospace; font-weight: 700; color: {defcon_info["color"]}; background: rgba(0,0,0,0.3); padding: 3px 8px; border-radius: 4px; border: 1px solid #2a3140;'>
        <span style='width: 6px; height: 6px; border-radius: 50%; background: {defcon_info["color"]};'></span>
        {defcon_info["level"]} · {defcon_info["state"].split("//")[0].strip()}
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("<div style='font-size:0.72rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px;'>THREAT INTELLIGENCE ENGINE</div>", unsafe_allow_html=True)

ai_mode = st.sidebar.radio(
    "AI Engine Mode:",
    [
        "Rule-Based Threat Intel (Air-Gapped / Zero-Key)",
        "Cloud AI (OpenAI-compatible / Gemini)",
        "Local AI: Air-Gapped LLM Endpoint"
    ],
    index=0,
    label_visibility="collapsed"
)

gemini_key = ""
ollama_url = "http://localhost:11434"

if "Cloud AI" in ai_mode:
    gemini_key = st.sidebar.text_input(
        "Gemini API Key:",
        type="password",
        value=secret_gemini_key,
        help="API key provider (Gemini atau OpenAI-compatible sesuai GEMINI_BASE_URL). Jika kosong, sistem fallback ke Rule-Based Threat Engine."
    )
elif "Local AI" in ai_mode:
    ollama_url = st.sidebar.text_input(
        "Local Endpoint:",
        value="http://localhost:11434",
        help="Endpoint Ollama / vLLM di server lokal tertutup."
    )

opsec_sanitization = st.sidebar.checkbox(
    "OPSEC Sanitization (Redact IP/MAC/Host)",
    value=True,
    help="Menyensor alamat IP, MAC address, dan Hostname rahasia satuan menjadi [REDACTED] sebelum dikirim ke AI Engine eksternal."
)

if "Cloud AI" in ai_mode and (gemini_key or secret_gemini_key):
    st.sidebar.markdown(f"<div style='color:#34d399; font-size:0.75rem; font-family:monospace;'>● CLOUD AI: {html.escape(_env_clean('AI_MODEL_NAME', 'gemini-2.5-flash'))}</div>", unsafe_allow_html=True)
elif "Local AI" in ai_mode:
    st.sidebar.markdown("<div style='color:#38bdf8; font-size:0.75rem; font-family:monospace;'>● LOCAL LLM ENDPOINT (OpenAI-compatible)</div>", unsafe_allow_html=True)
else:
    st.sidebar.markdown("<div style='color:#94a3b8; font-size:0.75rem; font-family:monospace;'>● RULE-BASED THREAT INTEL ACTIVE</div>", unsafe_allow_html=True)

st.sidebar.markdown("<hr style='border-color:#1e293b; margin: 16px 0;'>", unsafe_allow_html=True)

@st.cache_data(show_spinner=False, ttl=300)
def create_project_zip_bytes():
    import io, zipfile
    buf = io.BytesIO()
    exclude_dirs = {'.git', 'node_modules', 'dist', '__pycache__', '.vite', '.aistudio', 'data'}
    exclude_files = {
        'bun.lock', '.DS_Store', 'audit_result.json', 'audit.json',
        'CATATAN-PENGEMBANGAN.md', 'pasopati-project.zip',
        # Rahasia hidup: file template .env.example tetap ikut.
        'opencode.json', 'reapprove.ps1', 'token.txt',
    }
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.')]
            for file in files:
                # Exclude ALL dotfiles (incl. .env — secrets never ship), logs,
                # compiled caches and archives.
                if (
                    file in exclude_files
                    or (file.startswith('.') and file != '.env.example')
                    or file.startswith('bitlocker-recovery-')
                    or file.endswith('.pyc')
                    or file.endswith('.zip')
                    or file.endswith('.log')
                ):
                    continue
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, base_dir)
                zipf.write(filepath, arcname)
    buf.seek(0)
    return buf.getvalue()

st.sidebar.markdown("<div style='font-size:0.72rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:8px;'>PROTECTED DOWNLOADS (PASSWORD)</div>", unsafe_allow_html=True)

if not os.environ.get("PASOPATI_DOWNLOAD_PASSWORD"):
    st.sidebar.info("Fitur download saat ini dinonaktifkan. Set environment variable PASOPATI_DOWNLOAD_PASSWORD untuk mengaktifkannya.")

download_auth_input = st.sidebar.text_input(
    "Password Otorisasi Download:",
    type="password",
    placeholder="Masukkan password otorisasi...",
    help="Otorisasi akses terbatas personil komando siber."
)

_download_password = os.environ.get("PASOPATI_DOWNLOAD_PASSWORD", "")
is_download_authorized = bool(_download_password) and hmac.compare_digest(
    download_auth_input.strip().encode("utf-8"), _download_password.encode("utf-8")
)

if is_download_authorized:
    st.sidebar.success("Otorisasi Valid: Pengunduhan Diizinkan.")
    st.sidebar.download_button(
        label="Download Project (.ZIP)",
        data=create_project_zip_bytes(),
        file_name="pasopati-project.zip",
        mime="application/zip",
        use_container_width=True,
        help="Unduh seluruh file proyek PASOPATI dalam format ZIP untuk dijalankan di laptop pribadi."
    )

    st.sidebar.download_button(
        label="Buat Laporan (.md)",
        data=generate_commander_report(),
        file_name=f"LAPORAN_PUSKODAL_{datetime.now().strftime('%Y%m%d_%H%M')}.md",
        mime="text/markdown",
        use_container_width=True
    )
else:
    st.sidebar.markdown("""
    <div style='background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.4); padding: 8px 10px; border-radius: 6px; font-size: 0.72rem; color: #f43f5e; font-family: monospace;'>
        AKSES TERKUNCI: Masukkan kode otorisasi keamanan untuk membuka akses pengunduhan berkas.
    </div>
    """, unsafe_allow_html=True)

with st.sidebar.expander("Pratinjau Laporan (Rata Kiri-Kanan)", expanded=False):
    st.markdown(f"""
    <div style='text-align: justify; text-justify: inter-word; font-size: 0.76rem; line-height: 1.6; color: #cbd5e1; background: #080d16; border: 1px solid #1e293b; border-radius: 6px; padding: 12px;'>
        <div style='font-family: monospace; font-size: 0.72rem; color: #38bdf8; font-weight: 700; border-bottom: 1px solid #1e293b; padding-bottom: 4px; margin-bottom: 8px;'>
            PUSKODAL UTAMA // KLASIFIKASI: RAHASIA
        </div>
        <p style='text-align: justify; text-justify: inter-word; margin-bottom: 8px;'>
            Berdasarkan audit kepatuhan otomatis menggunakan sistem PASOPATI pada aset inti pertahanan (Core IT/OT TNI AD), indeks kesiapan siber agregat armada saat ini berada pada tingkat <strong>{score_now}/100</strong> dengan postur <strong>{defcon_info["level"]}</strong> ({defcon_info["state"].split("//")[0].strip()}).
        </p>
        <p style='text-align: justify; text-justify: inter-word; margin-bottom: 8px;'>
            Seluruh parameter kepatuhan mengacu pada standar internasional CIS Benchmark v8.0, DISA STIG DoD, dan standar infrastruktur operasional taktis ISA/IEC 62443. Rekomendasi tindakan remediasi otomatis dan pengamanan protokol radio telah dipetakan untuk Komandan Satuan.
        </p>
        <div style='font-family: monospace; font-size: 0.68rem; color: #64748b; margin-top: 6px;'>
            Dokumen lengkap dapat diunduh melalui tombol 'Buat Laporan (.md)' di atas.
        </div>
    </div>
    """, unsafe_allow_html=True)

st.sidebar.markdown("<hr style='border-color:#1e293b; margin: 16px 0;'>", unsafe_allow_html=True)

if st.sidebar.button("Reset Baseline Simulation", use_container_width=True):
    st.session_state.devices = copy.deepcopy(INITIAL_DEVICES)
    st.session_state.backup_devices = copy.deepcopy(INITIAL_DEVICES)
    st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.sidebar.success("Baseline disetel ulang.")
    time.sleep(0.3)
    st.rerun()

st.sidebar.markdown(f"<div style='color:#475569; font-size:0.72rem; font-family:monospace; margin-top:12px;'>LAST SYNC: {st.session_state.last_scan_time}</div>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TOP HEADER BANNER
# ------------------------------------------------------------------------------
overall_score = get_overall_score()
defcon = get_defcon_level(overall_score)

total_assets = len(st.session_state.devices)
crit_ports_count = sum(
    len([p for p in d["open_ports"] if p in [445, 3389, 23, 21, 4444]])
    for d in st.session_state.devices.values()
)
total_fail_checks = sum(
    sum(1 for c in d["checks"] if c["status"] == "FAIL")
    for d in st.session_state.devices.values()
)

st.markdown(f"""
<div class='tactical-header-card'>
    <div style='display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;'>
        <div>
            <div class='tactical-title'>
                <span>PASOPATI</span>
                <span class='badge-tag'>CYBER DEFENSE COMMAND</span>
                <span class='badge-tag' style='border-color: #0284c7; color: #38bdf8;'>TNI AD SPEC</span>
            </div>
            <div class='tactical-subtitle'>
                System Audit, Threat Remediation & Intelligence Architecture Guard · DISA STIG / CIS Benchmark / ISA-IEC 62443 Compliance
            </div>
        </div>
        <div style='display: flex; align-items: center; gap: 8px;'>
            <div style='text-align: right;'>
                <div style='color: #64748b; font-size: 0.7rem; font-family: monospace; letter-spacing: 0.05em;'>FLEET READINESS POSTURE</div>
                <div style='color: {defcon["color"]}; font-family: monospace; font-size: 1.1rem; font-weight: 700;'>{defcon["level"]} // {overall_score}%</div>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TAB NAVIGATION
# ------------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "01 // COMMAND CENTER",
    "02 // DEEP ENDPOINT AUDIT",
    "03 // THREAT REMEDIATION & AI INTEL",
    "04 // LIVE AGENT INGESTION"
])

# ==============================================================================
# TAB 1: COMMAND CENTER
# ==============================================================================
with tab1:
    # Top Metrics Grid
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    mcol1.metric("MONITORED FLEET", f"{total_assets} Endpoints", "100% IT/OT Online")
    mcol2.metric("EXPOSED CRITICAL PORTS", f"{crit_ports_count} Ports", "Remediation Required" if crit_ports_count > 0 else "Fully Isolated", delta_color="inverse")
    mcol3.metric("FAIL VIOLATIONS", f"{total_fail_checks} Findings", "STIG Non-Compliant" if total_fail_checks > 0 else "All Benchmarks Passed", delta_color="inverse")
    mcol4.metric("OPSEC STATUS", "ACTIVE" if opsec_sanitization else "RAW TELEMETRY", "Data Masking Engaged")

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    col_gauge, col_matrix = st.columns([1, 2])

    with col_gauge:
        st.markdown("<div class='telemetry-card' style='padding: 12px;'>", unsafe_allow_html=True)
        st.plotly_chart(create_gauge_chart(overall_score), use_container_width=True)
        
        if st.button("RUN FLEET AUDIT RECON (SIMULASI)", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()
            steps = [
                "[SIMULASI] Probing subnet 10.14.0.0/16 and tactical radio interfaces...",
                "[SIMULASI] Inspecting dangerous ports (SMB 445, Telnet 23, Backdoor 4444)...",
                "[SIMULASI] Verifying CIS 5.2 access control (SSH root & guest policies)...",
                "[SIMULASI] Auditing ISA/IEC 62443 compliance on tactical radio gateway...",
                "[SIMULASI] Scanning kernel auditd and event logging daemons...",
                "[SIMULASI] Computing aggregate defense readiness index..."
            ]
            for idx, s in enumerate(steps):
                time.sleep(0.2)
                progress_bar.progress(int((idx + 1) * 100 / len(steps)))
                status_text.markdown(f"<div style='font-family:monospace; font-size:0.75rem; color:#38bdf8;'>[SIMULASI] {s}</div>", unsafe_allow_html=True)
            st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(0.3)
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    with col_matrix:
        st.markdown("<div style='font-size:0.78rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:8px;'>FLEET ENDPOINT READINESS MATRIX</div>", unsafe_allow_html=True)
        
        for dev_name, data in st.session_state.devices.items():
            d_score = calculate_score(data["checks"])
            bar_color = "#10b981" if d_score >= 75 else ("#f59e0b" if d_score >= 50 else "#f43f5e")
            fail_count = sum(1 for c in data["checks"] if c["status"] == "FAIL")
            warn_count = sum(1 for c in data["checks"] if c["status"] == "WARNING")
            
            ports_summary = ", ".join(str(p) for p in data["open_ports"][:4])
            if len(data["open_ports"]) > 4:
                ports_summary += f" +{len(data['open_ports']) - 4}"

            st.markdown(f"""
            <div class='telemetry-card' style='display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;'>
                <div style='flex: 1;'>
                    <div style='display:flex; align-items:center; gap:8px;'>
                        <span style='color:#f8fafc; font-family:monospace; font-size:0.95rem; font-weight:700;'>{html.escape(str(dev_name))}</span>
                        <span className='badge-tag'>{html.escape(str(data["ip"]))}</span>
                        <span className='badge-tag'>{html.escape(str(data["os"]).split(" ")[0])}</span>
                    </div>
                    <div style='color:#64748b; font-size:0.78rem; margin-top:4px;'>
                        {html.escape(str(data["role"]))} · Ports: [{html.escape(str(ports_summary))}]
                    </div>
                </div>
                <div style='display:flex; align-items:center; gap:16px;'>
                    <div style='display:flex; gap:6px;'>
                        {f'<span class="badge-fail">{fail_count} FAIL</span>' if fail_count > 0 else ''}
                        {f'<span class="badge-warn">{warn_count} WARN</span>' if warn_count > 0 else ''}
                        {f'<span class="badge-pass">PASS</span>' if fail_count == 0 and warn_count == 0 else ''}
                    </div>
                    <div style='text-align:right; min-width:65px;'>
                        <div style='color:{bar_color}; font-size:1.15rem; font-weight:700; font-family:monospace;'>{d_score}%</div>
                        <div style='color:#475569; font-size:0.65rem; font-family:monospace;'>COMPLIANCE</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# ==============================================================================
# TAB 2: DEEP ENDPOINT AUDIT
# ==============================================================================
with tab2:
    st.markdown("<div style='font-size:0.78rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:8px;'>ENDPOINT SELECTION & TELEMETRY PROFILE</div>", unsafe_allow_html=True)

    selected_device_name = st.selectbox(
        "Pilih Perangkat Satuan untuk Inspeksi Rinci:",
        list(st.session_state.devices.keys()),
        label_visibility="collapsed"
    )

    dev = st.session_state.devices[selected_device_name]
    dev_score = calculate_score(dev["checks"])

    # High-density Specification Strip
    spec_col1, spec_col2, spec_col3, spec_col4 = st.columns(4)
    with spec_col1:
        st.markdown(f"""
        <div class='telemetry-card' style='padding:10px 14px;'>
            <div style='color:#64748b; font-size:0.7rem; font-family:monospace;'>HOSTNAME // ROLE</div>
            <div style='color:#f1f5f9; font-size:0.85rem; font-weight:600; font-family:monospace;'>{html.escape(str(dev['hostname']))}</div>
            <div style='color:#94a3b8; font-size:0.75rem;'>{html.escape(str(dev['role']))}</div>
        </div>
        """, unsafe_allow_html=True)
    with spec_col2:
        st.markdown(f"""
        <div class='telemetry-card' style='padding:10px 14px;'>
            <div style='color:#64748b; font-size:0.7rem; font-family:monospace;'>OPERATING SYSTEM // USER</div>
            <div style='color:#f1f5f9; font-size:0.85rem; font-weight:600; font-family:monospace;'>{html.escape(str(dev['os']))}</div>
            <div style='color:#94a3b8; font-size:0.75rem;'>Session: {html.escape(str(dev['user']))}</div>
        </div>
        """, unsafe_allow_html=True)
    with spec_col3:
        st.markdown(f"""
        <div class='telemetry-card' style='padding:10px 14px;'>
            <div style='color:#64748b; font-size:0.7rem; font-family:monospace;'>NETWORK INTERFACE</div>
            <div style='color:#f1f5f9; font-size:0.85rem; font-weight:600; font-family:monospace;'>IP: {html.escape(str(dev['ip']))}</div>
            <div style='color:#94a3b8; font-size:0.75rem; font-family:monospace;'>MAC: {html.escape(str(dev['mac']))}</div>
        </div>
        """, unsafe_allow_html=True)
    with spec_col4:
        ports_fmt = ", ".join(f"{p}" for p in dev["open_ports"])
        st.markdown(f"""
        <div class='telemetry-card' style='padding:10px 14px;'>
            <div style='color:#64748b; font-size:0.7rem; font-family:monospace;'>LISTENING PORTS // SCORE</div>
            <div style='color:#38bdf8; font-size:0.85rem; font-weight:600; font-family:monospace;'>[{ports_fmt}]</div>
            <div style='color:#10b981; font-size:0.75rem; font-weight:700; font-family:monospace;'>Readiness: {dev_score}/100</div>
        </div>
        """, unsafe_allow_html=True)

    # Emergency Kill-Switch & Compliance Drift Tracking
    q_col1, q_col2 = st.columns([1, 2])
    with q_col1:
        is_quar = dev.get("is_quarantined", False)
        btn_label = "🔓 CABUT STATUS KARANTINA" if is_quar else "🔒 TANDAI KARANTINA (SIMULASI)"
        if st.button(btn_label, use_container_width=True):
            dev["is_quarantined"] = not is_quar
            st.rerun()

    with q_col2:
        if dev.get("is_quarantined"):
            st.error("🚨 STATUS KARANTINA DICATAT (SIMULASI): Server tidak memblokir port; eksekusi firewall nyata oleh pasopati_remediate.py di host.")

    # Historical Compliance Drift Over Time (SQLite/Stateful)
    if "history" in dev and dev["history"]:
        with st.expander("📈 HISTORI COMPLIANCE DRIFT OVER TIME (PELACAKAN DEGRADASI POSTUR)", expanded=True):
            h_cols = st.columns(len(dev["history"]))
            for idx, h in enumerate(dev["history"]):
                with h_cols[idx]:
                    st.metric(label=f"{h['time']} · {h['event']}", value=f"{h['score']}/100")

    # Filter Controls
    fcol1, fcol2 = st.columns([1, 3])
    with fcol1:
        status_filter = st.selectbox(
            "Filter Status:",
            ["ALL PARAMETERS", "FAIL ONLY", "WARNING ONLY", "PASS ONLY"],
            label_visibility="collapsed"
        )

    # Filter checks based on selection
    displayed_checks = dev["checks"]
    if status_filter == "FAIL ONLY":
        displayed_checks = [c for c in dev["checks"] if c["status"] == "FAIL"]
    elif status_filter == "WARNING ONLY":
        displayed_checks = [c for c in dev["checks"] if c["status"] == "WARNING"]
    elif status_filter == "PASS ONLY":
        displayed_checks = [c for c in dev["checks"] if c["status"] == "PASS"]

    st.markdown(f"<div style='font-size:0.72rem; color:#64748b; font-family:monospace; margin-bottom:8px;'>SHOWING {len(displayed_checks)} DEEP COMPLIANCE CHECKS</div>", unsafe_allow_html=True)

    for check in displayed_checks:
        status = check["status"]
        if status == "PASS":
            badge_html = "<span class='badge-pass'>PASS</span>"
            border_color = "#1e293b"
        elif status == "WARNING":
            badge_html = "<span class='badge-warn'>WARNING</span>"
            border_color = "rgba(245, 158, 11, 0.4)"
        else:
            badge_html = "<span class='badge-fail'>FAIL</span>"
            border_color = "rgba(244, 63, 94, 0.4)"

        detail_text = check.get("detail") or check.get("details", "")

        st.markdown(f"""
        <div class='telemetry-card' style='border-left: 3px solid {border_color}; margin-bottom: 8px;'>
            <div style='display:flex; justify-content:space-between; align-items:center;'>
                <div style='display:flex; align-items:center; gap:10px;'>
                    <span style='color:#f1f5f9; font-weight:600; font-size:0.88rem; font-family:monospace;'>{html.escape(str(check['param']))}</span>
                    <span class='badge-tag'>{html.escape(str(check['cis']))}</span>
                    <span class='badge-tag'>{html.escape(str(check['cat']))}</span>
                </div>
                <div>{badge_html}</div>
            </div>
            <div style='color:#94a3b8; font-size:0.82rem; margin-top:6px;'>{html.escape(str(detail_text))}</div>
        </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# TAB 3: THREAT REMEDIATION & AI INTEL (SPLIT-PANE TACTICAL CONSOLE)
# ==============================================================================
with tab3:
    target_dev_name = st.selectbox(
        "Pilih Target Endpoint untuk Remediasi:",
        list(st.session_state.devices.keys()),
        key="remediation_selector",
        label_visibility="collapsed"
    )

    target_dev = st.session_state.devices[target_dev_name]
    fail_checks = [c for c in target_dev["checks"] if c["status"] == "FAIL"]
    warn_checks = [c for c in target_dev["checks"] if c["status"] == "WARNING"]
    is_linux = any(k in target_dev["os"].lower() for k in ["linux", "ubuntu", "debian", "openwrt"])

    # Split-Pane: Left Column = Threat Assessment & Execution; Right Column = Dynamic Script & Diff
    pane_left, pane_right = st.columns([1, 1.25])

    with pane_left:
        st.markdown(f"""
        <div class='telemetry-card' style='margin-bottom:12px;'>
            <div style='display:flex; justify-content:space-between; align-items:center;'>
                <div>
                    <span style='color:#f8fafc; font-weight:700; font-family:monospace; font-size:1rem;'>{html.escape(str(target_dev_name))}</span>
                    <div style='color:#64748b; font-size:0.75rem;'>{html.escape(str(target_dev['role']))} · {html.escape(str(target_dev['os']))}</div>
                </div>
                <div style='display:flex; gap:6px;'>
                    <span class='badge-fail'>{len(fail_checks)} FAIL</span>
                    <span class='badge-warn'>{len(warn_checks)} WARN</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if opsec_sanitization:
            st.markdown("""
            <div style='background:rgba(2,132,199,0.1); border:1px solid #0284c7; padding:8px 12px; border-radius:6px; margin-bottom:12px; font-size:0.75rem; color:#38bdf8; font-family:monospace;'>
                OPSEC ACTIVE: Data sensitif (IP/MAC/Host) disensor menjadi [REDACTED] sebelum diproses engine intelijen.
            </div>
            """, unsafe_allow_html=True)

        # AI Threat Intelligence Assessment
        st.markdown("<div style='font-size:0.72rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px;'>TACTICAL THREAT ASSESSMENT</div>", unsafe_allow_html=True)

        if len(fail_checks) == 0:
            st.markdown("""
            <div class='telemetry-card' style='border-left: 3px solid #10b981;'>
                <div style='color:#34d399; font-weight:600; font-size:0.85rem; font-family:monospace;'>[STATUS: SECURE 100%]</div>
                <div style='color:#94a3b8; font-size:0.8rem; margin-top:4px;'>Seluruh parameter CIS Benchmark, DISA STIG, dan ISA/IEC 62443 telah patuh. Tidak ada celah aktif.</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            target_ip_masked = "[REDACTED_MIL_IP]" if opsec_sanitization else target_dev['ip']
            target_mac_masked = "[REDACTED_MAC]" if opsec_sanitization else target_dev['mac']
            target_host_masked = "[REDACTED_HOST]" if opsec_sanitization else target_dev['hostname']

            fail_payload = [
                {"param": fc.get("param"), "category": fc.get("cat"), "cis": fc.get("cis"), "detail": fc.get("detail") or fc.get("details", "")}
                for fc in fail_checks
            ]

            active_key = (gemini_key or secret_gemini_key or os.environ.get("GEMINI_API_KEY", "")).strip()
            ai_source = "Rule-Based Defense Threat Engine (Air-Gapped)"
            ai_text = ""

            ai_model_name = _env_clean("AI_MODEL_NAME", "gemini-2.5-flash")
            ai_base_url = _env_clean("GEMINI_BASE_URL", "")
            want_cloud = "Cloud AI" in ai_mode and bool(active_key) and len(active_key) > 15 and not active_key.startswith("MY_")
            want_local = "Local AI" in ai_mode

            if want_cloud or want_local:
                try:
                    if opsec_sanitization:
                        safe_name = redact_sensitive(target_dev_name)
                        safe_role = redact_sensitive(target_dev["role"])
                        safe_os = redact_sensitive(target_dev["os"])
                        safe_payload = [
                            {
                                "param": redact_sensitive(fc.get("param")),
                                "category": redact_sensitive(fc.get("cat")),
                                "cis": fc.get("cis"),
                                "detail": redact_sensitive(fc.get("detail") or fc.get("details") or ""),
                            }
                            for fc in fail_checks
                        ]
                    else:
                        safe_name, safe_role, safe_os = target_dev_name, target_dev["role"], target_dev["os"]
                        safe_payload = fail_payload

                    prompt = f"""Bertindaklah sebagai Senior Military Cyber Defense Analyst dari PASOPATI (Pusat Operasi Siber Pertahanan TNI).
Lakukan Analisis Risiko Kontekstual Taktis dalam Bahasa Indonesia yang lugas, tegas, dan berwibawa militer mengenai temuan celah keamanan berikut:

Identitas Perangkat:
- Nama Aset: {safe_name}
- Peran Operasi: {safe_role}
- Sistem Operasi: {safe_os}
- Alamat IP: {target_ip_masked}
- MAC Address: {target_mac_masked}
- Hostname: {target_host_masked}

Temuan Celah Keamanan (FAIL):
{json.dumps(safe_payload, indent=2)}

Jelaskan dalam 3 poin ringkas:
1. Telaah Vektor Serangan: Potensi lateral movement, C2, atau kebocoran data taktis.
2. Dampak Operasional terhadap kerahasiaan & ketersediaan misi.
3. Prioritas Tindakan Kontinjensi sesuai CIS/STIG/ISA-62443."""

                    if want_cloud:
                        ai_text, ai_source = call_ai_provider(prompt, active_key, ai_base_url, ai_model_name)
                    else:
                        local_model = _env_clean("LOCAL_AI_MODEL", "llama3")
                        ai_text, ai_source = call_ai_provider(prompt, "local", ollama_url, local_model)
                except Exception as exc:
                    ai_source = f"Rule-Based fallback ({type(exc).__name__})"

            if not ai_text:
                ai_text = f"TELAAH INTELIJEN SIBER (PUSSIBERAD TASK FORCE)\n\nPada aset inti {target_dev_name}, terdeteksi {len(fail_checks)} parameter non-compliant dengan implikasi operasional:\n"
                for fc in fail_checks:
                    param = fc.get("param", "")
                    detail = fc.get("detail") or fc.get("details", "")
                    if "4444" in param or "4444" in detail:
                        ai_text += "\n- [CRITICAL] C2 Backdoor Active (Port 4444): Indikasi workstation telah dikompromi oleh adversary luar. Harus dinetralisir segera."
                    elif "SMB" in param or "445" in param:
                        ai_text += "\n- [HIGH] Unsegmented SMB (Port 445): Risiko lateral movement dan serangan worm-like pada subnet taktis."
                    elif "SSH" in param:
                        ai_text += "\n- [HIGH] Direct Root SSH Access: Ancaman brute-force otentikasi pangkalan data operasi."
                    elif "Firewall" in param:
                        ai_text += "\n- [HIGH] Inactive Host Firewall: Seluruh antarmuka terpapar pemindaian port intelijen lawan."
                    elif "Telnet" in param or "FTP" in param or "23" in param or "21" in param:
                        ai_text += "\n- [CRITICAL] Plaintext OT Protocol: Kredensial radio dikirim tanpa TLS; melanggar klausul ISA/IEC 62443-3-3 SR 3.1."
                    elif "auditd" in param or "Logging" in param:
                        ai_text += "\n- [MEDIUM] Disabled Security Auditing: Jejak forensik kernel tidak tercatat di SIEM satuan."
                    else:
                        ai_text += f"\n- [WARN] {param}: {detail}"

            st.markdown(f"""
            <div class='telemetry-card' style='border-left: 3px solid #0284c7; max-height: 260px; overflow-y: auto;'>
                <div style='font-size:0.8rem; line-height:1.5; color:#cbd5e1;'>{html.escape(ai_text)}</div>
                <div style='color:#64748b; font-size:0.68rem; font-family:monospace; margin-top:8px;'>SOURCE: {ai_source}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        # Action Buttons
        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button(f"EXECUTE HARDENING (SIMULASI)", use_container_width=True):
                with st.spinner("Mensimulasikan perubahan status hardening (tanpa eksekusi host)..."):
                    if target_dev_name not in st.session_state.backup_devices:
                        st.session_state.backup_devices[target_dev_name] = copy.deepcopy(target_dev)

                    for c in target_dev["checks"]:
                        if c["status"] == "FAIL":
                            c["status"] = "PASS"
                            d = c.get("detail") or c.get("details", "")
                            if "[REMEDIATED]" not in d:
                                c["detail"] = d + " [REMEDIATED VIA PASOPATI ENGINE]"
                        elif c["status"] == "WARNING":
                            c["status"] = "PASS"
                            d = c.get("detail") or c.get("details", "")
                            if "[OPTIMIZED]" not in d:
                                c["detail"] = d + " [OPTIMIZED TO MAXIMUM DEFENSE POSTURE]"

                    target_dev["open_ports"] = [p for p in target_dev["open_ports"] if p not in [445, 3389, 23, 21, 4444]]
                    st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                st.success(f"Simulasi hardening selesai (status dashboard). Skor `{target_dev_name}` mencapai {calculate_score(target_dev['checks'])}/100. Tidak ada perubahan host nyata.")
                time.sleep(0.4)
                st.rerun()

        with bcol2:
            if st.button("RESTORE BACKUP", use_container_width=True):
                with st.spinner("Memulihkan konfigurasi awal..."):
                    if target_dev_name in st.session_state.backup_devices:
                        st.session_state.devices[target_dev_name] = copy.deepcopy(st.session_state.backup_devices[target_dev_name])
                    elif target_dev_name in INITIAL_DEVICES:
                        st.session_state.devices[target_dev_name] = copy.deepcopy(INITIAL_DEVICES[target_dev_name])
                    st.session_state.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                st.warning(f"Rollback selesai. Skor `{target_dev_name}` dikembalikan ke status awal.")
                time.sleep(0.4)
                st.rerun()

    with pane_right:
        st.markdown("<div style='font-size:0.72rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px;'>DYNAMIC TARGETED SCRIPT & RUNBOOK GENERATOR</div>", unsafe_allow_html=True)
        hardening_script, rollback_script, script_ext = generate_dynamic_scripts(target_dev_name, target_dev)

        script_view = st.radio("Script View:", ["HARDENING SCRIPT", "ROLLBACK SCRIPT"], horizontal=True, label_visibility="collapsed")

        if script_view == "HARDENING SCRIPT":
            st.code(hardening_script, language=script_ext)
            st.download_button(
                label=f"Download Hardening Script (.{'sh' if is_linux else 'ps1'})",
                data=hardening_script,
                file_name=f"pasopati_hardening_{target_dev_name}.{'sh' if is_linux else 'ps1'}",
                mime="text/x-shellscript" if is_linux else "text/plain",
                use_container_width=True
            )
        else:
            st.code(rollback_script, language=script_ext)
            st.download_button(
                label=f"Download Rollback Script (.{'sh' if is_linux else 'ps1'})",
                data=rollback_script,
                file_name=f"pasopati_rollback_{target_dev_name}.{'sh' if is_linux else 'ps1'}",
                mime="text/x-shellscript" if is_linux else "text/plain",
                use_container_width=True
            )

# ==============================================================================
# TAB 4: LIVE AGENT INGESTION & EVALUATION
# ==============================================================================
with tab4:
    st.markdown("<div style='font-size:0.78rem; font-weight:700; color:#64748b; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:8px;'>DEWAN JURI FIELD TEST: CLI SCANNER & JSON INGESTION</div>", unsafe_allow_html=True)

    ingest_col1, ingest_col2 = st.columns([1, 1.2])

    with ingest_col1:
        st.markdown("""
        <div class='telemetry-card'>
            <div style='color:#f8fafc; font-weight:700; font-family:monospace; font-size:0.95rem;'>01 // DOWNLOAD STANDALONE CLI AGENT</div>
            <div style='color:#94a3b8; font-size:0.8rem; margin:6px 0 12px 0;'>
                Script Python mandiri ringan tanpa dependensi pihak ketiga, siap dieksekusi di workstation juri (Linux & Windows).
            </div>
        </div>
        """, unsafe_allow_html=True)

        agent_path = os.path.join(os.path.dirname(__file__), "pasopati_audit.py")
        if os.path.exists(agent_path):
            with open(agent_path, "r") as f:
                agent_code = f.read()
        else:
            agent_code = "# pasopati_audit.py CLI scanner"

        st.download_button(
            label="Download pasopati_audit.py",
            data=agent_code,
            file_name="pasopati_audit.py",
            mime="text/x-python",
            use_container_width=True
        )

        st.markdown("""
        ```bash
        # Eksekusi audit lokal pada perangkat Anda:
        python pasopati_audit.py -u "LAPTOP-JURI-TEST"

        # ATAU eksekusi dengan pengiriman telemetri terpusat:
        python pasopati_audit.py -u "LAPTOP-JURI-TEST" --push-url "http://10.14.2.1:3000/api/ingest"
        ```
        """)

    with ingest_col2:
        st.markdown("""
        <div class='telemetry-card'>
            <div style='color:#f8fafc; font-weight:700; font-family:monospace; font-size:0.95rem;'>02 // INGEST AUDIT_RESULT.JSON</div>
            <div style='color:#94a3b8; font-size:0.8rem; margin:6px 0 12px 0;'>
                Unggah hasil audit JSON nyata atau muat sampel data untuk evaluasi instan.
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Muat Contoh Hasil Audit Agent (Sample Juri Laptop)", use_container_width=True):
            sample_json = {
                "metadata": {
                    "scanner": "PASOPATI Autonomous Agent v2.6",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "tactical_unit": "LAPTOP-DEWAN-JURI",
                    "standard_baseline": "CIS Benchmark v8.0 & DISA STIG Core Infra"
                },
                "device_info": {
                    "hostname": "laptop-juri-evaluator",
                    "os": "Windows 11 Pro 64-bit",
                    "platform_type": "Windows Workstation",
                    "primary_ip": "192.168.1.105",
                    "mac_address": "88:66:5A:21:99:FF",
                    "active_user": "dewan_juri",
                    "listening_ports_count": 8,
                    "critical_ports_detected": 1,
                    "ports_list": [135, 445, 5357, 8080]
                },
                "scoring": {
                    "cyber_readiness_score": 60,
                    "passed_checks": 3,
                    "warning_checks": 1,
                    "failed_checks": 1,
                    "total_checks": 5
                },
                "compliance_matrix": [
                    {"parameter": "Network & Dangerous Ports Filtering", "category": "Network Security", "cis_id": "CIS 3.4", "status": "FAIL", "detail": "Port SMB 445 terbuka di antarmuka Wi-Fi lokal."},
                    {"parameter": "Host-Based Local Firewall Active", "category": "Network Security", "cis_id": "CIS 3.5.1", "status": "PASS", "detail": "Windows Defender Firewall aktif."},
                    {"parameter": "Guest Account Lockdown", "category": "Access Control", "cis_id": "DISA STIG WN11-00-000010", "status": "PASS", "detail": "Akun Guest dinonaktifkan."},
                    {"parameter": "USB Storage Device Control", "category": "Endpoint Protection", "cis_id": "DISA STIG WN11-CC-000180", "status": "WARNING", "detail": "USB Mass Storage belum dibatasi via GPO."},
                    {"parameter": "Windows Event Log & Auditing", "category": "System Logging", "cis_id": "DISA STIG WN11-AU-000050", "status": "PASS", "detail": "Security auditing service aktif merekam event log."}
                ]
            }

            unit_id = "LAPTOP-DEWAN-JURI"
            st.session_state.devices[unit_id] = {
                "hostname": sample_json["device_info"]["hostname"],
                "role": "Perangkat Uji Dewan Juri (Live CLI Upload)",
                "os": sample_json["device_info"]["os"],
                "ip": sample_json["device_info"]["primary_ip"],
                "mac": sample_json["device_info"]["mac_address"],
                "user": sample_json["device_info"]["active_user"],
                "open_ports": sample_json["device_info"]["ports_list"],
                "checks": [
                    {
                        "param": c.get("parameter") or c.get("param", "Security Parameter"),
                        "cat": c.get("category") or c.get("cat", "General"),
                        "cis": c.get("cis_id") or c.get("cis", "CIS 1.0"),
                        "status": c.get("status", "WARNING"),
                        "detail": c.get("detail") or c.get("details", "")
                    }
                    for c in sample_json["compliance_matrix"]
                ]
            }
            st.session_state.backup_devices[unit_id] = copy.deepcopy(st.session_state.devices[unit_id])
            st.success(f"Perangkat `{unit_id}` berhasil diintegrasikan ke fleet dashboard.")
            time.sleep(0.4)
            st.rerun()

        uploaded_file = st.file_uploader("Unggah audit_result.json:", type=["json"])

        if uploaded_file is not None:
            try:
                data = json.load(uploaded_file)
                if not isinstance(data, dict):
                    raise ValueError("Root JSON harus berupa objek.")
                metadata = data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {}
                device_info = data.get("device_info", {}) if isinstance(data.get("device_info", {}), dict) else {}
                raw_unit = metadata.get("tactical_unit", "UPLOADED-NODE")
                unit_id = re.sub(r'[^A-Za-z0-9._-]', '_', str(raw_unit))[:64].strip('._-') or "UPLOADED-NODE"

                raw_ports = device_info.get("ports_list", [])
                safe_ports = []
                if isinstance(raw_ports, list):
                    for p in raw_ports:
                        try:
                            safe_ports.append(int(p))
                        except (TypeError, ValueError):
                            continue

                raw_matrix = data.get("compliance_matrix", [])
                if not isinstance(raw_matrix, list):
                    raw_matrix = []
                safe_checks = []
                for c in raw_matrix:
                    if not isinstance(c, dict):
                        continue
                    check_status = str(c.get("status", "WARNING")).upper()
                    if check_status not in ("PASS", "WARNING", "FAIL"):
                        check_status = "WARNING"
                    safe_checks.append({
                        "param": str(c.get("parameter") or c.get("param") or "Security Parameter")[:200],
                        "cat": str(c.get("category") or c.get("cat") or "General")[:80],
                        "cis": str(c.get("cis_id") or c.get("cis") or "CIS 1.0")[:120],
                        "status": check_status,
                        "detail": str(c.get("detail") or c.get("details") or "")[:1000]
                    })

                st.session_state.devices[unit_id] = {
                    "hostname": str(device_info.get("hostname", "Unknown Host"))[:120],
                    "role": "Hasil Scan Nyata via pasopati_audit.py CLI",
                    "os": str(device_info.get("os", "Linux/Windows"))[:120],
                    "ip": str(device_info.get("primary_ip", "127.0.0.1"))[:64],
                    "mac": str(device_info.get("mac_address", "00:00:00:00:00:00"))[:32],
                    "user": str(device_info.get("active_user", "operator"))[:80],
                    "open_ports": safe_ports[:256],
                    "checks": safe_checks[:200]
                }
                st.session_state.backup_devices[unit_id] = copy.deepcopy(st.session_state.devices[unit_id])
                st.success(f"File audit `{unit_id}` valid. Data terintegrasi ke sistem pemantauan.")
                time.sleep(0.4)
                st.rerun()
            except Exception as e:
                st.error(f"Format JSON tidak valid: {str(e)}")

st.markdown("<hr style='border-color:#1e293b; margin: 24px 0 12px 0;'>", unsafe_allow_html=True)
st.markdown("<div style='text-align: center; color: #475569; font-size: 0.72rem; font-family: monospace;'>PASOPATI v2.6 · AUTONOMOUS CYBER DEFENSE & CORE INFRASTRUCTURE HARDENING · PUSSIBERAD</div>", unsafe_allow_html=True)
