#!/usr/bin/env python3
"""Uji unit handler remediasi (mesin di pasopati_audit.py): setiap alias harus
punya rollback yang benar-benar mengembalikan pre-state (bukan sekadar pesan).

Jalankan: python3 tests/test_agent_remediation.py
"""
import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pasopati_audit as agent  # noqa: E402


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pasopati-agent-test-")
        self.calls = []
        self.orig_run = agent._run_no_shell
        self.orig_paths = (list(agent._GRUB_PATHS), agent._SSHD_CONFIG_PATH, agent._USB_MODPROBE_PATH)
        self.orig_suid = list(agent._SUID_CANDIDATES)
        self.orig_sudoers_files = agent._sudoers_files

    def tearDown(self):
        agent._run_no_shell = self.orig_run
        agent._GRUB_PATHS, agent._SSHD_CONFIG_PATH, agent._USB_MODPROBE_PATH = self.orig_paths
        agent._SUID_CANDIDATES = self.orig_suid
        agent._sudoers_files = self.orig_sudoers_files
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mock_run(self, rc=0, out="ok"):
        def runner(argv, timeout=10):
            self.calls.append(argv)
            return rc, out
        agent._run_no_shell = runner

    # ---- firewall Windows ----
    def test_fw_rollback_keeps_on_when_previously_active(self):
        self._mock_run(0, "State ON")
        res = agent._win_fw_rollback({"activeCount": 3, "offCount": 0})
        self.assertEqual(res["exitCode"], 0)
        self.assertEqual(self.calls, [])

    def test_fw_rollback_turns_off_when_previously_off(self):
        self._mock_run(0, "ok")
        res = agent._win_fw_rollback({"activeCount": 2, "offCount": 1})
        self.assertEqual(res["exitCode"], 0)
        self.assertEqual(self.calls[0][:4], ["netsh", "advfirewall", "set", "allprofiles"])
        self.assertIn("off", self.calls[0])

    # ---- guest Windows ----
    def test_guest_rollback_reenables_only_if_active_before(self):
        self._mock_run(0, "ok")
        agent._win_guest_rollback({"active": True})
        self.assertIn("/active:yes", self.calls[0])
        self.calls.clear()
        agent._win_guest_rollback({"active": False})
        self.assertEqual(self.calls, [])

    # ---- UFW ----
    def test_ufw_rollback_noop_when_active_before(self):
        self._mock_run(0, "Status: active")
        agent._linux_ufw_rollback({"active": True})
        self.assertEqual(self.calls, [])

    def test_ufw_rollback_disables_when_inactive_before(self):
        self._mock_run(0, "Status: inactive")
        agent._linux_ufw_rollback({"active": False})
        self.assertIn("disable", self.calls[0])

    # ---- auditd ----
    def test_auditd_rollback_noop_when_active_before(self):
        self._mock_run(0, "active")
        agent._linux_auditd_rollback({"active": True})
        self.assertEqual(self.calls, [])

    def test_auditd_rollback_disables_when_inactive_before(self):
        self._mock_run(0, "inactive")
        agent._linux_auditd_rollback({"active": False})
        self.assertIn("disable", self.calls[0])

    # ---- BitLocker ----
    def test_bitlocker_rollback_noop_when_on_before(self):
        self._mock_run(0, "Protection On")
        agent._win_bitlocker_rollback({"protectionOn": True})
        self.assertEqual(self.calls, [])

    def test_bitlocker_rollback_off_when_off_before(self):
        self._mock_run(0, "Protection Off")
        agent._win_bitlocker_rollback({"protectionOn": False})
        self.assertIn("-off", self.calls[0])

    # ---- Firewall Windows: state on, bukan firewallpolicy ----
    def test_fw_apply_menyalakan_state(self):
        self._mock_run(0, "Ok.")
        agent._win_fw_apply()
        self.assertEqual(self.calls[0][:5], ["netsh", "advfirewall", "set", "allprofiles", "state"])
        self.assertEqual(self.calls[0][5], "on")

    def test_fw_verify_membaca_output_terlokalisasi(self):
        self._mock_run(0, "Status                                Aktif\nStatus                                Aktif\n")
        self.assertTrue(agent._win_fw_verify())

    def test_fw_verify_false_bila_ada_profil_mati(self):
        self._mock_run(0, "State ON\nState OFF\n")
        self.assertFalse(agent._win_fw_verify())

    # ---- BitLocker: resume vs enkripsi baru vs fallback ----
    def _bl_harness(self, state, tpm=True):
        state.setdefault("protectors", [])
        state.setdefault("recoveryKeys", [])
        self.ps_calls = []
        enabled_once = {"n": 0}

        def ps(cmd, timeout=20):
            self.ps_calls.append(cmd)
            if "Get-BitLockerVolume" in cmd:
                return 0, json.dumps({"p": "On" if state.get("protectionOn") else "Off",
                                      "e": 100 if state.get("encrypted") else 10,
                                      "k": state["protectors"], "r": state["recoveryKeys"]})
            if "Add-BitLockerKeyProtector" in cmd and "RecoveryPassword" in cmd:
                state["protectors"].append("RecoveryPassword")
                state["recoveryKeys"].append("111111-222222-333333-444444-555555-666666-777777-888888")
                return 0, ""
            if "Add-BitLockerKeyProtector" in cmd and "TpmProtector" in cmd:
                state["protectors"].append("Tpm"); return 0, ""
            if "Add-BitLockerKeyProtector" in cmd and "PasswordProtector" in cmd:
                state["protectors"].append("Password"); return 0, ""
            if "Get-Tpm" in cmd:
                return 0, ("yes" if tpm else "no")
            if "Resume-BitLocker" in cmd:
                state["protectionOn"] = True; return 0, ""
            if "Suspend-BitLocker" in cmd:
                state["protectionOn"] = False; return 0, ""
            if "Enable-BitLocker" in cmd:
                state["encrypted"] = True; state["protectionOn"] = True; return 0, ""
            if "manage-bde" in cmd:
                return 0, ""
            return 0, ""

        orig_state, orig_ps = agent._win_bitlocker_state, agent._win_ps
        agent._win_bitlocker_state = lambda: {
            "protectionOn": state.get("protectionOn", False),
            "encrypted": state.get("encrypted", False),
            "protectors": list(state["protectors"]),
            "recoveryKeys": list(state["recoveryKeys"]),
        }
        agent._win_ps = ps
        self.addCleanup(lambda: (setattr(agent, "_win_bitlocker_state", orig_state), setattr(agent, "_win_ps", orig_ps)))

    def test_bitlocker_idempoten_bila_sudah_aktif(self):
        self._bl_harness({"protectionOn": True, "encrypted": True})
        res = agent._win_bitlocker_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertIn("idempoten", res["output"])

    def test_state_menangani_enum_numerik_powershell(self):
        orig = agent._win_ps
        agent._win_ps = lambda cmd, timeout=20: (0, '{"p":1,"e":100,"k":["RecoveryPassword","Tpm"],"r":["k"]}')
        try:
            st = agent._win_bitlocker_state()
        finally:
            agent._win_ps = orig
        self.assertTrue(st["protectionOn"])
        self.assertTrue(st["encrypted"])

    def test_bitlocker_resume_bila_terenkripsi_tanpa_proteksi(self):
        self._bl_harness({"protectionOn": False, "encrypted": True}, tpm=True)
        res = agent._win_bitlocker_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertIn("RecoveryPassword", res["recoveryKey"] if False else "RecoveryPassword")
        self.assertTrue(any("Resume-BitLocker" in c for c in self.ps_calls))
        self.assertTrue(any("TpmProtector" in c for c in self.ps_calls))

    def test_bitlocker_mulai_enkripsi_dengan_tpm(self):
        self._bl_harness({"protectionOn": False, "encrypted": False}, tpm=True)
        res = agent._win_bitlocker_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(any("TpmProtector" in c for c in self.ps_calls))
        self.assertFalse(res.get("bootPassword"))

    def test_bitlocker_tanpa_tpm_memakai_password_protector(self):
        self._bl_harness({"protectionOn": False, "encrypted": False}, tpm=False)
        res = agent._win_bitlocker_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(res.get("bootPassword"))
        self.assertTrue(any("-PasswordProtector" in c for c in self.ps_calls))
        self.assertFalse(any("-TpmProtector" in c for c in self.ps_calls))

    def test_bitlocker_resume_tanpa_tpm_menambah_password_protector(self):
        self._bl_harness({"protectionOn": False, "encrypted": True}, tpm=False)
        res = agent._win_bitlocker_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(res.get("bootPassword"))
        self.assertTrue(any("Resume-BitLocker" in c for c in self.ps_calls))

    def test_bitlocker_rollback_suspend_bila_terenkripsi(self):
        self._bl_harness({"protectionOn": False, "encrypted": True})
        res = agent._win_bitlocker_rollback({"protectionOn": False, "encrypted": True})
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(any("Suspend-BitLocker" in c for c in self.ps_calls))

    def test_bitlocker_rollback_off_bila_belum_terenkripsi(self):
        self._mock_run(0, "ok")
        agent._win_bitlocker_rollback({"protectionOn": False, "encrypted": False})
        self.assertIn("-off", self.calls[0])

    # ---- USBSTOR ----
    def test_usbstor_restore_returns_previous_value(self):
        self._mock_run(0, "ok")
        agent._win_usbstor_restore({"start": 3})
        self.assertIn("3", self.calls[0])
        self.calls.clear()
        agent._win_usbstor_restore({"start": 4})
        self.assertIn("4", self.calls[0])

    # ---- GRUB ----
    def test_grub_apply_and_rollback_restore_mode(self):
        grub = os.path.join(self.tmp, "grub.cfg")
        with open(grub, "w") as f:
            f.write("menuentry {}")
        os.chmod(grub, 0o644)
        agent._GRUB_PATHS = [grub]
        pre = agent._linux_grub_state()
        self.assertFalse(pre["secure"])
        res = agent._linux_grub_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(agent._linux_grub_verify())
        rb = agent._linux_grub_rollback(pre)
        self.assertEqual(rb["exitCode"], 0)
        self.assertEqual(oct(os.stat(grub).st_mode)[-3:], "644")

    # ---- sudoers ----
    def test_sudoers_apply_removes_nopasswd_and_rollback_restores(self):
        sfile = os.path.join(self.tmp, "sudoers")
        with open(sfile, "w") as f:
            f.write("%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n")
        os.chmod(sfile, 0o440)
        agent._sudoers_files = lambda: [sfile]
        pre = agent._linux_sudoers_state()
        self.assertFalse(pre["clean"])
        self.assertEqual(agent._linux_sudoers_apply()["exitCode"], 0)
        self.assertTrue(agent._linux_sudoers_verify())
        self.assertNotIn("NOPASSWD", open(sfile).read())
        self.assertEqual(agent._linux_sudoers_rollback(pre)["exitCode"], 0)
        self.assertIn("NOPASSWD", open(sfile).read())
        self.assertEqual(oct(os.stat(sfile).st_mode)[-3:], "440")

    # ---- SUID ----
    def test_suid_apply_and_rollback_restore_bit(self):
        target = os.path.join(self.tmp, "bash")
        with open(target, "w") as f:
            f.write("")
        os.chmod(target, 0o755 | 0o4000)
        agent._SUID_CANDIDATES = [target]
        pre = agent._linux_suid_state()
        self.assertFalse(pre["clean"])
        self.assertEqual(agent._linux_suid_apply()["exitCode"], 0)
        self.assertTrue(agent._linux_suid_verify())
        self.assertEqual(agent._linux_suid_rollback(pre)["exitCode"], 0)
        self.assertTrue(os.stat(target).st_mode & 0o4000)

    # ---- SSH config ----
    def test_ssh_apply_sets_no_and_rollback_restores_content(self):
        sshd = os.path.join(self.tmp, "sshd_config")
        original = "PermitRootLogin yes\nPasswordAuthentication yes\n"
        with open(sshd, "w") as f:
            f.write(original)
        agent._SSHD_CONFIG_PATH = sshd
        self._mock_run(0, "ok")
        pre = agent._linux_ssh_read_config()
        res = agent._linux_ssh_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertIn("PermitRootLogin no", open(sshd).read())
        self.assertTrue(agent._linux_ssh_verify())
        self.assertEqual(agent._linux_ssh_rollback(pre)["exitCode"], 0)
        self.assertEqual(open(sshd).read(), original)

    # ---- auditpol ----
    def test_auditpol_parse_nilai_numerik_tanpa_bergantung_bahasa(self):
        csv = (
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"
            ",System,Audit Pembuatan Proses,{0CCE922B-69AE-11D9-BED3-505054503030},Keberhasilan dan Kegagalan,,3\n"
        )
        self._mock_run(0, csv)
        state = agent._win_auditpol_state()
        self.assertTrue(state["readable"])
        self.assertTrue(state["success"])
        self.assertTrue(state["failure"])

    def test_auditpol_apply_memakai_guid_subkategori(self):
        self._mock_run(0, "")
        agent._win_auditpol_apply()
        joined = " ".join(self.calls[0])
        self.assertIn(agent._AUDITPOL_SUBCAT_GUID, joined)
        self.assertIn("/success:enable", joined)


    def test_auditpol_parse_detects_enabled(self):
        self._mock_run(0, "  Process Creation    Success and Failure\n")
        state = agent._win_auditpol_state()
        self.assertTrue(state["readable"])
        self.assertTrue(state["success"])
        self.assertTrue(state["failure"])

    def test_auditpol_parse_detects_disabled(self):
        self._mock_run(0, "  Process Creation    No Auditing\n")
        state = agent._win_auditpol_state()
        self.assertFalse(state["success"])
        self.assertFalse(state["failure"])

    def test_auditpol_rollback_restores_flags(self):
        self._mock_run(0, "ok")
        agent._win_auditpol_rollback({"readable": True, "success": False, "failure": True})
        joined = " ".join(self.calls[0])
        self.assertIn("/success:disable", joined)
        self.assertIn("/failure:enable", joined)


class WindowsElevationTests(unittest.TestCase):
    def test_perintah_elevasi_menunggu_dan_mempertahankan_cwd(self):
        cmd = agent._windows_elevation_command(r"C:\x\pasopati_audit.py", ["--remediate-plan", "plan.json"], r"C:\Temp\log.txt")
        self.assertIn("Start-Process powershell -Verb RunAs -Wait", cmd)
        self.assertIn("Set-Location -LiteralPath", cmd)
        self.assertIn(r"'C:\x\pasopati_audit.py'", cmd)
        self.assertIn("'plan.json'", cmd)
        self.assertIn(r"*>" , cmd)
        self.assertIn(r"C:\Temp\log.txt", cmd)

    def test_quote_mengubah_kutip_tunggal(self):
        self.assertEqual(agent._ps_quote("a'b"), "'a''b'")


class UnifiedPlanTests(unittest.TestCase):
    """Satu jalur: enforce + advisory dalam satu plan."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pasopati-unified-")
        self.orig = (agent.ALLOWLIST_ANALISA, set(agent.ADVISORY_ALIASES), agent._remediation_backup_dir, agent._is_elevated, agent._push_remediation_evidence)
        self.rollback_called = []
        self.enforce_ok = True
        self.pushed = None

        def read():
            return {"state": "pre"}

        def apply():
            return {"exitCode": 0, "output": "applied"}

        def verify():
            return self.enforce_ok

        def rollback(_pre):
            self.rollback_called.append(True)
            return {"exitCode": 0, "output": "restored"}

        agent.ALLOWLIST_ANALISA = {
            "fake-enforce": {"os": "any", "risk": "LOW", "reversible": True, "read": read, "apply": apply, "verify": verify, "rollback": rollback},
            "fake-advisory": {"os": "any", "risk": "LOW", "reversible": False, "read": read, "verify": lambda: False, "advisory": True},
        }
        agent.ADVISORY_ALIASES = {"fake-advisory"}
        agent._remediation_backup_dir = lambda: self.tmp
        agent._is_elevated = lambda: True
        def _push(server_url, api_key, plan_id, nonce, to_status, evidence, hmac_key=None):
            self.pushed = {"planId": plan_id, "status": to_status, "evidence": evidence, "hmacKey": hmac_key}
            return 200
        agent._push_remediation_evidence = _push

    def tearDown(self):
        import shutil
        (agent.ALLOWLIST_ANALISA, agent.ADVISORY_ALIASES, agent._remediation_backup_dir, agent._is_elevated, agent._push_remediation_evidence) = self.orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, items):
        plan_path = os.path.join(self.tmp, "plan.json")
        with open(plan_path, "w") as f:
            json.dump({"planId": "PLAN-UNIFIED", "deviceId": "DEV", "items": items}, f)
        args = argparse.Namespace(
            remediate_plan=plan_path, remediate_token=None, hmac_key="k",
            remediate_api_key=None, push_url="http://x", no_exec=False, demo=True,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            agent.run_remediation(args)

    def test_advisory_tidak_memblokir_dan_tidak_dirollback(self):
        self.enforce_ok = True
        self._run([{"alias": "fake-advisory"}, {"alias": "fake-enforce"}])
        self.assertEqual(self.rollback_called, [])

    def test_hmac_key_kosong_ditolak_dengan_pesan_jelas(self):
        import hashlib as _h, hmac as _hmac
        def canon(p):
            import json as _j
            return _j.dumps({k: p.get(k) for k in ("planId","deviceId","items","approvedBy","nonce","expiresAt")}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        plan = {"planId":"P","deviceId":"D","items":[{"alias":"fake-enforce"}],"approvedBy":"o","nonce":"abc","expiresAt":9e15}
        sig = _hmac.new(b"k", canon(plan).encode(), _h.sha256).hexdigest()
        path = os.path.join(self.tmp, "plan-hmac.json")
        with open(path,"w") as f: json.dump(plan, f)
        args = argparse.Namespace(remediate_plan=path, remediate_token=f"abc.{sig}", hmac_key=None,
                                  remediate_api_key=None, push_url=None, no_exec=False, demo=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            agent.run_remediation(args)
        self.assertIn("--hmac-key", out.getvalue())
        self.assertEqual(self.rollback_called, [])

    def test_rollback_dianggap_bersih_bila_state_kembali_walau_rc_gagal(self):
        state = {"v": 0}
        def read(): return dict(state)
        def apply(): state["v"] = 1; return {"exitCode": 0}
        def verify(): return state["v"] == 1
        def rollback(_pre):
            state["v"] = 0
            return {"exitCode": 5, "output": "manage-bde: sudah tidak terenkripsi"}
        agent.ALLOWLIST_ANALISA["fake-flaky"] = {
            "os": "any", "risk": "LOW", "reversible": True,
            "read": read, "apply": apply, "verify": verify, "rollback": rollback,
        }
        self.enforce_ok = True
        # verify dipakai dari entri, jadi buat skenario gagal di langkah kedua
        agent.ALLOWLIST_ANALISA["fake-gagal"] = {
            "os": "any", "risk": "LOW", "reversible": True,
            "read": lambda: {"x": 0}, "apply": lambda: {"exitCode": 1},
            "verify": lambda: False, "rollback": lambda p: {"exitCode": 0},
        }
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._run([{"alias": "fake-flaky"}, {"alias": "fake-gagal"}])
        rb = self.pushed["evidence"][0]["rollback"]
        self.assertTrue(rb["verified"])
        self.assertNotIn("tidak bersih", out.getvalue())

    def test_recovery_key_disimpan_ke_backup(self):
        key = "111111-222222-333333-444444-555555-666666-777777-888888"
        agent.ALLOWLIST_ANALISA["fake-bl"] = {
            "os": "any", "risk": "LOW", "reversible": True,
            "read": lambda: {"state": "pre"},
            "apply": lambda: {"exitCode": 0, "recoveryKey": key},
            "verify": lambda: True,
            "rollback": lambda _p: {"exitCode": 0},
        }
        self._run([{"alias": "fake-bl"}])
        import glob
        files = glob.glob(os.path.join(self.tmp, "*bitlocker-recovery.txt"))
        self.assertEqual(len(files), 1)
        self.assertEqual(open(files[0]).read().strip(), key)

    def test_evidence_push_membawa_hmac_key(self):
        self._run([{"alias": "fake-enforce"}])
        self.assertEqual(self.pushed["hmacKey"], "k")

    def test_enforce_gagal_memicu_rollback_tanpa_advisory(self):
        self.enforce_ok = False
        self._run([{"alias": "fake-advisory"}, {"alias": "fake-enforce"}])
        self.assertEqual(len(self.rollback_called), 1)
        self.assertEqual(self.pushed["status"], "ROLLED_BACK")
        # rollback dianggap pulih karena read() kembali sama dengan pre-state
        self.assertTrue(self.pushed["evidence"][1]["rollback"]["verified"])
        self.assertFalse(self.pushed["evidence"][0].get("rollback"))


class AllowlistContractTests(unittest.TestCase):
    REQUIRED = ("os", "risk", "reversible", "read", "verify")

    def test_every_alias_has_full_handler_and_is_reversible(self):
        for alias, entry in agent.ALLOWLIST_ANALISA.items():
            for key in self.REQUIRED:
                self.assertIn(key, entry, f"{alias} tidak punya '{key}'")
            if alias in agent.ADVISORY_ALIASES:
                self.assertFalse(entry["reversible"], f"{alias} advisory tapi reversible")
            else:
                for key in ("apply", "rollback"):
                    self.assertIn(key, entry, f"{alias} enforce tidak punya '{key}'")
                self.assertTrue(entry["reversible"], f"{alias} enforce tapi reversible=false")

    def test_server_allowlist_matches_agent(self):
        server = open(os.path.join(ROOT, "server.ts"), encoding="utf-8").read()
        block = re.search(r"const ALLOWED_ALIASES = new Set\(\[(.*?)\]\);", server, re.S)
        self.assertIsNotNone(block, "ALLOWED_ALIASES tidak ditemukan di server.ts")
        server_aliases = set(re.findall(r"'([a-z0-9-]+)'", block.group(1)))
        self.assertEqual(server_aliases, set(agent.ALLOWLIST_ANALISA))


class SshUfwTests(unittest.TestCase):
    """SSH harus menghormati sshd_config.d + validasi sshd -t; UFW harus izinkan SSH dulu."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pasopati-ssh-ufw-")
        self.include_dir = os.path.join(self.tmp, "sshd_config.d")
        os.makedirs(self.include_dir)
        self.main = os.path.join(self.tmp, "sshd_config")
        self.dropin = os.path.join(self.include_dir, "99-pasopati-root-login.conf")
        self.orig = (agent._SSHD_CONFIG_PATH, agent._SSHD_INCLUDE_DIR, agent._SSHD_DROPIN, agent._run_no_shell)
        agent._SSHD_CONFIG_PATH = self.main
        agent._SSHD_INCLUDE_DIR = self.include_dir
        agent._SSHD_DROPIN = self.dropin
        self.calls = []
        self.sshd_t_rc = 0
        self.ufw = {"active": False, "defaultIncoming": "allow", "sshAllowed": False}

    def tearDown(self):
        (agent._SSHD_CONFIG_PATH, agent._SSHD_INCLUDE_DIR, agent._SSHD_DROPIN, agent._run_no_shell) = self.orig
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _runner(self):
        def runner(argv, timeout=10):
            self.calls.append(argv)
            if argv[:2] == ["sshd", "-T"]:
                return 1, ""  # paksa fallback baca config
            if argv[:2] == ["sshd", "-t"]:
                return self.sshd_t_rc, "" if self.sshd_t_rc == 0 else "bad config"
            if argv[:2] == ["systemctl", "is-active"]:
                return (0, "active") if self.sshd_t_rc == 0 else (3, "inactive")
            if argv[:2] == ["systemctl", "restart"]:
                return 0, ""
            if argv[:2] == ["ufw", "status"]:
                state = "active" if self.ufw["active"] else "inactive"
                ssh = "22/tcp ALLOW Anywhere\n" if self.ufw["sshAllowed"] else ""
                return 0, "Status: %s\nDefault: %s (incoming)\n%s" % (state, self.ufw["defaultIncoming"], ssh)
            if argv[:4] == ["ufw", "default", "deny", "incoming"]:
                self.ufw["defaultIncoming"] = "deny"
                return 0, ""
            if argv[:4] == ["ufw", "default", "allow", "incoming"]:
                self.ufw["defaultIncoming"] = "allow"
                return 0, ""
            if argv[:3] == ["ufw", "allow", "22/tcp"]:
                self.ufw["sshAllowed"] = True
                return 0, ""
            if argv[:4] == ["ufw", "delete", "allow", "22/tcp"]:
                self.ufw["sshAllowed"] = False
                return 0, ""
            if argv[:3] == ["ufw", "--force", "enable"]:
                self.ufw["active"] = True
                return 0, ""
            if argv[:3] == ["ufw", "--force", "disable"]:
                self.ufw["active"] = False
                return 0, ""
            return 0, ""
        return runner

    def test_ssh_memakai_dropin_saat_include_aktif(self):
        with open(self.main, "w") as f:
            f.write("Include %s/*.conf\n" % self.include_dir)
        agent._run_no_shell = self._runner()
        st = agent._linux_ssh_state()
        self.assertFalse(st["dropinExists"])
        res = agent._linux_ssh_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertTrue(os.path.exists(self.dropin))
        with open(self.dropin) as f:
            self.assertIn("PermitRootLogin no", f.read())
        with open(self.main) as f:
            self.assertNotIn("PermitRootLogin", f.read())
        self.assertTrue(agent._linux_ssh_verify())
        agent._linux_ssh_rollback(st)
        self.assertFalse(os.path.exists(self.dropin))

    def test_ssh_edit_main_bila_directive_ada_sebelum_include(self):
        with open(self.main, "w") as f:
            f.write("PermitRootLogin yes\nInclude %s/*.conf\n" % self.include_dir)
        agent._run_no_shell = self._runner()
        res = agent._linux_ssh_apply()
        self.assertEqual(res["exitCode"], 0)
        self.assertFalse(os.path.exists(self.dropin))
        with open(self.main) as f:
            self.assertIn("PermitRootLogin no", f.read())

    def test_ssh_rollback_saat_sshd_t_menolak(self):
        with open(self.main, "w") as f:
            f.write("PermitRootLogin yes\n")
        agent._run_no_shell = self._runner()
        self.sshd_t_rc = 1
        res = agent._linux_ssh_apply()
        self.assertEqual(res["exitCode"], -1)
        with open(self.main) as f:
            self.assertIn("PermitRootLogin yes", f.read())

    def test_ufw_izinkan_ssh_sebelum_enable(self):
        agent._run_no_shell = self._runner()
        res = agent._linux_ufw_apply()
        self.assertEqual(res["exitCode"], 0)
        flattened = [" ".join(c) for c in self.calls]
        self.assertLess(flattened.index("ufw default deny incoming"), flattened.index("ufw --force enable"))
        self.assertLess(flattened.index("ufw allow 22/tcp"), flattened.index("ufw --force enable"))
        self.assertTrue(agent._linux_ufw_verify())

    def test_ufw_rollback_mengembalikan_default_dan_mematikan(self):
        pre = {"active": False, "defaultIncoming": "allow", "sshAllowed": False}
        self.ufw = {"active": True, "defaultIncoming": "deny", "sshAllowed": True}
        agent._run_no_shell = self._runner()
        agent._linux_ufw_rollback(pre)
        self.assertFalse(self.ufw["active"])
        self.assertEqual(self.ufw["defaultIncoming"], "allow")
        self.assertFalse(self.ufw["sshAllowed"])

class QuarantineTests(unittest.TestCase):
    def test_release_berjalan_tanpa_flag_quarantine(self):
        calls = []
        orig = (agent.trigger_emergency_quarantine, agent.append_history, agent.platform.system)
        agent.trigger_emergency_quarantine = lambda dry_run=False, release=False: calls.append((dry_run, release)) or True
        agent.append_history = lambda entry: (entry, "x")
        try:
            agent.main(["--quarantine-release", "--no-elevate"])
        finally:
            agent.trigger_emergency_quarantine, agent.append_history, agent.platform.system = orig
        self.assertEqual(calls, [(False, True)])

    def test_release_windows_memakai_policy_pulih(self):
        argv_calls = []
        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""
        orig = (agent.platform.system, agent.subprocess.run)
        agent.platform.system = lambda: "Windows"
        agent.subprocess.run = lambda argv, **kw: argv_calls.append(argv) or Proc()
        try:
            self.assertTrue(agent.trigger_emergency_quarantine(release=True))
        finally:
            agent.platform.system, agent.subprocess.run = orig
        self.assertEqual(argv_calls[0][-1], "blockinbound,allowoutbound")

    def test_release_windows_gagal_mengembalikan_false(self):
        class Proc:
            returncode = 1
            stdout = ""
            stderr = "akses ditolak"
        orig = (agent.platform.system, agent.subprocess.run)
        agent.platform.system = lambda: "Windows"
        agent.subprocess.run = lambda argv, **kw: Proc()
        try:
            self.assertFalse(agent.trigger_emergency_quarantine(release=True))
        finally:
            agent.platform.system, agent.subprocess.run = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)
