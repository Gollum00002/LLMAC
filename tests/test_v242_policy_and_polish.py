"""v2.4.2 — policy + polish release.

1. ACTIVATION-FORM INSTALL FIX (the live-found bug): `source
   .venv/bin/activate && pip install X` is advertised verbatim by the
   rejection hint, but v2.3-v2.4.1 had NO detection for it (only
   bin/pip|python tool tokens counted) — found live on 2026-10-25,
   session 12, when the exact form from the hint was rejected. These
   tests pin the fixed behavior: marker venvs, tracked venvs, shell
   variants, ordering (activation must PRECEDE the install), and the
   fail-closed defaults.
2. /INFO VENV PRUNING: remembered venvs that no longer exist on disk
   disappear from /info without a restart (session-12 finding: a
   deleted venv lingered until the next restart). v2.4.3 moved the
   remembered set to `discovered_venvs` ("venvs" = configured
   allow-list now) — the assertions below were updated accordingly.
3. DEPLOY OUTPUT: the success line now reports the transport cost
   ("N batch call(s), no exec" on v2.4.1+ servers, "exec fallback"
   on older ones) so deploys are self-verifying in output.
4. BOOTSTRAP PROMPT: teaches orient (v2.4.1 B1 adoption) — the prompt
   is the first thing every future agent reads.
5. HARNESS GUARD: tools/bench_llmac.py must define and run all nine
   scenarios (S6_edit_cas + S8_transfer ported in v2.4.2 so the
   committed gate covers the full baseline).
"""
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from core.policy import InstallPolicy

CLI = os.path.join(_PARENT, "llmac.py")


def run_cli(host, *args, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout)


def load_cli_module(tag="llmac_cli_test_242"):
    import importlib.util
    spec = importlib.util.spec_from_file_location(tag, CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1. Activation-form install policy
# ---------------------------------------------------------------------------

class TestActivateFormPolicy(unittest.TestCase):
    """The hint-advertised form must actually work (live bug, fixed)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v242-venv-")
        self.venv = os.path.join(self.tmp, ".venv")
        os.makedirs(os.path.join(self.venv, "bin"), exist_ok=True)
        with open(os.path.join(self.venv, "pyvenv.cfg"), "w") as f:
            f.write("home = /usr/bin\n")

    def _pol(self, tracked=None):
        return InstallPolicy(tracked or [])

    def test_source_activate_then_pip_install_allowed(self):
        r = self._pol().pre_exec(
            "source .venv/bin/activate && pip install six", self.tmp)
        self.assertIsNone(r, r and r["rule"])

    def test_dot_activate_pip3_allowed(self):
        r = self._pol().pre_exec(
            ". .venv/bin/activate && pip3 install six", self.tmp)
        self.assertIsNone(r)

    def test_activate_then_python_m_pip_allowed(self):
        r = self._pol().pre_exec(
            "source .venv/bin/activate && python -m pip install six",
            self.tmp)
        self.assertIsNone(r)

    def test_tracked_venv_without_marker_allowed(self):
        tracked = os.path.join(self.tmp, "tracked-env")
        r = self._pol([tracked]).pre_exec(
            "source tracked-env/bin/activate && pip install six", self.tmp)
        self.assertIsNone(r)

    def test_tracked_parent_of_activate_path_allowed(self):
        # activate inside a subdir of a tracked venv root
        tracked = os.path.normpath(self.venv)
        os.makedirs(os.path.join(self.venv, "sub", "bin"), exist_ok=True)
        r = self._pol([tracked]).pre_exec(
            "source sub/bin/activate && pip install six", self.venv)
        self.assertIsNone(r)

    def test_windows_activate_ps1_allowed(self):
        v = os.path.join(self.tmp, "wenv")
        os.makedirs(os.path.join(v, "Scripts"), exist_ok=True)
        with open(os.path.join(v, "pyvenv.cfg"), "w") as f:
            f.write("home = C:\\Python312\n")
        r = self._pol().pre_exec(
            "source wenv/Scripts/Activate.ps1 && pip install six", self.tmp)
        self.assertIsNone(r)

    def test_absolute_activate_path_allowed(self):
        r = self._pol().pre_exec(
            f"source {self.venv}/bin/activate && pip install six", "/tmp")
        self.assertIsNone(r)

    def test_activate_after_install_rejected(self):
        # Activation AFTER the install scopes nothing -> still rejected.
        r = self._pol().pre_exec(
            "pip install six && source .venv/bin/activate", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "install_not_in_venv")

    def test_activate_non_venv_rejected(self):
        r = self._pol().pre_exec(
            "source fakeenv/bin/activate && pip install six", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "install_not_in_venv")

    def test_activate_inside_repo_but_no_marker_rejected(self):
        # `bin/activate` exists but no pyvenv.cfg anywhere above it.
        d = os.path.join(self.tmp, "plain")
        os.makedirs(os.path.join(d, "bin"), exist_ok=True)
        with open(os.path.join(d, "bin", "activate"), "w") as f:
            f.write("#!/bin/sh\n")
        r = self._pol().pre_exec(
            "source plain/bin/activate && pip install six", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "install_not_in_venv")

    # -- regressions: everything that worked before still works ------

    def test_direct_tool_token_still_allowed(self):
        r = self._pol().pre_exec(".venv/bin/pip install six", self.tmp)
        self.assertIsNone(r)

    def test_bare_pip_still_rejected(self):
        r = self._pol().pre_exec("pip install six", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "install_not_in_venv")

    def test_system_manager_still_rejected(self):
        r = self._pol().pre_exec("pacman -S six", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "system_package_manager")

    def test_non_install_command_untouched(self):
        r = self._pol().pre_exec("cat .venv/bin/activate", self.tmp)
        self.assertIsNone(r)

    def test_venv_creation_still_tracked(self):
        p = self._pol()
        p.pre_exec("python3 -m venv other-env", self.tmp)
        # v2.4.3: creations land in DISCOVERED, never in the configured
        # allow-list (the old merged-set behavior is what made the GUI
        # blind to agent-created venvs).
        self.assertIn(os.path.join(self.tmp, "other-env"),
                      p.discovered_venvs)
        self.assertNotIn(os.path.join(self.tmp, "other-env"), p.venvs)


# ---------------------------------------------------------------------------
# 2. /info prunes dead remembered venvs
# ---------------------------------------------------------------------------

class TestInfoPrunesDeadVenvs(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_dead_venv_disappears_from_info(self):
        root = self.host.root
        # `python -m venv X` seeds the remembered set from the command
        # string even if creation itself fails (no ensurepip etc.).
        r1, _ = self.host.post("/exec", {
            "command": "python3 -m venv v242-prune",
            "cwd": root, "timeout": 90})
        if r1.get("returncode") == 0:
            info, _ = self.host.get("/info")
            self.assertIn(os.path.join(root, "v242-prune"),
                          info["venvs_discovered"])
            self.assertEqual(info["venvs"], [])   # configured stays clean
        # Delete it, then /info must not list it anymore (v2.4.2
        # pruning; v2.4.1 kept the stale entry until restart).
        self.host.post("/exec", {"command": "rm -rf v242-prune",
                                 "cwd": root})
        info2, _ = self.host.get("/info")
        self.assertNotIn(os.path.join(root, "v242-prune"),
                         info2["venvs_discovered"])


# ---------------------------------------------------------------------------
# 3. Deploy success output: batch calls + exec mode
# ---------------------------------------------------------------------------

class TestDeployOutput(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_fast_path_line_reports_calls_and_no_exec(self):
        local_dir = os.path.join(self.host.tmp, "locals")
        os.makedirs(local_dir)
        pairs = []
        for name, body in (("one.txt", "alpha"), ("two.txt", "beta")):
            lp = os.path.join(local_dir, name)
            with open(lp, "w") as f:
                f.write(body)
            pairs.append(f"{lp}={os.path.join(self.host.root, name)}")
        r = run_cli(self.host, "deploy",
                    *sum((["--pairs", p] for p in pairs), []))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2/2 verified", r.stdout)
        self.assertIn("1 batch call(s)", r.stdout)
        self.assertIn("no exec", r.stdout)
        self.assertNotIn("exec fallback", r.stdout)

    def test_fallback_line_reports_exec_fallback(self):
        """Old server (stat without sha256): the one sha256sum exec
        fires and the success line says so."""
        import hashlib
        mod = load_cli_module()
        content = "x"
        want_sha = hashlib.sha256(content.encode()).hexdigest()

        class FakeOldServer:
            retry_seconds = 0.0

            def post(self, path, payload=None, timeout=130.0):
                if path == "/batch":
                    results = []
                    for o in payload["ops"]:
                        if o["op"] == "write":
                            results.append({"index": len(results),
                                            "op": "write",
                                            "ok": {"path": o["path"],
                                                   "bytes": 1}})
                        else:              # OLD server: no sha256 key
                            results.append({"index": len(results),
                                            "op": "stat",
                                            "ok": {"path": o["path"],
                                                   "size": 1}})
                    return {"results": results}, 200
                if path == "/exec":
                    return {"stdout": f"{want_sha}  /r\n",
                            "returncode": 0, "stderr": ""}, 200
                raise AssertionError("unexpected " + path)

        ck = ("127.0.0.1", 1, "k", "", False)
        mod._CLIENT_CACHE[ck] = FakeOldServer()
        try:
            lp = os.path.join(self.host.tmp, "l.txt")
            with open(lp, "w") as f:
                f.write(content)
            args = SimpleNamespace(
                manifest=None, pairs=[f"{lp}=/r"], dry_run=False,
                no_verify=False, host="127.0.0.1", port=1, key="k",
                fp=None, plain=True, retry=0, conn="v242-hermetic",
                verbose=False)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = mod.cmd_deploy(args)
            self.assertEqual(rc, 0)
            self.assertIn("exec fallback)", buf.getvalue())
            self.assertIn("1 batch call(s)", buf.getvalue())
        finally:
            mod._CLIENT_CACHE.pop(ck, None)


# ---------------------------------------------------------------------------
# 4. Bootstrap prompt teaches orient
# ---------------------------------------------------------------------------

class TestBootstrapPromptOrient(unittest.TestCase):
    def test_prompt_teaches_orient(self):
        from core.server import build_prompt_text
        prompt = build_prompt_text(key="llmac_k", host="h", port=1,
                                   roots=["/r"], tls=False)
        self.assertIn("orient --path", prompt)
        self.assertIn("agent.md", prompt)          # unchanged advice
        self.assertIn("roots request", prompt)     # unchanged advice

    def test_prompt_mentions_batch_commands(self):
        from core.server import build_prompt_text
        prompt = build_prompt_text(key="llmac_k", host="h", port=1,
                                   roots=["/r"], tls=False)
        self.assertIn("deploy/run/verify/diff", prompt)


# ---------------------------------------------------------------------------
# 5. Harness coverage guard
# ---------------------------------------------------------------------------

class TestHarnessCoverage(unittest.TestCase):
    def test_bench_harness_defines_and_runs_all_nine(self):
        import importlib.util
        hpath = os.path.join(_PARENT, "tools", "bench_llmac.py")
        spec = importlib.util.spec_from_file_location(
            "llmac_bench_242", hpath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for fn in ("s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"):
            self.assertTrue(hasattr(mod, fn), f"harness lost {fn}")
        src = open(hpath, encoding="utf-8").read()
        self.assertIn("S6_edit_cas", src)
        self.assertIn("S8_transfer", src)
        # both must be wired into main()'s run order
        self.assertIn("s6(b, args.repo)", src)
        self.assertIn("s8(b, args.repo, args.big_file)", src)
        # and their scratch dirs cleaned up
        self.assertIn('"/bench-cas"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
