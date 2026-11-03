"""`llmac.py audit` regression tests (v2.7.2, reworked in v2.8).

v2.8: audit is OFFLINE. It hashes the client file's exact bytes, optionally
binds them to the block's Client-SHA256, and prints a static ast.parse
report. It contacts nothing, writes nothing and executes nothing. The real
CLI runs via subprocess, so the exact command an agent runs is the code
under test.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.server import build_prompt_text
from tests.helpers import TestHost

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(REPO, "llmac.py")


def _sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class AuditBase(unittest.TestCase):

    def _run(self, argv, cwd=None):
        cwd = cwd or tempfile.mkdtemp(prefix="llmac-audit-")
        return subprocess.run([sys.executable, CLI] + argv, cwd=cwd,
                              capture_output=True, text=True, timeout=60)


class CleanAuditTest(AuditBase):

    def test_clean_report_with_matching_hash(self):
        sha = _sha(CLI)
        p = self._run(["audit", "--expect-sha256", sha])
        self.assertEqual(p.returncode, 0, f"{p.stdout}\n{p.stderr}")
        out = p.stdout
        self.assertIn(f"sha256={sha}", out)
        self.assertIn("-> MATCH", out)
        self.assertIn("non-stdlib imports: core", out)  # guarded optional
        self.assertIn("red-flag calls (eval/exec/compile/__import__/"
                      "os.system/os.popen): (none)", out)
        self.assertIn("red-flag imports (pickle/marshal/ctypes/"
                      "subprocess): (none)", out)
        self.assertIn("audit: COMPLETE", out)
        self.assertIn("contacted nothing", out)

    def test_no_expectation_still_reports(self):
        p = self._run(["audit"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("(not requested", p.stdout)
        self.assertIn("static audit:", p.stdout)

    def test_audit_needs_no_host_key_or_network(self):
        # old flags are gone: the command cannot be pointed at a host
        p = self._run(["audit", "--host", "127.0.0.1", "--key", "k"])
        self.assertEqual(p.returncode, 2)
        self.assertIn("unrecognized arguments", p.stderr)


class FailClosedTest(AuditBase):

    def test_hash_mismatch_exits_1_with_report_still_printed(self):
        p = self._run(["audit", "--expect-sha256", "0" * 64])
        self.assertEqual(p.returncode, 1)
        self.assertIn("-> MISMATCH", p.stdout)
        self.assertIn("Do not use this file", p.stderr)
        # evidence is produced even on failure
        self.assertIn("static audit:", p.stdout)

    def test_unreadable_file_exits_2(self):
        p = self._run(["audit", "--file", "/nonexistent/llmac.py"])
        self.assertEqual(p.returncode, 2)

    def test_audit_flags_red_calls_in_a_different_file(self):
        work = tempfile.mkdtemp(prefix="llmac-audit-")
        evil = os.path.join(work, "evil.py")
        with open(evil, "w", encoding="utf-8") as f:
            f.write("import pickle, os\nexec('x=1')\nos.system('id')\n"
                    "open('/tmp/x','w')\n")
        p = self._run(["audit", "--file", evil], cwd=work)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("exec()", p.stdout)
        self.assertIn("os.system()", p.stdout)
        self.assertIn("import pickle", p.stdout)
        self.assertIn("open('/tmp/x', 'w')", p.stdout)

    def test_audit_never_executes_the_audited_source(self):
        work = tempfile.mkdtemp(prefix="llmac-audit-")
        marker = os.path.join(work, "executed.marker")
        bait = os.path.join(work, "bait.py")
        with open(bait, "w", encoding="utf-8") as f:
            f.write(f"open({marker!r}, 'w').write('ran')\n")
        p = self._run(["audit", "--file", bait], cwd=work)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.exists(marker),
                         "audit must never execute the audited file")


class WritesNothingTest(AuditBase):

    def test_audit_writes_nothing(self):
        work = tempfile.mkdtemp(prefix="llmac-audit-")
        p = self._run(["audit", "--expect-sha256", _sha(CLI)], cwd=work)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(os.listdir(work), [],
                         "audit must not create files")

    def test_save_to_is_gone(self):
        p = self._run(["audit", "--save-to", "x.py"])
        self.assertEqual(p.returncode, 2)


class BlockCarriesAuditTest(unittest.TestCase):

    def test_block_audit_command_is_offline_and_hash_pinned(self):
        host = TestHost(tls=True)
        try:
            prompt = build_prompt_text(
                key=host.key, host="127.0.0.1", port=host.port,
                roots=host.roots, fingerprint="SHA256:" + "a" * 64, tls=True)
            self.assertIn(
                f"python3 llmac.py audit --expect-sha256 {_sha(CLI)}",
                prompt)
            self.assertLess(prompt.index("llmac.py audit"),
                            prompt.index("connect --host"),
                            "audit must be offered before connect")
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
