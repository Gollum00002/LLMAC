"""v2.7.2 — `llmac.py audit` regression tests (ASK-018).

The audit command is the agent-side half of the self-verifying chain:
it must bind the payload to the block (fingerprint + Payload-SHA256)
and to the local copy, produce a static ast.parse report, and never
write or execute anything without an explicit, successful opt-in.

Like test_selfverifying_bootstrap.py, tests drive the REAL CLI via
subprocess against a live TestHost — the exact command an agent runs
is the code under test, not a reimplementation.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.server import build_prompt_text
from core.tlsutil import cert_fingerprint, tls_paths
from tests.helpers import TestHost

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(REPO, "cli.py")


class AuditBase(unittest.TestCase):

    def _served(self, host: TestHost):
        served, status = host.get("/bootstrap")
        self.assertEqual(status, 200)
        return served["cli_py"], served["cli_sha256"]

    def _fp(self, host: TestHost) -> str:
        cert_path, _ = tls_paths(host.data_dir)
        return cert_fingerprint(cert_path) or ""

    def _run(self, argv, cwd):
        return subprocess.run([sys.executable, CLI] + argv, cwd=cwd,
                              capture_output=True, text=True, timeout=60)


class CleanAuditTest(AuditBase):
    """Happy path: pinned TLS fetch, hash-bind, static report, exit 0."""

    def test_audit_clean_report_on_live_tls_host(self):
        host = TestHost(tls=True)
        try:
            _src, sha = self._served(host)
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--fp", self._fp(host),
                           "--expect-sha256", sha], cwd=work)
            self.assertEqual(p.returncode, 0,
                             f"audit failed:\n{p.stdout}\n{p.stderr}")
            out = p.stdout
            self.assertIn("transport: fingerprint pinned + verified "
                          "BEFORE any request", out)
            self.assertIn(f"payload : sha256={sha}", out)
            self.assertIn("-> MATCH", out)
            self.assertIn("non-stdlib imports: core", out)
            self.assertIn("red-flag calls (eval/exec/compile/__import__/"
                          "os.system/os.popen): (none)", out)
            self.assertIn("red-flag imports (pickle/marshal/ctypes/"
                          "subprocess): (none)", out)
            self.assertIn("audit: COMPLETE", out)
        finally:
            host.stop()

    def test_audit_plain_http_works(self):
        host = TestHost(tls=False)
        try:
            _src, sha = self._served(host)
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--plain", "--expect-sha256", sha], cwd=work)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("tls=no (plain HTTP", p.stdout)
        finally:
            host.stop()


class FailClosedTest(AuditBase):
    """Tamper scenarios exit non-zero and write nothing."""

    def test_wrong_fingerprint_exits_3_before_request(self):
        host = TestHost(tls=True)
        try:
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--fp", "SHA256:" + "0" * 64], cwd=work)
            self.assertEqual(p.returncode, 3)
            self.assertIn("fingerprint mismatch", p.stderr)
            self.assertNotIn("payload : sha256=", p.stdout)
        finally:
            host.stop()

    def test_expect_hash_mismatch_exits_1_and_refuses_save(self):
        host = TestHost(tls=True)
        try:
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            save_to = os.path.join(work, "should-not-exist.py")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--expect-sha256", "0" * 64,
                           "--save-to", save_to], cwd=work)
            self.assertEqual(p.returncode, 1)
            self.assertIn("-> MISMATCH", p.stdout)
            self.assertIn("possible tampering", p.stderr)
            self.assertIn("save-to REFUSED", p.stderr)
            self.assertFalse(os.path.isfile(save_to))
        finally:
            host.stop()

    def test_local_tamper_detected(self):
        host = TestHost(tls=True)
        try:
            src, _sha = self._served(host)
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            local = os.path.join(work, "llmac.py")
            with open(local, "w", encoding="utf-8") as f:
                f.write(src + "\n# tampered\n")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--local", local], cwd=work)
            self.assertEqual(p.returncode, 1)
            self.assertIn("DIFFERS from served payload", p.stdout)
        finally:
            host.stop()


class WritesNothingTest(AuditBase):
    """Default posture: read-only. Explicit opt-in is byte-exact."""

    def test_audit_writes_nothing_by_default(self):
        host = TestHost(tls=True)
        try:
            _src, sha = self._served(host)
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--expect-sha256", sha], cwd=work)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(os.listdir(work), [],
                             "audit must not create files by default")
        finally:
            host.stop()

    def test_save_to_writes_exact_served_bytes(self):
        host = TestHost(tls=True)
        try:
            src, sha = self._served(host)
            work = tempfile.mkdtemp(prefix="llmac-audit-")
            save_to = os.path.join(work, "audited-cli.py")
            p = self._run(["audit", "--host", "127.0.0.1",
                           "--port", str(host.port), "--key", host.key,
                           "--expect-sha256", sha,
                           "--save-to", save_to], cwd=work)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(save_to, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), src)
            self.assertIn(f"saved: {save_to}", p.stdout)
        finally:
            host.stop()


class BlockCarriesAuditTest(AuditBase):
    """The connection block must offer the audit BEFORE the connect."""

    def test_block_carries_audit_step_before_connect(self):
        host = TestHost(tls=True)
        try:
            _src, sha = self._served(host)
            prompt = build_prompt_text(
                key=host.key, host="127.0.0.1", port=host.port,
                roots=host.roots, fingerprint=self._fp(host), tls=True)
            self.assertIn(f"llmac.py audit --host 127.0.0.1", prompt)
            self.assertIn(f"--expect-sha256 {sha}", prompt)
            self.assertLess(prompt.index("audit --host"),
                            prompt.index("connect --host"),
                            "audit must be offered before connect")
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
