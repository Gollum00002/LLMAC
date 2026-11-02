"""v2.7.1 — self-verifying bootstrap regression tests.

The connection block's one-liner must (a) pin the server certificate
fingerprint BEFORE any HTTP bytes are sent, (b) verify the served
payload against the bootstrap response's cli_sha256, and (c) fail
closed: every tamper scenario exits non-zero WITHOUT writing llmac.py.

Happy paths run the generated command VERBATIM against a live local
host (same technique as test_bootstrap_prompt.py — the generated text
is what agents paste, so that is what must be executed here, not a
hand-rebuilt equivalent).
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.server import build_prompt_text
from core.tlsutil import cert_fingerprint, tls_paths
from tests.helpers import TestHost

_FP_RE = re.compile(r"F='([0-9a-f]{64})'")


def _extract_one_liner(prompt: str) -> str:
    """Pull the `python3 -c "<body>"` payload out of the prompt block."""
    for line in prompt.splitlines():
        if 'python3 -c "' in line:
            return line.split('python3 -c "', 1)[1].rsplit('"', 1)[0]
    raise AssertionError("no self-install one-liner found in prompt:\n"
                         + prompt)


def _tls_prompt(host: TestHost) -> str:
    cert_path, _key_path = tls_paths(host.data_dir)
    fp = cert_fingerprint(cert_path) or ""
    return build_prompt_text(key=host.key, host="127.0.0.1",
                             port=host.port, roots=host.roots,
                             fingerprint=fp, tls=True)


class PromptPayloadHashTest(unittest.TestCase):
    """The block must carry the hash and the one-liner must verify it."""

    def test_prompt_carries_payload_sha256_matching_served_payload(self):
        host = TestHost(tls=True)
        try:
            served, status = host.get("/bootstrap")
            self.assertEqual(status, 200)
            self.assertIn("cli_sha256", served)
            self.assertEqual(
                hashlib.sha256(served["cli_py"].encode("utf-8")).hexdigest(),
                served["cli_sha256"])
            prompt = _tls_prompt(host)
            self.assertIn(f"Payload-SHA256:  {served['cli_sha256']}", prompt)
            body = _extract_one_liner(prompt)
            # TLS one-liner pins the cert and verifies the payload:
            self.assertIn("getpeercert(binary_form=True)", body)
            self.assertIn("cert fingerprint mismatch", body)
            self.assertIn("cli_sha256", body)
            self.assertIn("payload hash mismatch", body)
            self.assertIn("payload hash missing", body)
        finally:
            host.stop()

    def test_plain_prompt_has_no_ssl_and_carries_hash(self):
        host = TestHost(tls=False)
        try:
            served, _status = host.get("/bootstrap")
            prompt = build_prompt_text(key=host.key, host="127.0.0.1",
                                       port=host.port, roots=host.roots,
                                       tls=False)
            body = _extract_one_liner(prompt)
            self.assertNotIn("ssl", body)
            self.assertIn("cli_sha256", body)
            self.assertIn(f"Payload-SHA256:  {served['cli_sha256']}", prompt)
        finally:
            host.stop()


class TamperMustAbortTest(unittest.TestCase):
    """Fail closed: tampered pin or hash => non-zero exit, no file."""

    def _run(self, body: str):
        work = tempfile.mkdtemp(prefix="llmac-tamper-")
        proc = subprocess.run([sys.executable, "-c", body], cwd=work,
                              capture_output=True, text=True, timeout=60)
        return proc, work

    def _assert_no_file(self, work: str):
        self.assertFalse(os.path.isfile(os.path.join(work, "llmac.py")),
                         "llmac.py must NOT be written on tamper abort")

    def test_wrong_cert_fingerprint_aborts_before_any_request(self):
        host = TestHost(tls=True)
        try:
            body = _extract_one_liner(_tls_prompt(host))
            m = _FP_RE.search(body)
            self.assertIsNotNone(m, "one-liner carries no pin constant")
            bad = "0" * 64
            body_bad = body[:m.start(1)] + bad + body[m.end(1):]
            proc, work = self._run(body_bad)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("fingerprint mismatch", proc.stderr + proc.stdout)
            self._assert_no_file(work)
        finally:
            host.stop()

    def test_tampered_payload_hash_aborts_without_writing(self):
        host = TestHost(tls=True)
        try:
            body = _extract_one_liner(_tls_prompt(host))
            needle = "want=d.get('cli_sha256','')"
            self.assertIn(needle, body)
            body_bad = body.replace(needle, "want='0' * 64")
            proc, work = self._run(body_bad)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("payload hash mismatch", proc.stderr + proc.stdout)
            self._assert_no_file(work)
        finally:
            host.stop()

    def test_missing_payload_hash_aborts_without_writing(self):
        host = TestHost(tls=True)
        try:
            body = _extract_one_liner(_tls_prompt(host))
            needle = "want=d.get('cli_sha256','')"
            body_bad = body.replace(needle, "want=''")
            proc, work = self._run(body_bad)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("payload hash missing", proc.stderr + proc.stdout)
            self._assert_no_file(work)
        finally:
            host.stop()


class HappyPathVerbatimTest(unittest.TestCase):
    """The exact pasted command installs a verified, runnable client."""

    def _verbatim(self, prompt: str, host: TestHost):
        body = _extract_one_liner(prompt)
        # Sanity: the key must travel in headers=, never as positional
        # data (v2.1.0 post-mortem), and the body must be shell-safe.
        self.assertIn("headers={'Authorization':", body)
        self.assertNotIn("',{'Authorization':", body)
        self.assertNotIn('"', body)
        work = tempfile.mkdtemp(prefix="llmac-happy-")
        proc = subprocess.run([sys.executable, "-c", body], cwd=work,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0,
                         f"one-liner failed:\n{proc.stderr}\n--- body ---\n"
                         f"{body}")
        installed = os.path.join(work, "llmac.py")
        self.assertTrue(os.path.isfile(installed))
        served, _status = host.get("/bootstrap")
        with open(installed, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), served["cli_py"])
        comp = subprocess.run([sys.executable, "-m", "py_compile", "llmac.py"],
                              cwd=work, capture_output=True, text=True,
                              timeout=60)
        self.assertEqual(comp.returncode, 0, comp.stderr)

    def test_tls_verbatim(self):
        host = TestHost(tls=True)
        try:
            self._verbatim(_tls_prompt(host), host)
        finally:
            host.stop()

    def test_plain_verbatim(self):
        host = TestHost(tls=False)
        try:
            prompt = build_prompt_text(key=host.key, host="127.0.0.1",
                                       port=host.port, roots=host.roots,
                                       tls=False)
            self._verbatim(prompt, host)
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
