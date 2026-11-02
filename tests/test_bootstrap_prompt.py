"""Regression tests for the agent self-install one-liner.

The one-liner that build_prompt_text() hands to every new agent (GUI
"Copy Prompt", headless banner, agent.md) is executed VERBATIM here —
as a `python3 -c` subprocess in a clean temp directory against a live
local host, for both TLS and plain modes.

Why: v2.1.0 shipped a broken one-liner (Authorization dict passed as
the positional `data` arg instead of `headers=`). It crashed with
"TypeError: can't concat str to bytes" on CPython and would have sent
the key in the body as a POST to a GET-only route besides. The whole
125-test suite stayed green because tests/helpers.py always used the
correct headers= form — the generated *text* was never executed as
written. These tests close that gap permanently.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.server import build_prompt_text
from core.tlsutil import cert_fingerprint
from tests.helpers import TestHost


def _extract_one_liner(prompt: str) -> str:
    """Pull the `python3 -c "<body>"` payload out of the prompt block."""
    for line in prompt.splitlines():
        if 'python3 -c "' in line:
            return line.split('python3 -c "', 1)[1].rsplit('"', 1)[0]
    raise AssertionError("no self-install one-liner found in prompt:\n" + prompt)


class OneLinerVerbatimTest(unittest.TestCase):
    """Run the generated command exactly as an agent would paste it."""

    def _run_verbatim(self, host: TestHost, prompt: str) -> str:
        body = _extract_one_liner(prompt)
        # Sanity: the key must travel in headers=, never as positional data.
        self.assertIn("headers={'Authorization':", body)
        self.assertNotIn("',{'Authorization':", body)
        work = tempfile.mkdtemp(prefix="llmac-bootstrap-")
        proc = subprocess.run([sys.executable, "-c", body], cwd=work,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0,
                         f"one-liner crashed:\n{proc.stderr}\n--- body ---\n{body}")
        installed = os.path.join(work, "llmac.py")
        self.assertTrue(os.path.isfile(installed),
                        "one-liner did not write llmac.py")
        # What we installed must be exactly what the host serves.
        served, status = host.get("/bootstrap")
        self.assertEqual(status, 200)
        with open(installed, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), served["cli_py"])
        # And it must be a valid, runnable Python file.
        comp = subprocess.run([sys.executable, "-m", "py_compile", "llmac.py"],
                              cwd=work, capture_output=True, text=True,
                              timeout=60)
        self.assertEqual(comp.returncode, 0, comp.stderr)
        return installed

    def test_one_liner_tls_verbatim(self):
        host = TestHost(tls=True)
        try:
            from core.tlsutil import tls_paths
            cert_path, _key_path = tls_paths(host.data_dir)
            fp = cert_fingerprint(cert_path)
            prompt = build_prompt_text(key=host.key, host="127.0.0.1",
                                       port=host.port, roots=host.roots,
                                       fingerprint=fp or "", tls=True)
            self._run_verbatim(host, prompt)
        finally:
            host.stop()

    def test_one_liner_plain_verbatim(self):
        host = TestHost(tls=False)
        try:
            prompt = build_prompt_text(key=host.key, host="127.0.0.1",
                                       port=host.port, roots=host.roots,
                                       tls=False)
            self.assertNotIn("ssl", _extract_one_liner(prompt))
            self._run_verbatim(host, prompt)
        finally:
            host.stop()


class BootstrapRouteTest(unittest.TestCase):
    """POST /bootstrap must work too (defensive alias added in v2.1.1)."""

    def test_bootstrap_accepts_post_with_empty_body(self):
        host = TestHost()
        try:
            resp, status = host.req("POST", "/bootstrap")
            self.assertEqual(status, 200)
            self.assertIn("cli_py", resp)
            self.assertIn("hint", resp)
        finally:
            host.stop()

    def test_bootstrap_get_still_works(self):
        host = TestHost()
        try:
            resp, status = host.get("/bootstrap")
            self.assertEqual(status, 200)
            self.assertIn("cli_py", resp)
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
