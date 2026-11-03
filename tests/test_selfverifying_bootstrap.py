"""v2.8 — the download one-liner must fail closed.

Whatever is fetched from the release URL (a tampered asset, a stale
release, a swapped file) must be rejected BEFORE llmac.py is written
whenever its SHA-256 differs from the Client-SHA256 in the block. The
generated one-liner is executed verbatim, as in test_bootstrap_prompt.py.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.constants import CLI_PATH
from tests.helpers import TestHost
from tests.test_bootstrap_prompt import (
    _SHA_RE, extract_one_liner, make_prompt)


class TamperMustAbortTest(unittest.TestCase):
    """Fail closed: wrong bytes or wrong pin => non-zero exit, no file."""

    def _run(self, body: str):
        work = tempfile.mkdtemp(prefix="llmac-tamper-")
        proc = subprocess.run([sys.executable, "-c", body], cwd=work,
                              capture_output=True, text=True, timeout=60)
        return proc, work

    def _assert_no_file(self, work: str):
        self.assertFalse(os.path.isfile(os.path.join(work, "llmac.py")),
                         "llmac.py must NOT be written on a hash mismatch")

    def test_tampered_asset_aborts_without_writing(self):
        host = TestHost(tls=False)
        try:
            src_dir = tempfile.mkdtemp(prefix="llmac-evil-")
            evil = os.path.join(src_dir, "llmac.py")
            with open(CLI_PATH, "rb") as f:
                data = f.read()
            with open(evil, "wb") as f:
                f.write(data + b"\nimport os; os.system('echo pwned')\n")
            # block pins the REAL hash; the URL serves the tampered bytes
            body = extract_one_liner(make_prompt(
                host, tls=False, url=pathlib.Path(evil).as_uri()))
            proc, work = self._run(body)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("sha256 mismatch", proc.stderr + proc.stdout)
            self._assert_no_file(work)
        finally:
            host.stop()

    def test_wrong_pinned_hash_aborts_without_writing(self):
        host = TestHost(tls=False)
        try:
            body = extract_one_liner(make_prompt(
                host, tls=False, url=pathlib.Path(CLI_PATH).as_uri()))
            m = _SHA_RE.search(body)
            self.assertIsNotNone(m, "one-liner carries no hash constant")
            bad = body[:m.start(1)] + "0" * 64 + body[m.end(1):]
            proc, work = self._run(bad)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("sha256 mismatch", proc.stderr + proc.stdout)
            self._assert_no_file(work)
        finally:
            host.stop()

    def test_unreachable_url_aborts_without_writing(self):
        host = TestHost(tls=False)
        try:
            gone = pathlib.Path(tempfile.mkdtemp()) / "nope.py"
            body = extract_one_liner(make_prompt(
                host, tls=False, url=gone.as_uri()))
            proc, work = self._run(body)
            self.assertNotEqual(proc.returncode, 0)
            self._assert_no_file(work)
        finally:
            host.stop()


class OneLinerExecutesNothingTest(unittest.TestCase):
    """The one-liner only downloads, hashes and writes; no exec paths."""

    def test_no_exec_primitives_in_one_liner(self):
        host = TestHost(tls=False)
        try:
            body = extract_one_liner(make_prompt(host, tls=False))
            for prim in ("exec(", "eval(", "compile(", "__import__",
                         "subprocess", "os.system", "importlib", "runpy"):
                self.assertNotIn(prim, body)
            # only stdlib network + hashing imports
            self.assertEqual(
                re.findall(r"import ([\w.,]+)", body),
                ["urllib.request,hashlib,sys"])
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
