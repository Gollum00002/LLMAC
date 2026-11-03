"""v2.8 — the connection block's download one-liner and the removed
/bootstrap route.

The host no longer serves code. The block tells the agent to download
llmac.py from the public GitHub release and verify its SHA-256. The
one-liner that build_prompt_text() generates is executed VERBATIM here
(as `python3 -c`, in a clean temp directory) against a file:// URL that
stands in for the GitHub asset (LLMAC_CLIENT_URL), because the generated
text is what agents paste, so that is what must be tested — not a
hand-rebuilt equivalent. (v2.1.0 once shipped a broken one-liner that
every other test missed for exactly that reason.)
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.constants import CLI_PATH, CLIENT_DOWNLOAD_URL, CLIENT_REPO_URL
from core.server import build_prompt_text
from core.tlsutil import cert_fingerprint, tls_paths
from tests.helpers import TestHost

_SHA_RE = re.compile(r"W='([0-9a-f]{64})'")


def local_sha256() -> str:
    with open(CLI_PATH, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def extract_one_liner(prompt: str) -> str:
    """Pull the `python3 -c "<body>"` payload out of the prompt block."""
    for line in prompt.splitlines():
        if 'python3 -c "' in line:
            return line.split('python3 -c "', 1)[1].rsplit('"', 1)[0]
    raise AssertionError("no download one-liner found in prompt:\n" + prompt)


def make_prompt(host: TestHost, *, tls: bool, url: str = "",
                **kw) -> str:
    fp = ""
    if tls:
        cert_path, _ = tls_paths(host.data_dir)
        fp = cert_fingerprint(cert_path) or ""
    env = {"LLMAC_CLIENT_URL": url} if url else {}
    with mock.patch.dict(os.environ, env):
        return build_prompt_text(key=host.key, host="127.0.0.1",
                                 port=host.port, roots=host.roots,
                                 fingerprint=fp, tls=tls, **kw)


class OneLinerVerbatimTest(unittest.TestCase):
    """Run the generated command exactly as an agent would paste it."""

    def _run(self, body: str):
        work = tempfile.mkdtemp(prefix="llmac-dl-")
        proc = subprocess.run([sys.executable, "-c", body], cwd=work,
                              capture_output=True, text=True, timeout=60)
        return proc, work

    def _check(self, tls: bool):
        host = TestHost(tls=tls)
        try:
            url = pathlib.Path(CLI_PATH).as_uri()
            prompt = make_prompt(host, tls=tls, url=url)
            body = extract_one_liner(prompt)
            # shell-safe: it is embedded in a double-quoted string
            for bad in ('"', "$", "`", "!"):
                self.assertNotIn(bad, body)
            proc, work = self._run(body)
            self.assertEqual(proc.returncode, 0,
                             f"one-liner failed:\n{proc.stderr}\n--- body "
                             f"---\n{body}")
            self.assertIn("sha256 OK", proc.stdout)
            installed = os.path.join(work, "llmac.py")
            with open(installed, "rb") as f, open(CLI_PATH, "rb") as g:
                self.assertEqual(f.read(), g.read())
            comp = subprocess.run([sys.executable, "-m", "py_compile",
                                   "llmac.py"], cwd=work,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(comp.returncode, 0, comp.stderr)
        finally:
            host.stop()

    def test_one_liner_tls_verbatim(self):
        self._check(tls=True)

    def test_one_liner_plain_verbatim(self):
        self._check(tls=False)

    def test_one_liner_never_contacts_the_host(self):
        host = TestHost(tls=False)
        try:
            body = extract_one_liner(make_prompt(
                host, tls=False, url=pathlib.Path(CLI_PATH).as_uri()))
            self.assertNotIn(str(host.port), body)
            self.assertNotIn("127.0.0.1", body)
            self.assertNotIn(host.key, body)
            self.assertNotIn("Authorization", body)
            self.assertNotIn("/bootstrap", body)
        finally:
            host.stop()


class PromptContentTest(unittest.TestCase):
    """The block points at GitHub, pins a hash, and never at the host."""

    def test_block_names_github_source_and_pins_local_hash(self):
        host = TestHost(tls=True)
        try:
            prompt = make_prompt(host, tls=True)
            self.assertIn(f"Client-Source:  {CLIENT_REPO_URL}", prompt)
            self.assertIn(f"Client-File:    {CLIENT_DOWNLOAD_URL}", prompt)
            self.assertIn(f"Client-SHA256:  {local_sha256()}", prompt)
            self.assertIn("does NOT serve code", prompt)
        finally:
            host.stop()

    def test_block_has_no_trace_of_host_served_code(self):
        host = TestHost(tls=True)
        try:
            prompt = make_prompt(host, tls=True)
            for gone in ("/bootstrap", "Payload-SHA256", "cli_py",
                         "cli_sha256", "Authorization"):
                self.assertNotIn(gone, prompt)
        finally:
            host.stop()

    def test_hash_is_byte_exact_sha256sum(self):
        # no newline normalisation: must equal what `sha256sum llmac.py`
        # prints, i.e. what the maintainer publishes on the release page.
        with open(CLI_PATH, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(local_sha256(), want)

    def test_audit_is_offered_before_connect_and_is_offline(self):
        host = TestHost(tls=True)
        try:
            prompt = make_prompt(host, tls=True)
            self.assertIn(
                f"python3 llmac.py audit --expect-sha256 {local_sha256()}",
                prompt)
            self.assertNotIn("audit --host", prompt)
            self.assertLess(prompt.index("llmac.py audit"),
                            prompt.index("connect --host"))
        finally:
            host.stop()

    def test_unavailable_hash_drops_the_one_liner(self):
        host = TestHost(tls=False)
        try:
            prompt = make_prompt(host, tls=False, client_sha256="")
            self.assertNotIn('python3 -c "', prompt)
            self.assertIn("(unavailable", prompt)
            self.assertIn("release page", prompt)
        finally:
            host.stop()


class BootstrapRouteRemovedTest(unittest.TestCase):
    """GET/POST /bootstrap answer 410 with a pointer and NO code."""

    def _check(self, method: str):
        host = TestHost()
        try:
            resp, status = host.req(method, "/bootstrap")
            self.assertEqual(status, 410)
            self.assertEqual(resp["error"], "bootstrap_removed")
            self.assertEqual(resp["download"], CLIENT_DOWNLOAD_URL)
            self.assertEqual(resp["source"], CLIENT_REPO_URL)
            blob = repr(resp)
            for gone in ("cli_py", "cli_sha256", "def main", "argparse"):
                self.assertNotIn(gone, blob)
        finally:
            host.stop()

    def test_get_is_410(self):
        self._check("GET")

    def test_post_is_410(self):
        self._check("POST")

    def test_unauthenticated_gets_401_not_a_pointer(self):
        host = TestHost()
        try:
            resp, status = host.get("/bootstrap", key="llmac_wrong")
            self.assertEqual(status, 401)
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
