"""Shared test fixture: spin up a headless LLMAC server on an ephemeral port."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import urllib.request

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.server import build_context, make_server, EXEC_SHELL
from core.state import History, StateStore, make_default_agent


class TestHost:
    """A disposable LLMAC host bound to 127.0.0.1:<ephemeral>."""

    def __init__(self, *, roots: list = None, agents: list = None,
                 settings: dict = None, tls: bool = False):
        _base = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), ".test-tmp")
        os.makedirs(_base, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="llmac-test-", dir=_base)
        self.data_dir = os.path.join(self.tmp, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.roots = roots or [self._mkroot("root1")]
        self.agents = agents or [make_default_agent("testkey_llmac_1234567890")]
        base_settings = {"tls": tls, "allow_exec": True,
                         "approval_policy": "auto", "venvs": []}
        if settings:
            base_settings.update(settings)
        self.settings = base_settings
        if self.settings.get("allow_exec"):
            # Tests that enable exec imply the default agent may exec.
            self.agents[0] = dict(self.agents[0])
            self.agents[0]["perms"] = dict(self.agents[0].get("perms") or {})
            self.agents[0]["perms"]["exec"] = True
            self.agents[0]["perms"]["proc"] = True
        self.state_store = StateStore(self.data_dir)
        self.history = History(self.data_dir)
        self.ctx = build_context(self.state_store, self.roots, self.agents,
                                 self.settings, self.history)
        cert = keyf = None
        if tls:
            from core import tlsutil
            cert, keyf = tlsutil.ensure_cert(self.data_dir)
        self.server = make_server("127.0.0.1", 0, self.ctx, cert, keyf)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f"http{'s' if tls else ''}://127.0.0.1:{self.port}"

    def _mkroot(self, name: str) -> str:
        d = os.path.join(self.tmp, name)
        os.makedirs(d, exist_ok=True)
        return d

    @property
    def key(self) -> str:
        return self.agents[0]["key"]

    @property
    def root(self) -> str:
        return self.roots[0]

    # ---- client helpers -------------------------------------------------

    def req(self, method: str, path: str, payload: dict = None,
            key: str = None) -> tuple:
        body = json.dumps(payload or {}).encode() if payload is not None else None
        r = urllib.request.Request(
            self.base + path, data=body, method=method,
            headers={"Authorization": f"Bearer {key or self.key}",
                     "Content-Type": "application/json"})
        # TLS test hosts use a self-signed cert — proper fingerprint
        # pinning is covered by test_tls.py; here we just need the
        # transport to work.
        kwargs = {"timeout": 30}
        if self.base.startswith("https"):
            import ssl
            kwargs["context"] = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(r, **kwargs) as resp:
                return json.loads(resp.read().decode()), resp.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode()), e.code

    def post(self, path: str, payload: dict = None, key: str = None):
        return self.req("POST", path, payload, key)

    def get(self, path: str, key: str = None):
        return self.req("GET", path, None, key)

    # ---- lifecycle ------------------------------------------------------

    def stop(self):
        self.ctx.procs.stop_all()
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def wait_for(self, cond, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return True
            time.sleep(0.05)
        return False


def make_tree(base: str, files: dict) -> str:
    """Create files under base: {'sub/dir/file.txt': 'content'}"""
    for rel, content in files.items():
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
    return base
