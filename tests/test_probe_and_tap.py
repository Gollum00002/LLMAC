"""v2.8: probe (pre-connection silence check), --tap (unsolicited-data
monitor) and core.netinfo (zero-packet IPv4 discovery for the bind
dropdown).

The probe contract under test:
  * against a REAL LLMAC TLS host: silent window or clean idle close
    -> PASS, with the pinned fingerprint verified on the wire;
  * wrong pin -> FAIL before any listening;
  * a listener that pushes bytes right after the handshake -> FAIL
    with a hex preview (plain and TLS variants);
  * nothing listening -> FAIL unreachable.

The tap contract under test:
  * a normal request/response against a real host produces NO events;
  * server-initiated bytes on an idle connection DO produce an event
    (via a socketpair stand-in for the keep-alive connection);
  * a clean idle EOF is quiet (connection dropped, no event).
"""
import argparse
import contextlib
import io
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import helpers  # noqa: F401  (sets sys.path, defines TestHost)
import llmac
from core import netinfo, tlsutil


def _push_listener(tls_ctx=None):
    """A server that pushes bytes the instant a client connects (after
    the TLS handshake when a context is given). Returns (port, stop)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    state = {"running": True}

    def serve():
        while state["running"]:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                if tls_ctx is not None:
                    c = tls_ctx.wrap_socket(c, server_side=True)
                c.sendall(b"PUSHED-UNSOLICITED")
                c.close()
            except Exception:
                pass

    threading.Thread(target=serve, daemon=True).start()

    def stop():
        state["running"] = False
        try:
            srv.close()
        except OSError:
            pass

    return port, stop


class TestNetinfo(unittest.TestCase):
    def test_bind_scope(self):
        self.assertEqual(netinfo.bind_scope("0.0.0.0"), "wildcard")
        self.assertEqual(netinfo.bind_scope("::"), "wildcard")
        self.assertEqual(netinfo.bind_scope(""), "wildcard")
        self.assertEqual(netinfo.bind_scope("127.0.0.1"), "loopback")
        self.assertEqual(netinfo.bind_scope("localhost"), "loopback")
        self.assertEqual(netinfo.bind_scope("::1"), "loopback")
        self.assertEqual(netinfo.bind_scope("192.168.1.50"), "specific")
        self.assertEqual(netinfo.bind_scope("10.0.0.2"), "specific")

    def test_bindable_filters_loopback_and_apipa(self):
        self.assertFalse(netinfo._bindable("127.0.0.1"))
        self.assertFalse(netinfo._bindable("127.0.4.4"))
        self.assertFalse(netinfo._bindable("169.254.7.7"))
        self.assertTrue(netinfo._bindable("192.168.1.50"))
        self.assertTrue(netinfo._bindable("10.0.0.2"))

    def test_local_ipv4s_smoke(self):
        """Zero-packet discovery never raises and never offers
        loopback/APIPA addresses as bind targets."""
        ips = netinfo.local_ipv4s()
        self.assertIsInstance(ips, list)
        for ip in ips:
            self.assertIsInstance(ip, str)
            self.assertFalse(ip.startswith("127."),
                             f"loopback leaked into results: {ip}")
            self.assertFalse(ip.startswith("169.254."),
                             f"APIPA leaked into results: {ip}")
        # Primary route (when one exists) comes first and is included.
        primary = netinfo._primary_route_ipv4()
        if primary and netinfo._bindable(primary):
            self.assertIn(primary, ips)


@unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
class TestProbeAgainstRealHost(unittest.TestCase):
    """The compliant case: a real LLMAC host must be silent."""

    def setUp(self):
        llmac._TAP["events"] = []
        self.host = helpers.TestHost(tls=True)
        self.fp = tlsutil.cert_fingerprint(
            tlsutil.tls_paths(self.host.data_dir)[0])

    def tearDown(self):
        self.host.stop()

    def test_pass_silent_window(self):
        res = llmac.probe_host("127.0.0.1", self.host.port,
                               fingerprint=self.fp, wait=1.0, tls=True)
        self.assertEqual(res["verdict"], "PASS", res["reason"])
        self.assertEqual(res["bytes_received"], 0)
        self.assertEqual(res["fingerprint"], self.fp)

    def test_pass_clean_idle_close(self):
        # A shorter window on the same host: either silent-timeout or a
        # clean server-side idle close is a PASS — never unsolicited
        # bytes. Assert the stronger invariant (no bytes, ever).
        res = llmac.probe_host("127.0.0.1", self.host.port,
                               fingerprint=self.fp, wait=0.5, tls=True)
        self.assertEqual(res["verdict"], "PASS", res["reason"])
        self.assertEqual(res["bytes_received"], 0)

    def test_fail_fingerprint_mismatch(self):
        wrong = "SHA256:" + "0" * 64
        res = llmac.probe_host("127.0.0.1", self.host.port,
                               fingerprint=wrong, wait=0.5, tls=True)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertIn("mismatch", res["reason"])
        self.assertNotEqual(res["fingerprint"], wrong)

    def test_cmd_probe_rc_and_json(self):
        args = argparse.Namespace(host="127.0.0.1", port=self.host.port,
                                  fp=self.fp, wait=0.5, plain=False,
                                  json=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = llmac.cmd_probe(args)
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["verdict"], "PASS")

    def test_cmd_probe_rc_fail_on_mismatch(self):
        args = argparse.Namespace(host="127.0.0.1", port=self.host.port,
                                  fp="SHA256:" + "0" * 64, wait=0.5,
                                  plain=False, json=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = llmac.cmd_probe(args)
        self.assertEqual(rc, 1)


class TestProbeAgainstPushers(unittest.TestCase):
    """The hostile case: bytes pushed with no request sent."""

    def test_fail_unsolicited_plain(self):
        port, stop = _push_listener()
        try:
            res = llmac.probe_host("127.0.0.1", port, wait=3.0, tls=False)
            self.assertEqual(res["verdict"], "FAIL")
            self.assertEqual(res["bytes_received"],
                             len(b"PUSHED-UNSOLICITED"))
            self.assertEqual(res["preview"],
                             b"PUSHED-UNSOLICITED"[:64].hex())
            self.assertIn("UNSOLICITED", res["reason"])
        finally:
            stop()

    @unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
    def test_fail_unsolicited_tls(self):
        tmp = tempfile.mkdtemp(prefix="llmac-probe-push-")
        try:
            cert, key = tlsutil.ensure_cert(tmp)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            port, stop = _push_listener(tls_ctx=ctx)
            try:
                res = llmac.probe_host("127.0.0.1", port, wait=3.0,
                                       tls=True)
                self.assertEqual(res["verdict"], "FAIL")
                self.assertEqual(res["bytes_received"],
                                 len(b"PUSHED-UNSOLICITED"))
                self.assertTrue(res["fingerprint"].startswith("SHA256:"))
            finally:
                stop()
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_fail_unreachable(self):
        # Grab a port and close it again — nothing is listening.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        res = llmac.probe_host("127.0.0.1", port, wait=0.5, tls=False)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertIn("unreachable", res["reason"])


class _FakeConn:
    """Stand-in for an http.client connection: the tap monitor only
    touches .sock and .close()."""

    def __init__(self, sock):
        self.sock = sock

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TestTap(unittest.TestCase):
    def setUp(self):
        llmac._TAP["events"] = []

    def _wait_for(self, cond, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_no_false_positive_against_real_host(self):
        host = helpers.TestHost(tls=False)
        client = None
        try:
            client = llmac.Client("127.0.0.1", host.port, host.key,
                                  tls=False, tap=True)
            res, status = client._request("GET", "/health")
            self.assertEqual(status, 200)
            self.assertEqual(res.get("server"), "llmac")
            # Let the monitor poll the idle connection a few times.
            self.assertFalse(
                self._wait_for(lambda: bool(llmac._TAP["events"]),
                               timeout=1.0),
                "tap flagged a compliant host")
            self.assertEqual(llmac._TAP["events"], [])
        finally:
            if client is not None:
                if client._conn is not None:
                    try:
                        client._conn.close()
                    except OSError:
                        pass
                client._tap_stop()
            host.stop()

    def test_flags_server_initiated_bytes(self):
        client = llmac.Client("127.0.0.1", 9, "k", tls=False, tap=True)
        a, b = socket.socketpair()
        try:
            client._conn = _FakeConn(a)
            b.sendall(b"surprise")
            self.assertTrue(
                self._wait_for(lambda: bool(llmac._TAP["events"])),
                "tap missed unsolicited bytes on an idle connection")
            ev = llmac._TAP["events"][0]
            self.assertIn("server-initiated", ev["detail"])
            # The poisoned connection was dropped.
            self.assertIsNone(client._conn)
        finally:
            client._tap_stop()
            b.close()

    def test_clean_idle_eof_is_quiet(self):
        client = llmac.Client("127.0.0.1", 9, "k", tls=False, tap=True)
        a, b = socket.socketpair()
        try:
            client._conn = _FakeConn(a)
            b.close()   # peer closes the idle connection
            self.assertTrue(
                self._wait_for(lambda: client._conn is None),
                "tap did not drop a cleanly closed idle connection")
            self.assertEqual(llmac._TAP["events"], [])
        finally:
            client._tap_stop()

    def test_readable_bytes_never_consumes(self):
        client = llmac.Client("127.0.0.1", 9, "k", tls=False, tap=True)
        a, b = socket.socketpair()
        try:
            # Quiet: nothing readable.
            self.assertIsNone(client._tap_readable_bytes(a))
            # Pushed: readable — but MSG_PEEK must not consume the byte.
            b.sendall(b"xy")
            time.sleep(0.05)
            self.assertEqual(client._tap_readable_bytes(a), 1)
            got = a.recv(2)
            self.assertEqual(got, b"xy")
            # Peer closed: a clean EOF reads as 0.
            b.close()
            self.assertEqual(client._tap_readable_bytes(a), 0)
        finally:
            client._tap_stop()
            a.close()


class TestPromptCarriesProbe(unittest.TestCase):
    """The connection block must make the probe step 3, REQUIRED."""

    def test_prompt_contains_probe_step(self):
        from core.server import build_prompt_text
        text = build_prompt_text(
            key="llmac_test_key", host="192.168.1.50", port=8765,
            roots=["/tmp"], fingerprint="SHA256:" + "a" * 64, tls=True,
            client_sha256="b" * 64)
        self.assertIn(
            "probe --host 192.168.1.50 --port 8765 --wait 10 "
            "--fp SHA256:", text)
        self.assertIn("REQUIRED", text)
        self.assertIn("4. Connect only after the probe passes", text)
        self.assertIn("--tap", text)


if __name__ == "__main__":
    unittest.main()
