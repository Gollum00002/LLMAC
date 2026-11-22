"""v2.8.3: a connection that never completes the TLS handshake must not
block the accept loop (regression: one half-open TCP connection made
every later client time out until the host was restarted)."""
import os
import socket
import sys
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core import tlsutil
from helpers import TestHost


def _tls_health(port, timeout=5.0):
    import ssl, json
    ctx = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname="127.0.0.1") as t:
            t.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n"
                      b"Connection: close\r\n\r\n")
            buf = b""
            while True:
                c = t.recv(4096)
                if not c:
                    break
                buf += c
    return json.loads(buf.split(b"\r\n\r\n", 1)[1].decode())


@unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
class TestStalledHandshake(unittest.TestCase):
    def setUp(self):
        self.host = TestHost(tls=True)
        self.stalled = []

    def tearDown(self):
        for s in self.stalled:
            try:
                s.close()
            except OSError:
                pass
        self.host.stop()

    def test_silent_tcp_peer_does_not_block_others(self):
        # Several peers: TCP connect, then silence (never a ClientHello).
        for _ in range(5):
            self.stalled.append(socket.create_connection(
                ("127.0.0.1", self.host.port)))
        time.sleep(0.3)
        t0 = time.time()
        resp = _tls_health(self.host.port, timeout=5.0)
        self.assertEqual(resp["server"], "llmac")
        self.assertLess(time.time() - t0, 3.0)

    def test_plain_http_on_tls_port_is_dropped_and_server_survives(self):
        s = socket.create_connection(("127.0.0.1", self.host.port))
        self.stalled.append(s)
        s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.3)
        self.assertEqual(_tls_health(self.host.port)["server"], "llmac")

    def test_garbage_handshake_does_not_kill_server(self):
        s = socket.create_connection(("127.0.0.1", self.host.port))
        self.stalled.append(s)
        s.sendall(os.urandom(512))
        time.sleep(0.3)
        self.assertEqual(_tls_health(self.host.port)["server"], "llmac")


if __name__ == "__main__":
    unittest.main()


class TestStopServer(unittest.TestCase):
    """GUI Stop must return promptly even with a stalled peer connected."""

    @unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
    def test_stop_with_stalled_peer_returns_quickly(self):
        from core.server import stop_server
        host = TestHost(tls=True)
        stalled = socket.create_connection(("127.0.0.1", host.port))
        try:
            time.sleep(0.3)
            t0 = time.time()
            self.assertTrue(stop_server(host.server))
            self.assertLess(time.time() - t0, 3.0)
        finally:
            stalled.close()
            import shutil
            shutil.rmtree(host.tmp, ignore_errors=True)

    def test_stop_server_is_bounded_when_shutdown_wedges(self):
        from core.server import stop_server

        class Wedged:
            closed = False
            def shutdown(self):
                time.sleep(30)
            def server_close(self):
                self.closed = True
        w = Wedged()
        t0 = time.time()
        self.assertFalse(stop_server(w, timeout=0.5))
        self.assertLess(time.time() - t0, 2.0)
        self.assertTrue(w.closed)
