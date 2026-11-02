"""TLS utility tests: cert generation, fingerprint, HTTPS serving."""
import json
import os
import ssl
import sys
import tempfile
import unittest
import urllib.request

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core import tlsutil
from helpers import TestHost


class TestTlsUtil(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tls-test-")

    @unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
    def test_cert_generation_and_fingerprint(self):
        cert, key = tlsutil.ensure_cert(self.tmp)
        self.assertIsNotNone(cert)
        self.assertTrue(os.path.isfile(cert))
        fp = tlsutil.cert_fingerprint(cert)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertEqual(len(fp), len("SHA256:") + 64)
        # Regenerating on existing cert is a no-op:
        cert2, _ = tlsutil.ensure_cert(self.tmp)
        self.assertEqual(cert2, cert)
        self.assertEqual(tlsutil.cert_fingerprint(cert2), fp)

    @unittest.skipIf(not tlsutil.openssl_available(), "openssl missing")
    def test_https_server_roundtrip(self):
        from core.state import make_default_agent
        host = TestHost(tls=True)
        try:
            self.host = host
            fp = tlsutil.cert_fingerprint(
                tlsutil.tls_paths(host.data_dir)[0])
            self.assertIsNotNone(fp)
            ctx = ssl._create_unverified_context()
            url = f"https://127.0.0.1:{host.port}/health"
            with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
                resp = json.loads(r.read().decode())
                self.assertEqual(resp["server"], "llmac")
            # Fingerprint of the live connection must match the file:
            import socket as _s, hashlib
            with _s.create_connection(("127.0.0.1", host.port),
                                       timeout=10) as sock:
                with ctx.wrap_socket(sock,
                                     server_hostname="127.0.0.1") as ts:
                    der = ts.getpeercert(binary_form=True)
            live = "SHA256:" + hashlib.sha256(der).hexdigest()
            self.assertEqual(live, fp)
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main()
