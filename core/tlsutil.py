"""TLS utilities: self-signed cert generation + fingerprinting (TOFU).

The host generates a 10-year self-signed RSA cert on first run (via the
``openssl`` CLI, which is present on virtually all Linux/macOS systems and
most Windows dev boxes via Git for Windows). The certificate fingerprint is
displayed in the GUI and included in the agent connection prompt; the CLI
pins it on first use (trust-on-first-use, SSH-style) and verifies it on
every subsequent connection.

If ``openssl`` is unavailable, TLS is disabled with a warning and the host
must bind to localhost (or sit behind a tunnel).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from typing import Optional, Tuple

CERT_DIRNAME = "tls"
CERT_NAME = "server.crt"
KEY_NAME = "server.key"
CERT_DAYS = 3650  # 10 years


def tls_paths(data_dir: str) -> Tuple[str, str]:
    d = os.path.join(os.path.abspath(data_dir), CERT_DIRNAME)
    return os.path.join(d, CERT_NAME), os.path.join(d, KEY_NAME)


def cert_fingerprint(cert_path: str) -> Optional[str]:
    """SHA-256 fingerprint of the DER certificate, SSH-style."""
    try:
        with open(cert_path, "rb") as f:
            pem = f.read()
    except OSError:
        return None
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    i = pem.find(begin)
    j = pem.find(end)
    if i < 0 or j < 0:
        return None
    import base64
    b64 = pem[i + len(begin):j]
    try:
        der = base64.b64decode(b"".join(b64.split()))
    except Exception:
        return None
    return "SHA256:" + hashlib.sha256(der).hexdigest()


def openssl_available() -> bool:
    try:
        p = subprocess.run(["openssl", "version"], capture_output=True,
                           timeout=10)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_cert(data_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Generate the self-signed cert if missing. Returns (cert, key) paths
    on success, or (None, None) if TLS cannot be provisioned."""
    cert_path, key_path = tls_paths(data_dir)
    cert_dir = os.path.dirname(cert_path)
    os.makedirs(cert_dir, exist_ok=True)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        # Sanity: fingerprint computable
        if cert_fingerprint(cert_path):
            return cert_path, key_path
        # Corrupt cert — regenerate below.
        pass

    # Subject/SAN: machine hostname + localhost + local IPs.
    hostname = os.uname().nodename if hasattr(os, "uname") else "llmac-host"
    san = (f"DNS:localhost,DNS:{hostname}"
           f",IP:127.0.0.1,IP:0.0.0.0,IP:10.0.0.1,IP:192.168.0.1")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path,
        "-out", cert_path,
        "-days", str(CERT_DAYS),
        "-subj", "/CN=LLMAC self-signed",
        "-addext", f"subjectAltName={san}",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=60)
        if p.returncode != 0:
            return None, None
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    if os.name == "posix":
        for path in (key_path, cert_path):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    if not cert_fingerprint(cert_path):
        return None, None
    return cert_path, key_path
