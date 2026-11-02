#!/usr/bin/env python3
"""
LLMAC v2 — Host entry point.

Run the PyQt6 GUI (default) or a headless server:

  python host.py                                   # GUI
  python host.py --dir /path/to/share              # GUI with pre-set roots
  python host.py --headless --dir /a --dir /b      # headless
  python host.py --headless --expose               # bind 0.0.0.0 (careful!)
  python host.py --headless --allow-exec           # enable raw exec
  python host.py --headless --policy destructive   # approval policy

See README.md for the security model.
"""
from __future__ import annotations

import argparse
import os
import sys

from core.constants import (
    DEFAULT_DATA_DIR, DEFAULT_HOST, DEFAULT_PORT,
)
from core.state import set_permissive_umask


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LLMAC v2 host")
    p.add_argument("--dir", action="append", default=[],
                   help="Directory to share (repeatable).")
    p.add_argument("--host", default=None,
                   help=f"Bind address (default {DEFAULT_HOST}).")
    p.add_argument("--port", type=int, default=None,
                   help=f"Port (default {DEFAULT_PORT}).")
    p.add_argument("--key", default=None,
                   help="Set the default agent's key (override persisted).")
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                   help=f"Data directory (default: {DEFAULT_DATA_DIR}).")
    p.add_argument("--headless", action="store_true",
                   help="Run without GUI (no PyQt6 needed).")
    p.add_argument("--expose", action="store_true",
                   help="Bind to 0.0.0.0 (all interfaces). WARNING: exposes "
                        "the server to your network — prefer localhost + a "
                        "tunnel.")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable TLS (plaintext HTTP).")
    p.add_argument("--allow-exec", action="store_true", dest="allow_exec",
                   help="Enable raw shell exec (off by default).")
    p.add_argument("--policy", default=None,
                   choices=["auto", "destructive", "strict"],
                   help="Approval policy (headless default: auto; GUI "
                        "default: destructive).")
    return p


def main() -> int:
    set_permissive_umask()
    args = build_parser().parse_args()

    if args.headless:
        from core.server import run_headless
        return run_headless(
            roots=[os.path.abspath(d) for d in args.dir if os.path.isdir(d)],
            key=args.key or "",
            host=args.host,
            port=args.port,
            data_dir=args.data_dir,
            expose=args.expose,
            allow_exec=args.allow_exec,
            policy=args.policy,
            tls=(not args.no_tls),
        )

    # GUI mode — lazily import gui.py (which imports PyQt6).
    try:
        import gui
    except ImportError as e:
        print(f"ERROR: PyQt6 GUI not available ({e}).", file=sys.stderr)
        print("Install with:  pip install PyQt6", file=sys.stderr)
        print("Or run headless:  python host.py --headless --dir /path",
              file=sys.stderr)
        print("\nFalling back to headless mode.\n", file=sys.stderr)
        from core.server import run_headless
        roots = [os.path.abspath(d) for d in args.dir if os.path.isdir(d)]
        if not roots:
            from core.state import StateStore
            persisted = StateStore(args.data_dir).load()
            roots = [os.path.abspath(d) for d in (persisted.get("roots") or [])
                     if os.path.isdir(d)]
        if not roots:
            print("ERROR: no --dir given and no persisted state.",
                  file=sys.stderr)
            return 2
        return run_headless(roots=roots, key=args.key or "", host=args.host,
                            port=args.port, data_dir=args.data_dir,
                            expose=args.expose, allow_exec=args.allow_exec,
                            policy=args.policy, tls=(not args.no_tls))

    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    # v2.2 theme: Fusion + dark palette + QSS with drawn affordances
    # (the chevron/tick glyphs live under <data_dir>/assets).
    gui.apply_theme(app, args.data_dir)
    window = gui.HostWindow(
        data_dir=args.data_dir,
        cli_overrides={
            k: v for k, v in {
                "roots": [os.path.abspath(d) for d in args.dir
                          if os.path.isdir(d)],
                "key": args.key,
                "host": args.host,
                "port": args.port,
                "expose": args.expose,
                "allow_exec": args.allow_exec,
                "policy": args.policy,
                "tls": (False if args.no_tls else None),
            }.items() if v
        } or None,
        app=app,
    )
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
