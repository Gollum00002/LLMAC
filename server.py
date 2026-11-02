#!/usr/bin/env python3
"""Backward-compat shim: `python server.py` == `python host.py --headless`.

v2 keeps this entry because run.sh / muscle memory may reference it.
All logic lives in the `core` package.
"""
from __future__ import annotations

import sys

from host import build_parser
from core.constants import DEFAULT_DATA_DIR
from core.server import run_headless
from core.state import set_permissive_umask


def main() -> int:
    set_permissive_umask()
    args = build_parser().parse_args()
    return run_headless(
        roots=[__import__("os").path.abspath(d)
               for d in args.dir if __import__("os").path.isdir(d)],
        key=args.key or "",
        host=args.host,
        port=args.port,
        data_dir=args.data_dir,
        expose=args.expose,
        allow_exec=args.allow_exec,
        policy=args.policy,
        tls=(not args.no_tls),
    )


if __name__ == "__main__":
    raise SystemExit(main())
