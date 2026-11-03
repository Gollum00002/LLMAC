"""Search / tree: context-cheap codebase navigation for agents.

* content search — literal or regex, across text files under a root,
  capped results, optional context lines
* name search — glob patterns against basenames and relative paths
* tree — depth/entry-capped listing with sensible ignores

Ignores: a built-in set (node_modules, .venv, .git, __pycache__, ...) plus
the first .gitignore files encountered while walking (a pragmatic subset:
comments, blanks, negations and anchored rules are skipped or handled
simply).
"""
from __future__ import annotations

import fnmatch
import os
import re
from typing import List, Optional

from .constants import (
    DEFAULT_IGNORES, MAX_SEARCH_FILES, MAX_SEARCH_RESULTS, MAX_TREE_ENTRIES,
)

_MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024   # skip files larger than this for grep
_MAX_GITIGNORE_LINES = 200


def _prune_protected(dir_path: str, dirs: list, protected: list) -> list:
    """Drop directory entries that live inside a protected tree (e.g. the
    server's own data dir). Walk paths are built from a resolved base, so a
    lexical prefix match is sufficient (symlinks are never descended)."""
    if not protected:
        return dirs
    out = []
    for d in dirs:
        full = os.path.join(dir_path, d)
        if any(full == p or full.startswith(p + os.sep) for p in protected):
            continue
        out.append(d)
    return out


def _gitignore_patterns(dir_path: str) -> list:
    """Return fnmatch patterns from .gitignore in dir_path (best-effort)."""
    gi = os.path.join(dir_path, ".gitignore")
    try:
        with open(gi, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    pats = []
    for line in lines[:_MAX_GITIGNORE_LINES]:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.startswith("/") or ".." in line:
            continue  # anchored/negated rules: skip (pragmatic subset)
        pats.append(line.rstrip("/"))
    return pats


def _ignored(name: str, gitignore_pats: list, include_hidden: bool) -> bool:
    if name in DEFAULT_IGNORES:
        return True
    if not include_hidden and name.startswith("."):
        return True
    for pat in gitignore_pats:
        if fnmatch.fnmatch(name, pat):
            return True
    return False


def _walk(root: str, include_hidden: bool = False,
          use_gitignore: bool = True, max_files: int = MAX_SEARCH_FILES,
          protected: list = ()):
    """Yield (dirpath, dirs, files) top-down with pruning. Stops silently
    when max_files is exhausted (sets a flag the caller can read).
    ``protected`` trees are never entered (server data dir).
    v2.4.9: a single-FILE root yields one synthetic entry (the Task 29
    live finding) — content_search and name_search on --path <FILE>
    now scan that one file instead of dying at the API layer."""
    files_seen = 0
    if os.path.isfile(root):
        yield (os.path.dirname(root) or ".", [],
               [os.path.basename(root)], False)
        return
    stack = [root]
    while stack:
        dir_path = stack.pop()
        try:
            entries = os.scandir(dir_path)
        except OSError:
            continue
        gi = _gitignore_patterns(dir_path) if use_gitignore else []
        dirs, files = [], []
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    dirs.append(e.name)
                else:
                    files.append(e.name)
            except OSError:
                continue
        entries.close()
        dirs = sorted(d for d in dirs
                      if not _ignored(d, gi, include_hidden))
        dirs = _prune_protected(dir_path, dirs, list(protected))
        files = sorted(f for f in files
                       if not _ignored(f, gi, include_hidden))
        files_seen += len(files)
        yield dir_path, dirs, files, (files_seen >= max_files)
        if files_seen >= max_files:
            return
        for d in reversed(dirs):
            stack.append(os.path.join(dir_path, d))


def content_search(root: str, query: str, regex: bool = False,
                   glob: Optional[str] = None, max_results: int = 50,
                   context: int = 0, include_hidden: bool = False,
                   protected: list = ()) -> dict:
    """grep-like search. Returns {matches, files_scanned, truncated}."""
    max_results = max(1, min(int(max_results), MAX_SEARCH_RESULTS))
    context = max(0, min(int(context), 3))
    if regex:
        try:
            rx = re.compile(query)
        except re.error as e:
            return {"error": f"invalid_regex: {e}"}
    matches: List[dict] = []
    files_scanned = 0
    truncated = False
    if not query:
        return {"error": "missing query"}

    for dir_path, _dirs, files, over in _walk(root, include_hidden,
                                             protected=protected):
        if over:
            truncated = True
            break
        for name in files:
            if glob and not fnmatch.fnmatch(name, glob):
                continue
            path = os.path.join(dir_path, name)
            try:
                if os.path.getsize(path) > _MAX_TEXT_FILE_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="strict") as f:
                    lines = f.readlines()
            except (OSError, UnicodeDecodeError):
                continue
            files_scanned += 1
            for i, line in enumerate(lines, start=1):
                hit = (rx.search(line) if regex else (query in line))
                if not hit:
                    continue
                entry = {
                    "path": path,
                    "line": i,
                    "text": line.rstrip("\r\n")[:400],
                }
                if context:
                    lo = max(0, i - 1 - context)
                    hi = min(len(lines), i - 1 + context + 1)
                    entry["context"] = [
                        {"line": lo + k + 1,
                         "text": lines[lo + k].rstrip("\r\n")[:400]}
                        for k in range(hi - lo)
                    ]
                matches.append(entry)
                if len(matches) >= max_results:
                    truncated = True
                    return {
                        "matches": matches, "files_scanned": files_scanned,
                        "truncated": truncated,
                    }
    return {"matches": matches, "files_scanned": files_scanned,
            "truncated": truncated}


def name_search(root: str, pattern: str, max_results: int = 100,
                include_hidden: bool = False,
                protected: list = ()) -> dict:
    """Glob against basenames and relative paths."""
    max_results = max(1, min(int(max_results), MAX_SEARCH_RESULTS))
    if not pattern:
        return {"error": "missing pattern"}
    rx = None
    # Treat / in pattern as part of relpath match
    hits: List[dict] = []
    files_scanned = 0
    truncated = False
    for dir_path, _dirs, files, over in _walk(root, include_hidden,
                                             protected=protected):
        if over:
            truncated = True
            break
        for name in files:
            rel = os.path.relpath(os.path.join(dir_path, name), root)
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern):
                path = os.path.join(dir_path, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = None
                hits.append({"path": path, "rel": rel, "size": size})
                if len(hits) >= max_results:
                    truncated = True
                    return {"matches": hits, "files_scanned": files_scanned,
                            "truncated": truncated}
        files_scanned += len(files)
    return {"matches": hits, "files_scanned": files_scanned,
            "truncated": truncated}


def tree(root: str, depth: int = 3, max_entries: int = 400,
         include_hidden: bool = False, protected: list = ()) -> dict:
    """Flat, depth-capped listing: [{path, name, depth, type, size}]."""
    depth = max(0, min(int(depth), 8))
    max_entries = max(1, min(int(max_entries), MAX_TREE_ENTRIES))
    entries: List[dict] = []
    truncated = False
    prot = list(protected)

    def walk_dir(dir_path: str, cur_depth: int):
        nonlocal truncated
        if truncated:
            return
        if cur_depth > depth:
            return
        gi = _gitignore_patterns(dir_path)
        try:
            it = os.scandir(dir_path)
        except OSError:
            return
        with it:
            items = sorted(it, key=lambda e: (not e.is_dir(), e.name.lower()))
        items = [e for e in items
                 if not any(
                     os.path.join(dir_path, e.name) == p
                     or os.path.join(dir_path, e.name).startswith(p + os.sep)
                     for p in prot)]
        for e in items:
            if truncated:
                return
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if _ignored(e.name, gi, include_hidden):
                continue
            entries.append({
                "path": e.path,
                "name": e.name,
                "depth": cur_depth,
                "type": "dir" if is_dir else "file",
                "size": None if is_dir else _safe_size(e.path),
            })
            if len(entries) >= max_entries:
                truncated = True
                return
            if is_dir:
                walk_dir(e.path, cur_depth + 1)

    walk_dir(root, 1)
    return {"entries": entries, "truncated": truncated,
            "root": root}


def _safe_size(path: str):
    try:
        return os.path.getsize(path)
    except OSError:
        return None
