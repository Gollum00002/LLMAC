"""Surgical edit primitives: apply small structured ops to text files.

An edit request carries a list of ops applied sequentially; if any op
fails the file is left untouched (all-or-nothing). The result includes a
unified diff of what changed so the agent (and the human, via the log)
sees exactly what happened without re-reading the file.
"""
from __future__ import annotations

import difflib
import re
from typing import List, Optional


class EditError(Exception):
    """Raised when an edit op cannot be applied. Message is agent-facing."""


def _split_lines_keepends(text: str) -> List[str]:
    # splitlines(keepends=True) loses info on some exotic line endings
    # (e.g. \x0b, \x0c are treated as line breaks). Use str.splitlines(True)
    # but re-join carefully: we only support \n / \r\n which covers 99.9%.
    return text.splitlines(keepends=True)


def _normalize_nl(text: str) -> str:
    return text.replace("\r\n", "\n")


def apply_ops(text: str, ops: list) -> tuple:
    """Apply edit ops. Returns (new_text, total_changes).

    Ops (each a dict with "op" key):
      replace:   {find, replace, occurrence?: "first"|"all"|<int>, regex?: bool}
      lines:     {start, end, content}     1-based inclusive line range
      insert:    {content, before_line? | after_line?}  (default: top)
      append:    {content}                 at end of file
      delete_lines: {start, end}
    """
    if not ops:
        raise EditError("No ops supplied.")
    nl_text = _normalize_nl(text)
    # Work in lines; rejoin without endings, then handle final newline.
    lines = nl_text.split("\n")
    trailing_newline = nl_text.endswith("\n")
    if trailing_newline:
        lines = lines[:-1]  # last element is "" artifact

    changes = 0
    for i, op in enumerate(ops):
        kind = op.get("op")
        try:
            if kind == "replace":
                n, lines = _op_replace(lines, op)
            elif kind == "lines":
                n, lines = _op_lines(lines, op)
            elif kind == "insert":
                n, lines = _op_insert(lines, op)
            elif kind == "append":
                n, lines = _op_append(lines, op)
            elif kind == "delete_lines":
                n, lines = _op_delete_lines(lines, op)
            else:
                raise EditError(f"Unknown edit op {kind!r} (op #{i + 1}).")
        except EditError as e:
            raise EditError(f"[op #{i + 1}] {e}") from None
        changes += n

    if changes == 0:
        raise EditError(
            "Edit produced no changes (pattern not found / range empty).")

    new_text = "\n".join(lines)
    if trailing_newline or new_text:
        if trailing_newline:
            new_text += "\n"
    return new_text, changes


def _content_lines(content: str) -> List[str]:
    parts = _normalize_nl(content).split("\n")
    # Drop the trailing-"" artifact of a final newline: apply_ops re-adds
    # the final newline itself. Without this, insert/append/lines ops
    # added a stray blank line for every content string ending in \n (F11).
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def _validate_range(lines: List[str], start, end, opname: str):
    try:
        s, e = int(start), int(end)
    except (TypeError, ValueError):
        raise EditError(f"{opname}: start/end must be integers.") from None
    n = len(lines)
    if s < 1 or e < s or s > n:
        raise EditError(
            f"{opname}: line range {s}-{e} invalid for a {n}-line file "
            f"(1-based, start >= 1, end >= start).")
    return s, min(e, n)


def _op_replace(lines: List[str], op: dict) -> tuple:
    find = op.get("find", "")
    replace = op.get("replace", "")
    if not find:
        raise EditError("replace: 'find' must be a non-empty string.")
    if not op.get("regex") and find == replace:
        raise EditError("replace: 'find' and 'replace' are identical — "
                        "this would be a no-op.")
    occurrence = op.get("occurrence", "first")
    regex = bool(op.get("regex", False))

    joined = "\n".join(lines)
    if regex:
        try:
            rx = re.compile(find, re.MULTILINE)
        except re.error as e:
            raise EditError(f"replace: invalid regex: {e}") from None
        if occurrence == "all":
            new, n = rx.subn(replace, joined)
        else:
            idx = 1 if occurrence == "first" else _as_int(occurrence, "occurrence")
            matches = list(rx.finditer(joined))
            if len(matches) < idx:
                raise EditError(
                    f"replace: regex matched {len(matches)} time(s), "
                    f"occurrence {idx} requested.")
            m = matches[idx - 1]
            new = joined[:m.start()] + m.expand(replace) + joined[m.end():]
            n = 1
    else:
        if occurrence == "all":
            n = joined.count(find)
            new = joined.replace(find, replace)
        else:
            idx = 1 if occurrence == "first" else _as_int(occurrence, "occurrence")
            pos = -1
            for _ in range(idx):
                pos = joined.find(find, pos + 1)
                if pos < 0:
                    raise EditError(
                        f"replace: {find!r} occurs fewer than "
                        f"{idx} time(s) in the file.")
            new = joined[:pos] + replace + joined[pos + len(find):]
            n = 1
    return n, new.split("\n")


def _as_int(value, field: str) -> int:
    try:
        v = int(value)
        if v < 1:
            raise ValueError
        return v
    except (TypeError, ValueError):
        raise EditError(
            f"{field} must be 'first', 'all', or a positive integer.") from None


def _op_lines(lines: List[str], op: dict) -> tuple:
    s, e = _validate_range(lines, op.get("start"), op.get("end"), "lines")
    content = _content_lines(op.get("content", ""))
    new = lines[: s - 1] + content + lines[e:]
    return (e - s + 1), new


def _op_insert(lines: List[str], op: dict) -> tuple:
    content = _content_lines(op.get("content", ""))
    before = op.get("before_line")
    after = op.get("after_line")
    if before is None and after is None:
        at = 1
    elif before is not None:
        at = _as_int(before, "before_line")
    else:
        at = _as_int(after, "after_line") + 1
    if at < 1 or at > len(lines) + 1:
        raise EditError(
            f"insert: position {at} invalid for a {len(lines)}-line file.")
    new = lines[: at - 1] + content + lines[at - 1:]
    return len(content), new


def _op_append(lines: List[str], op: dict) -> tuple:
    content = _content_lines(op.get("content", ""))
    return len(content), lines + content


def _op_delete_lines(lines: List[str], op: dict) -> tuple:
    s, e = _validate_range(lines, op.get("start"), op.get("end"), "delete_lines")
    return (e - s + 1), lines[: s - 1] + lines[e:]


def unified_diff(before: str, after: str, path: str = "",
                 context: int = 2) -> str:
    """Unified diff of the change, trimmed to a sane size."""
    diff = difflib.unified_diff(
        _normalize_nl(before).splitlines(keepends=True),
        _normalize_nl(after).splitlines(keepends=True),
        fromfile=f"a/{path or 'file'}",
        tofile=f"b/{path or 'file'}",
        n=context,
    )
    text = "".join(diff)
    if not text.endswith("\n"):
        text += "\n"
    if len(text) > 32 * 1024:
        # Keep head + tail so the agent sees what changed without blowing
        # its context window.
        head = text[:20 * 1024].rsplit("\n", 1)[0] + "\n"
        tail = "\n" + text[-10 * 1024:]
        text = head + "...[diff truncated]...\n" + tail
    return text


def apply_edits_atomic(read_text: str, ops: list):
    """Validate ops against read_text without writing.

    Returns (new_text, changes, diff). Raises EditError on any failure.
    """
    new_text, changes = apply_ops(read_text, ops)
    return new_text, changes, unified_diff(read_text, new_text)
