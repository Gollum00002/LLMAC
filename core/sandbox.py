"""Sandbox v2: path containment + exec command checking.

Security model changes vs v1:

* ``resolve()`` now requires BOTH the lexical path and the fully-resolved
  (realpath) path to be inside a shared root. This defeats symlinks placed
  inside a root that point outside it, and ``..`` traversal.
* ``~`` (home) references are rejected outright in file operations and exec.
* ``check_exec_command`` is token-based (shlex) instead of a regex over the
  raw string, simulates ``cd`` so relative-path escapes are caught, checks
  redirect targets (``>``, ``>>``, ``<``, ``&>``), and rejects shell variable
  expansion / command substitution / process substitution tokens.

This is still a *static* analysis — it cannot see through ``python -c "...``
payloads or files written earlier that run later. Raw exec remains an
explicit opt-in (settings.allow_exec) and the docs recommend running the
host under a dedicated user account for strong isolation. The checks below
make accidental and most naive bypasses fail closed.
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Optional

from .constants import (
    EXEC_ALLOWED_OUTSIDE, EXEC_TOKEN_DENYLIST, EXEC_WRITE_ALLOWED_OUTSIDE,
)
# v2.4.5: the sudo package-install SHAPE is defined once in policy.py
# (which forces the approval) and shared here so the sandbox layer can
# let exactly that form through to it. policy.py has no imports of
# sandbox, so this is acyclic.
from .policy import _SUDO_FIRST_RE, _SUDO_PKG_RE

# Variable-like expansion: $VAR, ${..}, $(..), $[
_VAR_RE = re.compile(r"\$[A-Za-z_{(\[]")
# Windows drive-letter path
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_REDIRECT_TOKENS = {
    ">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>", ">|", "2>&1", "1>&2",
}
_INPUT_REDIRECT = "<"
_CD_TOKENS = {"cd", "pushd"}


class ProtectedPathError(PermissionError):
    """Raised when a path resolves inside the server's own data directory.

    That tree holds host secrets (agent keys, the TLS private key, the audit
    log) and is off-limits to every agent operation, read or write, no
    matter which approval policy is active."""


class Sandbox:
    """Wraps the list of shared root directories and enforces path safety.

    ``protected`` is a list of absolute host paths (typically the server's
    own data directory) that agents may never touch — even though they sit
    inside a shared root. Enforced for file ops, search/tree walkers and
    exec path tokens alike."""

    def __init__(self, roots: list, protected: list | None = None):
        self.roots = [os.path.realpath(os.path.abspath(r)) for r in roots]
        self.protected = [os.path.realpath(os.path.abspath(p))
                          for p in (protected or [])]

    # ------------------------------------------------------------------
    # Path containment for file operations
    # ------------------------------------------------------------------

    def is_protected(self, target: str) -> bool:
        """True if the path lives inside a protected tree (realpath check)."""
        if not self.protected or not target:
            return False
        real = os.path.realpath(os.path.abspath(target))
        for pr in self.protected:
            if real == pr or real.startswith(pr + os.sep):
                return True
        return False

    def is_path_allowed(self, target: str) -> bool:
        if not target:
            return False
        if target.startswith("~"):
            return False
        abs_target = os.path.abspath(target)
        # The server's own data dir is off-limits even when it sits inside
        # a shared root (it holds host secrets: keys, TLS key, audit log).
        if self.is_protected(abs_target):
            return False
        # BOTH the lexically-normalized path AND its fully-resolved path
        # (symlinks followed) must live inside the SAME root. Either
        # escaping (symlink inside root pointing out; path outside pointing
        # in) is a reject.
        real_target = os.path.realpath(abs_target)

        def inside(p: str, root: str) -> bool:
            return (p == root or p.startswith(root + os.sep)
                    or (os.path.altsep and p.startswith(root + os.path.altsep)))

        for root in self.roots:
            if inside(abs_target, root) and inside(real_target, root):
                return True
        return False

    def resolve(self, target: str) -> str:
        """Return the absolute real path or raise PermissionError."""
        if target.startswith("~"):
            raise PermissionError(
                "'~' paths are not allowed. Use absolute paths inside the "
                "shared directories.")
        if self.is_protected(target):
            raise ProtectedPathError(
                "The server's own data directory is off-limits: it holds the "
                "host's secrets (agent keys, TLS key, audit log) and is "
                "never accessible to agents.")
        if not self.is_path_allowed(target):
            raise PermissionError(
                f"Path '{target}' is outside the shared directories.")
        return os.path.realpath(os.path.abspath(target))

    def roots_for(self, agent_roots: list) -> list:
        """Intersect this sandbox's roots with an agent's root scope.

        Empty agent_roots means "all roots". Agent-root entries may be
        subdirectories of shared roots (scoping to a subtree) — in that case
        the deepest shared root containing them is used, further restricted
        to the agent's own path.
        """
        if not agent_roots:
            return list(self.roots)
        out = []
        for r in agent_roots:
            r_real = os.path.realpath(os.path.abspath(r))
            for root in self.roots:
                if r_real == root or r_real.startswith(root + os.sep):
                    out.append(r_real)
                    break
        return out

    # ------------------------------------------------------------------
    # Exec command checking
    # ------------------------------------------------------------------

    def check_exec_command(self, command: str, cwd: str) -> Optional[str]:
        """Return an error message if the command is not allowed, else None.

        Tokenizes with shlex (quotes stripped), simulates ``cd`` so later
        relative paths are checked against the *runtime* working directory,
        validates redirect targets, and rejects variables/substitution.
        """
        # Raw substring bans that survive tokenization ambiguities:
        for substr in ("$(", "`", "<(", ">${", "${"):
            if substr in command:
                return (f"EXEC REJECTED: shell expansion/substitution "
                        f"({substr!r}) is not allowed in exec commands.")

        posix_mode = os.name != "nt"
        try:
            tokens = shlex.split(command, posix=posix_mode)
        except ValueError as e:
            return f"EXEC REJECTED: command does not tokenize cleanly ({e})."
        if not posix_mode:
            # shlex(posix=False) keeps quotes in tokens — strip them.
            tokens = [t.strip('"\'') for t in tokens]

        # Privilege escalators: banned at exact-token granularity, anywhere
        # in the stream. With NOPASSWD sudo on the host, 'sudo reboot' is a
        # real reboot; there is no legitimate agent use for these.
        # v2.4.5 exception: the single-command DISTRO PACKAGE INSTALL
        # (`sudo pacman -S x` and siblings) passes THROUGH this layer so
        # the policy layer can attach the forced host approval with the
        # 2-minute countdown. The exact allowed shape is shared with
        # policy.py (same regexes — they cannot drift), and every other
        # sudo/su/doas/pkexec form still dies right here. Policy NEVER
        # silently allows a sudo command: marker (forced approval) or
        # rejection, so this exception cannot become a bypass.
        normalized = " ".join(command.split())
        sudo_pkg_form = bool(
            _SUDO_FIRST_RE.match(normalized)
            and _SUDO_PKG_RE.fullmatch(normalized))
        for t in tokens:
            if t in EXEC_TOKEN_DENYLIST:
                if sudo_pkg_form and t == "sudo":
                    continue
                return ("EXEC REJECTED: privilege-escalation commands are "
                        f"not allowed ({t!r} found in the command). If the "
                        "task genuinely needs root, ask the host to run it "
                        "themselves.")

        vcwd = os.path.realpath(cwd)
        i = 0
        n = len(tokens)
        while i < n:
            tok = tokens[i]

            # Redirect targets: the token AFTER a redirect operator is a
            # file that will be WRITTEN — it must be INSIDE the sandbox.
            # Writes never use the system read whitelist; only /dev/null,
            # /dev/stdout, /dev/stderr, /dev/full are exempt.
            if tok in _REDIRECT_TOKENS or (
                    re.fullmatch(r"[0-3]>>?", tok) and tok not in ("2>&1", "1>&2")):
                if i + 1 >= n:
                    return "EXEC REJECTED: redirect operator with no target."
                err = self._check_path_token(tokens[i + 1], vcwd,
                                             "redirect target",
                                             writable=True)
                if err:
                    return err
                i += 2
                continue
            if tok == _INPUT_REDIRECT:
                if i + 1 >= n:
                    return "EXEC REJECTED: '<' with no target."
                err = self._check_path_token(tokens[i + 1], vcwd, "input redirect")
                if err:
                    return err
                i += 2
                continue

            # Variable-like expansion anywhere in a token.
            if _VAR_RE.search(tok):
                return ("EXEC REJECTED: shell variables ($VAR, ${...}) are not "
                        "allowed. Spell out absolute paths inside the shared "
                        "directories.")

            # Any token beginning with '~' (bare or path) is a home
            # reference — opaque to static analysis, always reject.
            if tok.startswith("~"):
                return ("EXEC REJECTED: '~' paths are not allowed. Use "
                        "absolute paths inside the shared directories.")

            # `cd` / `pushd` change the effective working directory —
            # simulate so subsequent relative paths are checked correctly.
            if tok in _CD_TOKENS and i + 1 < n and tokens[i + 1] != "--":
                target = tokens[i + 1]
                if target.startswith("~"):
                    return ("EXEC REJECTED: 'cd ~' escapes the shared "
                            "directories. Stay inside them.")
                new_cwd = os.path.realpath(
                    os.path.normpath(os.path.join(vcwd, target)))
                if not self._path_ok(new_cwd):
                    return (f"EXEC REJECTED: 'cd {target}' leaves the shared "
                            f"directories.")
                vcwd = new_cwd
                i += 2
                continue

            # Path-like tokens: anything with a separator or a drive letter.
            if "/" in tok or "\\" in tok or _WIN_PATH_RE.match(tok):
                err = self._check_path_token(tok, vcwd, "path")
                if err:
                    return err
            i += 1
        return None

    def _path_ok(self, path: str, writable: bool = False) -> bool:
        """Inside a root OR in the static system whitelist (reads only).

        With ``writable`` True (redirect write targets) the whitelist
        shrinks to EXEC_WRITE_ALLOWED_OUTSIDE — /tmp & friends must never
        be writable drop targets."""
        path = path.rstrip("/\\") or "/"
        if path == "/":
            return False
        if self.is_protected(path):
            return False
        if self.is_path_allowed(path):
            return True
        if writable:
            return path in EXEC_WRITE_ALLOWED_OUTSIDE
        for allowed in EXEC_ALLOWED_OUTSIDE:
            if path == allowed or path.startswith(allowed + "/"):
                return True
        return False

    def _check_path_token(self, tok: str, vcwd: str, what: str,
                          writable: bool = False) -> Optional[str]:
        if not tok:
            return None
        if tok.startswith("~"):
            return ("EXEC REJECTED: '~' paths are not allowed "
                    f"({what}: {tok}).")
        if os.path.isabs(tok) or _WIN_PATH_RE.match(tok):
            resolved = os.path.realpath(os.path.normpath(tok))
        else:
            resolved = os.path.realpath(os.path.normpath(os.path.join(vcwd, tok)))
        if self.is_protected(resolved):
            return (f"EXEC REJECTED: {what} '{tok}' is inside the server's "
                    "own data directory — that tree is off-limits to agents.")
        if not self._path_ok(resolved, writable=writable):
            if writable:
                return (f"EXEC REJECTED: {what} '{tok}' is outside the "
                        "shared directories. Redirect targets must stay "
                        "inside the sandbox (only /dev/null, /dev/stdout "
                        "and /dev/stderr are exempt).")
            return (f"EXEC REJECTED: {what} '{tok}' resolves outside the "
                    f"shared directories. Add it to the shared roots in the "
                    f"GUI if you need it.")
        return None
