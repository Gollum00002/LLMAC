"""v2.6.0 (ASK-014) — transcript evidence helpers.

Qt-free by design: the Sessions-tab GUI uses these to search and
export the live-session thread, and the test suite imports them
directly on platforms without PyQt6. A rule-6 capture cites an
exported transcript as its durable evidence artifact, so the exports
carry a metadata preamble (agent, exported-at, time range, entry
count) and the FULL merged thread — the same ts-ordered notes +
user messages the tab renders, never just the visible window."""

import html
import re
from datetime import datetime

EXPORT_FILTERS = "Markdown (*.md);;Plain text (*.txt);;HTML (*.html)"

_SAN = re.compile(r"[^A-Za-z0-9._-]+")


def count_hits(text: str, term: str) -> int:
    """Case-insensitive, non-overlapping occurrence count. An empty
    term counts nothing; regex metacharacters in the term are literal
    (the search box is user text, not a pattern)."""
    if not term:
        return 0
    return len(re.findall(re.escape(term), text, re.IGNORECASE))


def _stamp(ts) -> str:
    return (ts or "")[11:19] or "--:--:--"


def _who(item: dict, agent: str) -> str:
    return "YOU" if item.get("kind") == "message" else agent


def _preamble(agent: str, items: list, generated_at: str) -> list:
    if items:
        first = items[0].get("ts") or "n/a"
        last = items[-1].get("ts") or "n/a"
        rng = f"{first} .. {last}"
    else:
        rng = "n/a"
    return [
        f"agent: {agent}",
        f"exported: {generated_at}",
        f"time range: {rng}",
        f"entries: {len(items)}",
    ]


def transcript_markdown(agent: str, items: list, generated_at: str) -> str:
    """The default durable artifact: metadata preamble + the full
    thread as markdown, one entry per block, YOU vs the agent."""
    out = [f"# LLMAC transcript — {agent}", ""]
    out += [f"- {kv}" for kv in _preamble(agent, items, generated_at)]
    out.append("")
    for it in items:
        out.append(f"**[{_stamp(it.get('ts'))}] {_who(it, agent)}:**")
        out.append((it.get("text") or "").rstrip())
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def transcript_plaintext(agent: str, items: list, generated_at: str) -> str:
    """Plain-text export: one line per entry, grep-friendly."""
    out = [f"LLMAC transcript — {agent}"]
    out += [f"  {kv}" for kv in _preamble(agent, items, generated_at)]
    out.append("")
    for it in items:
        out.append(
            f"[{_stamp(it.get('ts'))}] {_who(it, agent)}: "
            f"{(it.get('text') or '').rstrip()}")
    return "\n".join(out).rstrip() + "\n"


def transcript_html(agent: str, items: list, generated_at: str) -> str:
    """Standalone HTML export — the same sender colors as the live
    render; every text node is escaped."""
    esc = html.escape
    parts = [
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>LLMAC transcript — {esc(agent)}</title></head>"
        '<body style="font-family:sans-serif;max-width:80ch;'
        'margin:2em auto;">'
        f"<h2>LLMAC transcript — {esc(agent)}</h2><ul>"]
    parts += [f"<li>{esc(kv)}</li>"
              for kv in _preamble(agent, items, generated_at)]
    parts.append("</ul>")
    for it in items:
        who = _who(it, agent)
        color = "#6cb6ff" if who == "YOU" else "#4ade80"
        parts.append(
            '<div style="margin:0 0 10px 0;">'
            f'<span style="color:#768390;">[{esc(_stamp(it.get("ts")))}]</span> '
            f'<b style="color:{color};">{esc(who)}</b> '
            f'{esc((it.get("text") or "").rstrip())}</div>')
    parts.append("</body></html>")
    return "".join(parts)


def default_export_name(agent: str, ts=None) -> str:
    """transcript-<sanitized-agent>-<YYYYmmdd-HHMMSS>.md — safe on both
    platforms, sorts by export time."""
    safe = _SAN.sub("-", (agent or "").strip()).strip("-.") or "agent"
    when = (ts or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"transcript-{safe}-{when}.md"


def guess_format(path: str, filter_selected: str = "") -> str:
    """The export format from the chosen extension; the selected
    filter breaks ties when the path has none. Unknown -> markdown."""
    low = (path or "").lower()
    if low.endswith(".txt"):
        return "txt"
    if low.endswith(".html") or low.endswith(".htm"):
        return "html"
    if low.endswith(".md"):
        return "md"
    if "Plain text" in (filter_selected or ""):
        return "txt"
    if "HTML" in (filter_selected or ""):
        return "html"
    return "md"
