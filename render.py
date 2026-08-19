"""Markdown generation, and the rule that never destroys a writeup."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any

from client import Challenge, same_origin

SOLUTION_HEADING = "## Solution"
SOLUTION_PLACEHOLDER = "<!-- writeup goes here -->"

# Horizontal whitespace only: \s would swallow the trailing newline and shift the
# preserved writeup by a line on every run.
_SOLUTION_RE = re.compile(r"^##[ \t]+Solution[ \t]*$", re.MULTILINE)
# Anything that could change meaning as a bare YAML scalar gets quoted.
_UNSAFE_YAML = re.compile(r"^[\s>|&*!%@`#\-?{}\[\],]|[:#\n\"']|\s$")
_YAML_KEYWORDS = frozenset({"true", "false", "null", "yes", "no", "on", "off", "~"})

# Inline markdown links only. A bare URL in prose is usually a service the
# challenge talks about ("browse to https://host:8088"), not a file to fetch.
# The <> form is markdown's way of spelling a destination containing spaces.
_ABS = r"https?://"
_MD_LINK = re.compile(rf"\[[^\]]*\]\(\s*(?:<\s*({_ABS}[^<>\n]+?)\s*>|({_ABS}[^\s<>()]+))\s*\)")


def slugify(text: str) -> str:
    # Decompose accents first so "Ünïcode" becomes "unicode" rather than "n-code".
    folded = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", folded.lower()).strip("-")
    return slug or "unnamed"


def description_links(description: str, base_url: str) -> list[str]:
    """Absolute links in a description that may be attachments hosted off-instance.

    Some organisers never populate CTFd's `files` array and paste object storage
    links into the markdown instead. Links back to the instance are excluded: those
    are navigation, and anything CTFd itself serves already appears in `files`.
    """
    found: list[str] = []
    for match in _MD_LINK.finditer(description):
        url = match.group(1) or match.group(2)
        if url not in found and not same_origin(url, base_url):
            found.append(url)
    return found


# YAML frontmatter


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    needs_quotes = (
        text == ""
        or text.lower() in _YAML_KEYWORDS
        or _is_numeric(text)
        or bool(_UNSAFE_YAML.search(text))
    )
    if needs_quotes:
        escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    return text


def _is_numeric(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def _yaml_list(values: list[str]) -> str:
    return "[" + ", ".join(_yaml_scalar(value) for value in values) + "]"


def challenge_url(base_url: str, challenge: Challenge) -> str:
    return f"{base_url.rstrip('/')}/challenges#{slugify(challenge.name)}-{challenge.id}"


def frontmatter(challenge: Challenge, base_url: str, file_names: list[str]) -> str:
    fields: list[tuple[str, str]] = [
        ("id", _yaml_scalar(challenge.id)),
        ("name", _yaml_scalar(challenge.name)),
        ("category", _yaml_scalar(challenge.category)),
        ("value", _yaml_scalar(challenge.value)),
        ("type", _yaml_scalar(challenge.type)),
        ("tags", _yaml_list(challenge.tags)),
        ("solved", _yaml_scalar(challenge.solved_by_me)),
        ("solves", _yaml_scalar(challenge.solves)),
        ("url", _yaml_scalar(challenge_url(base_url, challenge))),
    ]
    if challenge.connection_info:
        fields.append(("connection_info", _yaml_scalar(challenge.connection_info)))
    if challenge.attribution:
        fields.append(("attribution", _yaml_scalar(challenge.attribution)))
    if file_names:
        fields.append(("files", _yaml_list([f"files/{name}" for name in file_names])))

    body = "\n".join(f"{key}: {value}" for key, value in fields)
    return f"---\n{body}\n---\n"


# Documents


def render_challenge(challenge: Challenge, base_url: str, file_names: list[str]) -> str:
    """The generated part of a challenge README, up to and including the Solution heading."""
    parts = [frontmatter(challenge, base_url, file_names), f"\n# {challenge.name}\n"]

    description = challenge.description.strip()
    parts.append(f"\n## Description\n\n{description or '_No description._'}\n")

    if challenge.connection_info:
        parts.append(f"\n## Connection\n\n```\n{challenge.connection_info}\n```\n")

    if file_names:
        links = "\n".join(f"- [{name}](<files/{name}>)" for name in file_names)
        parts.append(f"\n## Files\n\n{links}\n")

    unlocked = [hint for hint in challenge.hints if hint.content]
    if unlocked:
        lines = "\n".join(
            f"- **{hint.title or f'Hint {hint.id}'}**: {hint.content}" for hint in unlocked
        )
        parts.append(f"\n## Hints\n\n{lines}\n")

    parts.append(f"\n{SOLUTION_HEADING}\n\n{SOLUTION_PLACEHOLDER}\n")
    return "".join(parts)


def render_index(ctf_name: str, base_url: str, entries: list[tuple[Challenge, str]]) -> str:
    """Top level README listing every challenge, grouped by category.

    `entries` pairs each challenge with its path relative to the output directory.
    """
    by_category: dict[str, list[tuple[Challenge, str]]] = {}
    for challenge, rel_path in entries:
        by_category.setdefault(challenge.category or "Uncategorized", []).append(
            (challenge, rel_path)
        )

    lines = [f"# {ctf_name}\n", f"\n<{base_url.rstrip('/')}>\n", "\n## Challenges\n"]
    for category in sorted(by_category, key=str.lower):
        lines.append(f"\n### {category}\n\n")
        for challenge, rel_path in sorted(by_category[category], key=lambda e: e[0].name.lower()):
            suffix = f" <em>({', '.join(challenge.tags)})</em>" if challenge.tags else ""
            lines.append(f"- [{challenge.name}](<{rel_path}/>) `{challenge.value}`{suffix}\n")
    return "".join(lines)


# Writing, without destroying the user's work


def merge_challenge(existing: str | None, generated: str) -> str | None:
    """Regenerate the metadata half of a README while keeping the writeup verbatim.

    Returns None when the file has been restructured such that the Solution heading
    is gone. Rewriting it would risk destroying prose, so it is left alone instead.
    """
    if existing is None:
        return generated

    match = _SOLUTION_RE.search(existing)
    if match is None:
        return None

    preserved = existing[match.end() :]
    if preserved.strip() in {"", SOLUTION_PLACEHOLDER}:
        return generated

    head, _, _ = generated.partition(SOLUTION_HEADING)
    merged = head + SOLUTION_HEADING + preserved
    return merged if merged != existing else existing


def write_challenge_readme(path: Path, generated: str) -> bool:
    """Write the README if it changed. Returns False when skipped or already current."""
    existing = read_verbatim(path) if path.exists() else None
    merged = merge_challenge(existing, generated)
    if merged is None or merged == existing:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    write_verbatim(path, merged)
    return True


# CTFd stores descriptions with CRLF, and a writeup may use any line ending. Python's
# default newline translation would rewrite CRLF as LF on the way in, which both loses
# the byte for byte promise above and makes every comparison against generated content
# fail, rewriting unchanged READMEs on every run.
def read_verbatim(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_verbatim(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(content)
