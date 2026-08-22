"""The dump workflow: fetch, diff against the manifest, download, render."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from client import (
    MAX_DOWNLOAD_BYTES,
    Challenge,
    CTFdClient,
    CTFdError,
    NotAnArtifact,
    TooLarge,
    file_sha256,
    safe_filename,
)
from render import (
    description_links,
    render_challenge,
    render_index,
    slugify,
    write_challenge_readme,
)

MANIFEST_VERSION = 1
LEGACY_STATE_DIR = ".ctfd-dumper"

# Only fields that reach the rendered README participate in the change hash. A
# shifting solve count or a re-signed file token must not mark everything dirty.
TRACKED_FIELDS = (
    "name",
    "category",
    "value",
    "type",
    "description",
    "connection_info",
    "attribution",
    "max_attempts",
)


@dataclass
class Settings:
    url: str
    name: str
    output: Path
    jobs: int = 4
    download_files: bool = True
    dry_run: bool = False
    force: bool = False


@dataclass
class Summary:
    changes: Counter[str] = field(default_factory=Counter)
    hidden: list[str] = field(default_factory=list)
    vanished: list[str] = field(default_factory=list)
    files_downloaded: int = 0
    files_skipped: int = 0
    files_too_large: list[str] = field(default_factory=list)
    readmes_written: int = 0
    readmes_preserved: int = 0
    errors: list[str] = field(default_factory=list)


# Manifest: what was dumped last time, and whether it still matches the server


@dataclass
class FileRecord:
    sha256: str
    size: int


@dataclass
class ChallengeRecord:
    name: str
    path: str
    detail_hash: str
    files: dict[str, FileRecord] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def manifest_path(settings: Settings) -> Path:
    """Per-CTF state in the user's local data directory, outside the dump."""
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "ctfd-dumper" / f"{slugify(settings.name) or 'ctf'}.json"


def load_manifest(settings: Settings) -> dict[int, ChallengeRecord]:
    """Read the previous run's records, treating an unreadable manifest as absent.

    Damage of any kind must degrade into a full redump, never into a crash that
    leaves the user unable to run the tool at all.
    """
    try:
        path = manifest_path(settings)
        legacy = settings.output / LEGACY_STATE_DIR / "manifest.json"
        source = path if path.exists() else legacy
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION:
            return {}
        return {
            int(cid): ChallengeRecord(
                name=entry.get("name", ""),
                path=entry.get("path", ""),
                detail_hash=entry.get("detail_hash", ""),
                files={
                    name: FileRecord(meta.get("sha256", ""), meta.get("size", 0))
                    for name, meta in (entry.get("files") or {}).items()
                },
                raw=entry.get("raw") if isinstance(entry.get("raw"), dict) else {},
            )
            for cid, entry in (data.get("challenges") or {}).items()
        }
    except (OSError, AttributeError, TypeError, ValueError):
        return {}


def save_manifest(settings: Settings, records: dict[int, ChallengeRecord]) -> None:
    path = manifest_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": MANIFEST_VERSION,
        "ctf": {"name": settings.name, "url": settings.url},
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "challenges": {
            str(cid): {
                "name": record.name,
                "path": record.path,
                "detail_hash": record.detail_hash,
                "files": {
                    name: {"sha256": file.sha256, "size": file.size}
                    for name, file in sorted(record.files.items())
                },
                "raw": record.raw,
            }
            for cid, record in sorted(records.items())
        },
    }
    # Written aside and moved into place, so an interrupted save cannot corrupt it.
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)

    # Older versions stored one JSON file per challenge. Once the combined
    # manifest is safely in place, remove that redundant legacy directory.
    legacy_state = settings.output / LEGACY_STATE_DIR
    if legacy_state.is_dir():
        shutil.rmtree(legacy_state)


def challenge_hash(challenge: Challenge) -> str:
    """Stable hash over the fields that affect rendered output, plus hints and tags."""
    payload: dict[str, Any] = {name: getattr(challenge, name, None) for name in TRACKED_FIELDS}
    payload["tags"] = sorted(challenge.tags)
    payload["hints"] = sorted(
        (hint.id, hint.cost, hint.title, hint.content) for hint in challenge.hints
    )
    canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# The run


@dataclass
class _Planned:
    challenge: Challenge
    raw: dict
    rel_path: str
    new_hash: str
    change: str


@dataclass
class _Result:
    """Per challenge outcome, aggregated on the main thread.

    Workers return counts instead of touching Summary so no locking is needed.
    """

    record: ChallengeRecord | None = None
    downloaded: int = 0
    skipped: int = 0
    too_large: list[str] = field(default_factory=list)
    readme_written: bool = False
    readme_preserved: bool = False
    errors: list[str] = field(default_factory=list)


def dump(settings: Settings, client: CTFdClient) -> Summary:
    summary = Summary()
    records = load_manifest(settings)

    challenges = client.list_challenges()
    visible = [c for c in challenges if not c.is_hidden]
    summary.hidden = [c.name for c in challenges if c.is_hidden]

    if not visible:
        print("No visible challenges returned by the instance.")
        return summary

    details, summary.errors = _fetch_details(client, visible, settings.jobs)
    planned = _plan(details, records)
    for item in planned:
        summary.changes[item.change] += 1

    seen = {item.challenge.id for item in planned}
    # Challenges recorded previously that the server no longer offers are reported,
    # never acted on: those directories hold the user's writeups.
    summary.vanished = [record.name for cid, record in sorted(records.items()) if cid not in seen]

    if settings.dry_run:
        return summary

    settings.output.mkdir(parents=True, exist_ok=True)
    results = _run_workers(planned, settings, client, records)

    for item, result in zip(planned, results, strict=True):
        summary.files_downloaded += result.downloaded
        summary.files_skipped += result.skipped
        summary.files_too_large.extend(result.too_large)
        summary.readmes_written += int(result.readme_written)
        summary.readmes_preserved += int(result.readme_preserved)
        summary.errors.extend(result.errors)
        if result.record is not None:
            records[item.challenge.id] = result.record

    index_entries = [
        (item.challenge, item.rel_path.removeprefix("challenges/")) for item in planned
    ]
    index = render_index(settings.name, settings.url, index_entries)
    _write_if_changed(settings.output / "challenges" / "README.md", index)
    save_manifest(settings, records)
    return summary


def _fetch_details(
    client: CTFdClient, challenges: list[Challenge], jobs: int
) -> tuple[list[tuple[Challenge, dict]], list[str]]:
    errors: list[str] = []
    fetched: list[tuple[Challenge, dict]] = []

    def fetch(challenge: Challenge) -> tuple[Challenge, dict] | str:
        try:
            return client.get_challenge(challenge.id)
        except CTFdError as exc:
            return f"challenge {challenge.id} ({challenge.name}): {exc}"

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        progress = _Progress("Fetching challenges", len(challenges))
        for result in pool.map(fetch, challenges):
            progress.advance()
            if isinstance(result, str):
                errors.append(result)
            elif not result[0].is_hidden:
                fetched.append(result)
        progress.done()
    return fetched, errors


def _run_workers(
    planned: list[_Planned],
    settings: Settings,
    client: CTFdClient,
    records: dict[int, ChallengeRecord],
) -> list[_Result]:
    progress = _Progress("Writing challenges", len(planned))

    def work(item: _Planned) -> _Result:
        try:
            return _process(item, settings, client, records)
        except (CTFdError, OSError) as exc:
            return _Result(errors=[f"challenge {item.challenge.id} ({item.challenge.name}): {exc}"])
        finally:
            progress.advance()

    with ThreadPoolExecutor(max_workers=settings.jobs) as pool:
        results = list(pool.map(work, planned))
    progress.done()
    return results


def _plan(
    details: list[tuple[Challenge, dict]], records: dict[int, ChallengeRecord]
) -> list[_Planned]:
    planned: list[_Planned] = []
    used_paths: set[str] = set()
    for challenge, raw in details:
        new_hash = challenge_hash(challenge)
        previous = records.get(challenge.id)
        if previous is None:
            change = "new"
        else:
            change = "unchanged" if previous.detail_hash == new_hash else "changed"
        planned.append(
            _Planned(
                challenge=challenge,
                raw=raw,
                rel_path=_unique_path(challenge, used_paths),
                new_hash=new_hash,
                change=change,
            )
        )
    return planned


def _unique_path(challenge: Challenge, used: set[str]) -> str:
    """Directory for a challenge, disambiguated when two share a slug."""
    base = f"challenges/{slugify(challenge.category or 'uncategorized')}/{slugify(challenge.name)}"
    rel_path = base if base not in used else f"{base}-{challenge.id}"
    used.add(rel_path)
    return rel_path


def _process(
    item: _Planned, settings: Settings, client: CTFdClient, records: dict[int, ChallengeRecord]
) -> _Result:
    challenge = item.challenge
    challenge_dir = settings.output / item.rel_path
    challenge_dir.mkdir(parents=True, exist_ok=True)

    previous = records.get(challenge.id)
    result = _Result()
    files: dict[str, FileRecord] = {}
    names: list[str] = []
    declared: list[str] = []

    for index, (url_path, external) in enumerate(_attachments(challenge, settings.url)):
        name = _unique_name(safe_filename(url_path, f"file-{index}.bin"), names)
        names.append(name)
        if not external:
            declared.append(name)
        key = f"files/{name}"

        if not settings.download_files:
            # Keep the previous record so --no-files does not erase known hashes.
            if previous and key in previous.files:
                files[key] = previous.files[key]
            continue

        known = None if settings.force else (previous.files.get(key) if previous else None)
        target = challenge_dir / "files" / name
        # Verify the file on disk rather than trusting the manifest, so a copy
        # deleted or truncated outside the tool is repaired on the next run.
        if known is not None and file_sha256(target) == known.sha256:
            files[key] = known
            result.skipped += 1
            continue
        try:
            sha256, size = client.download(url_path, target, reject_html=external)
        except NotAnArtifact:
            # A prose link that happens to point off-instance. Nothing went wrong.
            continue
        except TooLarge as exc:
            # Deliberately not an error: the challenge is still complete without a
            # file this size, so the run stays green and the next one tries again.
            result.too_large.append(
                f"challenge {challenge.id} ({challenge.name}) file {name}: {exc}"
            )
            continue
        except (CTFdError, OSError) as exc:
            # One bad attachment must not cost us the challenge's description.
            result.errors.append(f"challenge {challenge.id} ({challenge.name}) file {name}: {exc}")
            continue
        files[key] = FileRecord(sha256, size)
        result.downloaded += 1

    # Only link files that are actually on disk, so a failed download does not
    # leave a dead link in the writeup. With --no-files nothing is expected on
    # disk, so the list documents what the instance declares. Links scraped from
    # the description are left out there: without fetching them we cannot tell an
    # attachment from an ordinary link, and they are already in the description.
    listed = [n for n in names if f"files/{n}" in files] if settings.download_files else declared

    readme = challenge_dir / "README.md"
    existed = readme.exists()
    if write_challenge_readme(readme, render_challenge(challenge, settings.url, listed)):
        result.readme_written = True
    elif existed:
        result.readme_preserved = True

    result.record = ChallengeRecord(
        name=challenge.name,
        path=item.rel_path,
        # An incomplete challenge gets no valid hash, so the next run retries it.
        detail_hash="" if result.errors else item.new_hash,
        files=files,
        raw=item.raw,
    )
    return result


def _attachments(challenge: Challenge, base_url: str) -> list[tuple[str, bool]]:
    """Everything worth downloading, paired with whether it came from the description.

    Description links are guesses, so they are the ones subjected to the web page
    check; what CTFd lists in `files` is taken at its word and may legitimately be
    an .html file.
    """
    return [(url_path, False) for url_path in challenge.files] + [
        (url, True) for url in description_links(challenge.description, base_url)
    ]


def _unique_name(name: str, taken: list[str]) -> str:
    if name not in taken:
        return name
    stem, dot, suffix = name.partition(".")
    counter = 2
    while f"{stem}-{counter}{dot}{suffix}" in taken:
        counter += 1
    return f"{stem}-{counter}{dot}{suffix}"


def _write_if_changed(path: Path, content: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


class _Progress:
    """A single self-overwriting counter line on stderr, silent when redirected."""

    def __init__(self, label: str, total: int) -> None:
        self.label = label
        self.total = total
        self.count = 0
        self.enabled = sys.stderr.isatty() and total > 0

    def advance(self) -> None:
        self.count += 1
        if self.enabled:
            print(f"\r{self.label} {self.count}/{self.total}", end="", file=sys.stderr, flush=True)

    def done(self) -> None:
        if self.enabled:
            print("\r\033[K", end="", file=sys.stderr, flush=True)


def print_summary(summary: Summary, dry_run: bool) -> None:
    rows = [
        (change.capitalize(), summary.changes.get(change, 0))
        for change in ("new", "changed", "unchanged")
    ]
    if not dry_run:
        rows += [
            ("Files downloaded", summary.files_downloaded),
            ("Files already current", summary.files_skipped),
            ("READMEs written", summary.readmes_written),
            ("READMEs left alone", summary.readmes_preserved),
        ]
    width = max(len(label) for label, _ in rows)
    print("\nDry run" if dry_run else "\nDump complete")
    for label, count in rows:
        print(f"  {label:<{width}}  {count}")

    if summary.hidden:
        print(
            f"\nSkipped {len(summary.hidden)} locked or hidden challenge(s). "
            "Solve their prerequisites and run again."
        )
    if summary.vanished:
        print("No longer offered by the instance (left on disk): " + ", ".join(summary.vanished))
    if summary.files_too_large:
        limit = MAX_DOWNLOAD_BYTES // (1024 * 1024)
        print(
            f"\nSkipped {len(summary.files_too_large)} attachment(s) over {limit} MiB. "
            "Download them by hand if you need them."
        )
        for warning in summary.files_too_large:
            print(f"  too large: {warning}")
    for error in summary.errors:
        print(f"error: {error}", file=sys.stderr)
