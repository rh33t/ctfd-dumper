#!/usr/bin/env python3
"""ctfd-dumper: dump a CTFd instance into a writeup repository.

    python3 main.py --url https://myctf.ctfd.io --token ctfd_...

Running a script puts its own directory on sys.path, so the modules next to this
file import without any install.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tomllib
from pathlib import Path

from client import CTFdClient, CTFdError
from dumper import Settings, dump, print_summary
from render import slugify

VERSION = "0.1.0"

# Fields a --creds file or the environment can supply. The command line still wins.
ENV_KEYS = {
    "url": "CTFD_URL",
    "token": "CTFD_TOKEN",
    "email": "CTFD_EMAIL",
    "password": "CTFD_PASSWORD",
    "name": "CTFD_NAME",
    "output": "CTFD_OUTPUT",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Dump challenges, files and metadata from a CTFd instance "
        "into a writeup repository.",
        epilog="Every credential option also reads from a --creds TOML file and from an "
        "environment variable (CTFD_URL, CTFD_TOKEN, CTFD_NAME, CTFD_OUTPUT, CTFD_EMAIL, "
        "CTFD_PASSWORD); precedence is command line, then --creds, then environment.",
    )
    # Credential defaults resolve later (resolve_sources) so --creds can sit between the
    # command line and the environment; leaving them None here marks "not passed".
    parser.add_argument("-u", "--url", help="CTFd base URL")
    parser.add_argument(
        "-t",
        "--token",
        help="API token, or 'session=...' to use a browser cookie",
    )
    parser.add_argument(
        "-e",
        "--email",
        help="Log in with this address or username instead of a token",
    )
    parser.add_argument(
        "--password",
        help="Password for --email. Omit to be prompted",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="CTF name, used as the index title (defaults to the host)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output directory (defaults to a slug of the host)",
    )
    parser.add_argument(
        "--creds",
        metavar="FILE",
        help="TOML file supplying any of url, token, email, password, name, output",
    )
    parser.add_argument("-j", "--jobs", type=int, default=4, help="Concurrent requests")
    parser.add_argument(
        "--no-files", action="store_true", help="Skip attachments, write metadata only"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would change, write nothing"
    )
    parser.add_argument(
        "--force", action="store_true", help="Redownload every file, ignoring hashes"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show tracebacks")
    parser.add_argument("--version", action="version", version=f"ctfd-dumper {VERSION}")
    return parser


def load_creds(path: str, parser: argparse.ArgumentParser) -> dict[str, str]:
    """Read credential fields from a TOML file.

    Keys may sit at the top level or under a [ctfd] table. TOML's quoting is explicit,
    so a token or password with % @ # or quotes needs no special handling. Only the
    known keys are read; every value must be a string.
    """
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        parser.error(f"cannot read --creds file: {exc}")
    except tomllib.TOMLDecodeError as exc:
        parser.error(f"invalid --creds file: {exc}")
    table = data.get("ctfd", data)
    creds: dict[str, str] = {}
    for key in ENV_KEYS:
        if key not in table:
            continue
        value = table[key]
        if not isinstance(value, str):
            parser.error(f"--creds file: {key} must be a string, got {type(value).__name__}")
        creds[key] = value
    return creds


def resolve_sources(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Fill unset credential fields from --creds, then the environment. The command
    line already sat in args, so anything still None falls back in that order."""
    creds = load_creds(args.creds, parser) if args.creds else {}
    for key, env in ENV_KEYS.items():
        if getattr(args, key) is None:
            value = creds.get(key) or os.environ.get(env)
            if value is not None:
                setattr(args, key, value)


def to_settings(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Settings:
    if not args.url:
        parser.error("no CTFd URL. Pass --url or set CTFD_URL.")
    if not args.token and not args.email:
        parser.error(
            "no way to authenticate. Pass an API token (--token or CTFD_TOKEN) "
            "or an account to log in with (--email or CTFD_EMAIL)."
        )
    host = args.url.split("//")[-1].split("/")[0]
    return Settings(
        url=args.url.rstrip("/"),
        # A CTF without an explicit name is titled after its host, which beats a placeholder.
        name=args.name or host,
        # Never the working directory: the index README would land on top of whatever
        # README.md is already there. A directory named after the instance is also what
        # you want when dumping several CTFs from one place.
        output=Path(args.output or slugify(host)).expanduser(),
        jobs=max(1, args.jobs),
        download_files=not args.no_files,
        dry_run=args.dry_run,
        force=args.force,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    resolve_sources(args, parser)
    settings = to_settings(args, parser)

    # A token needs no round trip, so it wins when both are configured.
    password = args.password
    if not args.token and not password:
        # Prompting keeps the password out of shell history and process listings.
        password = getpass.getpass(f"Password for {args.email}: ")

    print(f"{settings.name}  {settings.url} -> {settings.output}")
    try:
        with CTFdClient(settings.url, args.token) as client:
            if not args.token:
                client.login(args.email, password or "")
                print(f"Logged in as {args.email}")
            summary = dump(settings, client)
    except CTFdError as exc:
        if args.verbose:
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted. Re-run to resume.", file=sys.stderr)
        return 130

    print_summary(summary, settings.dry_run)
    return 1 if summary.errors else 0


if __name__ == "__main__":
    sys.exit(main())
