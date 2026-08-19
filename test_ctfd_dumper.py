"""Tests for the invariants that would cost a user real work if they broke.

Run with: python3 -m unittest

Everything network-facing is driven against a real HTTP server rather than a mock.
Mocks hid a path traversal bug and a per-file error isolation bug during this tool's
initial development; both only showed up against a live socket.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import client as client_mod
import main as cli
import render
from client import CTFdClient, CTFdError, safe_filename
from render import merge_challenge, read_verbatim, slugify, write_verbatim

Response = tuple[int, dict[str, str], bytes]

# A stub CTFd. `routes` maps a path to a response, or to a list of responses served
# in order so a retry can be observed. `seen` records the headers each request
# arrived with, so credential scoping can be asserted.
routes: dict[str, Response | list[Response]] = {}
seen: list[tuple[str, dict[str, str]]] = []
posted: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler's naming)
        path = urlparse(self.path).path
        seen.append((path, dict(self.headers)))
        route = routes.get(path, (404, {}, b"nope"))
        if isinstance(route, list):
            # A script of responses; the last one repeats once the script runs out.
            route = route.pop(0) if len(route) > 1 else route[0]
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if "Location" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if "Location" not in headers:
            self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        posted.append(self.rfile.read(length).decode())
        status, headers, body = routes.get("POST " + urlparse(self.path).path, (404, {}, b""))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        pass


def _serve() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    # A short poll interval keeps shutdown() from dominating the suite's runtime.
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def api(payload: object) -> tuple[int, dict[str, str], bytes]:
    body = json.dumps({"success": True, "data": payload}).encode()
    return 200, {"Content-Type": "application/json"}, body


def challenge(cid: int, name: str, category: str = "Crypto", **extra: object) -> dict:
    data = {
        "id": cid,
        "name": name,
        "category": category,
        "type": "standard",
        "value": 100,
        "solves": 5,
        "solved_by_me": False,
        "tags": [],
        "description": f"Description for {name}",
        "hints": [],
        "files": [],
    }
    data.update(extra)
    return data


class ServerTestCase(unittest.TestCase):
    """Base class giving each test a live stub instance and a scratch directory."""

    def setUp(self) -> None:
        routes.clear()
        seen.clear()
        posted.clear()
        self.server, self.url = _serve()
        self.addCleanup(self.server.shutdown)
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out, True)

    def publish(self, *challenges: dict) -> None:
        routes["/api/v1/challenges"] = api(list(challenges))
        for item in challenges:
            routes[f"/api/v1/challenges/{item['id']}"] = api(item)

    def run_cli(self, *extra: str) -> int:
        return self.run_argv("--token", "tok", *extra)

    def run_argv(self, *auth_and_flags: str) -> int:
        argv = ["--url", self.url, "--output", str(self.out), *auth_and_flags]
        # The CLI is deliberately chatty; keep its output out of the test report.
        with open(os.devnull, "w") as null, redirect_stdout(null), redirect_stderr(null):
            return cli.main(argv)

    def readme(self, category: str, name: str) -> Path:
        return self.out / "challenges" / category / name / "README.md"


class TestSolutionPreservation(unittest.TestCase):
    """The core promise: re-running never destroys a writeup."""

    def test_a_handwritten_solution_survives_a_regenerated_header(self) -> None:
        existing = "---\nid: 1\n---\n\n# Old\n\n## Solution\n\nI factored n with yafu.\n"
        generated = "---\nid: 1\n---\n\n# New\n\n## Solution\n\n<!-- writeup goes here -->\n"
        merged = merge_challenge(existing, generated)
        assert merged is not None
        self.assertIn("# New", merged)
        self.assertTrue(merged.endswith("## Solution\n\nI factored n with yafu.\n"))

    def test_a_readme_without_the_solution_heading_is_left_alone(self) -> None:
        # Rewriting a restructured file would risk destroying prose, so it is skipped.
        self.assertIsNone(merge_challenge("# Mine\n\nAll my own notes.\n", "regenerated"))

    def test_an_untouched_placeholder_is_replaced_wholesale(self) -> None:
        existing = "old\n\n## Solution\n\n<!-- writeup goes here -->\n"
        self.assertEqual(merge_challenge(existing, "new\n\n## Solution\n"), "new\n\n## Solution\n")

    def test_a_writeup_keeps_its_line_endings(self) -> None:
        # Read and write go through the verbatim helpers precisely so CRLF survives:
        # CTFd serves CRLF descriptions and a writeup may use any ending. Default
        # newline translation would rewrite them and break the byte for byte promise.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "README.md"
            write_verbatim(path, "head\r\nmore\n\n## Solution\n\nmy\r\nwork\r\n")
            merged = merge_challenge(read_verbatim(path), "new\n\n## Solution\n\nplaceholder\n")
            assert merged is not None
            self.assertTrue(merged.endswith("## Solution\n\nmy\r\nwork\r\n"))


class TestRendering(unittest.TestCase):
    def test_slugify(self) -> None:
        self.assertEqual(slugify("Baby RSA!"), "baby-rsa")
        self.assertEqual(slugify("Ünïcode"), "unicode")
        self.assertEqual(slugify("!!!"), "unnamed")

    def test_frontmatter_quotes_values_that_would_change_meaning(self) -> None:
        text = render.frontmatter(client_mod.parse_challenge(challenge(1, "a: b")), "http://x", [])
        self.assertIn('name: "a: b"', text)

    def test_only_unlocked_hints_are_rendered(self) -> None:
        detail = challenge(
            1,
            "Chall",
            hints=[
                {"id": 1, "cost": 10, "title": "Locked", "content": None},
                {"id": 2, "cost": 0, "title": "Free", "content": "look at the exponent"},
            ],
        )
        text = render.render_challenge(client_mod.parse_challenge(detail), "http://x", [])
        self.assertIn("look at the exponent", text)
        self.assertNotIn("Locked", text)

    def test_description_links_off_instance_are_candidates(self) -> None:
        base = "https://ctf.example.com"
        text = (
            "[grab it](https://files.example.net/a.zip) "
            "[home](https://ctf.example.com/page) "
            "browse to https://ctf.example.com:8088"
        )
        # Only the markdown link to another host: prose URLs are services, not files.
        self.assertEqual(render.description_links(text, base), ["https://files.example.net/a.zip"])


class TestFilenameSafety(unittest.TestCase):
    def test_a_filename_is_always_a_plain_basename(self) -> None:
        cases = {
            "/files/abc/chall.zip?token=x": "chall.zip",
            # Only the basename is taken, so the name itself cannot escape. The URL
            # is separately refused by download(); see the traversal test above.
            "/files/../../etc/passwd": "passwd",
            # A decoded name that still contains separators has no safe basename.
            "/files/%2e%2e%2fpasswd": "fallback.bin",
            "/files/%2fetc%2fpasswd": "fallback.bin",
            "http://host/": "fallback.bin",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(safe_filename(url, "fallback.bin"), expected)


class TestCredentialScoping(ServerTestCase):
    """A token must never leak to a host the instance merely redirects to."""

    def test_credentials_are_dropped_when_the_instance_redirects_off_origin(self) -> None:
        other, other_url = _serve()
        self.addCleanup(other.shutdown)
        routes["/blob"] = (200, {}, b"payload")
        routes["/files/a.zip"] = (302, {"Location": f"{other_url}/blob"}, b"")

        with CTFdClient(self.url, "secret-token") as c:
            c.download("/files/a.zip", self.out / "a.zip")

        self.assertEqual((self.out / "a.zip").read_bytes(), b"payload")
        blob = next(headers for path, headers in seen if path == "/blob")
        self.assertNotIn("authorization", {k.lower() for k in blob})

    def test_credentials_survive_a_redirect_within_the_instance(self) -> None:
        routes["/real.zip"] = (200, {}, b"payload")
        routes["/files/a.zip"] = (302, {"Location": "/real.zip"}, b"")

        with CTFdClient(self.url, "secret-token") as c:
            c.download("/files/a.zip", self.out / "a.zip")

        real = next(headers for path, headers in seen if path == "/real.zip")
        self.assertEqual(real.get("Authorization"), "Bearer secret-token")

    def test_a_session_cookie_is_withheld_from_other_hosts(self) -> None:
        other, other_url = _serve()
        self.addCleanup(other.shutdown)
        routes["/blob"] = (200, {}, b"payload")

        with CTFdClient(self.url, "session=abc123") as c:
            c.download(f"{other_url}/blob", self.out / "a.zip")

        blob = next(headers for path, headers in seen if path == "/blob")
        self.assertNotIn("cookie", {k.lower() for k in blob})

    def test_a_rate_limited_request_is_retried(self) -> None:
        # Retry-After is honoured, so this costs no wall clock time.
        routes["/api/v1/challenges"] = [(429, {"Retry-After": "0"}, b"slow down"), api([])]

        with CTFdClient(self.url, "tok", max_retries=1) as c:
            self.assertEqual(c.list_challenges(), [])

        self.assertEqual([path for path, _ in seen], ["/api/v1/challenges"] * 2)

    def test_a_traversing_file_path_is_refused_before_any_request(self) -> None:
        with CTFdClient(self.url, "tok") as c, self.assertRaises(CTFdError):
            c.download("/files/../../secret", self.out / "x")
        self.assertEqual(seen, [])


class TestLogin(ServerTestCase):
    """The email and password path, for instances with token generation disabled."""

    NONCE = "a" * 32

    def serve_login_form(self) -> None:
        form = f'<input type="hidden" name="nonce" value="{self.NONCE}">'.encode()
        routes["/login"] = (200, {"Content-Type": "text/html"}, form)

    def test_login_posts_the_nonce_and_keeps_the_session(self) -> None:
        self.serve_login_form()
        routes["POST /login"] = (302, {"Location": "/challenges", "Set-Cookie": "session=s"}, b"")

        with CTFdClient(self.url) as c:
            c.login("me@example.com", "hunter2")

        self.assertIn(f"nonce={self.NONCE}", posted[0])
        self.assertIn("name=me%40example.com", posted[0])

    def test_the_nonce_is_also_read_from_theme_javascript(self) -> None:
        script = f"var init = {{'csrfNonce': '{self.NONCE}'}};".encode()
        routes["/login"] = (200, {"Content-Type": "text/html"}, script)
        routes["POST /login"] = (302, {"Location": "/challenges"}, b"")

        with CTFdClient(self.url) as c:
            c.login("me", "pw")

        self.assertIn(f"nonce={self.NONCE}", posted[0])

    def test_a_wrong_password_is_reported_from_the_rerendered_page(self) -> None:
        # CTFd answers a failed login with a 200 and the error inlined in the HTML.
        self.serve_login_form()
        routes["POST /login"] = (200, {}, b"Your username or password is incorrect")

        with CTFdClient(self.url) as c, self.assertRaisesRegex(CTFdError, "password is incorrect"):
            c.login("me", "wrong")

    def test_an_oauth_only_account_gets_an_actionable_message(self) -> None:
        self.serve_login_form()
        page = b"Your account was registered with 3rd party authentication"
        routes["POST /login"] = (200, {}, page)

        with CTFdClient(self.url) as c, self.assertRaisesRegex(CTFdError, "session cookie|API"):
            c.login("me", "pw")

    def test_the_cli_logs_in_before_dumping_when_given_an_email(self) -> None:
        self.serve_login_form()
        routes["POST /login"] = (302, {"Location": "/challenges"}, b"")
        self.publish(challenge(1, "Baby RSA"))

        self.assertEqual(self.run_argv("--email", "me@example.com", "--password", "pw"), 0)

        self.assertIn("name=me%40example.com", posted[0])
        self.assertTrue(self.readme("crypto", "baby-rsa").exists())

    def test_a_login_page_without_a_nonce_is_refused(self) -> None:
        routes["/login"] = (200, {"Content-Type": "text/html"}, b"<html>custom theme</html>")

        with CTFdClient(self.url) as c, self.assertRaisesRegex(CTFdError, "nonce"):
            c.login("me", "pw")
        # Nothing was posted, so the password never left the process.
        self.assertEqual(posted, [])


class TestDump(ServerTestCase):
    def test_first_run_builds_the_tree(self) -> None:
        routes["/files/chall.zip"] = (200, {}, b"contents")
        self.publish(challenge(1, "Baby RSA", files=["/files/chall.zip?token=x"]))

        self.assertEqual(self.run_cli(), 0)

        readme = self.readme("crypto", "baby-rsa")
        self.assertIn("# Baby RSA", readme.read_text())
        self.assertIn("## Solution", readme.read_text())
        self.assertEqual((readme.parent / "files" / "chall.zip").read_bytes(), b"contents")
        self.assertIn("Baby RSA", (self.out / "README.md").read_text())
        self.assertTrue((self.out / ".ctfd-dumper" / "manifest.json").exists())
        self.assertTrue((self.out / ".ctfd-dumper" / "raw" / "1.json").exists())

    def test_a_second_run_changes_nothing_on_disk(self) -> None:
        routes["/files/chall.zip"] = (200, {}, b"contents")
        self.publish(challenge(1, "Baby RSA", files=["/files/chall.zip"]))
        self.run_cli()
        before = {p: p.read_bytes() for p in self.out.rglob("*") if p.is_file()}

        self.run_cli()

        after = {p: p.read_bytes() for p in self.out.rglob("*") if p.is_file()}
        # The manifest restamps its timestamp; nothing the user reads may change.
        manifest = self.out / ".ctfd-dumper" / "manifest.json"
        self.assertEqual(
            {k: v for k, v in before.items() if k != manifest},
            {k: v for k, v in after.items() if k != manifest},
        )

    def test_a_changed_description_keeps_the_writeup(self) -> None:
        self.publish(challenge(1, "Baby RSA"))
        self.run_cli()
        readme = self.readme("crypto", "baby-rsa")
        write_verbatim(readme, read_verbatim(readme).replace("<!-- writeup goes here -->", "n=..."))

        self.publish(challenge(1, "Baby RSA", description="Now with a hint"))
        self.run_cli()

        text = readme.read_text()
        self.assertIn("Now with a hint", text)
        self.assertIn("n=...", text)

    def test_a_crlf_description_settles_after_one_run(self) -> None:
        # CTFd serves CRLF. If newline translation crept back in, the README would be
        # rewritten on every single run and never compare equal.
        self.publish(challenge(1, "Baby RSA", description="line one\r\nline two\r\n"))
        self.run_cli()
        first = self.readme("crypto", "baby-rsa").read_bytes()

        self.publish(challenge(1, "Baby RSA", description="line one\r\nline two\r\n"))
        self.run_cli()

        self.assertEqual(self.readme("crypto", "baby-rsa").read_bytes(), first)

    def test_a_deleted_attachment_is_redownloaded(self) -> None:
        routes["/files/chall.zip"] = (200, {}, b"contents")
        self.publish(challenge(1, "Baby RSA", files=["/files/chall.zip"]))
        self.run_cli()
        target = self.readme("crypto", "baby-rsa").parent / "files" / "chall.zip"
        target.unlink()

        self.run_cli()

        # Files are re-hashed on disk, not merely looked up in the manifest.
        self.assertEqual(target.read_bytes(), b"contents")

    def test_hidden_challenges_are_skipped(self) -> None:
        self.publish(challenge(1, "???", category="???"), challenge(2, "Real"))
        self.assertEqual(self.run_cli(), 0)
        self.assertFalse((self.out / "challenges" / "unnamed").exists())
        self.assertTrue(self.readme("crypto", "real").exists())

    def test_one_broken_challenge_does_not_abort_the_run(self) -> None:
        routes["/api/v1/challenges"] = api([challenge(1, "Good"), challenge(2, "Broken")])
        routes["/api/v1/challenges/1"] = api(challenge(1, "Good"))
        routes["/api/v1/challenges/2"] = (403, {}, b"nope")

        # A partial dump is still a dump, but the exit code has to report the failure.
        self.assertEqual(self.run_cli("--jobs", "2"), 1)
        self.assertTrue(self.readme("crypto", "good").exists())

    def test_a_failed_attachment_still_yields_a_readme(self) -> None:
        routes["/files/gone.zip"] = (404, {}, b"")
        self.publish(challenge(1, "Baby RSA", files=["/files/gone.zip"]))

        self.assertEqual(self.run_cli(), 1)

        readme = self.readme("crypto", "baby-rsa")
        self.assertIn("# Baby RSA", readme.read_text())
        # Nothing links to a file that is not there.
        self.assertNotIn("gone.zip", readme.read_text())

    def test_an_incomplete_challenge_is_retried_next_run(self) -> None:
        routes["/files/gone.zip"] = (404, {}, b"")
        self.publish(challenge(1, "Baby RSA", files=["/files/gone.zip"]))
        self.run_cli()

        routes["/files/gone.zip"] = (200, {}, b"contents")
        self.run_cli()

        target = self.readme("crypto", "baby-rsa").parent / "files" / "gone.zip"
        self.assertEqual(target.read_bytes(), b"contents")

    def test_dry_run_writes_nothing(self) -> None:
        self.publish(challenge(1, "Baby RSA"))
        self.assertEqual(self.run_cli("--dry-run"), 0)
        self.assertFalse((self.out / "challenges").exists())

    def test_vanished_challenges_are_left_on_disk(self) -> None:
        self.publish(challenge(1, "Baby RSA"), challenge(2, "Gone"))
        self.run_cli()

        self.publish(challenge(1, "Baby RSA"))
        self.run_cli()

        # Those directories hold writeups; removing them is the user's call.
        self.assertTrue(self.readme("crypto", "gone").exists())

    def test_a_description_link_to_a_file_is_downloaded(self) -> None:
        other, other_url = _serve()
        self.addCleanup(other.shutdown)
        routes["/bucket/harry.jpg"] = (200, {"Content-Type": "image/jpeg"}, b"jpegdata")
        self.publish(
            challenge(1, "Forensics", description=f"[harry.jpg]({other_url}/bucket/harry.jpg)")
        )

        self.assertEqual(self.run_cli(), 0)

        target = self.readme("crypto", "forensics").parent / "files" / "harry.jpg"
        self.assertEqual(target.read_bytes(), b"jpegdata")

    def test_a_description_link_to_a_web_page_is_not_an_error(self) -> None:
        other, other_url = _serve()
        self.addCleanup(other.shutdown)
        routes["/share"] = (200, {"Content-Type": "text/html; charset=utf-8"}, b"<html></html>")
        self.publish(challenge(1, "Forensics", description=f"[drive]({other_url}/share)"))

        self.assertEqual(self.run_cli(), 0)

        # A share page is not an attachment, and leaves no empty files/ behind.
        self.assertFalse((self.readme("crypto", "forensics").parent / "files").exists())

    def test_no_files_skips_downloads_but_still_lists_them(self) -> None:
        routes["/files/chall.zip"] = (200, {}, b"contents")
        self.publish(challenge(1, "Baby RSA", files=["/files/chall.zip"]))

        self.assertEqual(self.run_cli("--no-files"), 0)

        readme = self.readme("crypto", "baby-rsa")
        self.assertIn("chall.zip", readme.read_text())
        self.assertFalse((readme.parent / "files").exists())

    def test_a_corrupt_manifest_degrades_to_a_full_redump(self) -> None:
        self.publish(challenge(1, "Baby RSA"))
        self.run_cli()
        (self.out / ".ctfd-dumper" / "manifest.json").write_text("{ not json")

        self.assertEqual(self.run_cli(), 0)

    def test_a_host_that_is_not_ctfd_reports_cleanly(self) -> None:
        routes["/api/v1/challenges"] = (200, {"Content-Type": "text/html"}, b"<html></html>")
        # An expected failure exits 1 with a message, never a traceback.
        self.assertEqual(self.run_cli(), 1)


class TestCli(unittest.TestCase):
    def test_help_works(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_a_missing_url_is_a_usage_error_not_a_traceback(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["--token", "tok"])
        self.assertEqual(caught.exception.code, 2)

    def test_missing_credentials_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["--url", "https://ctf.example.com"])
        self.assertEqual(caught.exception.code, 2)

    def test_creds_file_fills_unset_fields_and_the_command_line_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            creds = Path(tmp) / "creds.toml"
            # A password with % @ and quotes is exactly what tripped up ini parsing.
            creds.write_text(
                '[ctfd]\nurl = "https://fromfile.example.com"\ntoken = "tok_file"\n'
                'name = "FileCTF"\npassword = "pw%with@\\"quotes"\n'
            )
            parser = cli.build_parser()

            args = parser.parse_args(["--creds", str(creds)])
            cli.resolve_sources(args, parser)
            self.assertEqual(args.url, "https://fromfile.example.com")
            self.assertEqual(args.token, "tok_file")
            self.assertEqual(args.name, "FileCTF")
            self.assertEqual(args.password, 'pw%with@"quotes')

            args = parser.parse_args(["--creds", str(creds), "--token", "tok_cli"])
            cli.resolve_sources(args, parser)
            self.assertEqual(args.token, "tok_cli")

    def test_a_missing_creds_file_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["--creds", "/no/such/creds.toml", "--url", "https://ctf.example.com"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_malformed_creds_file_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            creds = Path(tmp) / "creds.toml"
            creds.write_text("this is not = valid = toml")
            with self.assertRaises(SystemExit) as caught:
                cli.main(["--creds", str(creds)])
            self.assertEqual(caught.exception.code, 2)

    def test_the_output_directory_defaults_to_a_slug_of_the_host(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["--url", "https://2026.uiuc.tf/ctfd/", "--token", "t"])
        settings = cli.to_settings(args, parser)
        self.assertEqual(settings.output, Path("2026-uiuc-tf"))
        self.assertEqual(settings.name, "2026.uiuc.tf")
        self.assertEqual(settings.url, "https://2026.uiuc.tf/ctfd")


if __name__ == "__main__":
    unittest.main()
