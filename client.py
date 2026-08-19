"""HTTP access to a CTFd instance: authentication, the JSON API, and downloads."""

from __future__ import annotations

import hashlib
import os
import random
import re
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import httpx

CHUNK_SIZE = 64 * 1024
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_REDIRECTS = 5
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# CTFd embeds its CSRF nonce both as a hidden form field and in the theme's
# bootstrap JS. Themes vary, so try every known shape before giving up.
_NONCE_PATTERNS = (
    re.compile(r"""name=["']nonce["'][^>]*?value=["']([0-9a-fA-F]{16,})["']"""),
    re.compile(r"""value=["']([0-9a-fA-F]{16,})["'][^>]*?name=["']nonce["']"""),
    re.compile(r"""['"]csrfNonce['"]\s*:\s*['"]([0-9a-fA-F]{16,})['"]"""),
)


class CTFdError(Exception):
    """Any failure that should surface to the user as a clean message."""


class AuthError(CTFdError):
    pass


class NotAnArtifact(CTFdError):
    """The URL served a web page, so there is no file behind it to save."""


class TooLarge(CTFdError):
    """The file is over MAX_DOWNLOAD_BYTES and was left on the server."""


# Challenge data


@dataclass
class Hint:
    id: int
    cost: int = 0
    title: str | None = None
    # Present only once the hint is unlocked or the CTF has ended.
    content: str | None = None


@dataclass
class Challenge:
    """A CTFd challenge, from either the list or the detail endpoint.

    The list endpoint omits the description, hints and files, which parse as empty.
    """

    id: int
    name: str
    category: str = ""
    type: str = "standard"
    value: int = 0
    description: str = ""
    connection_info: str | None = None
    attribution: str | None = None
    max_attempts: int | None = None
    solves: int | None = None
    solved_by_me: bool = False
    tags: list[str] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    # URL paths relative to the site root, already carrying a signed ?token=.
    files: list[str] = field(default_factory=list)

    @property
    def is_hidden(self) -> bool:
        """CTFd anonymises locked challenges instead of omitting them.

        Depending on the instance's anonymisation mode the name and category are
        replaced with '???', or kept while the type is forced to 'hidden'.
        """
        return self.type == "hidden" or self.name == "???"


def _int(value: Any, default: int | None = 0) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _str(value: Any, default: str | None = "") -> Any:
    return value if isinstance(value, str) else default


def _tags(value: Any) -> list[str]:
    """Accept both tag shapes CTFd serves: "rsa" and {"value": "rsa"}.

    Which one you get depends on the instance's version, so both have to work. A tag
    in some third shape is dropped rather than allowed to abort the whole dump.
    """
    if not isinstance(value, list):
        return []
    tags = []
    for item in value:
        tag = item.get("value") if isinstance(item, dict) else item
        if isinstance(tag, str):
            tags.append(tag)
    return tags


def parse_challenge(data: dict[str, Any]) -> Challenge:
    """Build a Challenge from an API payload, ignoring fields we do not use.

    Unknown fields appear between CTFd minor versions and must never abort a dump,
    so everything is read defensively and only a missing id is fatal.
    """
    if not isinstance(data, dict) or _int(data.get("id"), None) is None:
        raise CTFdError(f"Unrecognised challenge payload: {data!r:.120}")
    hints = [
        Hint(
            id=_int(hint.get("id")),
            cost=_int(hint.get("cost")),
            title=_str(hint.get("title"), None),
            content=_str(hint.get("content"), None),
        )
        for hint in data.get("hints") or []
        if isinstance(hint, dict)
    ]
    return Challenge(
        id=_int(data["id"]),
        name=_str(data.get("name")),
        category=_str(data.get("category")),
        type=_str(data.get("type")) or "standard",
        value=_int(data.get("value")),
        description=_str(data.get("description")),
        connection_info=_str(data.get("connection_info"), None),
        attribution=_str(data.get("attribution"), None),
        max_attempts=_int(data.get("max_attempts"), None),
        solves=_int(data.get("solves"), None),
        solved_by_me=bool(data.get("solved_by_me", False)),
        tags=_tags(data.get("tags")),
        hints=hints,
        files=[path for path in data.get("files") or [] if isinstance(path, str)],
    )


# URLs and files


def safe_filename(url: str, fallback: str) -> str:
    """Derive a filename that cannot escape its target directory.

    CTFd file URLs are attacker controlled from this tool's point of view, so the
    basename is taken after decoding and any separator or traversal component is
    rejected outright rather than stripped.
    """
    name = unquote(PurePosixPath(urlparse(url).path).name)
    # A decoded name may itself contain separators (%2f) or be a traversal token.
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        return fallback
    return name


def same_origin(left: str, right: str) -> bool:
    return _origin(left) == _origin(right)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlparse(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS.get(scheme, 0)


def file_sha256(path: Path) -> str | None:
    """sha256 of a file, or None if it is not there."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk)
    except FileNotFoundError:
        return None
    return digest.hexdigest()


def _is_html(response: httpx.Response) -> bool:
    media_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    return media_type in HTML_TYPES


def _has_traversal(url_path: str) -> bool:
    path = urlparse(url_path).path
    return ".." in path.split("/") or ".." in unquote(path).split("/")


def _mib(size: int) -> str:
    return f"{size / (1024 * 1024):.0f} MiB"


def _retry_after(response: httpx.Response) -> float | None:
    header = response.headers.get("Retry-After")
    if not header:
        return None
    try:
        return min(float(header), 60.0)
    except ValueError:
        return None


class _Retryable(Exception):
    """Internal signal that a download attempt may be worth repeating.

    `retry_after` is the server's own instruction when it gave one; otherwise the
    caller falls back to its exponential backoff, which needs the attempt number.
    """

    def __init__(self, reason: str, retry_after: float | None, cause: Exception | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after
        self.cause = cause


# Client


class CTFdClient:
    def __init__(
        self,
        base_url: str,
        credential: str | None = None,
        *,
        timeout: float = 30.0,
        max_retries: int = 4,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.max_retries = max_retries
        headers = {"Accept": "application/json"}
        # With no credential the caller is expected to call login(), which fills
        # the cookie jar instead of setting a static auth header.
        if credential is None:
            pass
        # A value of the form "session=..." is a browser cookie rather than a token.
        elif credential.startswith("session="):
            headers["Cookie"] = credential
        else:
            headers["Authorization"] = f"Bearer {credential}"
        self._client = client or httpx.Client(
            timeout=timeout,
            headers=headers,
            follow_redirects=False,
        )
        if client is not None:
            self._client.headers.update(headers)

    def __enter__(self) -> CTFdClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def login(self, identity: str, password: str) -> None:
        """Exchange credentials for a session, stored in the client's cookie jar.

        CTFd guards its login form with a per-session CSRF nonce, so this has to
        fetch the form first and post the nonce back on the same session.
        """
        login_url = urljoin(self.base_url, "login")
        html_headers = {"Accept": "text/html"}

        page = self._request("GET", login_url, headers=html_headers)
        if page.status_code != 200:
            raise AuthError(
                f"Could not load the login page ({page.status_code}). "
                "Check the URL, or use an API token instead."
            )

        nonce = _extract_nonce(page.text)
        if nonce is None:
            raise AuthError(
                "Could not find a CSRF nonce on the login page. The instance may use a "
                "custom theme or a third party login. Use an API token instead."
            )

        # Deliberately not retried: a repeated password post can trip lockouts.
        response = self._client.request(
            "POST",
            login_url,
            data={"name": identity, "password": password, "nonce": nonce},
            headers=html_headers,
        )

        if response.is_redirect:
            location = response.headers.get("Location", "")
            if "login" in location:
                raise AuthError("Login was rejected. Check the address and password.")
            return

        raise AuthError(_login_failure_reason(response))

    def list_challenges(self) -> list[Challenge]:
        data = self._get_json("api/v1/challenges")
        if not isinstance(data, list):
            raise CTFdError("The challenge list endpoint did not return a list.")
        return [parse_challenge(item) for item in data]

    def get_challenge(self, challenge_id: int) -> tuple[Challenge, dict[str, Any]]:
        """Return the parsed challenge and the raw payload, so nothing is lost on disk."""
        data = self._get_json(f"api/v1/challenges/{challenge_id}")
        if not isinstance(data, dict):
            raise CTFdError(f"Challenge {challenge_id} did not return an object.")
        return parse_challenge(data), data

    def download(
        self, url_path: str, destination: Path, *, reject_html: bool = False
    ) -> tuple[str, int]:
        """Stream a file to `destination` and return its (sha256, size).

        `url_path` may be relative to the instance or an absolute URL on another
        host. Downloads land in a sibling .part file that is replaced into position
        only once complete, so an interrupted run never leaves a truncated file that
        a later hash check would accept.

        With `reject_html` the download is abandoned before any bytes are written if
        the host answers with a web page, which is how a link that merely looks like
        an attachment is told apart from a real one.

        Anything over MAX_DOWNLOAD_BYTES raises TooLarge and leaves nothing behind.
        """
        # urljoin resolves '..' segments, so a crafted file path would silently
        # redirect the request away from where CTFd said the file lives.
        if _has_traversal(url_path):
            raise CTFdError(f"Refusing to fetch {url_path}: the path escapes its directory")
        # Not lstripped: an instance under a subpath returns '/ctfd/files/...', which
        # already carries the same prefix base_url ends with. Stripping the leading
        # slash would make urljoin append it a second time.
        url = urljoin(self.base_url, url_path)
        partial = destination.parent / (destination.name + ".part")

        for attempt in range(self.max_retries + 1):
            try:
                digest, size = self._stream_to(url, partial, reject_html)
            except _Retryable as exc:
                partial.unlink(missing_ok=True)
                if attempt == self.max_retries:
                    raise CTFdError(f"Download of {url} failed: {exc.reason}") from exc.cause
                delay = exc.retry_after if exc.retry_after is not None else self._backoff(attempt)
                time.sleep(delay)
                continue
            except BaseException:
                partial.unlink(missing_ok=True)
                raise

            os.replace(partial, destination)
            return digest, size

        raise CTFdError(f"Download of {url} failed after {self.max_retries} retries.")

    def _stream_to(self, url: str, partial: Path, reject_html: bool) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        try:
            with ExitStack() as stack:
                response = self._follow(url, stack)
                final_url = str(response.request.url)
                if response.status_code in RETRY_STATUSES:
                    raise _Retryable(f"HTTP {response.status_code}", _retry_after(response), None)
                _raise_for_response(response, final_url)
                if reject_html and _is_html(response):
                    raise NotAnArtifact(f"{final_url} served a web page, not a file")
                declared = int(response.headers.get("Content-Length") or 0)
                if declared > MAX_DOWNLOAD_BYTES:
                    raise TooLarge(
                        f"{final_url} is {_mib(declared)}, "
                        f"over the {_mib(MAX_DOWNLOAD_BYTES)} limit"
                    )
                # Created only now, so a rejected or failed URL leaves no empty directory.
                partial.parent.mkdir(parents=True, exist_ok=True)
                with partial.open("wb") as handle:
                    for chunk in response.iter_bytes(CHUNK_SIZE):
                        handle.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                        # A chunked response declares no length, so the cap has to
                        # be enforced against what actually arrives as well.
                        if size > MAX_DOWNLOAD_BYTES:
                            raise TooLarge(
                                f"{final_url} is over the {_mib(MAX_DOWNLOAD_BYTES)} limit"
                            )
                    handle.flush()
                    os.fsync(handle.fileno())
        except httpx.TransportError as exc:
            raise _Retryable(str(exc), None, exc) from exc
        return digest.hexdigest(), size

    def _follow(self, url: str, stack: ExitStack) -> httpx.Response:
        """Walk redirects by hand, so credentials can be dropped at each origin hop.

        httpx's own redirect handling keeps a manually set Cookie header across
        hosts, which would hand a CTFd session to whichever file host the instance
        redirects to.
        """
        for _ in range(MAX_REDIRECTS + 1):
            response = self._open(url)
            if not response.is_redirect:
                stack.callback(response.close)
                return response
            location = response.headers.get("Location", "")
            response.close()
            if "login" in location:
                raise AuthError(
                    f"Downloading {url} redirected to the login page. "
                    "Your token or session cookie is missing, expired or wrong."
                )
            if not location:
                raise CTFdError(f"{url} redirected without saying where to.")
            url = urljoin(url, location)
        raise CTFdError(f"Gave up after {MAX_REDIRECTS} redirects while downloading {url}.")

    def _open(self, url: str) -> httpx.Response:
        request = self._client.build_request("GET", url)
        if not same_origin(url, self.base_url):
            # The cookie jar is already domain scoped; these two are set by hand.
            request.headers.pop("Authorization", None)
            request.headers.pop("Cookie", None)
        return self._client.send(request, stream=True, follow_redirects=False)

    def _get_json(self, path: str) -> Any:
        url = urljoin(self.base_url, path.lstrip("/"))
        response = self._request("GET", url)
        _raise_for_response(response, url)
        try:
            payload = response.json()
        except ValueError as exc:
            raise CTFdError(f"{url} did not return JSON. Is this a CTFd instance?") from exc
        if not isinstance(payload, dict) or not payload.get("success", False):
            raise CTFdError(f"{url} returned an error: {_describe_errors(payload)}")
        return payload.get("data")

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                last_error = exc
                if attempt == self.max_retries:
                    raise CTFdError(f"Could not reach {url}: {exc}") from exc
                time.sleep(self._backoff(attempt))
                continue

            if response.status_code in RETRY_STATUSES and attempt < self.max_retries:
                response.close()
                # CTFd rate limits and sends Retry-After; respect it when it parses.
                after = _retry_after(response)
                time.sleep(after if after is not None else self._backoff(attempt))
                continue
            return response

        raise CTFdError(f"Could not reach {url}: {last_error}")

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(2.0**attempt, 30.0) + random.uniform(0, 0.3)


def _raise_for_response(response: httpx.Response, url: str) -> None:
    if response.is_redirect:
        location = response.headers.get("Location", "")
        if "login" in location:
            raise AuthError(
                "The instance redirected to the login page. "
                "Your token or session cookie is missing, expired or wrong."
            )
        raise CTFdError(f"{url} unexpectedly redirected to {location or '(no location)'}")
    if response.status_code in {401, 403}:
        raise AuthError(
            f"Access denied for {url} ({response.status_code}). "
            "Check the token, and that the CTF is running and visible to you."
        )
    if response.status_code == 404:
        raise CTFdError(f"{url} was not found (404).")
    if response.status_code >= 400:
        raise CTFdError(f"{url} failed with HTTP {response.status_code}.")


def _describe_errors(payload: Any) -> str:
    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, dict):
            return "; ".join(
                f"{key or 'error'}: {', '.join(map(str, value))}"
                if isinstance(value, list)
                else f"{key or 'error'}: {value}"
                for key, value in errors.items()
            )
        if errors:
            return str(errors)
    return str(payload)


def _extract_nonce(html: str) -> str | None:
    for pattern in _NONCE_PATTERNS:
        match = pattern.search(html)
        if match:
            return match.group(1)
    return None


def _login_failure_reason(response: httpx.Response) -> str:
    """Turn CTFd's re-rendered login page back into a usable message.

    A failed login is a 200 with the error inlined in the HTML, not a 4xx.
    """
    if response.status_code == 429:
        return "Too many login attempts. CTFd is rate limiting you; wait and retry."
    body = response.text
    if "3rd party authentication" in body:
        return (
            "This account signs in through a third party provider and has no password. "
            "Log in via the browser and pass the session cookie, or use an API token."
        )
    if "username or password is incorrect" in body:
        return "Your username or password is incorrect."
    if response.status_code != 200:
        return f"Login failed with HTTP {response.status_code}."
    return "Login failed and the instance did not say why. Try an API token instead."
