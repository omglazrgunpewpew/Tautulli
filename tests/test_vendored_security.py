"""Security regressions for Tautulli's vendored dependencies."""

import http.client
import io
import sys
import threading
import time
import zlib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_PATH = REPO_ROOT / "lib"
sys.path.insert(0, str(LIB_PATH))

import certifi  # noqa: E402
import jwt  # noqa: E402
import mako  # noqa: E402
import urllib3  # noqa: E402
from urllib3.exceptions import ProtocolError  # noqa: E402
from mako.exceptions import TemplateLookupException  # noqa: E402
from mako.template import Template  # noqa: E402
from mako.lookup import TemplateLookup  # noqa: E402


class MemorySocket:
    """Provide an in-memory HTTP response without opening a socket."""

    def __init__(self, data):
        self.data = data

    def makefile(self, mode):
        return io.BytesIO(self.data)


def make_chunked_response(body, headers):
    """Build an urllib3 response backed by an in-memory HTTP response."""
    raw_headers = b"".join(
        f"{name}: {value}\r\n".encode("ascii") for name, value in headers.items()
    )
    raw_response = b"HTTP/1.1 200 OK\r\n" + raw_headers + b"\r\n" + body
    original = http.client.HTTPResponse(MemorySocket(raw_response))
    original.begin()
    return urllib3.response.HTTPResponse(
        body=original,
        headers=headers,
        preload_content=False,
    )


def test_imports_use_the_pinned_vendored_versions():
    assert Path(jwt.__file__).resolve().is_relative_to(LIB_PATH.resolve())
    assert Path(urllib3.__file__).resolve().is_relative_to(LIB_PATH.resolve())
    assert Path(certifi.__file__).resolve().is_relative_to(LIB_PATH.resolve())
    assert Path(mako.__file__).resolve().is_relative_to(LIB_PATH.resolve())
    assert jwt.__version__ == "2.15.0"
    assert urllib3.__version__ == "2.8.0"
    assert certifi.__version__ == "2026.10.23"
    assert mako.__version__ == "1.4.2"
    assert "BEGIN CERTIFICATE" in Path(certifi.where()).read_text(encoding="ascii")


def test_mako_rejects_drive_letter_parent_traversal():
    with pytest.raises(TemplateLookupException, match="cannot be relative outside"):
        Template(uri="C:/../../outside.html")


def test_mako_accepts_drive_letter_uri_and_renders_templates(tmp_path):
    assert Template("drive path is safe", uri="C:/templates/index.html").render() == (
        "drive path is safe"
    )

    (tmp_path / "index.html").write_text("Hello ${name}!", encoding="utf-8")
    lookup = TemplateLookup(directories=[str(tmp_path)])
    assert lookup.get_template("/index.html").render(name="Mako") == "Hello Mako!"


def test_pyjwt_does_not_reuse_unverified_claim_options():
    key = "test-key-that-is-at-least-32-bytes-long"
    expired_token = jwt.encode({"exp": int(time.time()) - 60}, key, algorithm="HS256")
    options = {"verify_signature": False}

    assert jwt.decode(expired_token, options=options)
    assert options == {"verify_signature": False}

    options["verify_signature"] = True
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(expired_token, key, algorithms=["HS256"], options=options)


def test_pyjwt_roundtrip_and_rejects_a_wrong_signature():
    key = "test-key-that-is-at-least-32-bytes-long"
    token = jwt.encode({"sub": "local-test"}, key, algorithm="HS256")
    wrong_key = "wrong-key-that-is-also-at-least-32-bytes-long"

    assert jwt.decode(token, key, algorithms=["HS256"]) == {"sub": "local-test"}
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, wrong_key, algorithms=["HS256"])


def test_urllib3_chunked_deflate_with_trailing_bytes_completes():
    plain = b"x" * 256
    compressed = zlib.compress(plain) + b"trailing-data-after-deflate-eof"
    chunked_body = (
        f"{len(compressed):x}\r\n".encode("ascii")
        + compressed
        + b"\r\n0\r\n\r\n"
    )
    response = make_chunked_response(
        chunked_body,
        {"Transfer-Encoding": "chunked", "Content-Encoding": "deflate"},
    )
    result = []
    failure = []
    finished = threading.Event()

    def stream_response():
        try:
            result.extend(response.stream(amt=64, decode_content=True))
        except BaseException as error:
            failure.append(error)
        finally:
            finished.set()

    worker = threading.Thread(target=stream_response, daemon=True)
    worker.start()
    assert finished.wait(timeout=5), "chunked deflate stream did not complete"
    assert not failure, failure
    assert b"".join(result) == plain


def test_urllib3_rejects_oversized_chunk_size_lines():
    response = make_chunked_response(
        b"f" * 100_000 + b"\r\n",
        {"Transfer-Encoding": "chunked"},
    )

    with pytest.raises(ProtocolError, match="chunk size line exceeded"):
        list(response.stream(amt=1))
