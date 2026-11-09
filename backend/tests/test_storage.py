"""ZIP validation must reject traversal, symlinks, bombs and junk."""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from app.storage import ArchiveError, inspect_zip


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_accepts_a_normal_archive() -> None:
    data = make_zip({"src/app.py": b"print('hello')\n", "README.md": b"# project\n"})
    info = inspect_zip(data)
    assert info["file_count"] == 2
    assert info["compressed_bytes"] == len(data)


def test_rejects_path_traversal() -> None:
    data = make_zip({"../../etc/passwd": b"root:x:0:0"})
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(data)
    assert exc.value.code == "path_traversal"


def test_rejects_absolute_path() -> None:
    data = make_zip({"/etc/cron.d/job": b"* * * * * root id"})
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(data)
    assert exc.value.code == "absolute_path"


def test_rejects_symlink_entries() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16) | 0o600
        archive.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(buffer.getvalue())
    assert exc.value.code == "symlink"


def test_rejects_non_zip_payload() -> None:
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(b"not a zip at all")
    assert exc.value.code == "not_zip"


def test_rejects_empty_payload() -> None:
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(b"")
    assert exc.value.code == "empty"


def test_rejects_oversized_upload() -> None:
    # Incompressible bytes, so the archive itself exceeds the cap.
    payload = os.urandom(8192)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("big.bin", payload)
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(buffer.getvalue(), max_bytes=1024)
    assert exc.value.code == "too_large"


def test_rejects_corrupt_archive() -> None:
    payload = make_zip({"a.txt": b"hello"})
    with pytest.raises(ArchiveError) as exc:
        inspect_zip(payload[: len(payload) // 2])
    assert exc.value.code in {"corrupt", "not_zip", "empty"}
