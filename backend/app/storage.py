"""Source archive validation and storage.

Rules enforced here, in order:
  * size cap on the upload
  * ZIP magic bytes
  * no absolute paths, no traversal segments, no symlinks
  * extracted-size and file-count caps (defends against zip bombs)
  * extracted files stay inside the allocated work directory

Uploaded application code is never executed.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import tempfile
import zipfile
from pathlib import Path

from app.config import settings


class ArchiveError(Exception):
    """The archive is unsafe, unsupported or corrupt."""

    def __init__(self, message: str, code: str = "invalid_archive") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return (mode & 0o170000) == 0o120000


def inspect_zip(data: bytes, *, max_bytes: int | None = None) -> dict[str, int]:
    """Validate a ZIP and return counts without extracting it."""
    limit = max_bytes or settings.max_zip_bytes

    if not data:
        raise ArchiveError("The uploaded file is empty.", "empty")
    if len(data) > limit:
        raise ArchiveError(
            f"The archive exceeds the {limit} byte upload limit.", "too_large"
        )
    if not data.startswith(b"PK"):
        raise ArchiveError("The uploaded file is not a ZIP archive.", "not_zip")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ArchiveError("The archive is corrupt or truncated.", "corrupt") from exc

    names = [info.filename for info in archive.infolist()]
    if not names:
        raise ArchiveError("The archive contains no entries.", "empty")

    total = 0
    files = 0
    for info in archive.infolist():
        name = info.filename
        if name.startswith("/") or name.startswith("\\"):
            raise ArchiveError(f"Absolute path in archive: {name}", "absolute_path")
        parts = name.replace("\\", "/").split("/")
        if ".." in parts:
            raise ArchiveError(f"Path traversal in archive: {name}", "path_traversal")
        if _is_symlink(info):
            raise ArchiveError(f"Symbolic link in archive: {name}", "symlink")
        if info.is_dir():
            continue
        files += 1
        total += info.file_size
        if files > settings.max_file_count:
            raise ArchiveError(
                f"The archive has more than {settings.max_file_count} files.",
                "too_many_files",
            )
        if total > settings.max_extracted_bytes:
            raise ArchiveError(
                f"Extracted contents exceed {settings.max_extracted_bytes} bytes.",
                "too_large_extracted",
            )

    return {"file_count": files, "uncompressed_bytes": total, "compressed_bytes": len(data)}


def safe_extract(data: bytes, destination: Path) -> Path:
    """Extract a validated archive into *destination* and return its root."""
    inspect_zip(data)
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            target = (root / info.filename).resolve()
            if root not in target.parents and target != root:
                raise ArchiveError(
                    f"Refusing to write outside the work directory: {info.filename}",
                    "escape",
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)

    return root


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def storage_root() -> Path:
    """Absolute storage root.

    A relative SOURCE_STORAGE_DIR is resolved against the repository root, not
    the process working directory, so starting uvicorn from `backend/` cannot
    nest archives under `backend/backend/sources`.
    """
    configured = Path(settings.source_storage_dir)
    root = configured if configured.is_absolute() else (REPO_ROOT / configured).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def store_source(workspace_id: str, project_id: str, filename: str, data: bytes) -> str:
    """Persist an archive under a workspace-scoped path and return the path."""
    inspect_zip(data)
    root = storage_root()
    safe_name = "".join(c for c in filename if c.isalnum() or c in "._-")[:120] or "source.zip"
    directory = root / workspace_id / project_id
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{sha256(data)[:16]}-{safe_name}"
    target.write_bytes(data)
    return str(target)


def read_source(path: str) -> bytes:
    root = storage_root()
    target = Path(path).resolve()
    if root not in target.parents:
        raise ArchiveError("Source path is outside the storage root.", "escape")
    if not target.is_file():
        raise ArchiveError("Source archive is no longer available.", "missing")
    return target.read_bytes()


def work_directory() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="vibecheck-scan-")


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def ensure_within(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    if root.resolve() not in resolved.parents and resolved != root.resolve():
        raise ArchiveError("Resolved path left the work directory.", "escape")
    return resolved


__all__ = [
    "ArchiveError",
    "inspect_zip",
    "safe_extract",
    "sha256",
    "store_source",
    "read_source",
    "work_directory",
    "cleanup",
    "ensure_within",
]
