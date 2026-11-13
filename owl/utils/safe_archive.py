"""Safely extract local ZIP archives into a bounded cache subdirectory.

No network requests or external unzip process. Archive entries are checked
before extraction for path traversal, symlinks, and decompression bombs.
"""
from __future__ import annotations

import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 1000
MAX_BYTES = 100 * 1024 * 1024


def safe_extract_zip(zip_path: str, cache_dir: str) -> list[str]:
    archive = Path(zip_path)
    if archive.suffix.lower() != ".zip":
        raise ValueError("Only .zip files are supported")
    destination = Path(cache_dir) / archive.stem
    base = destination.resolve()

    with zipfile.ZipFile(archive, "r") as zipped:
        infos = zipped.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("ZIP has too many entries")
        total = 0
        targets: set[str] = set()
        approved: list[tuple[zipfile.ZipInfo, Path]] = []
        for info in infos:
            raw = info.filename.replace("\\", "/")
            relative = PurePosixPath(raw)
            if (not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:", raw)
                    or any(part == ".." for part in relative.parts)
                    or relative.is_absolute()):
                raise ValueError(f"Unsafe ZIP member: {info.filename!r}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError(f"ZIP symlink is forbidden: {info.filename!r}")
            target = (destination / relative).resolve()
            if not target.is_relative_to(base):
                raise ValueError(f"ZIP member escapes destination: {info.filename!r}")
            if str(target) in targets:
                raise ValueError(f"Duplicate ZIP member: {info.filename!r}")
            targets.add(str(target))
            if not info.is_dir():
                total += info.file_size
                if total > MAX_BYTES:
                    raise ValueError("ZIP uncompressed size exceeds limit")
            approved.append((info, target))

        # A file entry cannot also be an ancestor of another member.
        # Reject before creating the destination, irrespective of ZIP order.
        file_targets = {target for info, target in approved if not info.is_dir()}
        for _info, target in approved:
            for parent in target.parents:
                if parent == base:
                    break
                if parent in file_targets:
                    raise ValueError(f"ZIP file/directory path conflict: {target}")

        destination.mkdir(parents=True, exist_ok=True)
        extracted = []
        for info, target in approved:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(info) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=64 * 1024)
            extracted.append(str(target))
        return extracted
