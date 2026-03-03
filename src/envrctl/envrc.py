from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .managed_block import (
    SECRET_ENV_PREFIX,
    ManagedBlock,
    parse_export_line,
    parse_managed_block,
    render_managed_block,
    split_envrc,
)

ENVRC_FILENAME = ".envrc"


@dataclass
class EnvrcDocument:
    before: str
    after: str
    managed: Optional[ManagedBlock]
    has_block: bool


def load_envrc(path: Path) -> EnvrcDocument:
    if not path.exists():
        return EnvrcDocument(before="", after="", managed=None, has_block=False)
    text = path.read_text()
    before, managed_lines, after, has_block = split_envrc(text)
    managed = parse_managed_block(managed_lines) if managed_lines is not None else None
    return EnvrcDocument(
        before=before, after=after, managed=managed, has_block=has_block
    )


def ensure_managed_block(doc: EnvrcDocument) -> ManagedBlock:
    if doc.managed is None:
        return ManagedBlock()
    return doc.managed


def extract_unmanaged_exports(
    text: str,
) -> tuple[str, dict[str, str], dict[str, str]]:
    lines = text.splitlines()
    kept: list[str] = []
    exports: dict[str, str] = {}
    secret_refs: dict[str, str] = {}
    for line in lines:
        parsed = parse_export_line(line)
        if parsed is None:
            kept.append(line)
            continue
        var, value = parsed
        if var.startswith(SECRET_ENV_PREFIX):
            secret_var = var[len(SECRET_ENV_PREFIX) :]
            if secret_var:
                secret_refs[secret_var] = value
            continue
        exports[var] = value
    cleaned = "\n".join(kept).rstrip()
    return cleaned, exports, secret_refs


def render_envrc(doc: EnvrcDocument, managed: ManagedBlock) -> str:
    block_text = render_managed_block(managed).rstrip()
    parts = []
    before = doc.before.rstrip()
    after = doc.after.lstrip()
    if before:
        parts.append(before)
    parts.append(block_text)
    if doc.has_block and after:
        parts.append(after)
    elif not doc.has_block and after:
        parts.append(after)
    content = "\n\n".join(part for part in parts if part)
    return content.rstrip() + "\n"


def write_envrc(path: Path, doc: EnvrcDocument, managed: ManagedBlock) -> bool:
    content = render_envrc(doc, managed)
    _atomic_write(path, content)
    return is_world_writable(path)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def is_world_writable(path: Path) -> bool:
    if not path.exists():
        return False
    mode = path.stat().st_mode
    return bool(mode & 0o002)
