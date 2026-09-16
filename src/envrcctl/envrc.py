from __future__ import annotations

import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from .errors import EnvrcctlError
from .managed_block import (
    SECRET_ENV_PREFIX,
    VARIABLE_RE,
    ManagedBlock,
    logical_lines,
    parse_export_line,
    parse_managed_block,
    render_managed_block,
    split_envrc,
)

ENVRC_FILENAME = ".envrc"


@dataclass(frozen=True)
class _Snapshot:
    path: str
    content: bytes | None
    identity: tuple[int, ...] | None = None
    mode: int = 0o600


@dataclass
class EnvrcDocument:
    before: str
    after: str
    managed: ManagedBlock | None
    has_block: bool
    _snapshot: _Snapshot | None = field(default=None, repr=False, compare=False)
    _directory_fd: int | None = field(default=None, repr=False, compare=False)


class EnvrcRollbackError(EnvrcctlError):
    """A transaction failed and its document could not be safely restored."""

    def __init__(self, original_error: BaseException, rollback_error: BaseException) -> None:
        self.original_error = original_error
        self.rollback_error = rollback_error
        super().__init__(
            f"Operation failed ({type(original_error).__name__}); "
            f".envrc rollback failed ({type(rollback_error).__name__}). "
            "File/store state may be inconsistent; inspect .envrc and the OS store before retrying."
        )


@contextmanager
def _open_parent(path: Path, *, create: bool = False) -> Iterator[int]:
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parent.parts[1:]:
            try:
                child_fd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o755, dir_fd=fd)
                child_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child_fd
        yield fd
    finally:
        os.close(fd)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _snapshot_at(path: Path, directory_fd: int) -> _Snapshot:
    absolute = os.path.abspath(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return _Snapshot(absolute, None)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise EnvrcctlError(".envrc is not a regular file; refusing to read or write.")
        content = handle.read()
        if _identity(info) != _identity(os.fstat(handle.fileno())):
            raise EnvrcctlError(".envrc changed while reading; retry the operation.")
    return _Snapshot(absolute, content, _identity(info), stat.S_IMODE(info.st_mode))


def load_envrc(path: Path) -> EnvrcDocument:
    try:
        with _open_parent(path) as directory_fd:
            snapshot = _snapshot_at(path, directory_fd)
    except FileNotFoundError:
        snapshot = _Snapshot(os.path.abspath(path), None)
    except OSError as exc:
        raise EnvrcctlError(
            f"Cannot safely read .envrc (symlinks are not allowed): {exc.strerror}."
        ) from exc
    return _document_from_snapshot(snapshot)


def _document_from_snapshot(snapshot: _Snapshot) -> EnvrcDocument:
    try:
        text = snapshot.content.decode("utf-8") if snapshot.content is not None else ""
    except UnicodeError as exc:
        raise EnvrcctlError(".envrc is not valid UTF-8; refusing to edit.") from exc
    before, managed_lines, after, has_block = split_envrc(text)
    managed = parse_managed_block(managed_lines) if managed_lines is not None else None
    return EnvrcDocument(before, after, managed, has_block, snapshot)


def ensure_managed_block(doc: EnvrcDocument) -> ManagedBlock:
    if doc.managed is None:
        return ManagedBlock(include_inject=False)
    return doc.managed


def extract_unmanaged_exports(
    text: str, *, strict: bool = False
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Extract literal exports; strict migration accepts only exports and comments.

    Unknown compound syntax is retained untouched in diagnostic mode. No shell is
    executed, and strict errors leave the caller's original document untouched.
    """
    kept: list[str] = []
    exports: dict[str, str] = {}
    secret_refs: dict[str, str] = {}
    for line in logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        parsed = parse_export_line(line)
        if parsed is None:
            if strict:
                raise EnvrcctlError(
                    "Unsafe or unsupported shell syntax outside the managed block; "
                    "migrate only top-level literal exports and comments."
                )
            # Simple diagnostic commands cannot introduce a conditional/function scope.
            first = stripped.split(maxsplit=1)[0]
            if first in {
                "if",
                "then",
                "else",
                "elif",
                "fi",
                "for",
                "while",
                "until",
                "do",
                "done",
                "case",
                "esac",
                "function",
                "select",
                "export",
            } or any(char in stripped for char in ";&|(){}<>\\'\"`$\n"):
                return text, {}, {}
            kept.append(line)
            continue
        var, value = parsed
        target = exports
        if var.startswith(SECRET_ENV_PREFIX):
            var = var[len(SECRET_ENV_PREFIX) :]
            if not VARIABLE_RE.fullmatch(var):
                if strict:
                    raise EnvrcctlError("Invalid unmanaged secret variable name.")
                return text, {}, {}
            target = secret_refs
        if var in target and target[var] != value:
            if strict:
                raise EnvrcctlError(
                    f"Conflicting unmanaged exports for {var}; refusing to migrate."
                )
            return text, {}, {}
        target[var] = value
    return "".join(kept), exports, secret_refs


def render_envrc(doc: EnvrcDocument, managed: ManagedBlock) -> str:
    before = doc.before
    if before and not before.endswith("\n"):
        before += "\n"
    if not doc.has_block and before and not before.endswith("\n\n"):
        before += "\n"
    return before + render_managed_block(managed) + doc.after


def validate_envrc_write_target(path: Path) -> None:
    try:
        with _open_parent(path) as directory_fd:
            _snapshot_at(path, directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise EnvrcctlError(
            f"Cannot safely write .envrc (symlinks are not allowed): {exc.strerror}."
        ) from exc


def _validate_snapshot(doc: EnvrcDocument, current: _Snapshot) -> None:
    if doc._snapshot is None:
        if current.content is not None:
            raise EnvrcctlError("Load the existing .envrc before writing it.")
    elif current != doc._snapshot:
        raise EnvrcctlError(".envrc changed since it was loaded; retry the operation.")
    if current.mode & 0o002:
        raise EnvrcctlError(".envrc is world-writable; fix permissions before writing.")


@contextmanager
def _write_lock(directory_fd: int, name: str) -> Iterator[None]:
    lock_name = f"{name}.lock"
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    created = False
    try:
        fd = os.open(lock_name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
        created = True
    except FileExistsError:
        fd = os.open(lock_name, flags, dir_fd=directory_fd)
    try:
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise EnvrcctlError("Unsafe .envrc lock file; refusing to write.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        current = os.stat(lock_name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise EnvrcctlError(".envrc lock file changed; retry the operation.")
        yield
    finally:
        os.close(fd)


def preflight_envrc_write(
    path: Path, doc: EnvrcDocument, managed: ManagedBlock | None = None
) -> None:
    """Validate a pending edit before backend mutation; write rechecks under lock.

    This is not a transaction spanning an external secret store. A later I/O error
    or concurrent edit must still be handled by the caller.
    """
    if managed is not None:
        render_envrc(doc, managed)
    try:
        with _locked_document_parent(path, doc) as directory_fd:
            _validate_snapshot(doc, _snapshot_at(path, directory_fd))
            if not os.access(".", os.W_OK | os.X_OK, dir_fd=directory_fd):
                raise EnvrcctlError(".envrc parent directory is not writable.")
    except OSError as exc:
        raise EnvrcctlError(
            f"Cannot safely write .envrc (symlinks are not allowed): {exc.strerror}."
        ) from exc


@contextmanager
def envrc_transaction(path: Path) -> Iterator[EnvrcDocument]:
    """Validate and lock a document, restoring its original bytes on exceptions.

    Call write_envrc before the final backend mutation. A successful exit performs
    no additional writes. On failure, only this transaction's own last file
    version may be restored; a concurrent external change is never overwritten.
    This does not undo a backend that partially mutates its store before failing.
    """
    path = Path(os.path.abspath(path))
    with ExitStack() as stack:
        try:
            directory_fd = stack.enter_context(_open_parent(path, create=True))
            stack.enter_context(_write_lock(directory_fd, path.name))
            snapshot = _snapshot_at(path, directory_fd)
            doc = _document_from_snapshot(snapshot)
        except OSError as exc:
            raise EnvrcctlError(f"Cannot safely update .envrc: {exc.strerror}.") from exc
        doc._directory_fd = directory_fd
        try:
            preflight_envrc_write(path, doc)
            yield doc
        except BaseException as original_error:
            if doc._snapshot != snapshot:
                try:
                    _restore_snapshot(path, snapshot, doc)
                except BaseException as rollback_error:
                    raise EnvrcRollbackError(original_error, rollback_error) from original_error
            raise
        finally:
            doc._directory_fd = None


def _restore_snapshot(path: Path, original: _Snapshot, doc: EnvrcDocument) -> None:
    with _locked_document_parent(path, doc) as directory_fd:
        current = _snapshot_at(path, directory_fd)
        _validate_snapshot(doc, current)
        if original.content is None:
            _validate_parent(path, directory_fd)
            os.unlink(path.name, dir_fd=directory_fd)
            doc._snapshot = _Snapshot(original.path, None)
            os.fsync(directory_fd)
        else:
            _atomic_write(
                path,
                original.content,
                directory_fd=directory_fd,
                snapshot=current,
                document=doc,
                mode=original.mode,
            )
        restored = _document_from_snapshot(doc._snapshot)
        doc.before = restored.before
        doc.after = restored.after
        doc.managed = restored.managed
        doc.has_block = restored.has_block


@contextmanager
def _locked_document_parent(
    path: Path, doc: EnvrcDocument, *, create: bool = False
) -> Iterator[int]:
    if doc._directory_fd is not None:
        if doc._snapshot is None or doc._snapshot.path != os.path.abspath(path):
            raise EnvrcctlError("The .envrc transaction belongs to another path.")
        yield doc._directory_fd
    else:
        with _open_parent(path, create=create) as directory_fd:
            with _write_lock(directory_fd, path.name):
                yield directory_fd


def write_envrc(path: Path, doc: EnvrcDocument, managed: ManagedBlock) -> bool:
    content = render_envrc(doc, managed)
    try:
        with _locked_document_parent(path, doc, create=True) as directory_fd:
            current = _snapshot_at(path, directory_fd)
            _validate_snapshot(doc, current)
            _atomic_write(path, content, directory_fd=directory_fd, snapshot=current, document=doc)
    except OSError as exc:
        raise EnvrcctlError(f"Cannot safely write .envrc: {exc.strerror}.") from exc
    return bool(doc._snapshot.mode & 0o002)


def _validate_parent(path: Path, directory_fd: int) -> None:
    with _open_parent(path) as current_parent:
        original = os.fstat(directory_fd)
        current = os.fstat(current_parent)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise EnvrcctlError(".envrc parent directory changed; refusing to replace.")


def _atomic_write(
    path: Path,
    content: str | bytes,
    *,
    directory_fd: int,
    snapshot: _Snapshot,
    document: EnvrcDocument,
    mode: int | None = None,
) -> None:
    payload = content.encode("utf-8") if isinstance(content, str) else content
    mode = snapshot.mode & 0o777 if mode is None else mode
    name = f"{path.name}.{secrets.token_hex(16)}.tmp"
    fd = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
    )
    created: os.stat_result | None = None
    replaced = False
    try:
        created = os.fstat(fd)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
            current_temp = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (current_temp.st_dev, current_temp.st_ino) != (created.st_dev, created.st_ino):
                raise EnvrcctlError(".envrc staging file changed; refusing to replace.")
            if _snapshot_at(path, directory_fd) != snapshot:
                raise EnvrcctlError(
                    ".envrc changed while preparing the update; retry the operation."
                )
            _validate_parent(path, directory_fd)
            os.replace(name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            replaced = True
            # Record our installed inode before any later failure can trigger rollback.
            document._snapshot = _Snapshot(snapshot.path, payload, _identity(current_temp), mode)
            installed = os.fstat(handle.fileno())
            document._snapshot = _Snapshot(snapshot.path, payload, _identity(installed), mode)
            try:
                os.fsync(directory_fd)
            except OSError as exc:
                raise EnvrcctlError(
                    ".envrc was replaced, but directory fsync failed; durability is uncertain."
                ) from exc
    finally:
        if fd != -1:
            os.close(fd)
        if not replaced and created is not None:
            with suppress(OSError):
                remaining = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (remaining.st_dev, remaining.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(name, dir_fd=directory_fd)


def is_world_writable(path: Path) -> bool:
    if not path.exists():
        return False
    return bool(path.stat().st_mode & 0o002)


def is_group_writable(path: Path) -> bool:
    if not path.exists():
        return False
    return bool(path.stat().st_mode & 0o020)
