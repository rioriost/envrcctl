import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from envrcctl import envrc
from envrcctl.envrc import (
    ENVRC_FILENAME,
    EnvrcDocument,
    EnvrcRollbackError,
    ensure_managed_block,
    envrc_transaction,
    extract_unmanaged_exports,
    is_group_writable,
    is_world_writable,
    load_envrc,
    preflight_envrc_write,
    render_envrc,
    validate_envrc_write_target,
    write_envrc,
)
from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import BEGIN_MARKER, END_MARKER, ManagedBlock


def test_load_envrc_missing_file(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(envrc_path)
    assert doc.has_block is False
    assert doc.managed is None
    assert doc.before == ""
    assert doc.after == ""


def test_ensure_managed_block_creates_default() -> None:
    doc = EnvrcDocument(before="", after="", managed=None, has_block=False)
    block = ensure_managed_block(doc)
    assert isinstance(block, ManagedBlock)
    assert block.exports == {}
    assert block.secret_refs == {}


def test_extract_unmanaged_exports() -> None:
    text = "\n".join(
        [
            "# comment",
            "export FOO=bar",
            'export ENVRCCTL_SECRET_API_KEY="kc:svc:acct"',
            "echo ok",
        ]
    )
    cleaned, exports, secret_refs = extract_unmanaged_exports(text)
    assert "export FOO=bar" not in cleaned
    assert "ENVRCCTL_SECRET_API_KEY" not in cleaned
    assert "echo ok" in cleaned
    assert exports == {"FOO": "bar"}
    assert secret_refs == {"API_KEY": "kc:svc:acct"}


def test_render_envrc_inserts_managed_block(tmp_path: Path) -> None:
    doc = EnvrcDocument(before="# before", after="# after", managed=None, has_block=False)
    block = ManagedBlock(inherit=True, exports={"FOO": "bar"}, include_inject=True)
    content = render_envrc(doc, block)
    assert BEGIN_MARKER in content
    assert END_MARKER in content
    assert "# before" in content
    assert "# after" in content
    assert "export FOO=bar" in content


def test_render_envrc_preserves_after_when_block_present(tmp_path: Path) -> None:
    doc = EnvrcDocument(before="# before", after="# after", managed=ManagedBlock(), has_block=True)
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)
    content = render_envrc(doc, block)
    assert "# before" in content
    assert "# after" in content


def test_is_world_writable_missing_file(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    assert is_world_writable(envrc_path) is False


def test_is_group_writable_missing_file(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    assert is_group_writable(envrc_path) is False


def test_is_group_writable_detects_permissions(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.write_text("# placeholder\n", encoding="utf-8")

    os.chmod(envrc_path, 0o660)
    assert is_group_writable(envrc_path) is True
    assert is_world_writable(envrc_path) is False


def test_write_envrc_and_permissions(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(envrc_path)
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)

    warn = write_envrc(envrc_path, doc, block)
    assert warn is False
    assert envrc_path.exists()

    os.chmod(envrc_path, 0o666)
    assert is_world_writable(envrc_path) is True


def test_write_envrc_rejects_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "real.envrc"
    target.write_text("# existing\n", encoding="utf-8")

    link = tmp_path / ENVRC_FILENAME
    link.symlink_to(target)

    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)

    with pytest.raises(EnvrcctlError):
        load_envrc(link)
    doc = EnvrcDocument(before="", after="", managed=None, has_block=False)
    with pytest.raises(EnvrcctlError):
        write_envrc(link, doc, block)


def test_write_envrc_rejects_non_file_path(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    envrc_path.mkdir()

    doc = EnvrcDocument(before="", after="", managed=None, has_block=False)
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)

    with pytest.raises(EnvrcctlError):
        write_envrc(envrc_path, doc, block)


def test_write_envrc_rejects_symlink_parent(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()

    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)

    envrc_path = link_dir / ENVRC_FILENAME
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)

    with pytest.raises(EnvrcctlError):
        load_envrc(envrc_path)
    doc = EnvrcDocument(before="", after="", managed=None, has_block=False)
    with pytest.raises(EnvrcctlError):
        write_envrc(envrc_path, doc, block)


def test_unrelated_edits_preserve_literal_values_and_outside_bytes(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    before = "# before \t\r\n\n"
    after = "\n# after \t\r\n\n"
    value = 'it\'s "literal": \r\n$HOME\\日本語\u2028\n'
    initial = EnvrcDocument(before, after, None, True)
    write_envrc(path, initial, ManagedBlock(exports={"VALUE": value}))
    loaded = load_envrc(path)
    assert loaded.before == before
    assert loaded.after == after
    assert loaded.managed.exports["VALUE"] == value
    loaded.managed.exports["OTHER"] = "updated"
    write_envrc(path, loaded, loaded.managed)
    again = load_envrc(path)
    assert again.before == before
    assert again.after == after
    assert again.managed.exports == {"VALUE": value, "OTHER": "updated"}


@pytest.mark.parametrize(
    "text",
    [
        'export TARGET="$HOME/bin"\n',
        "export TARGET=$(false)\n",
        "export TARGET=`false`\n",
        "if true; then\n  export TARGET=conditional\nfi\n",
        "function setup() {\n  export TARGET=local\n}\n",
        "setup() {\nexport TARGET=local\n}\n",
        "export TARGET=one; echo complex\n",
        "export TARGET='unterminated\n",
        "cat <<EOF\nexport TARGET=heredoc\nEOF\n",
        "export TARGET=one\nexport TARGET=two\n",
        'export SAFE=one\necho "$SAFE"\n',
    ],
)
def test_strict_extraction_rejects_unsafe_or_ambiguous_shell(text: str) -> None:
    with pytest.raises(EnvrcctlError):
        extract_unmanaged_exports(text, strict=True)


@pytest.mark.parametrize(
    "text",
    [
        "if true; then\n  export TARGET=conditional\nfi\n",
        "setup() {\nexport TARGET=local\n}\n",
        'export TARGET="$HOME"\n',
        "cat <<EOF\nexport TARGET=heredoc\nEOF\n",
    ],
)
def test_diagnostic_extraction_preserves_complex_shell(text: str) -> None:
    assert extract_unmanaged_exports(text) == (text, {}, {})


def test_strict_extraction_handles_multiline_and_preserves_kept_text() -> None:
    text = "# comment \t\r\n\nexport VALUE='first\r\nsecond'\n# last  \n"
    cleaned, exports, references = extract_unmanaged_exports(text, strict=True)
    assert cleaned == "# comment \t\r\n\n# last  \n"
    assert exports == {"VALUE": "first\r\nsecond"}
    assert references == {}


@pytest.mark.parametrize("name", ["VALUE", "ENVRCCTL_SECRET_VALUE"])
@pytest.mark.parametrize("literal", ["'dummy\0value'", '"dummy\0value"', "'dummy\r\n\0value'"])
def test_migration_rejects_embedded_nul_without_mutating_file(
    tmp_path: Path, name: str, literal: str
) -> None:
    path = tmp_path / ENVRC_FILENAME
    text = f"# preserved\r\nexport SAFE=literal\nexport {name}={literal}\n# final \t\n"
    original = text.encode("utf-8")
    path.write_bytes(original)
    path.chmod(0o640)
    original_entries = set(tmp_path.iterdir())
    doc = load_envrc(path)
    assert extract_unmanaged_exports(doc.before) == (text, {}, {})
    with pytest.raises(EnvrcctlError):
        cleaned, exports, references = extract_unmanaged_exports(doc.before, strict=True)
        doc.before = cleaned
        write_envrc(path, doc, ManagedBlock(exports=exports, secret_refs=references))
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert set(tmp_path.iterdir()) == original_entries


@pytest.mark.parametrize("name", ["VALUE", "ENVRCCTL_SECRET_VALUE"])
def test_loading_hand_edited_managed_nul_refuses_update_without_mutation(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / ENVRC_FILENAME
    original = (
        f"# before\r\n{BEGIN_MARKER}\nexport {name}='dummy\0value'\n{END_MARKER}\n# after\r\n"
    ).encode()
    path.write_bytes(original)
    path.chmod(0o640)
    original_entries = set(tmp_path.iterdir())
    with pytest.raises(EnvrcctlError, match="malformed"):
        doc = load_envrc(path)
        block = ensure_managed_block(doc)
        block.exports["OTHER"] = "updated"
        write_envrc(path, doc, block)
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert set(tmp_path.iterdir()) == original_entries


@pytest.mark.parametrize("initially_exists", [False, True])
def test_embedded_nul_write_is_rejected_before_filesystem_mutation(
    tmp_path: Path, initially_exists: bool
) -> None:
    path = tmp_path / ENVRC_FILENAME
    if initially_exists:
        path.write_bytes(b"# original\r\n")
        path.chmod(0o640)
    original_entries = set(tmp_path.iterdir())
    doc = load_envrc(path)
    with pytest.raises(EnvrcctlError, match="NUL"):
        write_envrc(path, doc, ManagedBlock(exports={"VALUE": "dummy\0value"}))
    if initially_exists:
        assert path.read_bytes() == b"# original\r\n"
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    else:
        assert not path.exists()
    assert set(tmp_path.iterdir()) == original_entries


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o660, 0o750])
def test_atomic_write_preserves_existing_permissions(tmp_path: Path, mode: int) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    path.chmod(mode)
    doc = load_envrc(path)
    write_envrc(path, doc, ManagedBlock(exports={"FOO": "bar"}))
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_new_envrc_is_private(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    write_envrc(path, load_envrc(path), ManagedBlock())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_legacy_temporary_symlink_is_untouched(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    victim = tmp_path / "victim"
    victim.write_text("untouched", encoding="utf-8")
    old_temporary = tmp_path / ".envrc.tmp"
    old_temporary.symlink_to(victim)
    write_envrc(path, load_envrc(path), ManagedBlock(exports={"FOO": "bar"}))
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert old_temporary.is_symlink()
    assert not path.is_symlink()


def test_exclusive_temporary_creation_does_not_follow_symlinks(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ENVRC_FILENAME
    victim = tmp_path / "victim"
    victim.write_text("untouched", encoding="utf-8")
    collision = tmp_path / ".envrc.fixed.tmp"
    collision.symlink_to(victim)
    monkeypatch.setattr(envrc.secrets, "token_hex", lambda size: "fixed")
    with pytest.raises(EnvrcctlError):
        write_envrc(path, load_envrc(path), ManagedBlock())
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert collision.is_symlink()
    assert not path.exists()


@pytest.mark.parametrize("dangling", [False, True])
def test_preflight_rejects_symlink_target_without_touching_it(
    tmp_path: Path, dangling: bool
) -> None:
    path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(path)
    target = tmp_path / "victim"
    if not dangling:
        target.write_text("untouched", encoding="utf-8")
    path.symlink_to(target)
    for operation in (
        lambda: validate_envrc_write_target(path),
        lambda: preflight_envrc_write(path, doc),
        lambda: write_envrc(path, doc, ManagedBlock()),
    ):
        with pytest.raises(EnvrcctlError):
            operation()
    assert target.exists() is not dangling
    if not dangling:
        assert target.read_text(encoding="utf-8") == "untouched"


def test_unsafe_lock_file_is_not_followed(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    victim = tmp_path / "victim"
    victim.write_text("untouched", encoding="utf-8")
    (tmp_path / ".envrc.lock").symlink_to(victim)
    with pytest.raises(EnvrcctlError):
        preflight_envrc_write(path, load_envrc(path))
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert not path.exists()


def test_preflight_refuses_world_writable_and_invalid_values(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    path.chmod(0o666)
    doc = load_envrc(path)
    with pytest.raises(EnvrcctlError, match="world-writable"):
        preflight_envrc_write(path, doc, ManagedBlock())
    path.chmod(0o600)
    doc = load_envrc(path)
    with pytest.raises(EnvrcctlError, match="NUL"):
        preflight_envrc_write(path, doc, ManagedBlock(exports={"FOO": "\0"}))
    assert path.read_text(encoding="utf-8") == "# original\n"


@pytest.mark.parametrize("initially_exists", [False, True])
def test_stale_document_cannot_overwrite_newer_changes(
    tmp_path: Path, initially_exists: bool
) -> None:
    path = tmp_path / ENVRC_FILENAME
    if initially_exists:
        path.write_text("# original\n", encoding="utf-8")
    first = load_envrc(path)
    second = load_envrc(path)
    write_envrc(path, first, ManagedBlock(exports={"FIRST": "one"}))
    expected = path.read_bytes()
    with pytest.raises(EnvrcctlError, match="changed"):
        preflight_envrc_write(path, second)
    with pytest.raises(EnvrcctlError, match="changed"):
        write_envrc(path, second, ManagedBlock(exports={"SECOND": "two"}))
    assert path.read_bytes() == expected


def test_two_processes_detect_lost_update(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    code = """
import sys
from pathlib import Path
from envrcctl.envrc import load_envrc, write_envrc
from envrcctl.managed_block import ManagedBlock
from envrcctl.errors import EnvrcctlError
path = Path(sys.argv[1])
doc = load_envrc(path)
print("ready", flush=True)
input()
try:
    write_envrc(path, doc, ManagedBlock(exports={sys.argv[2]: "value"}))
except EnvrcctlError as exc:
    print(str(exc), flush=True)
    sys.exit(2)
"""
    children = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), key],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for key in ("FIRST", "SECOND")
    ]
    try:
        for child in children:
            assert child.stdout.readline().strip() == "ready"
        for child in children:
            child.stdin.write("\n")
            child.stdin.flush()
        results = [child.communicate(timeout=20) for child in children]
        assert sorted(child.returncode for child in children) == [0, 2]
        assert any("changed" in stdout for stdout, _ in results)
        assert len(load_envrc(path).managed.exports) == 1
        assert not list(tmp_path.glob(".envrc.*.tmp"))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=20)


@pytest.mark.parametrize("failure", ["replace", "file_fsync"])
def test_failed_atomic_write_preserves_original_and_cleans_staging(
    tmp_path: Path, monkeypatch, failure: str
) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    path.chmod(0o600)
    doc = load_envrc(path)

    def fail(*args, **kwargs):
        raise OSError("injected failure")

    monkeypatch.setattr(envrc.os, "replace" if failure == "replace" else "fsync", fail)
    with pytest.raises(EnvrcctlError):
        write_envrc(path, doc, ManagedBlock(exports={"FOO": "bar"}))
    assert path.read_text(encoding="utf-8") == "# original\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_directory_fsync_failure_reports_completed_replace(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(path)
    real_fsync = os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(envrc.os, "fsync", fail_directory)
    with pytest.raises(EnvrcctlError, match="was replaced"):
        write_envrc(path, doc, ManagedBlock(exports={"FOO": "bar"}))
    assert load_envrc(path).managed.exports == {"FOO": "bar"}
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_staging_symlink_replacement_is_not_installed(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.write_text("untouched", encoding="utf-8")
    real_fsync = os.fsync

    def replace_staging(fd):
        real_fsync(fd)
        staging = next(tmp_path.glob(".envrc.*.tmp"))
        staging.unlink()
        staging.symlink_to(victim)

    monkeypatch.setattr(envrc.os, "fsync", replace_staging)
    with pytest.raises(EnvrcctlError, match="staging"):
        write_envrc(path, load_envrc(path), ManagedBlock())
    assert path.read_text(encoding="utf-8") == "# original\n"
    assert victim.read_text(encoding="utf-8") == "untouched"
    assert next(tmp_path.glob(".envrc.*.tmp")).is_symlink()


def test_transaction_supports_preflight_and_write_without_relocking(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    with envrc_transaction(path) as doc:
        block = ManagedBlock(exports={"FOO": "first"})
        preflight_envrc_write(path, doc, block)
        write_envrc(path, doc, block)
        block.exports["BAR"] = "second"
        preflight_envrc_write(path, doc, block)
        write_envrc(path, doc, block)
    assert doc._directory_fd is None
    assert load_envrc(path).managed.exports == {"FOO": "first", "BAR": "second"}
    assert stat.S_IMODE((tmp_path / ".envrc.lock").stat().st_mode) == 0o600


def test_transaction_rejects_another_document_path(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    other_path = tmp_path / "other.envrc"
    with envrc_transaction(path) as doc:
        with pytest.raises(EnvrcctlError, match="another path"):
            write_envrc(other_path, doc, ManagedBlock())
    assert not path.exists()
    assert not other_path.exists()


def test_transaction_error_releases_lock_without_writing(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    with pytest.raises(RuntimeError, match="backend failure"):
        with envrc_transaction(path):
            raise RuntimeError("backend failure")
    assert not path.exists()
    with envrc_transaction(path) as doc:
        write_envrc(path, doc, ManagedBlock(exports={"AFTER": "works"}))
    assert load_envrc(path).managed.exports == {"AFTER": "works"}


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o750, 0o4600])
@pytest.mark.parametrize("exception_type", [RuntimeError, OSError, KeyboardInterrupt])
def test_transaction_failure_restores_exact_original_bytes_and_mode(
    tmp_path: Path, mode: int, exception_type: type[BaseException]
) -> None:
    path = tmp_path / ENVRC_FILENAME
    original = b"# original \t\r\nexport UNMANAGED='it'\"'\"'s'\n\n# no final newline"
    path.write_bytes(original)
    path.chmod(mode)
    error = exception_type("original backend failure")
    with pytest.raises(exception_type) as caught:
        with envrc_transaction(path) as doc:
            block = ensure_managed_block(doc)
            block.secret_refs["API"] = "kc:service:account"
            write_envrc(path, doc, block)
            assert path.read_bytes() != original
            raise error
    assert caught.value is error
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert doc._directory_fd is None
    assert doc.before.encode("utf-8") == original
    assert not doc.has_block
    assert doc.managed is None
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_transaction_failure_removes_only_newly_created_envrc(tmp_path: Path) -> None:
    path = tmp_path / "project" / ENVRC_FILENAME
    other = tmp_path / "must-remain"
    other.write_text("untouched", encoding="utf-8")
    with pytest.raises(RuntimeError, match="backend failure"):
        with envrc_transaction(path) as doc:
            write_envrc(path, doc, ManagedBlock(exports={"FOO": "value"}))
            assert path.exists()
            raise RuntimeError("backend failure")
    assert not path.exists()
    assert path.parent.is_dir()
    assert (path.parent / ".envrc.lock").is_file()
    assert other.read_text(encoding="utf-8") == "untouched"
    assert doc._snapshot.content is None
    assert not list(path.parent.glob(".envrc.*.tmp"))


def test_transaction_rollback_is_anchored_when_backend_changes_cwd(tmp_path: Path, monkeypatch):
    path = tmp_path / ENVRC_FILENAME
    path.write_bytes(b"# original\n")
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError):
        with envrc_transaction(Path(ENVRC_FILENAME)) as doc:
            write_envrc(Path(ENVRC_FILENAME), doc, ManagedBlock(exports={"NEW": "value"}))
            monkeypatch.chdir(other)
            raise RuntimeError("backend failure")
    assert path.read_bytes() == b"# original\n"
    assert not (other / ENVRC_FILENAME).exists()


def test_transaction_rolls_back_all_its_writes(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    original = b"# original\n"
    path.write_bytes(original)
    with pytest.raises(RuntimeError):
        with envrc_transaction(path) as doc:
            block = ManagedBlock(exports={"FIRST": "one"})
            write_envrc(path, doc, block)
            block.exports["SECOND"] = "two"
            write_envrc(path, doc, block)
            raise RuntimeError("backend failure")
    assert path.read_bytes() == original


@pytest.mark.parametrize("initially_exists", [False, True])
@pytest.mark.parametrize("external_change", ["edit", "symlink", "delete", "replace_parent"])
def test_transaction_rollback_refuses_external_changes(
    tmp_path: Path, initially_exists: bool, external_change: str
) -> None:
    parent = tmp_path / "project"
    parent.mkdir()
    path = parent / ENVRC_FILENAME
    if initially_exists:
        path.write_text("# original\n", encoding="utf-8")
    victim = tmp_path / "victim"
    victim.write_text("# external change\n", encoding="utf-8")
    original_error = RuntimeError("sensitive backend failure")
    with pytest.raises(EnvrcRollbackError) as caught:
        with envrc_transaction(path) as doc:
            write_envrc(path, doc, ManagedBlock(exports={"FOO": "value"}))
            if external_change == "edit":
                path.write_text("# external change\n", encoding="utf-8")
            elif external_change == "symlink":
                path.unlink()
                path.symlink_to(victim)
            elif external_change == "delete":
                path.unlink()
            else:
                parent.rename(tmp_path / "moved")
                parent.mkdir()
                path.write_text("# external change\n", encoding="utf-8")
            raise original_error
    assert "rollback failed" in str(caught.value)
    assert "sensitive backend failure" not in str(caught.value)
    assert caught.value.original_error is original_error
    assert caught.value.__cause__ is original_error
    assert isinstance(caught.value.rollback_error, (EnvrcctlError, OSError))
    assert victim.read_text(encoding="utf-8") == "# external change\n"
    if external_change == "delete":
        assert not path.exists()
    else:
        assert path.read_text(encoding="utf-8") == "# external change\n"
    if external_change == "symlink":
        assert path.is_symlink()


@pytest.mark.parametrize("initially_exists", [False, True])
def test_transaction_compensation_io_failure_is_explicit_and_redacted(
    tmp_path: Path, monkeypatch, initially_exists: bool
) -> None:
    path = tmp_path / ENVRC_FILENAME
    if initially_exists:
        path.write_text("# original\n", encoding="utf-8")
    original_error = RuntimeError("sensitive backend failure")
    rollback_error = OSError("sensitive rollback failure")

    def fail(*args, **kwargs):
        raise rollback_error

    with pytest.raises(EnvrcRollbackError) as caught:
        with envrc_transaction(path) as doc:
            write_envrc(path, doc, ManagedBlock(exports={"NEW": "value"}))
            monkeypatch.setattr(envrc.os, "replace" if initially_exists else "unlink", fail)
            raise original_error
    assert caught.value.original_error is original_error
    assert caught.value.rollback_error is rollback_error
    assert caught.value.__cause__ is original_error
    assert "rollback failed" in str(caught.value)
    assert "sensitive" not in str(caught.value)
    assert load_envrc(path).managed.exports == {"NEW": "value"}


@pytest.mark.parametrize("initially_exists", [False, True])
def test_transaction_rolls_back_replace_even_when_directory_fsync_failed(
    tmp_path: Path, monkeypatch, initially_exists: bool
) -> None:
    path = tmp_path / ENVRC_FILENAME
    original = b"# original\r\n"
    if initially_exists:
        path.write_bytes(original)
        path.chmod(0o640)
    real_fsync = os.fsync
    failed = False

    def fail_once(fd):
        nonlocal failed
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed = True
            raise OSError("injected directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(envrc.os, "fsync", fail_once)
    with pytest.raises(EnvrcctlError, match="was replaced"):
        with envrc_transaction(path) as doc:
            write_envrc(path, doc, ManagedBlock(exports={"NEW": "value"}))
            pytest.fail("Backend code must not run after a write failure.")
    if initially_exists:
        assert path.read_bytes() == original
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    else:
        assert not path.exists()
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_transaction_success_has_no_writes_after_backend_operation(tmp_path: Path, monkeypatch):
    path = tmp_path / ENVRC_FILENAME

    def unexpected_write(*args, **kwargs):
        pytest.fail("A successful backend operation must not be followed by filesystem writes.")

    with envrc_transaction(path) as doc:
        write_envrc(path, doc, ManagedBlock(exports={"COMMITTED": "value"}))
        monkeypatch.setattr(envrc.os, "replace", unexpected_write)
        monkeypatch.setattr(envrc.os, "unlink", unexpected_write)
        monkeypatch.setattr(envrc.os, "fsync", unexpected_write)
    assert load_envrc(path).managed.exports == {"COMMITTED": "value"}


def test_failed_write_leaves_backend_and_original_file_untouched(tmp_path: Path, monkeypatch):
    path = tmp_path / ENVRC_FILENAME
    path.write_bytes(b"# original\n")
    backend_calls = []

    def fail(*args, **kwargs):
        raise OSError("injected replacement failure")

    monkeypatch.setattr(envrc.os, "replace", fail)
    with pytest.raises(EnvrcctlError):
        with envrc_transaction(path) as doc:
            write_envrc(path, doc, ManagedBlock(exports={"NEW": "value"}))
            backend_calls.append("mutation")
    assert backend_calls == []
    assert path.read_bytes() == b"# original\n"
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_external_edit_during_staging_is_not_overwritten(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    doc = load_envrc(path)
    real_fsync = os.fsync

    def external_edit(fd):
        real_fsync(fd)
        path.write_text("# external edit\n", encoding="utf-8")

    monkeypatch.setattr(envrc.os, "fsync", external_edit)
    with pytest.raises(EnvrcctlError, match="changed"):
        write_envrc(path, doc, ManagedBlock(exports={"FOO": "bar"}))
    assert path.read_text(encoding="utf-8") == "# external edit\n"
    assert not list(tmp_path.glob(".envrc.*.tmp"))


def test_parent_replacement_during_write_is_rejected(tmp_path: Path, monkeypatch) -> None:
    parent = tmp_path / "project"
    parent.mkdir()
    path = parent / ENVRC_FILENAME
    path.write_text("# original\n", encoding="utf-8")
    doc = load_envrc(path)
    moved = tmp_path / "moved"
    real_fsync = os.fsync

    def move_parent(fd):
        real_fsync(fd)
        parent.rename(moved)
        parent.mkdir()
        (parent / ENVRC_FILENAME).write_text("# replacement\n", encoding="utf-8")

    monkeypatch.setattr(envrc.os, "fsync", move_parent)
    with pytest.raises(EnvrcctlError, match="parent directory changed"):
        write_envrc(path, doc, ManagedBlock())
    assert path.read_text(encoding="utf-8") == "# replacement\n"
    assert (moved / ENVRC_FILENAME).read_text(encoding="utf-8") == "# original\n"
    assert not list(moved.glob(".envrc.*.tmp"))


def test_write_nested_missing_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "project" / ENVRC_FILENAME
    write_envrc(path, load_envrc(path), ManagedBlock(exports={"FOO": "bar"}))
    assert load_envrc(path).managed.exports == {"FOO": "bar"}


def test_invalid_utf8_file_cannot_be_loaded(tmp_path: Path) -> None:
    path = tmp_path / ENVRC_FILENAME
    path.write_bytes(b"\xff")
    with pytest.raises(EnvrcctlError, match="UTF-8"):
        load_envrc(path)
    assert path.read_bytes() == b"\xff"


def test_strict_migration_preserves_effective_shell_values(tmp_path: Path) -> None:
    text = "# literal exports only\nexport FIRST='one\\two'\nexport SECOND='it'\"'\"'s'\n"
    before = tmp_path / "before.envrc"
    after = tmp_path / "after.envrc"
    before.write_text(text, encoding="utf-8")
    cleaned, exports, secret_refs = extract_unmanaged_exports(text, strict=True)
    doc = EnvrcDocument(cleaned, "", None, False)
    after.write_text(
        render_envrc(doc, ManagedBlock(exports=exports, secret_refs=secret_refs)),
        encoding="utf-8",
    )
    outputs = []
    for script in (before, after):
        outputs.append(
            subprocess.run(
                [
                    "bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    'source "$1"; printf "%s\\0%s" "$FIRST" "$SECOND"',
                    "bash",
                    str(script),
                ],
                capture_output=True,
                check=True,
            ).stdout
        )
    assert outputs[0] == outputs[1] == b"one\\two\0it's"
