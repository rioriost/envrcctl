import os
from pathlib import Path

from envrctl.envrc import (
    ENVRC_FILENAME,
    EnvrcDocument,
    ensure_managed_block,
    extract_unmanaged_exports,
    is_world_writable,
    load_envrc,
    render_envrc,
    write_envrc,
)
from envrctl.managed_block import BEGIN_MARKER, END_MARKER, ManagedBlock


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
    doc = EnvrcDocument(
        before="# before", after="# after", managed=None, has_block=False
    )
    block = ManagedBlock(inherit=True, exports={"FOO": "bar"}, include_inject=True)
    content = render_envrc(doc, block)
    assert BEGIN_MARKER in content
    assert END_MARKER in content
    assert "# before" in content
    assert "# after" in content
    assert "export FOO=bar" in content


def test_render_envrc_preserves_after_when_block_present(tmp_path: Path) -> None:
    doc = EnvrcDocument(
        before="# before", after="# after", managed=ManagedBlock(), has_block=True
    )
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)
    content = render_envrc(doc, block)
    assert "# before" in content
    assert "# after" in content


def test_write_envrc_and_permissions(tmp_path: Path) -> None:
    envrc_path = tmp_path / ENVRC_FILENAME
    doc = load_envrc(envrc_path)
    block = ManagedBlock(exports={"FOO": "bar"}, include_inject=True)

    warn = write_envrc(envrc_path, doc, block)
    assert warn is False
    assert envrc_path.exists()

    os.chmod(envrc_path, 0o666)
    assert is_world_writable(envrc_path) is True
