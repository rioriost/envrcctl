import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from envrcctl.errors import EnvrcctlError
from envrcctl.managed_block import (
    BEGIN_MARKER,
    END_MARKER,
    INJECT_LINE,
    LEGACY_INJECT_LINE,
    ManagedBlock,
    parse_export_line,
    parse_managed_block,
    render_managed_block,
    split_envrc,
)


def test_parse_export_line_handles_quotes() -> None:
    assert parse_export_line("export FOO=bar") == ("FOO", "bar")
    assert parse_export_line("export FOO='bar baz'") == ("FOO", "bar baz")
    assert parse_export_line('export FOO="bar baz"') == ("FOO", "bar baz")
    assert parse_export_line("echo nope") is None


def test_render_and_parse_roundtrip() -> None:
    block = ManagedBlock(
        inherit=True,
        exports={"FOO": "bar", "BAZ": "qux"},
        secret_refs={"OPENAI_API_KEY": "kc:st.rio.envrcctl:openai:prod"},
        include_inject=True,
    )
    rendered = render_managed_block(block)
    assert BEGIN_MARKER in rendered
    assert END_MARKER in rendered
    assert INJECT_LINE in rendered

    before, managed_lines, after, has_block = split_envrc(rendered)
    assert has_block is True
    assert managed_lines is not None
    assert before == ""
    assert after == ""

    parsed = parse_managed_block(managed_lines)
    assert parsed.inherit is True
    assert parsed.include_inject is True
    assert parsed.exports == block.exports
    assert parsed.secret_refs == block.secret_refs


def test_split_envrc_without_block() -> None:
    text = "export FOO=bar\n"
    before, managed_lines, after, has_block = split_envrc(text)
    assert has_block is False
    assert managed_lines is None
    assert before == text
    assert after == ""


def test_split_envrc_missing_end_marker() -> None:
    text = "\n".join([BEGIN_MARKER, "# managed: true", "export FOO=bar"])
    with pytest.raises(EnvrcctlError, match="markers"):
        split_envrc(text)


@pytest.mark.parametrize(
    "line",
    [
        "export BAD",
        "notexport",
        "source_up --unsafe",
        "source_upward",
        "export FOO='unterminated",
        'export FOO="$HOME/bin"',
        "export FOO=$(touch never-created)",
        "export FOO=bar; echo unsafe",
        "export FOO=one two",
        "export ENVRCCTL_SECRET_=invalid",
        "export ENVRCCTL_SECRET_1BAD=invalid",
    ],
)
def test_parse_managed_block_rejects_unsupported_lines(line: str) -> None:
    with pytest.raises(EnvrcctlError):
        parse_managed_block(["export GOOD=1", line])


@pytest.mark.parametrize(
    "text",
    [
        END_MARKER,
        END_MARKER + "\n" + BEGIN_MARKER,
        BEGIN_MARKER + "\n" + BEGIN_MARKER + "\n" + END_MARKER,
        (BEGIN_MARKER + "\n" + END_MARKER + "\n") * 2,
        BEGIN_MARKER + " unexpected\n" + END_MARKER,
        "# >>> envrcctl:begn\n" + END_MARKER,
    ],
)
def test_split_envrc_rejects_malformed_markers(text: str) -> None:
    with pytest.raises(EnvrcctlError, match="marker"):
        split_envrc(text)


LITERAL_VALUES = [
    "",
    "it's valid",
    '"double quoted"',
    """both 'single' and "double" quotes""",
    "first\nsecond",
    "\nleading and trailing\n",
    "carriage\rreturn\r\nline",
    "tab\tvertical\vform\f",
    "back\\slash\\",
    "$HOME ${HOME} $(touch never-created) `false`",
    "Unicode 日本語 🙂 \u2028 \u2029",
    " " * 3,
    "\n" + BEGIN_MARKER + "\n" + END_MARKER + "\n",
]


@pytest.mark.parametrize("value", LITERAL_VALUES)
def test_literal_render_parse_and_shell_roundtrip(value: str, tmp_path: Path) -> None:
    block = ManagedBlock(exports={"VALUE": value}, secret_refs={"API": value})
    rendered = render_managed_block(block)
    _, lines, _, present = split_envrc(rendered)
    assert present and lines is not None
    assert parse_managed_block(lines) == block
    script = tmp_path / "literal.envrc"
    script.write_bytes(rendered.encode("utf-8"))
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            'source "$1"; "$2" -c '
            '\'import json, os; print(json.dumps([os.environ["VALUE"], '
            'os.environ["ENVRCCTL_SECRET_API"]]))\'',
            "bash",
            str(script),
            sys.executable,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == [value, value]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("export FOO='it'\"'\"'s valid'", "it's valid"),
        (r"export FOO=two\ words", "two words"),
        (r'export FOO="\$HOME \`false\` \\ \" \q"', '$HOME `false` \\ " \\q'),
        ("export FOO=first\\\nsecond", "firstsecond"),
        ("export FOO='first\nsecond'", "first\nsecond"),
        ("export FOO=bar # retained literal", "bar"),
        ("export FOO=#hash", "#hash"),
        ("export FOO=", ""),
    ],
)
def test_literal_parser_supported_grammar(line: str, expected: str) -> None:
    assert parse_export_line(line) == ("FOO", expected)


@pytest.mark.parametrize(
    "value",
    [
        "$HOME",
        '"$HOME"',
        "$(false)",
        "`false`",
        "~",
        "{a,b}",
        "$'ansi'",
        "one;false",
        "one && false",
        "(false)",
        "'open",
        '"open',
        "open\\",
        "\0",
    ],
)
def test_literal_parser_refuses_nonliteral_values(value: str) -> None:
    assert parse_export_line("export FOO=" + value) is None


@pytest.mark.parametrize("name", ["VALUE", "ENVRCCTL_SECRET_VALUE"])
@pytest.mark.parametrize(
    "literal",
    [
        "'dummy\0value'",
        '"dummy\0value"',
        "dummy\0value",
        "'dummy\r\n\0value'",
    ],
)
def test_literal_and_managed_parsers_reject_embedded_nul(name: str, literal: str) -> None:
    line = f"export {name}={literal}"
    assert parse_export_line(line) is None
    with pytest.raises(EnvrcctlError, match="malformed"):
        parse_managed_block([line])


@pytest.mark.parametrize("field", ["exports", "secret_refs"])
def test_renderer_rejects_directly_constructed_embedded_nul(field: str) -> None:
    block = ManagedBlock(**{field: {"VALUE": "dummy\0value"}})
    with pytest.raises(EnvrcctlError, match="NUL"):
        render_managed_block(block)


def test_parser_does_not_execute_shell(tmp_path: Path) -> None:
    sentinel = tmp_path / "must-not-exist"
    assert parse_export_line(f"export FOO=$(touch {sentinel})") is None
    with pytest.raises(EnvrcctlError):
        parse_managed_block([f"export FOO=`touch {sentinel}`"])
    assert not sentinel.exists()


def test_parser_rejects_duplicate_exports() -> None:
    with pytest.raises(EnvrcctlError, match="Duplicate"):
        parse_managed_block(["export FOO=one", "export FOO=two"])


@pytest.mark.parametrize(
    "lines",
    [
        ["source_up", "source_up"],
        ["export FOO=one", "source_up"],
        [LEGACY_INJECT_LINE, INJECT_LINE],
        [LEGACY_INJECT_LINE, "export FOO=one"],
        [BEGIN_MARKER, "export FOO=one"],
    ],
)
def test_parser_refuses_ambiguous_managed_directive_order(lines: list[str]) -> None:
    with pytest.raises(EnvrcctlError):
        parse_managed_block(lines)


@pytest.mark.parametrize(
    "block",
    [
        ManagedBlock(exports={"invalid-name": "value"}),
        ManagedBlock(exports={"ENVRCCTL_SECRET_API": "value"}),
        ManagedBlock(secret_refs={"1INVALID": "value"}),
        ManagedBlock(exports={"VALID": "\0"}),
        ManagedBlock(exports={"VALID": "\ud800"}),
    ],
)
def test_renderer_refuses_unrepresentable_blocks(block: ManagedBlock) -> None:
    with pytest.raises(EnvrcctlError):
        render_managed_block(block)


def test_legacy_inject_line_is_upgraded() -> None:
    block = parse_managed_block([LEGACY_INJECT_LINE])
    assert block.include_inject
    assert INJECT_LINE in render_managed_block(block)
    assert LEGACY_INJECT_LINE not in render_managed_block(block)


@pytest.mark.parametrize("exit_code", [0, 1, 17])
def test_generated_inject_checks_status_before_eval(tmp_path: Path, exit_code: int) -> None:
    script = tmp_path / "inject.envrc"
    script.write_text(INJECT_LINE + "\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("INJECTED", None)
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            'envrcctl() { test "$1 $2" = "inject --shell" || return 99; '
            f"printf 'export INJECTED=yes\\n'; return {exit_code}; "
            '}; source "$1"; status=$?; printf "%s:%s" "$status" "${INJECTED-unset}"',
            "bash",
            str(script),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ("0:yes" if exit_code == 0 else "1:unset")
