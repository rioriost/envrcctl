from envrctl.managed_block import (
    BEGIN_MARKER,
    END_MARKER,
    INJECT_LINE,
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
        secret_refs={"OPENAI_API_KEY": "kc:com.rio.envrcctl:openai:prod"},
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
