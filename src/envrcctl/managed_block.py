from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from .errors import EnvrcctlError

BEGIN_MARKER = "# >>> envrcctl:begin"
END_MARKER = "# <<< envrcctl:end"
MANAGED_HEADER = "# managed: true"
INJECT_LINE = (
    "if _envrcctl_inject=$(envrcctl inject --shell); then "
    'eval "$_envrcctl_inject"; unset _envrcctl_inject; '
    "else unset _envrcctl_inject; return 1; fi"
)
LEGACY_INJECT_LINE = 'eval "$(envrcctl inject)"'
# Prefix label for secret environment variables.
SECRET_ENV_PREFIX = "ENVRCCTL_SECRET_"  # nosec B105

VARIABLE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
EXPORT_RE = re.compile(r"^[ \t]*export[ \t]+([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def parse_export_line(line: str) -> tuple[str, str] | None:
    """Parse one literal export, never evaluating expansions or shell commands."""
    match = EXPORT_RE.fullmatch(line.removesuffix("\n"))
    if not match:
        return None
    value = _unquote_value(match.group(2))
    return None if value is None else (match.group(1), value)


@dataclass
class ManagedBlock:
    inherit: bool = False
    exports: dict[str, str] = field(default_factory=dict)
    secret_refs: dict[str, str] = field(default_factory=dict)
    include_inject: bool = False


def logical_lines(text: str) -> list[str]:
    """Keep quoted newlines and shell continuations within their original statement."""
    lines: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    comment = False
    for index, char in enumerate(text):
        if comment:
            if char == "\n":
                comment = False
                lines.append(text[start : index + 1])
                start = index + 1
            continue
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"', "`"):
            quote = char
        elif char == "#" and (index == start or text[index - 1] in " \t;|&()"):
            comment = True
        elif char == "\n":
            lines.append(text[start : index + 1])
            start = index + 1
    if start < len(text):
        lines.append(text[start:])
    return lines


def split_envrc(text: str) -> tuple[str, list[str] | None, str, bool]:
    markers: list[tuple[str, int, int]] = []
    offset = 0
    for line in logical_lines(text):
        stripped = line.strip()
        if stripped in (BEGIN_MARKER, END_MARKER):
            markers.append((stripped, offset, offset + len(line)))
        elif stripped.startswith(("# >>> envrcctl:", "# <<< envrcctl:")):
            raise EnvrcctlError("Malformed envrcctl managed-block marker; refusing to edit.")
        offset += len(line)
    if not markers:
        return text, None, "", False
    if [marker[0] for marker in markers] != [BEGIN_MARKER, END_MARKER]:
        raise EnvrcctlError(
            "Malformed or duplicate envrcctl managed-block markers; refusing to edit."
        )
    _, begin, content_start = markers[0]
    _, content_end, end = markers[1]
    managed_text = text[content_start:content_end].removesuffix("\n")
    return text[:begin], managed_text.split("\n"), text[end:], True


def parse_managed_block(lines: list[str]) -> ManagedBlock:
    block = ManagedBlock(include_inject=False)
    seen: set[str] = set()
    for raw in logical_lines("\n".join(lines)):
        stripped = raw.strip()
        if stripped.startswith(("# >>> envrcctl:", "# <<< envrcctl:")):
            raise EnvrcctlError("Unexpected marker inside the managed block.")
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "source_up":
            if block.inherit or seen or block.include_inject:
                raise EnvrcctlError("source_up must appear once before managed exports.")
            block.inherit = True
            continue
        if stripped in (INJECT_LINE, LEGACY_INJECT_LINE):
            if block.include_inject:
                raise EnvrcctlError("Duplicate managed inject line; refusing to edit.")
            block.include_inject = True
            continue
        parsed = parse_export_line(raw)
        if parsed is None:
            raise EnvrcctlError("Unsupported or malformed managed-block line; refusing to edit.")
        if block.include_inject:
            raise EnvrcctlError("Managed exports must precede the inject line.")
        var, value = parsed
        if var in seen:
            raise EnvrcctlError(f"Duplicate managed export {var}; refusing to edit.")
        seen.add(var)
        if var.startswith(SECRET_ENV_PREFIX):
            secret_var = var[len(SECRET_ENV_PREFIX) :]
            if not VARIABLE_RE.fullmatch(secret_var):
                raise EnvrcctlError("Invalid managed secret variable name; refusing to edit.")
            block.secret_refs[secret_var] = value
        else:
            block.exports[var] = value
    return block


def render_managed_block(block: ManagedBlock) -> str:
    for key in block.exports:
        if not VARIABLE_RE.fullmatch(key) or key.startswith(SECRET_ENV_PREFIX):
            raise EnvrcctlError("Invalid or reserved managed export variable name.")
    for key in block.secret_refs:
        if not VARIABLE_RE.fullmatch(key):
            raise EnvrcctlError("Invalid managed secret variable name.")
    lines: list[str] = [BEGIN_MARKER, MANAGED_HEADER, ""]
    if block.inherit:
        lines.append("source_up")
        lines.append("")

    for key in sorted(block.exports.keys()):
        value = _shell_quote(block.exports[key])
        lines.append(f"export {key}={value}")

    if block.secret_refs:
        if lines and lines[-1] != "":
            lines.append("")
        for key in sorted(block.secret_refs.keys()):
            value = _shell_quote(block.secret_refs[key])
            lines.append(f"export {SECRET_ENV_PREFIX}{key}={value}")

    if block.include_inject:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(INJECT_LINE)

    lines.append("")
    lines.append(END_MARKER)
    return "\n".join(lines).rstrip() + "\n"


def _unquote_value(value: str) -> str | None:
    if "\0" in value:
        return None
    result: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                result.append(char)
        elif char == "\\":
            index += 1
            if index == len(value):
                return None
            escaped = value[index]
            if quote == '"' and escaped not in '$`"\\\n':
                result.append("\\")
            if escaped != "\n":
                result.append(escaped)
        elif quote == '"':
            if char == '"':
                quote = None
            elif char in "$`":
                return None
            else:
                result.append(char)
        elif char in ("'", '"'):
            quote = char
        elif char in " \t\n":
            tail = value[index:].lstrip(" \t\n")
            if not tail or (tail.startswith("#") and "\n" not in tail.rstrip("\n")):
                return "".join(result)
            return None
        elif char in "$`~;|&()<>{}*?[]":
            return None
        else:
            result.append(char)
        index += 1
    return "".join(result) if quote is None else None


def _shell_quote(value: str) -> str:
    if "\0" in value:
        raise EnvrcctlError("Environment values cannot contain NUL bytes.")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise EnvrcctlError("Environment values must be valid UTF-8.") from exc
    return shlex.quote(value)
