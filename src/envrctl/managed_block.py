from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

BEGIN_MARKER = "# >>> envrcctl:begin"
END_MARKER = "# <<< envrcctl:end"
MANAGED_HEADER = "# managed: true"
INJECT_LINE = 'eval "$(envrcctl inject)"'
SECRET_ENV_PREFIX = "ENVRCCTL_SECRET_"

EXPORT_RE = re.compile(r"^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def parse_export_line(line: str) -> tuple[str, str] | None:
    match = EXPORT_RE.match(line.strip())
    if not match:
        return None
    var, value = match.group(1), match.group(2).strip()
    return var, _unquote_value(value)


@dataclass
class ManagedBlock:
    inherit: bool = False
    exports: Dict[str, str] = field(default_factory=dict)
    secret_refs: Dict[str, str] = field(default_factory=dict)
    include_inject: bool = True


def split_envrc(text: str) -> Tuple[str, List[str] | None, str, bool]:
    lines = text.splitlines()
    begin_idx = _find_line_index(lines, BEGIN_MARKER)
    if begin_idx is None:
        return text, None, "", False
    end_idx = _find_line_index(lines, END_MARKER, start=begin_idx + 1)
    if end_idx is None:
        return text, None, "", False

    before = "\n".join(lines[:begin_idx])
    managed_lines = lines[begin_idx + 1 : end_idx]
    after = "\n".join(lines[end_idx + 1 :])
    return before, managed_lines, after, True


def parse_managed_block(lines: List[str]) -> ManagedBlock:
    block = ManagedBlock(include_inject=False)
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("source_up"):
            block.inherit = True
            continue
        if stripped == INJECT_LINE:
            block.include_inject = True
            continue
        match = EXPORT_RE.match(stripped)
        if not match:
            continue
        var, value = match.group(1), match.group(2).strip()
        value = _unquote_value(value)
        if var.startswith(SECRET_ENV_PREFIX):
            secret_var = var[len(SECRET_ENV_PREFIX) :]
            if secret_var:
                block.secret_refs[secret_var] = value
        else:
            block.exports[var] = value
    return block


def render_managed_block(block: ManagedBlock) -> str:
    lines: List[str] = [BEGIN_MARKER, MANAGED_HEADER, ""]
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


def _find_line_index(lines: List[str], needle: str, start: int = 0) -> int | None:
    for idx in range(start, len(lines)):
        if lines[idx].strip() == needle:
            return idx
    return None


def _unquote_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _shell_quote(value: str) -> str:
    return shlex.quote(value)
