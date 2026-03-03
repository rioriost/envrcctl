from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

from typer.main import get_command

from envrctl.cli import app

SHELLS = ("bash", "zsh", "fish")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_dir = repo_root / "completions"
    output_dir.mkdir(parents=True, exist_ok=True)

    command = get_command(app)

    for shell in SHELLS:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            command.main(
                ["--show-completion", shell],
                prog_name="envrcctl",
                standalone_mode=False,
            )
        content = buffer.getvalue()
        if not content.endswith("\n"):
            content += "\n"
        (output_dir / f"envrcctl.{shell}").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
