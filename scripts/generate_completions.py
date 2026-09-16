from __future__ import annotations

from pathlib import Path

from typer.completion import get_completion_script

SHELLS = ("bash", "zsh", "fish")


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for shell in SHELLS:
        content = get_completion_script(
            prog_name="envrcctl", complete_var="_ENVRCCTL_COMPLETE", shell=shell
        )
        if not content.strip():
            raise RuntimeError(f"Failed to generate {shell} completion.")
        if not content.endswith("\n"):
            content += "\n"
        (output_dir / f"envrcctl.{shell}").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    generate(Path(__file__).resolve().parents[1] / "completions")
