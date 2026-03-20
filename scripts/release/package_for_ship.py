#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def run(cmd: list[str], *, cwd: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def project_version(pyproject_path: Path) -> str:
    for line in pyproject_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("version = "):
            value = stripped.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
            if value.startswith("'") and value.endswith("'"):
                return value[1:-1]
    raise RuntimeError(f"Could not find project.version in {pyproject_path}")


def ensure_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required command not found in PATH: {name}")


def ensure_macos_arm64() -> None:
    if sys.platform != "darwin":
        raise RuntimeError("This script must run on macOS.")
    machine = os.uname().machine
    if machine != "arm64":
        raise RuntimeError("This script only supports Apple Silicon (arm64) macOS.")


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


@contextlib.contextmanager
def temporarily_remove_helper_binary(repo_root: Path):
    helper_path = repo_root / "src" / "envrcctl" / "envrcctl-macos-auth"
    backup_path = None

    if helper_path.exists():
        with tempfile.NamedTemporaryFile(
            prefix="envrcctl-macos-auth.", suffix=".bak", delete=False
        ) as tmp:
            backup_path = Path(tmp.name)
        shutil.move(str(helper_path), str(backup_path))

    try:
        yield
    finally:
        if backup_path is not None and backup_path.exists():
            if helper_path.exists():
                helper_path.unlink()
            helper_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(backup_path), str(helper_path))


def build_dist(repo_root: Path) -> tuple[Path, Path]:
    ensure_command("uv")
    dist_dir = repo_root / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)

    with temporarily_remove_helper_binary(repo_root):
        run(["uv", "build"], cwd=repo_root)

    version = project_version(repo_root / "pyproject.toml")
    sdist = dist_dir / f"envrcctl-{version}.tar.gz"
    wheel = dist_dir / f"envrcctl-{version}-py3-none-any.whl"

    if not sdist.exists():
        raise RuntimeError(f"Expected sdist was not created: {sdist}")
    if not wheel.exists():
        raise RuntimeError(f"Expected wheel was not created: {wheel}")

    return sdist, wheel


def generate_completions(repo_root: Path) -> None:
    ensure_command("uv")
    run(["uv", "run", "python", "scripts/generate_completions.py"], cwd=repo_root)

    expected = [
        repo_root / "completions" / "envrcctl.bash",
        repo_root / "completions" / "envrcctl.zsh",
        repo_root / "completions" / "envrcctl.fish",
    ]
    missing = [path for path in expected if not path.exists()]
    if missing:
        raise RuntimeError(
            "Completion generation did not create expected files: "
            + ", ".join(str(path) for path in missing)
        )


def build_helper(repo_root: Path) -> Path:
    ensure_macos_arm64()
    helper_path = repo_root / "src" / "envrcctl" / "envrcctl-macos-auth"
    run(["sh", "scripts/build_macos_auth_helper.sh"], cwd=repo_root)
    if not helper_path.exists():
        raise RuntimeError(f"Expected helper binary was not created: {helper_path}")
    if not os.access(helper_path, os.X_OK):
        raise RuntimeError(f"Helper binary is not executable: {helper_path}")
    return helper_path


def package_helper(repo_root: Path, version: str, helper_path: Path) -> Path:
    dist_dir = repo_root / "dist"
    archive_path = dist_dir / f"envrcctl-macos-auth-{version}-arm64.tar.gz"

    with tempfile.TemporaryDirectory() as tmpdir:
        stage_dir = Path(tmpdir)
        staged_helper = stage_dir / "envrcctl-macos-auth"
        shutil.copy2(helper_path, staged_helper)
        staged_helper.chmod(0o755)

        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(staged_helper, arcname="envrcctl-macos-auth")

    if not archive_path.exists():
        raise RuntimeError(f"Expected helper archive was not created: {archive_path}")

    return archive_path


def formula_content(
    *,
    version: str,
    source_sha256: str,
    helper_sha256: str,
    homepage: str,
    license_name: str,
) -> str:
    release_base = f"{homepage}/releases/download/v{version}"
    source_url = f"{release_base}/envrcctl-{version}.tar.gz"
    helper_url = f"{release_base}/envrcctl-macos-auth-{version}-arm64.tar.gz"

    return f"""class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Manage .envrc with managed blocks and OS-backed secrets"
  homepage "{homepage}"
  url "{source_url}"
  sha256 "{source_sha256}"
  license "{license_name}"

  depends_on arch: :arm64
  depends_on :macos
  depends_on "python@3.12"

  resource "envrcctl-macos-auth" do
    url "{helper_url}"
    sha256 "{helper_sha256}"
  end

  def install
    virtualenv_install_with_resources

    resource("envrcctl-macos-auth").stage do
      bin.install "envrcctl-macos-auth"
    end

    bash_completion.install "completions/envrcctl.bash" => "envrcctl"
    zsh_completion.install "completions/envrcctl.zsh" => "_envrcctl"
    fish_completion.install "completions/envrcctl.fish"
  end

  test do
    assert_predicate bin/"envrcctl", :exist?
    assert_predicate bin/"envrcctl-macos-auth", :exist?
    assert_match version.to_s, shell_output("#{{bin}}/envrcctl --version")
  end
end
"""


def write_formula(repo_root: Path, formula_text: str) -> Path:
    formula_dir = repo_root.parent / "homebrew-tap" / "Formula"
    formula_dir.mkdir(parents=True, exist_ok=True)
    formula_path = formula_dir / "envrcctl.rb"
    formula_path.write_text(formula_text, encoding="utf-8")
    return formula_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build local ship artifacts for envrcctl: completions, Python distributions, "
            "Apple Silicon helper archive, and Homebrew formula."
        )
    )
    parser.add_argument(
        "--homepage",
        default="https://github.com/rioriost/envrcctl",
        help="Project homepage / GitHub repository URL.",
    )
    parser.add_argument(
        "--license",
        dest="license_name",
        default="MIT",
        help="Homebrew formula license identifier.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_script()
    version = project_version(repo_root / "pyproject.toml")

    print(f"Preparing local ship artifacts for envrcctl {version}")
    print(f"Repository root: {repo_root}")

    generate_completions(repo_root)
    sdist_path, wheel_path = build_dist(repo_root)
    helper_binary = build_helper(repo_root)
    helper_archive = package_helper(repo_root, version, helper_binary)

    source_sha256 = sha256_file(sdist_path)
    helper_sha256 = sha256_file(helper_archive)

    formula_text = formula_content(
        version=version,
        source_sha256=source_sha256,
        helper_sha256=helper_sha256,
        homepage=args.homepage,
        license_name=args.license_name,
    )
    formula_path = write_formula(repo_root, formula_text)

    print()
    print("Artifacts prepared successfully:")
    print(f"- sdist:   {sdist_path}")
    print(f"- wheel:   {wheel_path}")
    print(f"- helper:  {helper_archive}")
    print(f"- formula: {formula_path}")
    print()
    print("SHA256:")
    print(f"- envrcctl-{version}.tar.gz: {source_sha256}")
    print(f"- envrcctl-macos-auth-{version}-arm64.tar.gz: {helper_sha256}")
    print()
    print("Next step: publish with your ship command.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
