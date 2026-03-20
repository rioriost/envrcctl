#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
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
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def project_version(pyproject_path: Path) -> str:
    for line in pyproject_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("version = "):
            value = stripped.split("=", 1)[1].strip()
            if value.startswith('"') and value.endswith('"'):
                return value[1:-1]
            if value.startswith("'") and value.endswith("'"):
                return value[1:-1]
    raise RuntimeError(f"Could not find project version in {pyproject_path}")


def project_dependencies(pyproject_path: Path) -> list[str]:
    text = pyproject_path.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^\[project\]\n.*?^dependencies\s*=\s*\[(.*?)\]", text)
    if not match:
        return []

    dependencies: list[str] = []
    for raw_line in match.group(1).splitlines():
        stripped = raw_line.strip().rstrip(",")
        if not stripped:
            continue
        if stripped.startswith('"') and stripped.endswith('"'):
            dependencies.append(stripped[1:-1])
        elif stripped.startswith("'") and stripped.endswith("'"):
            dependencies.append(stripped[1:-1])
    return dependencies


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def dependency_name(requirement: str) -> str:
    base = re.split(r"[<>=!~;\[\]\s]", requirement, maxsplit=1)[0]
    if not base:
        raise RuntimeError(f"Could not parse dependency requirement: {requirement}")
    return normalize_package_name(base)


def uv_lock_package_block(lock_text: str, package_name: str) -> str:
    normalized = normalize_package_name(package_name)
    current: list[str] = []
    in_package = False

    for line in lock_text.splitlines():
        if line == "[[package]]":
            if in_package:
                block = "\n".join(current)
                name_match = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
                if name_match and normalize_package_name(name_match.group(1)) == normalized:
                    return block
            current = [line]
            in_package = True
            continue

        if in_package:
            current.append(line)

    if in_package:
        block = "\n".join(current)
        name_match = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
        if name_match and normalize_package_name(name_match.group(1)) == normalized:
            return block

    raise RuntimeError(f"Package {package_name!r} not found in uv.lock")


def extract_sdist_url_and_sha(block: str, package_name: str) -> tuple[str, str]:
    sdist_match = re.search(
        r'sdist = \{ url = "([^"]+\.tar\.gz)", hash = "sha256:([0-9a-f]+)"',
        block,
    )
    if sdist_match:
        return sdist_match.group(1), sdist_match.group(2)

    raise RuntimeError(f"Could not find sdist URL and sha256 for {package_name!r} in uv.lock")


def dependency_resource_specs(repo_root: Path) -> list[tuple[str, str, str]]:
    lock_text = (repo_root / "uv.lock").read_text(encoding="utf-8")
    specs: list[tuple[str, str, str]] = []

    for requirement in project_dependencies(repo_root / "pyproject.toml"):
        package_name = dependency_name(requirement)
        block = uv_lock_package_block(lock_text, package_name)
        url, sha256 = extract_sdist_url_and_sha(block, package_name)
        specs.append((package_name, url, sha256))

    return specs


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required command not found in PATH: {name}")


def ensure_macos_arm64() -> None:
    if sys.platform != "darwin":
        raise RuntimeError("This script must run on macOS.")
    machine = getattr(__import__("os"), "uname")().machine
    if machine != "arm64":
        raise RuntimeError("This script only supports Apple Silicon (arm64) macOS.")


def dist_dir(repo_root: Path) -> Path:
    return repo_root / "dist"


def helper_output_path(repo_root: Path) -> Path:
    return repo_root / "src" / "envrcctl" / "envrcctl-macos-auth"


def generate_completions(repo_root: Path) -> None:
    require_command("uv")
    run(["uv", "run", "python", "scripts/generate_completions.py"], cwd=repo_root)

    expected = [
        repo_root / "completions" / "envrcctl.bash",
        repo_root / "completions" / "envrcctl.zsh",
        repo_root / "completions" / "envrcctl.fish",
    ]
    missing = [path for path in expected if not path.exists()]
    if missing:
        joined = ", ".join(str(path) for path in missing)
        raise RuntimeError(f"Completion generation did not create expected files: {joined}")


def sync_dev_environment(repo_root: Path) -> None:
    require_command("uv")
    run(["uv", "sync", "--extra", "test", "--group", "dev"], cwd=repo_root)


def clean_dist(repo_root: Path) -> None:
    out = dist_dir(repo_root)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)


def build_python_artifacts(repo_root: Path) -> tuple[Path, Path]:
    require_command("uv")
    run(["uv", "build"], cwd=repo_root)

    version = project_version(repo_root / "pyproject.toml")
    sdist = dist_dir(repo_root) / f"envrcctl-{version}.tar.gz"
    wheel = dist_dir(repo_root) / f"envrcctl-{version}-py3-none-any.whl"

    if not sdist.exists():
        raise RuntimeError(f"Expected sdist was not created: {sdist}")
    if not wheel.exists():
        raise RuntimeError(f"Expected wheel was not created: {wheel}")

    return sdist, wheel


def build_helper_binary(repo_root: Path) -> Path:
    ensure_macos_arm64()
    run(["sh", "scripts/build_macos_auth_helper.sh"], cwd=repo_root)

    helper_path = helper_output_path(repo_root)
    if not helper_path.exists():
        raise RuntimeError(f"Expected helper binary was not created: {helper_path}")
    if not helper_path.is_file():
        raise RuntimeError(f"Helper path is not a file: {helper_path}")
    return helper_path


def package_helper_archive(repo_root: Path, version: str, helper_binary: Path) -> Path:
    archive_path = dist_dir(repo_root) / f"envrcctl-macos-auth-{version}-arm64.tar.gz"

    with tempfile.TemporaryDirectory() as tmpdir:
        stage_dir = Path(tmpdir)
        staged_binary = stage_dir / "envrcctl-macos-auth"
        shutil.copy2(helper_binary, staged_binary)
        staged_binary.chmod(0o755)

        with tarfile.open(archive_path, "w:gz") as tf:
            tf.add(staged_binary, arcname="envrcctl-macos-auth")

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
    dependency_resources: list[tuple[str, str, str]],
) -> str:
    release_base = f"{homepage}/releases/download/{version}"
    source_url = f"{release_base}/envrcctl-{version}.tar.gz"
    helper_url = f"{release_base}/envrcctl-macos-auth-{version}-arm64.tar.gz"

    resource_blocks = []
    install_lines = []
    for package_name, package_url, package_sha256 in dependency_resources:
        resource_blocks.append(
            f"""  resource "{package_name}" do
    url "{package_url}"
    sha256 "{package_sha256}"
  end"""
        )
        install_lines.append(f'    venv.pip_install resource("{package_name}")')

    resources_section = "\n\n".join(resource_blocks)
    install_resources = "\n".join(install_lines)

    return f"""class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Manage .envrc with managed blocks and OS-backed secrets"
  homepage "{homepage}"
  url "{source_url}"
  sha256 "{source_sha256}"
  license "{license_name}"

  depends_on "python@3.12"

{resources_section}

  on_macos do
    on_arm do
      resource "envrcctl-macos-auth-arm64" do
        url "{helper_url}"
        sha256 "{helper_sha256}"
      end
    end
  end

  def install
    venv = virtualenv_create(libexec, "python3.12")
{install_resources}
    venv.pip_install buildpath

    bin.install_symlink libexec/"bin/envrcctl"

    if OS.mac? && Hardware::CPU.arm?
      resource("envrcctl-macos-auth-arm64").stage do
        bin.install "envrcctl-macos-auth"
      end
    end

    bash_completion.install "completions/envrcctl.bash" => "envrcctl"
    zsh_completion.install "completions/envrcctl.zsh" => "_envrcctl"
    fish_completion.install "completions/envrcctl.fish"
  end

  test do
    assert_predicate bin/"envrcctl", :exist?
    assert_match version.to_s, shell_output("#{{bin}}/envrcctl --version")
    if OS.mac? && Hardware::CPU.arm?
      assert_predicate bin/"envrcctl-macos-auth", :exist?
    end
  end
end
"""


def write_formula(repo_root: Path, formula_text: str, formula_dir: Path | None) -> Path:
    target_dir = formula_dir or (repo_root / "Formula")
    target_dir.mkdir(parents=True, exist_ok=True)
    formula_path = target_dir / "envrcctl.rb"
    formula_path.write_text(formula_text, encoding="utf-8")
    return formula_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build envrcctl release artifacts: sync dev dependencies, generate completions, "
            "build Python artifacts, build the Apple Silicon helper, package the helper tarball, "
            "and write a Homebrew formula. This is the canonical script entrypoint behind "
            "`make release-artifacts`."
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
    parser.add_argument(
        "--formula-dir",
        type=Path,
        default=None,
        help="Directory to write envrcctl.rb into. Defaults to ./Formula.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = project_root()
    version = project_version(repo_root / "pyproject.toml")

    print(f"Building release artifacts for envrcctl {version}")
    print(f"Repository root: {repo_root}")

    sdist_path = dist_dir(repo_root) / f"envrcctl-{version}.tar.gz"
    wheel_path = dist_dir(repo_root) / f"envrcctl-{version}-py3-none-any.whl"
    helper_archive = dist_dir(repo_root) / f"envrcctl-macos-auth-{version}-arm64.tar.gz"

    if not sdist_path.exists() or not wheel_path.exists() or not helper_archive.exists():
        sync_dev_environment(repo_root)
        generate_completions(repo_root)
        clean_dist(repo_root)
        sdist_path, wheel_path = build_python_artifacts(repo_root)
        helper_binary = build_helper_binary(repo_root)
        helper_archive = package_helper_archive(repo_root, version, helper_binary)
    else:
        print("Reusing existing release artifacts from dist/")

    source_sha256 = sha256_file(sdist_path)
    helper_sha256 = sha256_file(helper_archive)
    dependency_resources = dependency_resource_specs(repo_root)

    formula_path = write_formula(
        repo_root,
        formula_content(
            version=version,
            source_sha256=source_sha256,
            helper_sha256=helper_sha256,
            homepage=args.homepage,
            license_name=args.license_name,
            dependency_resources=dependency_resources,
        ),
        args.formula_dir,
    )

    print()
    print("Artifacts built successfully:")
    print(f"- sdist:   {sdist_path}")
    print(f"- wheel:   {wheel_path}")
    print(f"- helper:  {helper_archive}")
    print(f"- formula: {formula_path}")
    print()
    print("SHA256:")
    print(f"- envrcctl-{version}.tar.gz: {source_sha256}")
    print(f"- envrcctl-macos-auth-{version}-arm64.tar.gz: {helper_sha256}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
