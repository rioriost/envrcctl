#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

HELPER_NAME = "envrcctl-macos-auth"
MINIMUM_MACOS = "26.0"
PROVENANCE_NAME = "release-provenance.json"
NOTARIZATION_NAME = "notarization.json"


def release_settings(repo_root: Path) -> dict[str, str]:
    with (repo_root / "pyproject.toml").open("rb") as stream:
        table = tomllib.load(stream)
    for key in ("tool", "envrcctl", "release"):
        table = table.get(key, {})
        if not isinstance(table, dict):
            raise RuntimeError("[tool.envrcctl.release] must be a TOML table")
    supported = {"signing-identity", "notary-profile", "notary-keychain"}
    if table.keys() - supported:
        raise RuntimeError("Unknown setting in [tool.envrcctl.release]")
    for key, value in table.items():
        if (
            not isinstance(value, str)
            or not value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise RuntimeError(f"Release setting {key} must be a nonempty single-line string")
    return table


def resolve_credentials(repo_root: Path, args: argparse.Namespace) -> None:
    settings = release_settings(repo_root)
    for attribute, environment in (
        ("signing_identity", "SIGNING_IDENTITY"),
        ("notary_profile", "NOTARY_PROFILE"),
        ("notary_keychain", "NOTARY_KEYCHAIN"),
    ):
        if args.candidate and attribute.startswith("notary_"):
            setattr(args, attribute, None)
            continue
        value = getattr(args, attribute)
        source = "command line"
        if value is None:
            if environment in os.environ:
                value, source = os.environ[environment], environment
            elif not args.candidate:
                value = settings.get(attribute.replace("_", "-"))
                source = "pyproject.toml"
        if value is not None:
            if not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise RuntimeError(f"{source}: {attribute} must be a nonempty single-line string")
            if attribute == "notary_keychain":
                path = Path(value).expanduser()
                value = str(path if path.is_absolute() else repo_root / path)
            setattr(args, attribute, value)
            print(f"Selected {attribute} from {source}: {value}")


def keychain_arguments(keychain: str | None) -> list[str]:
    return ["--keychain", keychain] if keychain else []


def credential_command(cmd: list[str], repo_root: Path, description: str) -> str:
    try:
        result = subprocess.run(
            cmd, cwd=repo_root, capture_output=True, text=True, check=False, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"{description} could not run ({type(exc).__name__})") from None
    if result.returncode:
        raise RuntimeError(
            f"{description} failed (exit {result.returncode}). "
            "Check the selected identity/profile, Keychain access and Apple service availability. "
            "An inaccessible selected profile does not mean no credentials are stored."
        )
    return result.stdout


def preflight_credentials(repo_root: Path, args: argparse.Namespace) -> None:
    if not args.candidate and not args.notary_profile:
        raise RuntimeError(
            "No notarization profile is selected. Credentials may already exist in Keychain. "
            "Set [tool.envrcctl.release].notary-profile in pyproject.toml, NOTARY_PROFILE, "
            "or --notary-profile to the existing profile name. "
            "Use --candidate only for a private, unnotarized build."
        )
    if not args.signing_identity:
        if args.candidate:
            return
        raise RuntimeError(
            "No signing identity is selected. Set [tool.envrcctl.release].signing-identity, "
            "SIGNING_IDENTITY, or --signing-identity."
        )
    identities = credential_command(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
        repo_root,
        "Developer ID identity preflight",
    )
    available = re.findall(
        r'^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"(Developer ID Application: [^"]+)"\s*$',
        identities,
        re.MULTILINE,
    )
    matches = [
        fingerprint
        for fingerprint, name in available
        if args.signing_identity == name or args.signing_identity.upper() == fingerprint.upper()
    ]
    if len(matches) != 1:
        raise RuntimeError(
            "The selected signing identity must match one valid Developer ID identity"
        )
    if args.candidate:
        print(
            "Private candidate: signing identity verified; notarization is intentionally disabled."
        )
        return
    output = credential_command(
        [
            "xcrun",
            "notarytool",
            "history",
            "--keychain-profile",
            args.notary_profile,
            *keychain_arguments(args.notary_keychain),
            "--output-format",
            "json",
        ],
        repo_root,
        "Notarization profile preflight",
    )
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        raise RuntimeError("Notarization preflight returned invalid JSON") from None
    if not isinstance(response, dict) or not isinstance(response.get("history"), list):
        raise RuntimeError("Notarization preflight returned an invalid history response")
    print("Release credential preflight: OK (notarytool validated the stored profile)")


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


def package_dependencies(block: str) -> list[str]:
    deps_match = re.search(r"dependencies = \[(.*?)\]\n", block, re.DOTALL)
    if not deps_match:
        return []

    dependencies: list[str] = []
    for match in re.finditer(r'\{ name = "([^"]+)"(?:, marker = "([^"]+)")?', deps_match.group(1)):
        name = normalize_package_name(match.group(1))
        marker = match.group(2)
        if marker and "win32" in marker.lower():
            continue
        if marker and "windows" in marker.lower():
            continue
        dependencies.append(name)

    return dependencies


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


def extract_wheel_url_and_sha(block: str, package_name: str) -> tuple[str, str]:
    wheels = re.findall(
        r'\{ url = "([^"]+-(?:py3|py2\.py3)-none-any\.whl)", hash = "sha256:([0-9a-f]{64})"',
        block,
    )
    if len(wheels) == 1:
        return wheels[0]

    raise RuntimeError(f"Expected one locked universal Python wheel for {package_name!r}")


def dependency_resource_specs(repo_root: Path) -> list[tuple[str, str, str]]:
    lock_text = (repo_root / "uv.lock").read_text(encoding="utf-8")
    ordered_names: list[str] = []
    seen: set[str] = set()
    queue = [dependency_name(req) for req in project_dependencies(repo_root / "pyproject.toml")]

    while queue:
        package_name = normalize_package_name(queue.pop(0))
        if package_name in seen:
            continue
        seen.add(package_name)
        ordered_names.append(package_name)

        block = uv_lock_package_block(lock_text, package_name)
        for dependency in package_dependencies(block):
            if dependency not in seen and dependency not in queue:
                queue.append(dependency)

    specs: list[tuple[str, str, str]] = []
    for package_name in ordered_names:
        block = uv_lock_package_block(lock_text, package_name)
        url, sha256 = extract_wheel_url_and_sha(block, package_name)
        specs.append((package_name, url, sha256))

    return specs


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required command not found in PATH: {name}")


def ensure_macos_arm64() -> None:
    if sys.platform != "darwin":
        raise RuntimeError("This script must run on macOS.")
    machine = os.uname().machine
    if machine != "arm64":
        raise RuntimeError("This script only supports Apple Silicon (arm64) macOS.")


def dist_dir(repo_root: Path) -> Path:
    return repo_root / "dist"


def generate_completions(repo_root: Path, uv: str = "uv") -> None:
    require_command(uv)
    run([uv, "run", "--locked", "python", "scripts/generate_completions.py"], cwd=repo_root)

    expected = [
        repo_root / "completions" / "envrcctl.bash",
        repo_root / "completions" / "envrcctl.zsh",
        repo_root / "completions" / "envrcctl.fish",
    ]
    missing = [path for path in expected if not path.exists()]
    if missing:
        joined = ", ".join(str(path) for path in missing)
        raise RuntimeError(f"Completion generation did not create expected files: {joined}")


def sync_dev_environment(repo_root: Path, uv: str = "uv") -> None:
    require_command(uv)
    run([uv, "sync", "--locked", "--extra", "test", "--group", "dev"], cwd=repo_root)


def validate_python_artifacts(sdist: Path, wheel: Path) -> None:
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        if not members or any(not (m.isfile() or m.isdir()) for m in members):
            raise RuntimeError("Invalid sdist members")
        source_names = [m.name for m in members]
    with zipfile.ZipFile(wheel) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Invalid wheel checksum")
        wheel_names = archive.namelist()
        entrypoints = [n for n in wheel_names if n.endswith(".dist-info/entry_points.txt")]
        if len(entrypoints) != 1 or b"envrcctl.main:main" not in archive.read(entrypoints[0]):
            raise RuntimeError("Missing envrcctl wheel entrypoint")
    for name in source_names + wheel_names:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"Unsafe Python archive member: {name}")
        if "envrcctl" in path.parts and path.name.startswith(HELPER_NAME):
            raise RuntimeError(f"Native helper or backup in Python artifact: {name}")
    if not any(n.endswith("/src/envrcctl/main.py") for n in source_names):
        raise RuntimeError("Missing envrcctl source in sdist")
    if "envrcctl/main.py" not in wheel_names:
        raise RuntimeError("Missing envrcctl source in wheel")
    for shell in ("bash", "zsh", "fish"):
        if not any(n.endswith(f"/completions/envrcctl.{shell}") for n in source_names):
            raise RuntimeError(f"Missing {shell} completion in sdist")


def build_python_artifacts(repo_root: Path, output: Path, uv: str = "uv") -> tuple[Path, Path]:
    require_command(uv)
    run([uv, "build", "--out-dir", str(output)], cwd=repo_root)

    version = project_version(repo_root / "pyproject.toml")
    sdist = output / f"envrcctl-{version}.tar.gz"
    wheel = output / f"envrcctl-{version}-py3-none-any.whl"
    validate_python_artifacts(sdist, wheel)
    return sdist, wheel


def validate_helper_binary(helper: Path, repo_root: Path) -> None:
    ensure_macos_arm64()
    metadata = subprocess.run(
        ["xcrun", "vtool", "-show-build", str(helper)],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    architectures = subprocess.run(
        ["xcrun", "lipo", "-archs", str(helper)],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    minimums = re.findall(r"^\s*minos\s+(\S+)", metadata, re.MULTILINE)
    platforms = re.findall(r"^\s*platform\s+(\S+)", metadata, re.MULTILINE)
    if architectures != "arm64" or minimums != [MINIMUM_MACOS] or platforms != ["MACOS"]:
        raise RuntimeError(f"Helper must target arm64 macOS {MINIMUM_MACOS}")
    result = subprocess.run(
        [str(helper), "--help"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if "Usage:" not in result.stdout or HELPER_NAME not in result.stdout:
        raise RuntimeError("Helper --help did not return its usage")


def build_helper_binary(repo_root: Path, output: Path) -> Path:
    ensure_macos_arm64()
    helper_path = output / HELPER_NAME
    run(
        [
            "sh",
            "scripts/build_macos_auth_helper.sh",
            str(repo_root / "scripts/macos/envrcctl-macos-auth.swift"),
            str(helper_path),
        ],
        cwd=repo_root,
    )
    validate_helper_binary(helper_path, repo_root)
    return helper_path


def sign_helper(
    repo_root: Path,
    helper: Path,
    identity: str | None,
    notary_profile: str | None,
    notary_keychain: str | None = None,
) -> dict[str, str] | None:
    if identity:
        run(
            [
                "codesign",
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                identity,
                str(helper),
            ],
            cwd=repo_root,
        )
        run(["codesign", "--verify", "--strict", "--verbose=2", str(helper)], cwd=repo_root)
    if notary_profile:
        if not identity:
            raise RuntimeError("Notarization requires a Developer ID signing identity")
        submission = helper.parent / "helper-notarization.zip"
        run(
            ["ditto", "-c", "-k", "--keepParent", str(helper), str(submission)],
            cwd=repo_root,
        )
        result = subprocess.run(
            [
                "xcrun",
                "notarytool",
                "submit",
                str(submission),
                "--keychain-profile",
                notary_profile,
                *keychain_arguments(notary_keychain),
                "--wait",
                "--output-format",
                "json",
            ],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise RuntimeError("Helper notarization returned an invalid response")
        submission_id = response.get("id")
        if response.get("status") != "Accepted":
            safe_id = (
                submission_id
                if isinstance(submission_id, str)
                and re.fullmatch(r"[A-Za-z0-9-]{1,100}", submission_id)
                else "unavailable"
            )
            raise RuntimeError(
                f"Helper notarization was not accepted (submission: {safe_id}). "
                "Inspect it with notarytool info/log using the selected profile."
            )
        if not isinstance(submission_id, str) or not submission_id:
            raise RuntimeError("Accepted notarization response is missing its submission ID")
        print(f"Helper notarization accepted: {submission_id}")
        return {
            "status": "Accepted",
            "submission_id": submission_id,
            "profile": notary_profile,
            "signing_identity": identity,
        }
    return None


def validate_helper_archive(archive: Path, expected_sha256: str | None = None) -> None:
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) != 1:
            raise RuntimeError("Helper archive must have exactly one member")
        member = members[0]
        if (
            member.name != HELPER_NAME
            or not member.isfile()
            or member.mode & 0o7777 != 0o755
            or member.size == 0
        ):
            raise RuntimeError("Helper archive must contain only an executable regular helper")
        stream = tf.extractfile(member)
        assert stream is not None
        with stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise RuntimeError("Archived helper checksum does not match the built helper")


def package_helper_archive(
    repo_root: Path,
    version: str,
    helper_binary: Path,
    output: Path,
) -> Path:
    archive_path = output / f"envrcctl-macos-auth-{version}-arm64.tar.gz"
    with tempfile.TemporaryDirectory(prefix=".helper-stage-", dir=output) as staging:
        stage = Path(staging)
        pending = stage / "helper.tar.gz"
        # Save the failing operation's status before cleanup; never publish a partial tarball.
        run(
            [
                "sh",
                "-c",
                """
set -eu
trap 'status=$?; trap - 0; rm -f "$1/envrcctl-macos-auth" || :; exit "$status"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$2" "$1/envrcctl-macos-auth"
chmod 755 "$1/envrcctl-macos-auth"
COPYFILE_DISABLE=1 tar -C "$1" -czf "$1/helper.tar.gz" envrcctl-macos-auth
""",
                "package-helper",
                str(stage),
                str(helper_binary),
            ],
            cwd=repo_root,
        )
        validate_helper_archive(pending, sha256_file(helper_binary))
        pending.replace(archive_path)
    return archive_path


def input_hashes(repo_root: Path) -> dict[str, str]:
    paths = [
        repo_root / name
        for name in ("pyproject.toml", "uv.lock", "Makefile", "README.md", "LICENSE")
    ]
    for directory in ("src", "scripts", "tests", "completions"):
        paths.extend(
            p
            for p in (repo_root / directory).rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and not p.name.endswith((".pyc", ".pyo"))
            and not (p.parent == repo_root / "src/envrcctl" and p.name.startswith(HELPER_NAME))
        )
    paths.extend(
        repo_root / name
        for name in (".gitignore", ".python-version", "uv.toml", "hatch.toml")
        if (repo_root / name).is_file()
    )
    return {p.relative_to(repo_root).as_posix(): sha256_file(p) for p in sorted(set(paths))}


def artifact_paths(output: Path, version: str) -> tuple[Path, Path, Path]:
    return (
        output / f"envrcctl-{version}.tar.gz",
        output / f"envrcctl-{version}-py3-none-any.whl",
        output / f"envrcctl-macos-auth-{version}-arm64.tar.gz",
    )


def write_provenance(
    output: Path,
    version: str,
    inputs: dict[str, str],
    artifacts: tuple[Path, ...],
) -> Path:
    provenance = output / PROVENANCE_NAME
    provenance.write_text(
        json.dumps(
            {
                "schema": 1,
                "version": version,
                "minimum_macos": MINIMUM_MACOS,
                "inputs": inputs,
                "artifacts": {p.name: sha256_file(p) for p in artifacts},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return provenance


def verify_provenance(repo_root: Path, version: str) -> tuple[Path, Path, Path]:
    output = dist_dir(repo_root)
    try:
        data = json.loads((output / PROVENANCE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "Missing or invalid release provenance; rebuild release artifacts"
        ) from exc
    artifacts = artifact_paths(output, version)
    expected = {
        "schema": 1,
        "version": version,
        "minimum_macos": MINIMUM_MACOS,
        "inputs": input_hashes(repo_root),
        "artifacts": {p.name: sha256_file(p) for p in artifacts},
    }
    if data != expected:
        raise RuntimeError("Release provenance mismatch; rebuild release artifacts")
    validate_python_artifacts(artifacts[0], artifacts[1])
    validate_helper_archive(artifacts[2])
    return artifacts


def write_notarization_receipt(
    output: Path,
    version: str,
    artifacts: tuple[Path, ...],
    accepted: dict[str, str],
) -> Path:
    receipt = output / NOTARIZATION_NAME
    receipt.write_text(
        json.dumps(
            {
                "schema": 1,
                "version": version,
                **accepted,
                "artifacts": {path.name: sha256_file(path) for path in artifacts},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return receipt


def verify_release_ready(repo_root: Path, version: str) -> None:
    artifacts = verify_provenance(repo_root, version)
    try:
        receipt = json.loads((dist_dir(repo_root) / NOTARIZATION_NAME).read_text(encoding="utf-8"))
    except FileNotFoundError, json.JSONDecodeError:
        raise RuntimeError(
            "No valid notarization receipt. This is not a publishable release; "
            "run a full notarized build after release-preflight succeeds."
        ) from None
    if (
        not isinstance(receipt, dict)
        or type(receipt.get("schema")) is not int
        or receipt.get("schema") != 1
        or receipt.get("version") != version
        or receipt.get("status") != "Accepted"
        or any(
            not isinstance(receipt.get(key), str)
            or not receipt[key].strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in receipt[key])
            for key in ("submission_id", "signing_identity", "profile")
        )
        or receipt.get("artifacts") != {path.name: sha256_file(path) for path in artifacts}
    ):
        raise RuntimeError("Notarization receipt does not match the accepted release artifacts")
    print(f"Release ready: notarization {receipt['submission_id']} is Accepted for these artifacts")


def formula_content(
    *,
    version: str,
    source_sha256: str,
    wheel_sha256: str,
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
    url "{package_url}", using: :nounzip
    sha256 "{package_sha256}"
  end"""
        )
        install_lines.append(
            f'    venv.pip_install resource("{package_name}"), build_isolation: false'
        )

    resources_section = "\n\n".join(resource_blocks)
    install_resources = "\n".join(install_lines)

    return f"""class Envrcctl < Formula
  include Language::Python::Virtualenv

  desc "Manage .envrc with managed blocks and OS-backed secrets"
  homepage "{homepage}"
  url "{source_url}"
  sha256 "{source_sha256}"
  license "{license_name}"

  depends_on "python@3.14"

  on_macos do
    on_arm do
      depends_on macos: :tahoe

      resource "envrcctl-macos-auth-arm64" do
        url "{helper_url}"
        sha256 "{helper_sha256}"
      end
    end
  end

{resources_section}

  resource "envrcctl-wheel" do
    url "{release_base}/envrcctl-{version}-py3-none-any.whl", using: :nounzip
    sha256 "{wheel_sha256}"
  end

  def install
    # All Python packages are checksummed wheels fetched by Homebrew in advance.
    ENV["PIP_NO_INDEX"] = "1"
    ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    venv = virtualenv_create(libexec, "python3.14")
{install_resources}
    venv.pip_install resource("envrcctl-wheel"), build_isolation: false

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
    assert_path_exists bin/"envrcctl"
    assert_match "Manage .envrc", shell_output("#{{bin}}/envrcctl --help")
    if OS.mac? && Hardware::CPU.arm?
      assert_path_exists bin/"envrcctl-macos-auth"
      assert_match "Usage:", shell_output("#{{bin}}/envrcctl-macos-auth --help")
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build envrcctl release artifacts: sync dev dependencies, generate completions, "
            "build Python artifacts, build the Apple Silicon helper, package the helper tarball, "
            "and write a Homebrew formula. This is the canonical script entrypoint behind "
            "`make release-artifacts`."
        )
    )
    parser.add_argument(
        "--uv",
        default="uv",
        help="uv executable used for locked dependency sync and builds.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--preflight",
        action="store_true",
        help="Validate configured signing identity and Keychain profile before any build.",
    )
    mode.add_argument(
        "--verify-release",
        action="store_true",
        help="Require matching artifact provenance and an Accepted notarization receipt.",
    )
    mode.add_argument(
        "--build",
        action="store_true",
        help="Explicitly select the default: rebuild all artifacts from current source.",
    )
    mode.add_argument(
        "--formula-only",
        action="store_true",
        help="Only generate the formula; reject missing or mismatched artifact provenance.",
    )
    mode.add_argument(
        "--python-only",
        action="store_true",
        help="Sync, regenerate completions and rebuild Python artifacts (no release provenance).",
    )
    mode.add_argument(
        "--helper-only",
        action="store_true",
        help="Rebuild and package the helper only, without touching the tracked native binary.",
    )
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="Explicitly build a private candidate without notarization; not publishable.",
    )
    parser.add_argument(
        "--signing-identity",
        help="Developer ID Application identity used to sign the freshly built helper.",
    )
    parser.add_argument(
        "--notary-profile",
        help="Existing Keychain profile (overrides NOTARY_PROFILE and pyproject release settings).",
    )
    parser.add_argument(
        "--notary-keychain",
        help="Optional custom Keychain file (overrides NOTARY_KEYCHAIN and pyproject settings).",
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
    args = parser.parse_args(argv)
    if (args.formula_only or args.python_only or args.verify_release) and (
        args.signing_identity or args.notary_profile or args.notary_keychain or args.candidate
    ):
        parser.error("signing options require a helper build")
    if args.candidate and (args.notary_profile or args.notary_keychain or args.preflight):
        parser.error("--candidate cannot request notarization or release preflight")
    return args


def build_artifacts(repo_root: Path, version: str, args: argparse.Namespace) -> tuple[Path, ...]:
    output = dist_dir(repo_root)
    output.mkdir(parents=True, exist_ok=True)
    if not args.helper_only:
        sync_dev_environment(repo_root, args.uv)
        generate_completions(repo_root, args.uv)
    inputs = input_hashes(repo_root)
    # Keep all staging on the destination filesystem. Existing release files survive failures.
    with tempfile.TemporaryDirectory(prefix=".release-stage-", dir=output) as staging:
        stage = Path(staging)
        artifacts: tuple[Path, ...] = ()
        accepted = None
        if not args.helper_only:
            artifacts = build_python_artifacts(repo_root, stage, args.uv)
        if not args.python_only:
            helper = build_helper_binary(repo_root, stage)
            accepted = sign_helper(
                repo_root, helper, args.signing_identity, args.notary_profile, args.notary_keychain
            )
            artifacts += (package_helper_archive(repo_root, version, helper, stage),)
        if input_hashes(repo_root) != inputs:
            raise RuntimeError("Release inputs changed during the build; retry after edits finish")
        provenance = None
        receipt = None
        if not (args.python_only or args.helper_only):
            provenance = write_provenance(stage, version, inputs, artifacts)
            if accepted is not None:
                receipt = write_notarization_receipt(stage, version, artifacts, accepted)
        for artifact in artifacts:
            artifact.replace(output / artifact.name)
        if provenance is not None:
            provenance.replace(output / PROVENANCE_NAME)
        else:
            (output / PROVENANCE_NAME).unlink(missing_ok=True)
        if receipt is not None:
            receipt.replace(output / NOTARIZATION_NAME)
        else:
            (output / NOTARIZATION_NAME).unlink(missing_ok=True)
        return tuple(output / artifact.name for artifact in artifacts)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = project_root()
    version = project_version(repo_root / "pyproject.toml")

    print(f"Preparing release artifacts for envrcctl {version}")
    print(f"Repository root: {repo_root}")

    if args.verify_release:
        verify_release_ready(repo_root, version)
        return 0
    if not (args.formula_only or args.python_only or args.helper_only):
        resolve_credentials(repo_root, args)
        preflight_credentials(repo_root, args)
        if args.preflight:
            return 0
        if args.candidate:
            print("PRIVATE CANDIDATE: notarization is disabled; do not publish.")
    elif args.helper_only and (args.signing_identity or args.notary_profile):
        preflight_credentials(repo_root, args)
    if not args.formula_only:
        artifacts = build_artifacts(repo_root, version, args)
        if args.python_only or args.helper_only:
            print("Built artifacts (run a full build before formula generation):")
            for artifact in artifacts:
                print(f"- {artifact}")
            return 0
        if not args.candidate:
            verify_release_ready(repo_root, version)
    sdist_path, wheel_path, helper_archive = verify_provenance(repo_root, version)

    source_sha256 = sha256_file(sdist_path)
    helper_sha256 = sha256_file(helper_archive)
    dependency_resources = dependency_resource_specs(repo_root)

    formula_path = write_formula(
        repo_root,
        formula_content(
            version=version,
            source_sha256=source_sha256,
            wheel_sha256=sha256_file(wheel_path),
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
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"Release stage failed: {exc}", file=sys.stderr)
        raise SystemExit(exc.returncode if exc.returncode > 0 else 128 - exc.returncode) from exc
    except (OSError, RuntimeError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"Release failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
