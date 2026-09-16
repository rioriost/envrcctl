import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "release_artifacts.py"
spec = importlib.util.spec_from_file_location("release_artifacts", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

ROOT = SCRIPT.parents[1]


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    for variable in (
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
    ):
        directory = tmp_path / variable.lower()
        directory.mkdir()
        monkeypatch.setenv(variable, str(directory))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path.parent / "uv-cache"))
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    files = {
        "pyproject.toml": '[project]\nname = "envrcctl"\nversion = "1.0"\n',
        "uv.lock": "locked inputs\n",
        "Makefile": "release-artifacts:\n",
        "README.md": "readme",
        "LICENSE": "license",
        "src/envrcctl/main.py": "source",
        "src/envrcctl/envrcctl-macos-auth": "tracked helper",
        "src/envrcctl/envrcctl-macos-auth.bak": "old backup",
        "scripts/macos/envrcctl-macos-auth.swift": "swift source",
        "scripts/build_macos_auth_helper.sh": "build helper",
        "scripts/release_artifacts.py": "generator",
        "tests/test_example.py": "test source",
        **{f"completions/envrcctl.{shell}": shell for shell in ("bash", "zsh", "fish")},
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / "dist").mkdir()
    return root


def make_python_archives(output, version="1.0", extra=None):
    source, wheel, _ = release.artifact_paths(output, version)
    with tarfile.open(source, "w:gz") as archive:
        files = ["src/envrcctl/main.py"]
        files += [f"completions/envrcctl.{shell}" for shell in ("bash", "zsh", "fish")]
        if extra:
            files.append(extra)
        for name in files:
            member = tarfile.TarInfo(f"envrcctl-{version}/{name}")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("envrcctl/main.py", "source")
        archive.writestr(
            f"envrcctl-{version}.dist-info/entry_points.txt",
            "[console_scripts]\nenvrcctl = envrcctl.main:main\n",
        )
        if extra:
            archive.writestr(extra.removeprefix("src/"), "native")
    return source, wheel


def make_helper_archive(path, *, mode=0o755, name=release.HELPER_NAME, kind=tarfile.REGTYPE):
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.type = kind
        member.size = 6 if kind == tarfile.REGTYPE else 0
        archive.addfile(member, io.BytesIO(b"helper") if member.size else None)


def seed_release(root):
    artifacts = release.artifact_paths(root / "dist", "1.0")
    make_python_archives(root / "dist")
    make_helper_archive(artifacts[2])
    release.write_provenance(root / "dist", "1.0", release.input_hashes(root), artifacts)
    return artifacts


def test_runtime_resources_use_locked_universal_wheels():
    resources = release.dependency_resource_specs(SCRIPT.parents[1])
    assert {name for name, _, _ in resources} == {
        "click",
        "typer",
        "annotated-doc",
        "rich",
        "shellingham",
        "markdown-it-py",
        "pygments",
        "mdurl",
    }
    assert all(url.endswith("-none-any.whl") and len(sha) == 64 for _, url, sha in resources)


@pytest.mark.parametrize("filename", ["pkg-1.tar.gz", "pkg-1-cp314-cp314-macosx_14_0_arm64.whl"])
def test_source_or_platform_only_dependency_is_rejected(filename):
    block = f'{{ url = "https://example.com/{filename}", hash = "sha256:{"a" * 64}" }}'
    with pytest.raises(RuntimeError, match="locked universal Python wheel"):
        release.extract_wheel_url_and_sha(block, "pkg")


def test_formula_installs_only_explicit_wheels_with_index_disabled():
    formula = release.formula_content(
        version="0.3.2",
        source_sha256="a" * 64,
        wheel_sha256="b" * 64,
        helper_sha256="c" * 64,
        homepage="https://github.com/rioriost/envrcctl",
        license_name="MIT",
        dependency_resources=[("click", "https://example.com/click-1-py3-none-any.whl", "d" * 64)],
    )
    assert 'ENV["PIP_NO_INDEX"] = "1"' in formula
    assert 'venv.pip_install resource("click"), build_isolation: false' in formula
    assert 'venv.pip_install resource("envrcctl-wheel"), build_isolation: false' in formula
    assert "venv.pip_install buildpath" not in formula
    assert formula.count("using: :nounzip") == 2
    assert "envrcctl-0.3.2-py3-none-any.whl" in formula
    assert "depends_on macos: :tahoe" in formula
    assert 'shell_output("#{bin}/envrcctl-macos-auth --help")' in formula


@pytest.mark.parametrize(
    "changed",
    [
        "src/envrcctl/main.py",
        "pyproject.toml",
        "uv.lock",
        "Makefile",
        "scripts/release_artifacts.py",
        "scripts/macos/envrcctl-macos-auth.swift",
        "scripts/build_macos_auth_helper.sh",
        "completions/envrcctl.bash",
        "README.md",
    ],
)
def test_formula_only_rejects_changed_inputs_without_writing_formula(
    repository,
    monkeypatch,
    changed,
):
    seed_release(repository)
    path = repository / changed
    path.write_text(path.read_text() + "\n# changed\n")
    monkeypatch.setattr(release, "project_root", lambda: repository)
    with pytest.raises(RuntimeError, match="provenance mismatch"):
        release.main(["--formula-only"])
    assert not (repository / "Formula").exists()


@pytest.mark.parametrize("artifact", [0, 1, 2])
def test_provenance_rejects_changed_artifacts(repository, artifact):
    artifacts = seed_release(repository)
    with artifacts[artifact].open("ab") as output:
        output.write(b"changed")
    with pytest.raises(RuntimeError, match="provenance mismatch"):
        release.verify_provenance(repository, "1.0")


@pytest.mark.parametrize(
    "filename",
    ["envrcctl-macos-auth", "envrcctl-macos-auth.bak", "envrcctl-macos-auth.bak.old"],
)
def test_installing_generated_helper_or_backups_does_not_invalidate_provenance(
    repository,
    filename,
):
    artifacts = seed_release(repository)
    helper = repository / "src/envrcctl" / filename
    helper.write_bytes(b"new signed release helper")
    assert helper.relative_to(repository).as_posix() not in release.input_hashes(repository)
    assert release.verify_provenance(repository, "1.0") == artifacts


def test_formula_only_never_builds_and_accepts_matching_provenance(repository, monkeypatch):
    seed_release(repository)
    monkeypatch.setattr(release, "project_root", lambda: repository)
    monkeypatch.setattr(
        release,
        "build_artifacts",
        lambda *args: pytest.fail("formula-only started a build"),
    )
    monkeypatch.setattr(release, "dependency_resource_specs", lambda root: [])
    assert release.main(["--formula-only"]) == 0
    assert (repository / "Formula/envrcctl.rb").is_file()


@pytest.mark.parametrize("record", [None, "not json", "{}"])
def test_formula_only_requires_provenance(repository, record):
    if record is not None:
        (repository / "dist" / release.PROVENANCE_NAME).write_text(record)
    with pytest.raises((RuntimeError, OSError)):
        release.verify_provenance(repository, "1.0")


@pytest.mark.parametrize(
    "failure",
    [None, "sync", "completions", "python", "helper", "sign", "archive"],
)
def test_pipeline_always_rebuilds_in_order_and_stops_on_failure(repository, monkeypatch, failure):
    previous = seed_release(repository)
    previous_hashes = [release.sha256_file(path) for path in previous]
    before_helper = (repository / "src/envrcctl/envrcctl-macos-auth").read_bytes()
    calls = []
    stages = ["sync", "completions", "python", "helper", "sign", "archive", "formula"]

    def stage(name):
        calls.append(name)
        if name == failure:
            raise subprocess.CalledProcessError(23, name)

    def python_build(root, output, uv):
        stage("python")
        return make_python_archives(output)

    def helper_build(root, output):
        stage("helper")
        path = output / release.HELPER_NAME
        path.write_bytes(b"helper")
        return path

    def package(root, version, helper, output):
        stage("archive")
        path = release.artifact_paths(output, version)[2]
        make_helper_archive(path)
        return path

    monkeypatch.setattr(release, "project_root", lambda: repository)
    monkeypatch.setattr(release, "sync_dev_environment", lambda *args: stage("sync"))
    monkeypatch.setattr(release, "generate_completions", lambda *args: stage("completions"))
    monkeypatch.setattr(release, "build_python_artifacts", python_build)
    monkeypatch.setattr(release, "build_helper_binary", helper_build)
    monkeypatch.setattr(release, "sign_helper", lambda *args: stage("sign"))
    monkeypatch.setattr(release, "package_helper_archive", package)
    monkeypatch.setattr(release, "dependency_resource_specs", lambda root: [])
    monkeypatch.setattr(release, "write_formula", lambda *args: stage("formula"))
    if failure:
        with pytest.raises(subprocess.CalledProcessError) as error:
            release.main([])
        assert error.value.returncode == 23
        assert calls == stages[: stages.index(failure) + 1]
        assert [release.sha256_file(path) for path in previous] == previous_hashes
    else:
        assert release.main([]) == 0
        assert calls == stages
        release.verify_provenance(repository, "1.0")
    assert (repository / "src/envrcctl/envrcctl-macos-auth").read_bytes() == before_helper
    assert not list((repository / "dist").glob(".release-stage-*"))


@pytest.mark.parametrize("failed_command", ["cp", "chmod", "tar", "validation"])
@pytest.mark.parametrize("cleanup_fails", [False, True])
@pytest.mark.parametrize("existing_archive", [False, True])
def test_packaging_failure_preserves_status_and_previous_archive(
    repository,
    monkeypatch,
    failed_command,
    cleanup_fails,
    existing_archive,
):
    output = repository / "dist"
    helper = repository / "helper"
    helper.write_bytes(b"helper")
    final = release.artifact_paths(output, "1.0")[2]
    if existing_archive:
        final.write_bytes(b"previous valid release")
    commands = repository / "commands"
    commands.mkdir()
    if cleanup_fails:
        cleanup = commands / "rm"
        cleanup.write_text("#!/bin/sh\nexit 43\n")
        cleanup.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    if failed_command != "validation":
        executable = commands / failed_command
        executable.write_text("#!/bin/sh\nexit 29\n")
        executable.chmod(0o755)
        error = subprocess.CalledProcessError
    else:

        def reject(*args):
            raise RuntimeError("invalid archive")

        monkeypatch.setattr(release, "validate_helper_archive", reject)
        error = RuntimeError
    with pytest.raises(error) as caught:
        release.package_helper_archive(repository, "1.0", helper, output)
    if failed_command != "validation":
        assert caught.value.returncode == 29
    if existing_archive:
        assert final.read_bytes() == b"previous valid release"
    else:
        assert not final.exists()
    assert not list(output.glob(".helper-stage-*"))


def test_packaging_validates_exact_member_mode_and_checksum(repository):
    helper = repository / "helper"
    helper.write_bytes(b"helper")
    archive = release.package_helper_archive(repository, "1.0", helper, repository / "dist")
    release.validate_helper_archive(archive, release.sha256_file(helper))
    with pytest.raises(RuntimeError, match="checksum"):
        release.validate_helper_archive(archive, "0" * 64)


def test_inputs_changed_during_build_do_not_replace_release(repository, monkeypatch):
    artifacts = seed_release(repository)
    before = [release.sha256_file(path) for path in artifacts]
    monkeypatch.setattr(release, "sync_dev_environment", lambda *args: None)
    monkeypatch.setattr(release, "generate_completions", lambda *args: None)

    def build(root, output, uv):
        (root / "src/envrcctl/main.py").write_text("edited during build")
        return make_python_archives(output)

    monkeypatch.setattr(release, "build_python_artifacts", build)
    with pytest.raises(RuntimeError, match="inputs changed during"):
        release.build_artifacts(repository, "1.0", release.parse_args(["--python-only"]))
    assert [release.sha256_file(path) for path in artifacts] == before


def test_partial_build_invalidates_release_provenance(repository, monkeypatch):
    seed_release(repository)
    monkeypatch.setattr(release, "sync_dev_environment", lambda *args: None)
    monkeypatch.setattr(release, "generate_completions", lambda *args: None)
    monkeypatch.setattr(
        release,
        "build_python_artifacts",
        lambda root, output, uv: make_python_archives(output),
    )
    release.build_artifacts(repository, "1.0", release.parse_args(["--python-only"]))
    with pytest.raises(RuntimeError, match="Missing or invalid release provenance"):
        release.verify_provenance(repository, "1.0")


@pytest.mark.parametrize(
    "options",
    [
        {"mode": 0o644},
        {"mode": 0o4755},
        {"name": "../envrcctl-macos-auth"},
        {"kind": tarfile.SYMTYPE},
        {"name": "extra"},
    ],
)
def test_invalid_helper_archive_rejected(tmp_path, options):
    archive = tmp_path / "helper.tar.gz"
    make_helper_archive(archive, **options)
    with pytest.raises(RuntimeError):
        release.validate_helper_archive(archive)


@pytest.mark.parametrize(
    "name", ["envrcctl-macos-auth", "envrcctl-macos-auth.bak", "envrcctl-macos-auth.bak.old"]
)
def test_python_archive_rejects_native_helpers_and_backups(tmp_path, name):
    source, wheel = make_python_archives(tmp_path, extra=f"src/envrcctl/{name}")
    with pytest.raises(RuntimeError, match="Native helper or backup"):
        release.validate_python_artifacts(source, wheel)


@pytest.mark.parametrize(
    "minimum,architecture,platform",
    [
        ("25.0", "arm64", "MACOS"),
        ("27.0", "arm64", "MACOS"),
        ("26.0", "x86_64", "MACOS"),
        ("26.0", "arm64", "IOS"),
    ],
)
def test_helper_deployment_metadata_must_match_formula(
    monkeypatch, tmp_path, minimum, architecture, platform
):
    monkeypatch.setattr(release, "ensure_macos_arm64", lambda: None)

    def run(cmd, **kwargs):
        text = f" platform {platform}\n minos {minimum}\n" if "vtool" in cmd else architecture
        return subprocess.CompletedProcess(cmd, 0, stdout=text)

    monkeypatch.setattr(release.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="arm64 macOS 26.0"):
        release.validate_helper_binary(tmp_path / "helper", tmp_path)


def test_helper_help_is_executed_without_authentication(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(release, "ensure_macos_arm64", lambda: None)

    def run(cmd, **kwargs):
        calls.append(cmd)
        if "vtool" in cmd:
            text = " platform MACOS\n minos 26.0\n"
        elif "lipo" in cmd:
            text = "arm64"
        else:
            text = "Usage:\n envrcctl-macos-auth --help\n"
            assert kwargs["timeout"] == 10
        return subprocess.CompletedProcess(cmd, 0, stdout=text)

    monkeypatch.setattr(release.subprocess, "run", run)
    helper = tmp_path / "helper"
    release.validate_helper_binary(helper, tmp_path)
    assert calls[-1] == [str(helper), "--help"]


def test_helper_build_uses_current_swift_and_staged_output(repository, monkeypatch):
    output = repository / "dist/stage"
    output.mkdir()
    tracked = repository / "src/envrcctl/envrcctl-macos-auth"
    before = tracked.read_bytes()
    monkeypatch.setattr(release, "ensure_macos_arm64", lambda: None)
    validated = []
    monkeypatch.setattr(
        release,
        "validate_helper_binary",
        lambda helper, root: validated.append(helper),
    )

    def run(command, *, cwd):
        assert cwd == repository
        assert command == [
            "sh",
            "scripts/build_macos_auth_helper.sh",
            str(repository / "scripts/macos/envrcctl-macos-auth.swift"),
            str(output / release.HELPER_NAME),
        ]
        Path(command[-1]).write_bytes(b"freshly compiled helper")

    monkeypatch.setattr(release, "run", run)
    built = release.build_helper_binary(repository, output)
    assert built.read_bytes() == b"freshly compiled helper"
    assert validated == [built]
    assert tracked.read_bytes() == before


@pytest.mark.parametrize("status", ["Accepted", "Invalid", "In Progress"])
def test_signing_precedes_notarization_and_requires_acceptance(monkeypatch, tmp_path, status):
    calls = []
    monkeypatch.setattr(release, "run", lambda command, **kwargs: calls.append(command))

    def submit(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps({"status": status, "id": "test"}))

    monkeypatch.setattr(release.subprocess, "run", submit)
    if status == "Accepted":
        release.sign_helper(tmp_path, tmp_path / "helper", "Developer ID fixture", "fixture")
    else:
        with pytest.raises(RuntimeError, match="not accepted"):
            release.sign_helper(tmp_path, tmp_path / "helper", "Developer ID fixture", "fixture")
    assert [command[0] for command in calls] == ["codesign", "codesign", "ditto", "xcrun"]
    assert "--options" in calls[0] and "runtime" in calls[0] and "--timestamp" in calls[0]


@pytest.mark.parametrize(
    "args",
    [
        ["--notary-profile", "profile"],
        ["--formula-only", "--signing-identity", "identity"],
        ["--python-only", "--signing-identity", "identity"],
    ],
)
def test_signing_options_reject_incompatible_modes(args):
    with pytest.raises(SystemExit) as error:
        release.parse_args(args)
    assert error.value.code == 2


def test_explicit_build_mode_uses_current_source_and_no_default_signing_profile():
    args = release.parse_args(["--build"])
    assert args.build
    assert not args.formula_only
    assert args.signing_identity is None
    assert args.notary_profile is None
    with pytest.raises(SystemExit):
        release.parse_args(["--build", "--formula-only"])


def test_real_build_excludes_helper_and_backups_without_renaming(repository):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed")
    shutil.copyfile(ROOT / "pyproject.toml", repository / "pyproject.toml")
    helper = repository / "src/envrcctl/envrcctl-macos-auth"
    backup = helper.with_suffix(".bak")
    before = (helper.read_bytes(), backup.read_bytes())
    version = release.project_version(repository / "pyproject.toml")
    result = subprocess.run(
        [uv, "build", "--out-dir", str(repository / "dist")],
        cwd=repository,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    source, wheel, _ = release.artifact_paths(repository / "dist", version)
    release.validate_python_artifacts(source, wheel)
    assert (helper.read_bytes(), backup.read_bytes()) == before


@pytest.mark.parametrize("makeflags", ["-j8", ""])
@pytest.mark.parametrize("fail", [False, True])
@pytest.mark.parametrize("target", [None, "release-artifacts"])
def test_parallel_make_has_one_ordered_pipeline(tmp_path, makeflags, fail, target):
    shutil.copyfile(ROOT / "Makefile", tmp_path / "Makefile")
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts/release_artifacts.py"
    script.write_text(
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "for stage in ('sync', 'completions', 'python', 'helper', 'archive', 'formula'):\n"
        "    with Path('stages').open('a') as output: output.write(stage + '\\n')\n"
        "    time.sleep(0.02)\n"
        "    if stage == os.environ.get('FAIL_STAGE'): sys.exit(23)\n"
    )
    command = ["make", f"PYTHON={sys.executable}"]
    if target:
        command.append(target)
    if not makeflags:
        command += ["-j8"]
    result = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "MAKEFLAGS": makeflags, "FAIL_STAGE": "python" if fail else ""},
    )
    stages = (tmp_path / "stages").read_text().splitlines()
    assert stages == (
        ["sync", "completions", "python"]
        if fail
        else ["sync", "completions", "python", "helper", "archive", "formula"]
    )
    assert (result.returncode != 0) == fail


@pytest.mark.parametrize("status", [b"", b"?? a file.sh\0", b"R  new name.sh\0old name.py\0"])
def test_verify_works_in_stock_bash_with_nul_delimited_paths(tmp_path, status):
    repo = tmp_path / "repo"
    repo.mkdir()
    commands = tmp_path / "commands"
    commands.mkdir()
    git = commands / "git"
    git.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"if sys.argv[1] == 'rev-parse': print({str(repo)!r})\n"
        f"else: sys.stdout.buffer.write({status!r})\n",
    )
    git.chmod(0o755)
    shellcheck = commands / "shellcheck"
    shellcheck.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > checked\n")
    shellcheck.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", str(ROOT / ".zed/scripts/verify")],
        cwd=repo,
        env={**os.environ, "PATH": f"{commands}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if status:
        expected = "new name.sh" if status.startswith(b"R") else "a file.sh"
        assert (repo / "checked").read_text().strip() == expected
        assert "python:" not in result.stdout
    else:
        assert "no changes; skipping" in result.stdout


@pytest.mark.parametrize("runner", ["venv", "uv", "missing"])
@pytest.mark.parametrize("missing_module", [None, "pytest", "bandit"])
def test_verify_uses_project_python_and_fails_for_missing_checks(
    tmp_path,
    runner,
    missing_module,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    commands = tmp_path / "commands"
    commands.mkdir()
    git = commands / "git"
    git.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"if sys.argv[1] == 'rev-parse': print({str(repo)!r})\n"
        "else: sys.stdout.buffer.write(b' M src/a file.py\\0')\n",
    )
    git.chmod(0o755)
    if runner != "missing":
        selected = repo / ".venv/bin/python" if runner == "venv" else commands / "uv"
        selected.parent.mkdir(parents=True, exist_ok=True)
        selected.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> checks\n"
            f'case "$*" in *"-m {missing_module} --version") exit 7 ;; esac\n'
            "exit 0\n",
        )
        selected.chmod(0o755)
        if runner == "venv":
            unused_uv = commands / "uv"
            unused_uv.write_text("#!/bin/sh\nexit 99\n")
            unused_uv.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", str(ROOT / ".zed/scripts/verify")],
        cwd=repo,
        env={**os.environ, "PATH": f"{commands}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    if runner == "missing" or missing_module:
        assert result.returncode != 0
        assert "uv sync --locked --extra test --group dev" in result.stderr
        assert "verify: OK" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        prefix = "run --no-sync python " if runner == "uv" else ""
        assert (repo / "checks").read_text().splitlines() == [
            f"{prefix}-m pytest --version",
            f"{prefix}-m bandit --version",
            f"{prefix}-m pytest -q",
            f"{prefix}-m bandit -r src -x tests -s B404,B603,B607",
        ]
