import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "release_artifacts.py"
spec = importlib.util.spec_from_file_location("release_artifacts", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


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
