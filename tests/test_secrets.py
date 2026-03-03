import pytest

from envrctl import secrets
from envrctl.errors import EnvrcctlError


def test_parse_ref_valid_and_invalid() -> None:
    ref = secrets.parse_ref("kc:svc:acct")
    assert ref.scheme == "kc"
    assert ref.service == "svc"
    assert ref.account == "acct"
    assert ref.kind == "runtime"

    ref = secrets.parse_ref("kc:svc:openai:prod")
    assert ref.account == "openai:prod"
    assert ref.kind == "runtime"

    ref = secrets.parse_ref("kc:svc:openai:prod:admin")
    assert ref.account == "openai:prod"
    assert ref.kind == "admin"

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("invalid")

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("xx:svc:acct")

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("kc::acct")

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("kc:bad service:acct")

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("kc:svc:bad acct")

    with pytest.raises(EnvrcctlError):
        secrets.parse_ref("kc:svc:bad/act")


def test_format_ref_scheme_validation() -> None:
    assert secrets.format_ref("svc", "acct", scheme="kc") == "kc:svc:acct:runtime"

    with pytest.raises(EnvrcctlError):
        secrets.format_ref("svc", "acct", scheme="nope")


def test_resolve_backend_env_override(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setenv("ENVRCCTL_BACKEND", "ss")
    monkeypatch.setattr(secrets, "_backend_for_scheme", lambda scheme: sentinel)

    scheme, backend = secrets.resolve_backend()
    assert scheme == "ss"
    assert backend is sentinel


def test_resolve_backend_env_override_invalid(monkeypatch) -> None:
    monkeypatch.setenv("ENVRCCTL_BACKEND", "nope")

    with pytest.raises(EnvrcctlError):
        secrets.resolve_backend()


def test_resolve_backend_scheme_override_invalid() -> None:
    with pytest.raises(EnvrcctlError):
        secrets.resolve_backend("nope")


def test_backend_for_ref_dispatch(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setattr(secrets, "_backend_for_scheme", lambda scheme: sentinel)

    ref = secrets.SecretRef(scheme="kc", service="svc", account="acct", kind="runtime")
    assert secrets.backend_for_ref(ref) is sentinel


def test_resolve_backend_prefers_kc_on_darwin(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.delenv("ENVRCCTL_BACKEND", raising=False)
    monkeypatch.setattr(secrets.sys, "platform", "darwin")
    monkeypatch.setattr(secrets, "_backend_for_scheme", lambda scheme: sentinel)

    scheme, backend = secrets.resolve_backend()
    assert scheme == "kc"
    assert backend is sentinel


def test_resolve_backend_secret_tool_on_linux(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.delenv("ENVRCCTL_BACKEND", raising=False)
    monkeypatch.setattr(secrets.sys, "platform", "linux")
    monkeypatch.setattr(secrets, "_have_cmd", lambda cmd: True)
    monkeypatch.setattr(secrets, "_backend_for_scheme", lambda scheme: sentinel)

    scheme, backend = secrets.resolve_backend()
    assert scheme == "ss"
    assert backend is sentinel


def test_resolve_backend_no_backend_available(monkeypatch) -> None:
    monkeypatch.delenv("ENVRCCTL_BACKEND", raising=False)
    monkeypatch.setattr(secrets.sys, "platform", "linux")
    monkeypatch.setattr(secrets, "_have_cmd", lambda cmd: False)

    with pytest.raises(EnvrcctlError):
        secrets.resolve_backend()


def test_format_ref_requires_service_and_account() -> None:
    with pytest.raises(EnvrcctlError):
        secrets.format_ref("", "acct")
    with pytest.raises(EnvrcctlError):
        secrets.format_ref("svc", "")

    with pytest.raises(EnvrcctlError):
        secrets.format_ref("bad service", "acct")
    with pytest.raises(EnvrcctlError):
        secrets.format_ref("svc", "bad acct")
    with pytest.raises(EnvrcctlError):
        secrets.format_ref("svc", "bad/act")


def test_backend_for_scheme_kc_requires_darwin(monkeypatch) -> None:
    monkeypatch.setattr(secrets.sys, "platform", "linux")

    with pytest.raises(EnvrcctlError):
        secrets._backend_for_scheme("kc")


def test_backend_for_scheme_ss_requires_secret_tool(monkeypatch) -> None:
    monkeypatch.setattr(secrets, "_have_cmd", lambda cmd: False)

    with pytest.raises(EnvrcctlError):
        secrets._backend_for_scheme("ss")


def test_backend_for_scheme_unknown() -> None:
    with pytest.raises(EnvrcctlError):
        secrets._backend_for_scheme("nope")
