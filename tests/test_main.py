import runpy
import sys

import envrctl.cli as cli
import envrctl.main as main


def test_main_invokes_app(monkeypatch) -> None:
    called = {"ok": False}

    def fake_app() -> None:
        called["ok"] = True

    monkeypatch.setattr(main, "app", fake_app)
    main.main()

    assert called["ok"] is True


def test_main_module_runs_as_script(monkeypatch) -> None:
    called = {"ok": False}

    def fake_app() -> None:
        called["ok"] = True

    monkeypatch.setattr(cli, "app", fake_app)
    sys.modules.pop("envrctl.main", None)
    runpy.run_module("envrctl.main", run_name="__main__")

    assert called["ok"] is True
