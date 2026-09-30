import multiprocessing

from bfrs.gui import app


def test_gui_prepares_frozen_multiprocessing(monkeypatch):
    calls = []

    monkeypatch.setattr(
        multiprocessing,
        "freeze_support",
        lambda: calls.append("freeze_support"),
    )

    app._prepare_multiprocessing()

    assert calls == ["freeze_support"]
