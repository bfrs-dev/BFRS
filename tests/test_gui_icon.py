from importlib.resources import files


def test_packaged_application_icon_is_png():
    icon = files("bfrs.gui").joinpath("assets", "bfrs.png")
    payload = icon.read_bytes()

    assert payload.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(payload) > 1024
