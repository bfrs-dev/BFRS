import base64

from bfrs.gui.icon_data import ICON_PNG_BASE64


def test_embedded_application_icon_is_png():
    payload = base64.b64decode(ICON_PNG_BASE64)

    assert payload.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(payload) > 1024
