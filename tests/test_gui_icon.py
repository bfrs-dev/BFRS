import importlib.util
from pathlib import Path

from PIL import Image


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_icon_assets.py"
_SPEC = importlib.util.spec_from_file_location("bfrs_build_icon_assets", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_icon_generator_writes_valid_png_and_ico(tmp_path):
    png_path, ico_path = _MODULE.build_icon_assets(tmp_path)

    with Image.open(png_path) as image:
        image.load()
        assert image.format == "PNG"
        assert image.size == (1024, 1024)

    with Image.open(ico_path) as image:
        image.load()
        assert image.format == "ICO"
        assert image.size == (256, 256)
