"""Generate Windows icon assets from the embedded BFRS artwork."""

from __future__ import annotations

import base64
from io import BytesIO
from pathlib import Path
import sys

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from bfrs.gui.icon_data import ICON_PNG_BASE64  # noqa: E402


def build_icon_assets(output_dir: str | Path | None = None) -> tuple[Path, Path]:
    target = Path(output_dir) if output_dir is not None else ROOT / "packaging"
    target.mkdir(parents=True, exist_ok=True)

    source = Image.open(BytesIO(base64.b64decode(ICON_PNG_BASE64))).convert("RGBA")
    png_path = target / "bfrs.png"
    ico_path = target / "bfrs.ico"

    source.save(png_path, optimize=True)
    source.save(
        ico_path,
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    return png_path, ico_path


def main() -> int:
    png_path, ico_path = build_icon_assets()
    print(f"PNG icon: {png_path}")
    print(f"ICO icon: {ico_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
