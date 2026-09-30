"""Generate the Windows .ico file from the packaged BFRS PNG asset."""

from __future__ import annotations

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PNG = ROOT / "src" / "bfrs" / "gui" / "assets" / "bfrs.png"


def build_icon_assets(output_dir: str | Path | None = None) -> tuple[Path, Path]:
    target = Path(output_dir) if output_dir is not None else ROOT / "packaging"
    target.mkdir(parents=True, exist_ok=True)

    if not SOURCE_PNG.is_file():
        raise FileNotFoundError(f"BFRS icon source is missing: {SOURCE_PNG}")

    source = Image.open(SOURCE_PNG).convert("RGBA")
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
