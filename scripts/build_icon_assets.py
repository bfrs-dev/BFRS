"""Generate BFRS PNG/ICO assets procedurally for Windows packaging."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]


def _draw_bfrs_icon(size: int = 1024) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def s(value: int) -> int:
        return round(value * size / 1024)

    navy = (8, 26, 50, 255)
    dark = (12, 42, 78, 255)
    cyan = (44, 220, 255, 255)
    silver = (195, 219, 235, 255)
    light = (235, 247, 255, 255)
    steel = (130, 172, 205, 255)

    draw.rounded_rectangle(
        (s(80), s(80), s(944), s(944)),
        radius=s(160),
        fill=navy,
        outline=(74, 190, 255, 255),
        width=s(30),
    )

    draw.rounded_rectangle(
        (s(155), s(145), s(310), s(875)),
        radius=s(55),
        fill=dark,
        outline=cyan,
        width=s(22),
    )
    draw.rounded_rectangle(
        (s(250), s(150), s(840), s(505)),
        radius=s(165),
        fill=(11, 39, 74, 255),
        outline=cyan,
        width=s(26),
    )
    draw.rounded_rectangle(
        (s(250), s(510), s(840), s(865)),
        radius=s(165),
        fill=(11, 39, 74, 255),
        outline=cyan,
        width=s(26),
    )
    for box in ((390, 255, 700, 405), (390, 615, 700, 765)):
        draw.rounded_rectangle(tuple(s(v) for v in box), radius=s(75), fill=navy)

    traces = (
        ((175, 180), (175, 320), (240, 385)),
        ((190, 700), (190, 820), (260, 870)),
        ((125, 280), (125, 430), (210, 515)),
    )
    for points in traces:
        scaled = [(s(x), s(y)) for x, y in points]
        draw.line(scaled, fill=cyan, width=s(16), joint="curve")
        for x, y in (scaled[0], scaled[-1]):
            draw.ellipse(
                (x - s(18), y - s(18), x + s(18), y + s(18)),
                fill=dark,
                outline=cyan,
                width=s(10),
            )

    cx, cy, radius = s(360), s(520), s(210)
    draw.ellipse(
        (cx - radius, cy - radius, cx + radius, cy + radius),
        fill=silver,
        outline=(79, 217, 255, 255),
        width=s(24),
    )
    inner = s(28)
    draw.ellipse(
        (cx - radius + inner, cy - radius + inner, cx + radius - inner, cy + radius - inner),
        fill=steel,
        outline=light,
        width=s(12),
    )
    hub = s(72)
    draw.ellipse(
        (cx - hub, cy - hub, cx + hub, cy + hub),
        fill=(14, 35, 64, 255),
        outline=light,
        width=s(22),
    )
    core = s(28)
    draw.ellipse((cx - core, cy - core, cx + core, cy + core), fill=(207, 230, 243, 255))

    mx, my, mr = s(500), s(555), s(185)
    draw.ellipse(
        (mx - mr, my - mr, mx + mr, my + mr),
        outline=light,
        width=s(40),
    )
    ring = s(24)
    draw.ellipse(
        (mx - mr + ring, my - mr + ring, mx + mr - ring, my + mr - ring),
        outline=cyan,
        width=s(20),
    )
    draw.polygon(
        [
            (s(610), s(675)),
            (s(655), s(630)),
            (s(835), s(805)),
            (s(785), s(855)),
        ],
        fill=silver,
        outline=cyan,
    )
    draw.line((s(595), s(470), s(690), s(470)), fill=(145, 245, 255, 255), width=s(12))
    draw.line((s(642), s(423), s(642), s(517)), fill=(145, 245, 255, 255), width=s(12))

    return image


def build_icon_assets(output_dir: str | Path | None = None) -> tuple[Path, Path]:
    target = Path(output_dir) if output_dir is not None else ROOT / "packaging"
    target.mkdir(parents=True, exist_ok=True)

    source = _draw_bfrs_icon()
    png_path = target / "bfrs.png"
    ico_path = target / "bfrs.ico"

    source.save(png_path, optimize=True)
    source.save(
        ico_path,
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    return png_path, ico_path


def main() -> int:
    png_path, ico_path = build_icon_assets()
    print(f"PNG icon: {png_path}")
    print(f"ICO icon: {ico_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
