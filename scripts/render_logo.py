"""Renders docs/logo.svg's design to the PNG and ICO the plugin embeds.

The shapes are drawn with Pillow rather than rasterised from the SVG so the
build of the icons needs no SVG renderer. Keep the two in step by hand: the
coordinates below are the SVG's, in its 64-unit viewBox.

    python scripts/render_logo.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

NAVY = (0x0F, 0x22, 0x35, 255)
RED = (0xC0, 0x39, 0x2B, 255)
ORANGE = (0xE6, 0x7E, 0x22, 255)
WHITE = (0xFF, 0xFF, 0xFF, 255)

ROOT = Path(__file__).resolve().parent.parent
SUPERSAMPLE = 16  # draw at 1024 px and downscale, for clean anti-aliasing


def draw(size: int) -> Image.Image:
    s = 64 * SUPERSAMPLE
    k = SUPERSAMPLE
    img = Image.new("RGBA", (s, s), NAVY)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, s, 4 * k], fill=RED)
    radius = int(2.5 * k)
    stroke = 3 * k
    # Two plain bytes around a wildcard byte: the white cells are outlined,
    # the wildcard is filled. Outlines are drawn centred on the SVG's path,
    # so the box grows by half the stroke on each side.
    # Six bytes of a hex dump; the two filled ones are the wildcards. Each
    # outlined cell is drawn from its outer edge (the SVG path plus half the
    # stroke) so it comes out the same size as the filled ones.
    cells = [(7, 17, False), (25, 17, True), (43, 17, False), (7, 37, False), (25, 37, False), (43, 37, True)]
    half = stroke // 2
    for x, y, filled in cells:
        outer = [x * k - half, y * k - half, (x + 12) * k + half, (y + 12) * k + half]
        if filled:
            d.rounded_rectangle(outer, radius=3 * k, fill=ORANGE)
        else:
            d.rounded_rectangle(outer, radius=radius + half, outline=WHITE, width=stroke)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    resources = ROOT / "resources"
    draw(16).save(resources / "menu-icon.png", optimize=True)
    big = draw(256)
    big.save(resources / "SignatureLab.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
    draw(512).save(ROOT / "docs" / "logo-512.png", optimize=True)
    print("wrote resources/menu-icon.png, resources/SignatureLab.ico, docs/logo-512.png")


if __name__ == "__main__":
    main()
