"""Renders the 800x1200 Signature Lab cover for the Game Reversal Club site.

It matches the Pointer Lab cover: the same dark ground and glow, the name in
Source Code Pro Bold with "Lab" in orange, and rounded boxes. The boxes are a
real nine-byte signature read left to right, top to bottom:

    48 8B 05 ?? ?? ?? ?? 48 85      mov rax, [rip+disp32]; test rax, rax

with the RIP-relative displacement wildcarded, as Signature Lab masks it.

    python scripts/render_cover.py OUT.png
"""

import math
import os
import sys

from PIL import Image, ImageDraw, ImageFont

SCALE = 2
W, H = 800, 1200

EDGE = (0x0D, 0x11, 0x15)
GLOW = (0x1B, 0x21, 0x28)
WHITE = (0xE3, 0xE9, 0xEE)
ORANGE = (0xE6, 0x7E, 0x22)
CELL = (0x12, 0x16, 0x1B)

CELLS = [
    ["48", "8B", "05"],
    ["??", "??", "??"],
    ["??", "48", "85"],
]


def font(name, size):
    folders = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Fonts"),
        os.path.join(os.environ.get("WINDIR", "C:/Windows"), "Fonts"),
    ]
    for folder in folders:
        path = os.path.join(folder, name)
        if os.path.exists(path):
            return ImageFont.truetype(path, size * SCALE)
    raise SystemExit(f"{name} not found; install Source Code Pro")


def ground():
    img = Image.new("RGB", (W * SCALE, H * SCALE), EDGE)
    px = img.load()
    cx, cy, radius = 420 * SCALE, 720 * SCALE, 720 * SCALE
    for y in range(H * SCALE):
        for x in range(W * SCALE):
            t = min(1.0, math.hypot(x - cx, y - cy) / radius)
            t = t * t * (3 - 2 * t)
            px[x, y] = tuple(round(g + (e - g) * t) for g, e in zip(GLOW, EDGE))
    return img


def centred_text(draw, box, text, fnt, fill):
    left, top, right, bottom = box
    l, t, r, b = draw.textbbox((0, 0), text, font=fnt)
    x = (left + right) / 2 - (l + r) / 2
    y = (top + bottom) / 2 - (t + b) / 2
    draw.text((x, y), text, font=fnt, fill=fill)


def main(out):
    img = ground()
    draw = ImageDraw.Draw(img)
    s = SCALE

    title = font("SourceCodePro-Bold.ttf", 92)
    first, second = "Signature ", "Lab"
    w1 = draw.textlength(first, font=title)
    w2 = draw.textlength(second, font=title)
    x = (W * s - (w1 + w2)) / 2
    baseline = 205 * s
    draw.text((x, baseline), first, font=title, fill=WHITE, anchor="ls")
    draw.text((x + w1, baseline), second, font=title, fill=ORANGE, anchor="ls")

    regular = font("SourceCodePro-Regular.ttf", 64)
    bold = font("SourceCodePro-Bold.ttf", 64)
    size, gap, stroke, radius = 184, 36, 8, 30
    left = (W - (3 * size + 2 * gap)) // 2
    top = 380
    for row, values in enumerate(CELLS):
        for col, value in enumerate(values):
            x0 = (left + col * (size + gap)) * s
            y0 = (top + row * (size + gap)) * s
            box = (x0, y0, x0 + size * s, y0 + size * s)
            if value == "??":
                draw.rounded_rectangle(box, radius * s, fill=ORANGE)
                centred_text(draw, box, value, bold, CELL)
            else:
                draw.rounded_rectangle(box, radius * s, fill=CELL, outline=WHITE, width=stroke * s)
                centred_text(draw, box, value, regular, WHITE)

    img.resize((W, H), Image.LANCZOS).save(out, optimize=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "signature-lab-cover.png")
