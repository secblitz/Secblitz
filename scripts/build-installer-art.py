"""Make the installer banners from the source art. Run from the repository root:
python3 scripts/build-installer-art.py
Needs Pillow (scripts/requirements-art.txt). CI does not run this; the PNGs are committed."""
import pathlib
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
ART = ROOT / "installer" / "art"
FONT = ROOT / "assets" / "fonts" / "Lexend-SemiBold.ttf"
RATIO = 3.8
WIDTHS = (600, 750, 900, 1050, 1200, 1500)
INK = {"light": (24, 24, 27), "dark": (244, 244, 245)}
LIMIT = 1_500_000
ZOOM = 0.82  # share of the banner width the source art fills
SHIELD_Y = 0.47  # where the shield centre sits in the source art, as a share of its height
MARK_INK = (24, 24, 27, 255)


def curve(p0, c, p1, steps=16):
    return [
        ((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * c[0] + t * t * p1[0],
         (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * c[1] + t * t * p1[1])
        for t in (i / steps for i in range(1, steps + 1))
    ]


# Outlines from assets/secblitz.svg (viewBox 256); each Q segment is flattened.
OUTER = [(128, 40)]
OUTER += curve((128, 40), (96, 61), (50, 63)) + [(50, 106)]
OUTER += curve((50, 106), (50, 178), (128, 214))
OUTER += curve((128, 214), (206, 178), (206, 106)) + [(206, 63)]
OUTER += curve((206, 63), (160, 61), (128, 40))
INNER = [(128, 61)]
INNER += curve((128, 61), (101, 77), (67, 79)) + [(67, 107)]
INNER += curve((67, 107), (67, 165), (128, 196))
INNER += curve((128, 196), (189, 165), (189, 107)) + [(189, 79)]
INNER += curve((189, 79), (155, 77), (128, 61))
BOLT = [(120, 85.4), (143, 85.4), (131.5, 118.7), (153.4, 118.7), (115.4, 171.6), (123.5, 137.1), (101.6, 137.1)]


def logo(size):
    """The Secblitz mark drawn at 4x and reduced for smooth edges."""
    s = size * 4
    k = s / 256
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=int(56 * k), fill=MARK_INK)
    for points, fill in ((OUTER, "white"), (INNER, MARK_INK), (BOLT, "white")):
        d.polygon([(x * k, y * k) for x, y in points], fill=fill)
    return im.resize((size, size), Image.LANCZOS)


def banner(theme, width):
    src = Image.open(ART / "source" / f"hero-{theme}.jpg").convert("RGB")
    height = round(width / RATIO)
    # The shield nearly fills the source height, so the art is scaled down to leave room above
    # and below it, and the quiet left edge is stretched to fill the width.
    sw = round(width * ZOOM)
    sh = round(src.height * sw / src.width)
    art = src.resize((sw, sh), Image.LANCZOS)
    full = Image.new("RGB", (width, sh))
    gap = width - sw
    if gap > 0:
        strip = art.crop((0, 0, 2, sh)).resize((gap, sh), Image.BILINEAR)
        full.paste(strip.filter(ImageFilter.GaussianBlur(max(2, width // 60))), (0, 0))
    full.paste(art, (gap, 0))
    top = round(sh * SHIELD_Y - height / 2)
    top = min(max(top, 0), sh - height)
    im = full.crop((0, top, width, top + height))
    scale = width / 600
    mark = logo(round(30 * scale))
    x = round(28 * scale)
    y = (height - mark.height) // 2
    im.paste(mark, (x, y), mark)
    font = ImageFont.truetype(str(FONT), round(22 * scale))
    d = ImageDraw.Draw(im)
    tx = x + mark.width + round(10 * scale)
    box = d.textbbox((0, 0), "Secblitz", font=font)
    ty = y + (mark.height - (box[3] - box[1])) // 2 - box[1]
    d.text((tx, ty), "Secblitz", font=font, fill=INK[theme])
    return im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG)


def main():
    total = 0
    for theme in INK:
        for width in WIDTHS:
            path = ART / f"banner-{theme}-{width}.png"
            banner(theme, width).save(path, optimize=True)
            total += path.stat().st_size
    print(f"{total} bytes")
    if total > LIMIT:
        raise SystemExit(f"Banners are {total} bytes, over the {LIMIT} byte budget")


if __name__ == "__main__":
    main()
