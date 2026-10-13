# Installer banners

These pictures run across the top of every page of the Secblitz installer and the Remove Secblitz window.

- `banner-light-*.png` and `banner-dark-*.png` are the banners. There are six widths (600, 750, 900, 1050, 1200 and 1500 pixels) for each look, so the installer can pick the sharpest one for the screen scale without stretching it upwards. Every banner is 3.8 times wider than it is tall.
- `source/hero-light.jpg` and `source/hero-dark.jpg` are the pictures the banners are made from: a soft 3D shield made from the Secblitz logo.

The two source pictures were generated on 2026-10-13 with fal.ai, model `fal-ai/nano-banana-2/edit`, from the Secblitz logo. The prompts were:

Light:

> Create a wide banner illustration for a software installer. Turn the attached Secblitz logo into a soft, glossy 3D shield: keep the exact shield silhouette and the exact lightning bolt shape from the logo, the shield body in matte ink black (#18181B) with a soft white beveled rim and a white lightning bolt, subtle cool blue (#2563EB) rim light and a gentle glow beneath it. Place the shield on the right third, floating slightly above a soft reflection. Backdrop: calm, very soft gradient from light warm grey (#F7F7F8) to a pale cool blue, with faint, blurred abstract rounded shapes for depth. Leave the left two thirds clean and quiet for text. Premium, minimal, product render style, soft studio lighting. Absolutely no text, no letters, no numbers, no watermark, no other logos.

Dark:

> Create a wide banner illustration for a software installer, dark theme. Turn the attached Secblitz logo into a soft, glossy 3D shield: keep the exact shield silhouette and the exact lightning bolt shape from the logo, the shield body in satin ink black (#18181B) with a soft white beveled rim and a glowing white lightning bolt, cool blue (#2563EB) rim light and a gentle blue glow beneath it. Place the shield on the right third, floating slightly above a soft reflection. Backdrop: deep near-black (#0E0E10) fading into a dark midnight blue, with faint, blurred abstract rounded shapes and very subtle light particles for depth. Leave the left two thirds clean and dark for text. Premium, minimal, product render style. Absolutely no text, no letters, no numbers, no watermark, no other logos.

## Rebuilding the banners

From the repository root:

```sh
python3 -m pip install -r scripts/requirements-art.txt
python3 scripts/build-installer-art.py
```

The script scales the source picture, draws the logo and the name Secblitz on the left, and writes the twelve PNG files. It stops if they add up to more than 1.5 MB. The build does not run it, because the output can differ a little between Pillow versions, so the PNG files are committed.
