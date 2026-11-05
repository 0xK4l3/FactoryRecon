"""
Generates the RJ45 Ethernet icon/logo (PNG and Windows ICO) for FactoryRecon
using Pillow so the window titlebar and header have a crisp RJ45 connector logo.
"""

from __future__ import annotations

import os
from PIL import Image, ImageDraw


def generate_rj45_assets(base_dir: str) -> tuple[str, str]:
    """
    Creates rj45_logo.png (128x128) and rj45_icon.ico (multi-size) in base_dir.
    Returns (png_path, ico_path).
    """
    png_path = os.path.join(base_dir, "rj45_logo.png")
    ico_path = os.path.join(base_dir, "rj45_icon.ico")

    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded square badge background (deep navy-blue tech badge with cyan border)
    margin = 12
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=48,
        fill=(15, 23, 42, 255),
        outline=(56, 189, 248, 255),
        width=8,
    )

    # Outer RJ45 port socket housing (light metallic/slate)
    port_left = 48
    port_top = 48
    port_right = size - 48
    port_bottom = size - 52
    draw.rounded_rectangle(
        [port_left, port_top, port_right, port_bottom],
        radius=16,
        fill=(30, 41, 59, 255),
        outline=(148, 163, 184, 255),
        width=6,
    )

    # Inner recessed RJ45 cavity (T-shaped / stepped latch cutout at bottom)
    cav_left = 68
    cav_top = 68
    cav_right = size - 68
    cav_bottom = 160
    draw.rectangle(
        [cav_left, cav_top, cav_right, cav_bottom],
        fill=(9, 13, 24, 255),
    )

    # Latch step1 & step2 (bottom tab of RJ45 jack)
    step1_left = 92
    step1_right = size - 92
    step1_bottom = 180
    draw.rectangle(
        [step1_left, cav_bottom - 2, step1_right, step1_bottom],
        fill=(9, 13, 24, 255),
    )

    step2_left = 108
    step2_right = size - 108
    step2_bottom = 196
    draw.rectangle(
        [step2_left, step1_bottom - 2, step2_right, step2_bottom],
        fill=(9, 13, 24, 255),
    )

    # 8 Gold RJ45 Contact Pins at the top of the cavity
    num_pins = 8
    pin_area_left = cav_left + 14
    pin_area_right = cav_right - 14
    total_w = pin_area_right - pin_area_left
    spacing = total_w / num_pins
    pin_w = 7
    pin_top = cav_top + 6
    pin_bottom = cav_top + 42

    for i in range(num_pins):
        cx = int(pin_area_left + spacing * (i + 0.5))
        draw.rounded_rectangle(
            [cx - pin_w // 2, pin_top, cx + pin_w // 2, pin_bottom],
            radius=3,
            fill=(250, 204, 21, 255),  # Gold contact pin
        )

    # Activity & Link LEDs at top corners of RJ45 port (Green Link LED + Amber Activity LED)
    # Left LED (Green Link)
    draw.rounded_rectangle(
        [port_left + 12, port_bottom - 26, port_left + 38, port_bottom - 12],
        radius=4,
        fill=(16, 185, 129, 255),
    )
    # Right LED (Amber Activity)
    draw.rounded_rectangle(
        [port_right - 38, port_bottom - 26, port_right - 12, port_bottom - 12],
        radius=4,
        fill=(245, 158, 11, 255),
    )

    img.save(png_path, format="PNG")
    img.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    return png_path, ico_path


if __name__ == "__main__":
    generate_rj45_assets(os.path.dirname(os.path.abspath(__file__)))

