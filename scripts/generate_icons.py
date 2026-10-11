#!/usr/bin/env python3
"""
Generate PNG icons for SentinelX Chrome Extension using standard library only (struct + zlib).
No external image libraries (PIL/Pillow) required.
"""

import os
import struct
import zlib


def create_png(width: int, height: int, rgba_bytes: bytes) -> bytes:
    """Create a valid PNG byte stream from raw RGBA bytes."""
    # PNG signature
    png = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    # width (4), height (4), bit depth (1 = 8), color type (1 = 6 RGBA), compression (0), filter (0), interlace (0)
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    png += struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc

    # IDAT chunk (with scanline filter byte 0 prefix per row)
    raw_scanlines = bytearray()
    row_bytes = width * 4
    for y in range(height):
        raw_scanlines.append(0)  # Filter type 0 (None)
        raw_scanlines.extend(rgba_bytes[y * row_bytes : (y + 1) * row_bytes])

    compressed = zlib.compress(bytes(raw_scanlines), level=9)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    png += struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc

    # IEND chunk
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    png += struct.pack(">I", 0) + b"IEND" + iend_crc

    return png


def draw_sentinel_icon(size: int) -> bytes:
    """Draw a cybersecurity shield icon with a glowing 'X' core."""
    pixels = bytearray(size * size * 4)

    # Primary colors
    # Shield background: Deep navy/slate #0F172A
    # Shield border / accent: Electric cyan #06B6D4 / #38BDF8
    # Center core: Bright emerald / cyan #10B981

    center_x = size / 2.0
    center_y = size / 2.0
    scale = size / 16.0

    for y in range(size):
        for x in range(size):
            idx = (y * size + x) * 4

            # Coordinates relative to center normalized (-1 to 1)
            nx = (x - center_x) / (size / 2.0)
            ny = (y - center_y) / (size / 2.0)

            # Shield geometry: top half is curved/flat, bottom half tapers to point
            in_shield = False
            border_shield = False

            # Upper bounds
            if ny >= -0.85 and ny <= 0.85:
                # Width tapers as ny goes down
                if ny < 0.1:
                    max_w = 0.82
                else:
                    max_w = 0.82 * (1.0 - (ny - 0.1) / 0.8)

                dist_from_edge = max_w - abs(nx)
                if dist_from_edge >= 0:
                    in_shield = True
                    if dist_from_edge < (0.16 * 16.0 / max(size, 16)):
                        border_shield = True

            if in_shield:
                if border_shield:
                    # Electric cyan border
                    pixels[idx] = 14     # R
                    pixels[idx + 1] = 165 # G
                    pixels[idx + 2] = 233 # B
                    pixels[idx + 3] = 255 # A
                else:
                    # Check for center 'X' / radar pulse
                    is_cross = (abs(abs(nx) - abs(ny * 0.8)) < (0.15 * 16.0 / size)) and (abs(ny) < 0.5)
                    if is_cross:
                        # Bright cyan/green core
                        pixels[idx] = 56
                        pixels[idx + 1] = 189
                        pixels[idx + 2] = 248
                        pixels[idx + 3] = 255
                    else:
                        # Dark shield body
                        pixels[idx] = 15
                        pixels[idx + 1] = 23
                        pixels[idx + 2] = 42
                        pixels[idx + 3] = 255
            else:
                # Transparent background
                pixels[idx] = 0
                pixels[idx + 1] = 0
                pixels[idx + 2] = 0
                pixels[idx + 3] = 0

    return bytes(pixels)


def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "..", "extension", "icons")
    os.makedirs(icons_dir, exist_ok=True)

    sizes = [16, 48, 128]
    for size in sizes:
        rgba = draw_sentinel_icon(size)
        png_data = create_png(size, size, rgba)
        out_path = os.path.join(icons_dir, f"icon-{size}.png")
        with open(out_path, "wb") as f:
            f.write(png_data)
        print(f"Generated {out_path} ({size}x{size}, {len(png_data)} bytes)")


if __name__ == "__main__":
    main()
