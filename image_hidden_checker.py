#!/usr/bin/env python3
"""
image_hidden_checker.py

Forensic checker for suspicious/hidden data in common image formats.

Checks:
- PNG:
  * validates IHDR dimensions
  * collects/decompresses IDAT
  * estimates expected scanline payload size
  * detects extra decompressed scanlines / trailing decompressed bytes
  * reports chunks after IEND
  * reports trailing file bytes after IEND
- JPEG/JFIF:
  * parses markers
  * reports bytes after EOI (FFD9)
  * extracts basic SOF dimensions
  * flags embedded file signatures in trailing data
- GIF:
  * reports bytes after trailer byte 0x3B
- BMP:
  * compares declared file size vs actual file size
  * estimates expected pixel-array end
  * reports trailing bytes
- WebP:
  * compares RIFF-declared size vs actual file size
- Generic:
  * detects common embedded file signatures
  * extracts printable strings from suspicious trailing/extra regions
  * optional carving of suspicious regions to disk

This is a triage tool, not a full steganography detector.
"""

import argparse
import binascii
import os
import re
import struct
import sys
import zlib
from pathlib import Path

SIGS = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF87a": "GIF87a",
    b"GIF89a": "GIF89a",
    b"BM": "BMP",
    b"RIFF": "RIFF/WebP-or-other",
    b"PK\x03\x04": "ZIP",
    b"%PDF-": "PDF",
    b"\x7fELF": "ELF",
    b"Rar!\x1a\x07": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"\x1f\x8b\x08": "GZIP",
}

def human(n):
    units = ["B", "KiB", "MiB", "GiB"]
    x = float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.1f} {u}" if u != "B" else f"{int(x)} B"
        x /= 1024

def printable_strings(data, min_len=6):
    patt = rb"[\x20-\x7e]{%d,}" % min_len
    return [m.decode("ascii", "replace") for m in re.findall(patt, data)]

def scan_signatures(data, base_offset=0):
    hits = []
    for sig, name in SIGS.items():
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            hits.append((base_offset + i, name))
            start = i + 1
    return sorted(hits)

def save_region(outdir, src, label, data):
    if not data:
        return
    outdir.mkdir(parents=True, exist_ok=True)
    p = outdir / f"{src.stem}_{label}.bin"
    p.write_bytes(data)
    print(f"    carved -> {p}")

def png_expected_raw_bytes(width, height, bit_depth, color_type, interlace):
    # bits per pixel according to PNG color type
    channels = {
        0: 1,  # grayscale
        2: 3,  # truecolor
        3: 1,  # indexed
        4: 2,  # gray+alpha
        6: 4,  # RGBA
    }.get(color_type)
    if channels is None:
        return None

    bpp_bits = channels * bit_depth

    if interlace == 0:
        rowbytes = (width * bpp_bits + 7) // 8
        return height * (1 + rowbytes)  # one filter byte per row

    # Adam7 interlace passes
    passes = [
        (0,0,8,8), (4,0,8,8), (0,4,4,8), (2,0,4,4),
        (0,2,2,4), (1,0,2,2), (0,1,1,2),
    ]
    total = 0
    for x0, y0, dx, dy in passes:
        if width <= x0 or height <= y0:
            continue
        pw = (width - x0 + dx - 1) // dx
        ph = (height - y0 + dy - 1) // dy
        rowbytes = (pw * bpp_bits + 7) // 8
        total += ph * (1 + rowbytes)
    return total

def check_png(path, data, carve=False, outdir=None):
    print("[PNG]")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        print("  invalid PNG signature")
        return

    pos = 8
    idat = bytearray()
    ihdr = None
    iend_end = None
    chunks = []

    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        d0 = pos + 8
        d1 = d0 + length
        crc_end = d1 + 4
        if crc_end > len(data):
            print(f"  truncated chunk at 0x{pos:x}: {ctype!r}, length={length}")
            break
        payload = data[d0:d1]
        chunks.append((pos, ctype.decode("latin1"), length))

        if ctype == b"IHDR" and length == 13:
            ihdr = struct.unpack(">IIBBBBB", payload)
        elif ctype == b"IDAT":
            idat.extend(payload)
        elif ctype == b"IEND":
            iend_end = crc_end
            break
        pos = crc_end

    for off, typ, ln in chunks:
        print(f"  chunk {typ:4s} @ 0x{off:x}, len={ln}")

    if ihdr:
        width, height, depth, ctype, comp, filt, interlace = ihdr
        print(f"  dimensions: {width}x{height}, bit_depth={depth}, color_type={ctype}, interlace={interlace}")
        expected = png_expected_raw_bytes(width, height, depth, ctype, interlace)
        try:
            raw = zlib.decompress(bytes(idat))
            print(f"  decompressed IDAT: {len(raw)} bytes")
            if expected is not None:
                print(f"  expected image payload: {expected} bytes")
                if len(raw) > expected:
                    extra = raw[expected:]
                    print(f"  [!] EXTRA decompressed image data: {len(extra)} bytes")
                    if interlace == 0:
                        channels = {0:1,2:3,3:1,4:2,6:4}.get(ctype)
                        rowbytes = (width * channels * depth + 7) // 8 if channels else None
                        stride = 1 + rowbytes if rowbytes is not None else None
                        if stride:
                            full_extra_rows = len(extra) // stride
                            rem = len(extra) % stride
                            print(f"      ~= {full_extra_rows} complete extra scanline(s), remainder={rem} bytes")
                    sigs = scan_signatures(extra, expected)
                    if sigs:
                        print("      signatures in extra decompressed data:")
                        for off, name in sigs[:20]:
                            print(f"        0x{off:x}: {name}")
                    strs = printable_strings(extra)
                    if strs:
                        print("      printable strings:")
                        for s in strs[:20]:
                            print(f"        {s[:200]}")
                    if carve:
                        save_region(outdir, path, "png_extra_decompressed", extra)
                elif len(raw) < expected:
                    print(f"  [!] decompressed image data is SHORT by {expected-len(raw)} bytes")
                else:
                    print("  image payload length matches IHDR exactly")
        except Exception as e:
            print(f"  [!] IDAT decompression failed: {e}")

    if iend_end is None:
        print("  [!] no valid IEND found")
    elif iend_end < len(data):
        trailing = data[iend_end:]
        print(f"  [!] trailing bytes after IEND: {len(trailing)} bytes at 0x{iend_end:x}")
        for off, name in scan_signatures(trailing, iend_end)[:20]:
            print(f"      embedded signature @ 0x{off:x}: {name}")
        for s in printable_strings(trailing)[:20]:
            print(f"      string: {s[:200]}")
        if carve:
            save_region(outdir, path, "after_iend", trailing)

def jpeg_dimensions(data):
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1

        # standalone markers
        if marker in (0x01,) or 0xD0 <= marker <= 0xD9:
            continue

        if pos + 2 > len(data):
            break
        seglen = struct.unpack(">H", data[pos:pos+2])[0]
        if seglen < 2 or pos + seglen > len(data):
            break

        if marker in {
            0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,
            0xC9,0xCA,0xCB,0xCD,0xCE,0xCF
        }:
            seg = data[pos+2:pos+seglen]
            if len(seg) >= 5:
                precision = seg[0]
                height = struct.unpack(">H", seg[1:3])[0]
                width = struct.unpack(">H", seg[3:5])[0]
                return width, height, precision
        pos += seglen
    return None

def find_jpeg_eoi(data):
    # Last valid-looking EOI is usually safest for appended-data detection.
    # For ordinary JPEGs, first EOI after SOS entropy stream is the actual end.
    # Simple practical approach: use last FFD9 occurrence.
    return data.rfind(b"\xff\xd9")

def check_jpeg(path, data, carve=False, outdir=None):
    print("[JPEG/JFIF]")
    dims = jpeg_dimensions(data)
    if dims:
        print(f"  dimensions: {dims[0]}x{dims[1]}, precision={dims[2]} bits")
    eoi = find_jpeg_eoi(data)
    if eoi < 0:
        print("  [!] no JPEG EOI marker (FFD9) found")
        return
    end = eoi + 2
    print(f"  EOI @ 0x{eoi:x}")
    if end < len(data):
        trailing = data[end:]
        print(f"  [!] trailing bytes after EOI: {len(trailing)} bytes")
        for off, name in scan_signatures(trailing, end)[:20]:
            print(f"      embedded signature @ 0x{off:x}: {name}")
        for s in printable_strings(trailing)[:20]:
            print(f"      string: {s[:200]}")
        if carve:
            save_region(outdir, path, "after_eoi", trailing)
    else:
        print("  no trailing bytes after EOI")

def check_gif(path, data, carve=False, outdir=None):
    print("[GIF]")
    if len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        print(f"  dimensions: {w}x{h}")
    trailer = data.rfind(b"\x3b")
    if trailer < 0:
        print("  [!] GIF trailer byte 0x3B not found")
        return
    end = trailer + 1
    if end < len(data):
        trailing = data[end:]
        print(f"  [!] trailing bytes after GIF trailer: {len(trailing)} bytes")
        for off, name in scan_signatures(trailing, end)[:20]:
            print(f"      embedded signature @ 0x{off:x}: {name}")
        for s in printable_strings(trailing)[:20]:
            print(f"      string: {s[:200]}")
        if carve:
            save_region(outdir, path, "after_gif_trailer", trailing)
    else:
        print("  no trailing bytes after trailer")

def check_bmp(path, data, carve=False, outdir=None):
    print("[BMP]")
    if len(data) < 54:
        print("  [!] too short for standard BMP")
        return
    declared_size = struct.unpack("<I", data[2:6])[0]
    pixel_offset = struct.unpack("<I", data[10:14])[0]
    dib_size = struct.unpack("<I", data[14:18])[0]
    print(f"  declared file size: {declared_size}")
    print(f"  actual file size:   {len(data)}")
    print(f"  pixel offset: {pixel_offset}, DIB header size: {dib_size}")

    expected_end = None
    if dib_size >= 40 and len(data) >= 54:
        width = struct.unpack("<i", data[18:22])[0]
        height = struct.unpack("<i", data[22:26])[0]
        bpp = struct.unpack("<H", data[28:30])[0]
        compression = struct.unpack("<I", data[30:34])[0]
        print(f"  dimensions: {width}x{height}, bpp={bpp}, compression={compression}")
        if compression == 0 and width and height and bpp:
            rowbytes = ((abs(width) * bpp + 31) // 32) * 4
            expected_end = pixel_offset + rowbytes * abs(height)
            print(f"  estimated uncompressed pixel end: {expected_end}")

    candidates = []
    if declared_size and declared_size < len(data):
        candidates.append(("after_declared_bmp_size", declared_size))
    if expected_end and expected_end < len(data):
        candidates.append(("after_expected_pixels", expected_end))

    seen = set()
    for label, off in candidates:
        if off in seen:
            continue
        seen.add(off)
        trailing = data[off:]
        print(f"  [!] {len(trailing)} suspicious trailing bytes from 0x{off:x}")
        for pos, name in scan_signatures(trailing, off)[:20]:
            print(f"      embedded signature @ 0x{pos:x}: {name}")
        for s in printable_strings(trailing)[:20]:
            print(f"      string: {s[:200]}")
        if carve:
            save_region(outdir, path, label, trailing)

def check_webp(path, data, carve=False, outdir=None):
    print("[WebP/RIFF]")
    if len(data) < 12 or data[:4] != b"RIFF":
        print("  invalid RIFF header")
        return
    declared = struct.unpack("<I", data[4:8])[0] + 8
    kind = data[8:12]
    print(f"  RIFF type: {kind!r}")
    print(f"  declared RIFF size: {declared}, actual size: {len(data)}")
    if declared < len(data):
        trailing = data[declared:]
        print(f"  [!] trailing bytes after RIFF: {len(trailing)} bytes")
        for off, name in scan_signatures(trailing, declared)[:20]:
            print(f"      embedded signature @ 0x{off:x}: {name}")
        for s in printable_strings(trailing)[:20]:
            print(f"      string: {s[:200]}")
        if carve:
            save_region(outdir, path, "after_riff", trailing)

def generic_checks(path, data):
    print("[Generic]")
    print(f"  size: {len(data)} bytes ({human(len(data))})")
    hits = scan_signatures(data)
    if hits:
        print("  embedded/common signatures:")
        for off, name in hits[:30]:
            print(f"    0x{off:x}: {name}")

def inspect(path, carve=False, outdir=None):
    data = path.read_bytes()
    print("=" * 72)
    print(path)
    generic_checks(path, data)

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        check_png(path, data, carve, outdir)
    elif data.startswith(b"\xff\xd8\xff"):
        check_jpeg(path, data, carve, outdir)
    elif data.startswith((b"GIF87a", b"GIF89a")):
        check_gif(path, data, carve, outdir)
    elif data.startswith(b"BM"):
        check_bmp(path, data, carve, outdir)
    elif data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        check_webp(path, data, carve, outdir)
    else:
        print("[!] format-specific parser not implemented; generic signature scan only")

def main():
    ap = argparse.ArgumentParser(
        description="Check image files for extra scanlines, trailing data, and embedded payloads."
    )
    ap.add_argument("paths", nargs="+", help="image file(s) or directories")
    ap.add_argument("--recursive", "-r", action="store_true", help="recurse into directories")
    ap.add_argument("--carve", action="store_true", help="save suspicious extra/trailing regions")
    ap.add_argument("--outdir", default="carved_hidden", help="directory for carved data")
    args = ap.parse_args()

    exts = {
        ".png", ".jpg", ".jpeg", ".jfif", ".gif", ".bmp", ".webp",
        ".tif", ".tiff", ".ico"
    }

    files = []
    for x in args.paths:
        p = Path(x)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            it = p.rglob("*") if args.recursive else p.glob("*")
            files.extend(q for q in it if q.is_file() and q.suffix.lower() in exts)
        else:
            print(f"[!] not found: {p}", file=sys.stderr)

    outdir = Path(args.outdir)

    for p in files:
        try:
            inspect(p, args.carve, outdir)
        except Exception as e:
            print(f"[!] {p}: {e}")

if __name__ == "__main__":
    main()
