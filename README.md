# Image Hidden Data Checker

A lightweight forensic triage tool for detecting suspicious extra data, hidden scanlines, appended payloads, and embedded file signatures in common image formats.

It was designed for CTF, steganography, and image-forensics workflows where an image may contain data that normal viewers ignore.

## What It Checks

The script currently supports:

- **PNG**
  - Reads `IHDR` dimensions
  - Collects and decompresses `IDAT`
  - Calculates the expected decompressed image size
  - Detects extra decompressed scanlines beyond the declared height
  - Detects trailing data after `IEND`
  - Reports suspicious embedded signatures

- **JPEG / JPG / JFIF**
  - Extracts dimensions from SOF markers
  - Locates the JPEG end-of-image marker `FFD9`
  - Detects trailing bytes after EOI
  - Scans trailing data for embedded files and printable strings

- **GIF**
  - Reads dimensions
  - Finds the GIF trailer byte `0x3B`
  - Detects appended data after the logical end of the GIF

- **BMP**
  - Reads the declared file size
  - Reads the pixel-data offset
  - Estimates the expected end of uncompressed pixel data
  - Detects suspicious trailing bytes

- **WebP**
  - Reads the RIFF container size
  - Compares the declared RIFF size against the actual file size
  - Detects appended bytes after the RIFF container

- **Other image/file types**
  - Performs generic signature scanning for embedded or appended data

## Supported Embedded Signatures

The generic scanner currently looks for signatures including:

```text
PNG
JPEG
GIF
BMP
ZIP
PDF
ELF
RAR
7-Zip
GZIP
RIFF/WebP
```

A signature match does **not automatically mean a hidden file exists**. Random compressed image data can occasionally contain byte sequences that resemble file headers. Treat generic signature hits as leads, not proof.

## Requirements

Python 3 is required.

The script uses only the Python standard library, so no additional packages are necessary.

Check your version with:

```bash
python3 --version
```

## Basic Usage

Check a single image:

```bash
python3 image_hidden_checker.py problem.png
```

Check several files:

```bash
python3 image_hidden_checker.py image1.png image2.jpg image3.gif
```

Check image files in the current directory:

```bash
python3 image_hidden_checker.py *.png *.jpg *.jpeg *.jfif
```

Recursively scan a challenge directory:

```bash
python3 image_hidden_checker.py -r .
```

## Carving Suspicious Data

Use `--carve` to write suspicious extra or trailing regions to disk:

```bash
python3 image_hidden_checker.py --carve problem.png
```

By default, carved files are saved under:

```text
carved_hidden/
```

Specify another output directory with:

```bash
python3 image_hidden_checker.py --carve --outdir extracted problem.png
```

## Example: Hidden PNG Scanlines

Given:

```bash
python3 image_hidden_checker.py problem.png
```

Example output:

```text
========================================================================
problem.png
[Generic]
  size: 450827 bytes (440.3 KiB)
  embedded/common signatures:
    0x0: PNG
    0xe50c: BMP
    0x31194: BMP
    0x374c1: BMP
    ...

[PNG]
  chunk IHDR @ 0x8, len=13
  chunk pHYs @ 0x21, len=9
  chunk IDAT @ 0x36, len=450749
  chunk IEND @ 0x6e0ff, len=0
  dimensions: 1000x550, bit_depth=8, color_type=6, interlace=0
  decompressed IDAT: 2340585 bytes
  expected image payload: 2200550 bytes
  [!] EXTRA decompressed image data: 140035 bytes
      ~= 35 complete extra scanline(s), remainder=0 bytes
```

This is a strong finding.

The PNG declares:

```text
1000 x 550
```

but the decompressed `IDAT` stream contains enough data for:

```text
550 declared rows + 35 extra rows
```

Normal PNG viewers use the dimensions from the `IHDR` chunk and typically ignore image data beyond the declared height. That makes extra decompressed scanlines a useful place to hide information.

For this example:

```text
Expected payload:      2,200,550 bytes
Actual IDAT payload:   2,340,585 bytes
Difference:              140,035 bytes
```

For an 8-bit RGBA PNG with width `1000`:

```text
1 filter byte + (1000 × 4 bytes) = 4001 bytes per scanline
```

Therefore:

```text
140035 / 4001 = 35 extra scanlines
```

with no remainder.

## Understanding PNG Output

A normal non-interlaced PNG scanline contains:

```text
[filter byte][pixel bytes]
```

For an 8-bit RGBA image:

```text
bytes_per_row = 1 + width × 4
```

The checker compares:

```text
declared height × bytes_per_row
```

against the actual decompressed `IDAT` size.

If the actual data is larger, the script reports:

```text
[!] EXTRA decompressed image data
```

and estimates how many complete extra scanlines are present.

This is particularly useful for images where hidden rows have been appended below the visible image without updating the `IHDR` height.

## JPEG / JFIF Notes

JPEG and JFIF files work differently from PNG.

JPEG image data is encoded into compressed DCT blocks rather than straightforward filtered scanlines, so this script does not perform the same row-count comparison used for PNG.

Instead, it checks for:

```text
FFD9
```

which is the JPEG End Of Image marker.

Anything after the real EOI marker may be suspicious:

```text
JPEG data
FFD9
<appended hidden data>
```

Run:

```bash
python3 image_hidden_checker.py suspicious.jpg
```

and look for:

```text
[!] trailing bytes after EOI
```

## Generic Signature Results

You may see output like:

```text
embedded/common signatures:
  0x0: PNG
  0xe50c: BMP
  0x31194: BMP
  0x374c1: BMP
```

The signature at offset `0x0` is expected because the file itself is a PNG.

Later signatures may or may not indicate embedded files.

Compressed image data contains high-entropy bytes, so short signatures such as:

```text
BM
```

can occur accidentally.

A better indicator is a signature found inside:

- data after PNG `IEND`
- data after JPEG `FFD9`
- data after a GIF trailer
- data outside a declared RIFF size
- extra decompressed PNG scanlines
- a clearly structured block with readable strings

## Recommended CTF Workflow

Use this script as the first-pass structural check:

```bash
python3 image_hidden_checker.py --carve challenge.png
```

Then compare the results with other tools such as:

```bash
file challenge.png
exiftool challenge.png
pngcheck -v challenge.png
zsteg challenge.png
binwalk challenge.png
strings -a challenge.png
xxd challenge.png | less
```

For JPEG files:

```bash
exiftool image.jpg
binwalk image.jpg
strings -a image.jpg
xxd image.jpg | less
```

For suspicious carved data:

```bash
file carved_hidden/*
strings -a carved_hidden/*
xxd carved_hidden/<file> | head
```

## Command-Line Options

```text
usage: image_hidden_checker.py [-h] [--recursive] [--carve]
                               [--outdir OUTDIR]
                               paths [paths ...]
```

Options:

```text
-r, --recursive
    Recursively scan supported image files in directories.

--carve
    Save suspicious extra or trailing data to files.

--outdir DIR
    Directory used for carved output.
    Default: carved_hidden
```

## What This Tool Does Not Detect

This is a structural triage tool, not a universal steganography detector.

It does not currently attempt to automatically decode:

- pixel LSB steganography
- bit-plane steganography
- palette manipulation
- alpha-channel steganography
- DCT coefficient steganography
- JPEG quantization-based hiding
- EXIF/XMP semantic hiding
- encrypted payloads
- custom color-channel encodings
- visual glyph/cipher steganography

For those cases, combine this checker with tools such as:

```text
zsteg
steghide
stegseek
binwalk
exiftool
pngcheck
ImageMagick
CyberChef
Aperi'Solve
```

## Why This Tool Is Useful

Many image challenges are not traditional LSB steganography problems.

Instead, a challenge may exploit the structure of the file format itself:

```text
incorrect dimensions
extra scanlines
appended data
malformed chunks
unused image regions
embedded secondary files
metadata fields
```

A normal image viewer is designed to display the image, not expose those inconsistencies.

This checker focuses on those inconsistencies.

## Safety

Only use the script on files you are authorized to inspect.

Carved output should be treated as untrusted data. Do not execute extracted binaries or scripts without analyzing them first.

## Example

```bash
python3 image_hidden_checker.py --carve -r ./challenge-files
```

This provides a quick structural triage pass across a CTF or forensic image directory and saves suspicious regions for deeper analysis.
