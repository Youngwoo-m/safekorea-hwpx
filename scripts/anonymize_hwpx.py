#!/usr/bin/env python3
"""Create a separately saved, anonymized HWPX copy.

This utility performs literal replacements supplied in a JSON mapping, applies
conservative personal-data regexes, clears common package metadata, and can
replace embedded raster images with blank images of the same dimensions.
It does not replace a final rendered-page review.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zipfile
from pathlib import Path


TEXT_SUFFIXES = {".xml", ".txt", ".hpf", ".opf", ".html", ".xhtml"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}

PATTERNS = [
    (re.compile(r"(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"), "[연락처]"),
    (re.compile(r"(?<!\d)0(?:2|[3-6][1-5])[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"), "[연락처]"),
    (re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"), "[이메일]"),
    (re.compile(r"(?<!\d)\d{6}\s*[-]\s*[1-4]\d{6}(?!\d)"), "[주민등록번호]"),
]


def load_mapping(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "replace_all" in data:
        data = data["replace_all"]
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ValueError("mapping JSON must be an object or contain a replace_all object")
    return dict(sorted(data.items(), key=lambda item: len(item[0]), reverse=True))


def sanitize_text(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    count = 0
    for source, target in mapping.items():
        hits = text.count(source)
        if hits:
            text = text.replace(source, target)
            count += hits
    for pattern, target in PATTERNS:
        text, hits = pattern.subn(target, text)
        count += hits
    return text, count


def blank_image(data: bytes, suffix: str) -> bytes:
    from PIL import Image

    with Image.open(io.BytesIO(data)) as image:
        fmt = {".jpg": "JPEG", ".jpeg": "JPEG"}.get(suffix, suffix.lstrip(".").upper())
        if fmt == "JPG":
            fmt = "JPEG"
        mode = "RGB" if fmt in {"JPEG", "BMP"} else ("RGBA" if "A" in image.getbands() else "RGB")
        color = (255, 255, 255, 0) if mode == "RGBA" else (255, 255, 255)
        blank = Image.new(mode, image.size, color)
        output = io.BytesIO()
        blank.save(output, format=fmt)
        return output.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mapping", type=Path)
    parser.add_argument("--blank-images", action="store_true")
    args = parser.parse_args()

    if args.input.resolve() == args.output.resolve():
        parser.error("output must be a separate file")
    if args.output.exists():
        parser.error("output already exists")
    mapping = load_mapping(args.mapping)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    replacements = 0
    blanked = 0
    warnings: list[str] = []
    with zipfile.ZipFile(args.input, "r") as src, zipfile.ZipFile(args.output, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            suffix = Path(info.filename).suffix.lower()
            if suffix in TEXT_SUFFIXES:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    warnings.append(f"text-decode skipped: {info.filename}")
                else:
                    text, hits = sanitize_text(text, mapping)
                    replacements += hits
                    if info.filename.lower().endswith(("content.hpf", "meta.xml", "settings.xml")):
                        text = re.sub(r"(<[^>]*(?:creator|lastModifiedBy|author)[^>]*>).*?(</[^>]+>)", r"\1[작성자]\2", text, flags=re.I | re.S)
                    data = text.encode("utf-8")
            elif args.blank_images and suffix in IMAGE_SUFFIXES:
                try:
                    data = blank_image(data, suffix)
                    blanked += 1
                except Exception as exc:  # visual review is still mandatory
                    warnings.append(f"image skipped: {info.filename}: {exc}")

            clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            clone.compress_type = zipfile.ZIP_STORED if info.filename == "mimetype" else info.compress_type
            clone.comment = info.comment
            clone.extra = info.extra
            clone.internal_attr = info.internal_attr
            clone.external_attr = info.external_attr
            clone.create_system = info.create_system
            dst.writestr(clone, data)

    with zipfile.ZipFile(args.output, "r") as check:
        bad = check.testzip()
        if bad:
            raise RuntimeError(f"corrupt ZIP entry: {bad}")
        if "mimetype" not in check.namelist():
            raise RuntimeError("not a valid HWPX package: mimetype missing")

    print(json.dumps({"output": str(args.output), "replacements": replacements, "blanked_images": blanked, "warnings": warnings}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
