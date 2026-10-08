#!/usr/bin/env python3
"""Scan HWPX packages and ordinary text files for sensitive values."""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path


TEXT_SUFFIXES = {".xml", ".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".hpf", ".opf"}
PATTERNS = {
    "mobile": re.compile(r"(?<!\d)01[016789][-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
    "phone": re.compile(r"(?<!\d)0(?:2|[3-6][1-5])[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)"),
    "email": re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"),
    "resident_id": re.compile(r"(?<!\d)\d{6}\s*[-]\s*[1-4]\d{6}(?!\d)"),
}


def scan_text(label: str, text: str, terms: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append({"file": label, "type": kind, "value": match.group(0)})
    for term in terms:
        if term and term in text:
            findings.append({"file": label, "type": "term", "value": term})
    return findings


def read_terms(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def scan_file(path: Path, terms: list[str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    findings.extend(scan_text(str(path), path.name, terms))
    if path.suffix.lower() == ".hwpx":
        try:
            with zipfile.ZipFile(path, "r") as archive:
                for name in archive.namelist():
                    findings.extend(scan_text(f"{path}!{name}", name, terms))
                    if Path(name).suffix.lower() in TEXT_SUFFIXES:
                        try:
                            text = archive.read(name).decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        findings.extend(scan_text(f"{path}!{name}", text, terms))
        except zipfile.BadZipFile:
            findings.append({"file": str(path), "type": "invalid_hwpx", "value": "bad ZIP"})
    elif path.suffix.lower() in TEXT_SUFFIXES:
        try:
            findings.extend(scan_text(str(path), path.read_text(encoding="utf-8"), terms))
        except UnicodeDecodeError:
            pass
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--terms", type=Path, help="UTF-8 file with one prohibited term per line")
    args = parser.parse_args()
    terms = read_terms(args.terms)
    files: list[Path] = []
    for item in args.paths:
        if item.is_dir():
            files.extend(path for path in item.rglob("*") if path.is_file() and ".git" not in path.parts)
        elif item.is_file():
            files.append(item)
    findings: list[dict[str, str]] = []
    for path in sorted(set(files)):
        findings.extend(scan_file(path, terms))
    print(json.dumps({"files_scanned": len(set(files)), "findings": findings}, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
