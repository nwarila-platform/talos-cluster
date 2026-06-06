#!/usr/bin/env python3
"""Fail if tracked text files contain BOMs or common UTF-8 mojibake."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


BOM = b"\xef\xbb\xbf"

# These byte pairs are the UTF-8 encodings of the mojibake lead characters
# U+00C2, U+00C3, and U+00E2. They catch common round-trips such as section
# signs, accented Latin letters, dashes, ellipses, and comparison glyphs that
# were decoded as Windows-1252/Latin-1 and then re-saved as UTF-8.
MOJIBAKE_SIGNATURES = {
    b"\xc3\x82": "C3 82 (U+00C2)",
    b"\xc3\x83": "C3 83 (U+00C3)",
    b"\xc3\xa2": "C3 A2 (U+00E2)",
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return [Path(line) for line in result.stdout.splitlines() if line]


def is_binary(data: bytes) -> bool:
    return b"\0" in data


def main() -> int:
    failures: list[str] = []

    for path in tracked_files():
        data = path.read_bytes()
        if is_binary(data):
            continue

        if data.startswith(BOM):
            failures.append(f"{path}: UTF-8 BOM at byte offset 0")

        for signature, label in MOJIBAKE_SIGNATURES.items():
            if signature in data:
                failures.append(f"{path}: mojibake byte signature {label}")

    if failures:
        print("Tracked text encoding check failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("Tracked text encoding check passed: no UTF-8 BOMs or mojibake byte signatures found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
