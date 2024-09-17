#!/usr/bin/env python

import argparse
import hashlib
import pathlib
import shutil
from typing import Optional, List

ORIGINAL_C2_MD5: str = "dcd69f1dd28b02dd03dd7ed02984299a"  # original C2.EXE

C2_MD5: tuple[str, str] = (
    ORIGINAL_C2_MD5,
    "e70acde41802ddec06c4263bb357ac30",  # patched C2.EXE
)

C2_SIZE: int = 549888


def main() -> None:
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Path to C2.EXE of Microsoft Visual Studio 4.2.0 to disable C4786 warning",
    )
    parser.add_argument("path", type=pathlib.Path, help="Path of C2.EXE")
    parser.add_argument(
        "-f", dest="force", default=False, action="store_true", help="force"
    )
    args = parser.parse_args()

    if not args.path.is_file():
        parser.error("Input is not a file")

    binary: bytearray = bytearray(args.path.open("rb").read())
    md5: str = hashlib.md5(binary).hexdigest()
    print(md5, C2_MD5)

    msg_cb = parser.error if not args.force else print
    if len(binary) != C2_SIZE:
        msg_cb("file size is not correct")
    if md5 not in C2_MD5:
        msg_cb("md5 checksum does not match")

    if md5 == ORIGINAL_C2_MD5:
        backup: str = f"{args.path}.BAK"
        print(f'Creating backup "{backup}"')
        shutil.copyfile(args.path, backup)

    def nop_patch(start: int, count: int, expected: Optional[List[int]] = None) -> None:
        replacement: List[int] = [0x90] * count
        if expected:
            current: List[int] = list(binary[start : start + count])
            assert len(expected) == count
            assert current in (expected, replacement)
        print(f"Nopping {count} bytes at 0x{start:08x}")
        binary[start : start + count] = replacement

    print(
        "Disable C4786 warning: '%Fs' : identifier was truncated to '%d' characters in the debug information"
    )
    nop_patch(0x52F07, 5, [0xE8, 0x4F, 0xB3, 0xFE, 0xFF])  # 0x00453b07
    nop_patch(0x74832, 5, [0xE8, 0x24, 0x9A, 0xFC, 0xFF])  # 0x00475432

    args.path.open("wb").write(binary)
    print("done")


if __name__ == "__main__":
    raise SystemExit(main())
