#!/usr/bin/env python3
"""Per-lib flash use from a linker map: code, rodata and initialised data, plus the total against the
OTA slot.

    tools/size_report.py [out-matter/app.map] [--base other/app.map] [--top N]

Flash-resident output sections are classified as code (.xip.code_c, .ram.code_text), rodata
(.xip.code_p, .ram.code_rodata) and data (.data and friends). An input section is credited to the
lib that owns its object: libs/<name> -> <name>, apps and private apps -> app, platform/ -> platform,
vendor/ by component (mbedtls, lwip, adk, sdk), prebuilt archives -> lib<name>.a. With --base, the
columns show the change against the other map. The image size is read from the packed
part_firmware_is.data.* next to the map, when present.
"""
import argparse
import glob
import os
import re
import sys

SLOT = 0xE0000
CLASS = {".xip.code_c": "code", ".ram.code_text": "code", ".xip.code_p": "rodata",
         ".ram.code_rodata": "rodata", ".data": "data", ".ARM.exidx": "rodata"}
OUT_SEC = re.compile(r"^(\.\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)")
IN_FULL = re.compile(r"^ (\S+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S.*)$")
IN_SIZE = re.compile(r"^\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S.*)$")


def owner(path):
    """Name of the lib an object (or archive member) belongs to."""
    m = re.match(r"(.*\.a)\(", path)
    if m:
        return os.path.basename(m.group(1))
    p = re.sub(r"^.*?obj/", "", path)
    p = p.lstrip("_/") if p.startswith("__/") else p
    if p.startswith("libs/"):
        return p.split("/")[1]
    if p.startswith(("apps/", "private/")):
        return "app"
    if p.startswith("platform/"):
        return "platform"
    if "mbedtls" in p:
        return "mbedtls"
    if "lwip" in p:
        return "lwip"
    if p.startswith("vendor/"):
        return "sdk"
    return "other"


def parse(map_path):
    """{lib: {class: bytes}} for the flash-resident output sections of a GNU ld map."""
    use = {}
    started = False
    cls = None
    pending = None
    with open(map_path, errors="replace") as f:
        for line in f:
            if not started:
                started = line.startswith("Linker script and memory map")
                continue
            line = line.rstrip("\n")
            m = OUT_SEC.match(line)
            if m:
                cls, pending = CLASS.get(m.group(1)), None
                continue
            if cls is None:
                continue
            m = IN_FULL.match(line)
            if m:
                size, path = int(m.group(3), 16), m.group(4)
            else:
                m = IN_SIZE.match(line)
                if m and pending:
                    size, path = int(m.group(2), 16), m.group(3)
                else:
                    pending = line.strip().split()[0] if re.match(r"^ \S+$", line) else None
                    continue
            pending = None
            if size and not path.startswith(("0x", "*fill*")):
                d = use.setdefault(owner(path), {})
                d[cls] = d.get(cls, 0) + size
    return use


def image_size(map_path):
    files = glob.glob(os.path.join(os.path.dirname(map_path), "part_firmware_is.data.*.bin"))
    return os.path.getsize(files[0]) if files else None


def total(use):
    return sum(sum(c.values()) for c in use.values())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("map", nargs="?", default="out-matter/app.map")
    ap.add_argument("--base", help="map to compare against (columns become deltas)")
    ap.add_argument("--top", type=int, default=0, help="only the N largest libs")
    a = ap.parse_args()

    use = parse(a.map)
    base = parse(a.base) if a.base else {}
    num = "+10d" if a.base else "10d"
    libs = sorted(set(use) | set(base), key=lambda l: -(sum(use.get(l, {}).values()) - sum(base.get(l, {}).values())
                                                       if a.base else sum(use.get(l, {}).values())))
    if a.top:
        libs = libs[:a.top]
    print(f"{'lib':<28}{'code':>10}{'rodata':>10}{'data':>10}{'total':>10}")
    for l in libs:
        row = [use.get(l, {}).get(c, 0) - base.get(l, {}).get(c, 0) for c in ("code", "rodata", "data")]
        if a.base and not any(row):
            continue
        print(f"{l:<28}" + "".join(format(v, num) for v in row + [sum(row)]))
    t = total(use) - total(base)
    print(f"{'TOTAL' + (' (delta)' if a.base else ''):<28}{'':>30}{format(t, num)}")
    img = image_size(a.map)
    if img is not None and not a.base:
        print(f"packed app image {img} bytes (0x{img:X}) of slot 0x{SLOT:X} = {SLOT}: "
              f"{SLOT - img} bytes ({(SLOT - img) / 1024:.1f} KiB) free")
    elif not a.base:
        print(f"sections total {t} of slot {SLOT}: {SLOT - t} free (no packed image found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
