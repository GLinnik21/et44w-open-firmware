"""Pack an AmebaZ2 application ELF into flash images with ltchiptool (replaces Realtek's x86-only
elf2bin/checksum tools, so the build runs natively on arm64). The flash map comes from
platform/ambz2/partitions.def, not from ltchiptool's board file.

Usage: pack_image.py <app.axf> <bootloader.axf> <toolchain-bin-dir> [--layout partitions.def]
Writes next to <app.axf>:
  image_flash_is.0x000000.bin       ptable + boot + OTA1 (flash from 0x0, up to the end of the image;
                                    the data regions factory/kv are NOT touched when written)
  image_flash_wipe.0x000000.bin     the same padded with 0xFF to the full 2 MiB (first flash of a
                                    unit: wipes old Tuya data, kv and factory)
  image_firmware_is.<ota1>.bin      one slot image for OTA (identical bytes for either slot)
  image_part_table.* / image_bootloader.*   ltchiptool by-products
Fails (and removes the outputs) if the app does not fit in a slot.
"""
import argparse, os, re, shutil, sys
from collections import namedtuple

Part = namedtuple("Part", "name offset size owner")
Layout = namedtuple("Layout", "total parts")
DEFAULT_LAYOUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "platform", "ambz2", "partitions.def")
SECTOR = 0x1000
SLOT_ALIGN = 0x10000
FLASH_PART_RE = re.compile(r"^\s*FLASH_PART\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(\w+)\s*\)")
FLASH_TOTAL_RE = re.compile(r"^\s*FLASH_TOTAL\(\s*(0x[0-9A-Fa-f]+)\s*\)")
REQUIRED = ("ptable", "boot", "ota1", "ota2", "factory", "kv")


class LayoutError(Exception):
    pass


def parse_layout(text):
    total, parts = None, []
    for line in text.splitlines():
        line = line.split("//", 1)[0]
        m = FLASH_TOTAL_RE.match(line)
        if m:
            total = int(m.group(1), 16)
            continue
        m = FLASH_PART_RE.match(line)
        if m:
            parts.append(Part(m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4)))
        elif line.strip():
            raise LayoutError(f"unparsable line: {line.strip()!r}")
    if total is None:
        raise LayoutError("FLASH_TOTAL missing")
    return Layout(total, parts)


def load_layout(path=DEFAULT_LAYOUT):
    with open(path) as f:
        return parse_layout(f.read())


def validate_layout(layout):
    """Raise LayoutError unless the map tiles the flash exactly, with SDK alignment."""
    names = [p.name for p in layout.parts]
    if len(set(names)) != len(names):
        raise LayoutError("duplicate partition names")
    for r in REQUIRED:
        if r not in names:
            raise LayoutError(f"partition '{r}' missing")
    pos = 0
    for p in sorted(layout.parts, key=lambda p: p.offset):
        if p.offset < pos:
            raise LayoutError(f"{p.name} overlaps previous partition (0x{p.offset:X} < 0x{pos:X})")
        if p.offset > pos:
            raise LayoutError(f"gap before {p.name}: 0x{pos:X}..0x{p.offset:X} (declare it as 'none')")
        if p.size <= 0 or p.offset % SECTOR or p.size % SECTOR:
            raise LayoutError(f"{p.name}: offset/size not 4 KiB aligned")
        pos = p.offset + p.size
    if pos != layout.total:
        raise LayoutError(f"map ends at 0x{pos:X}, flash is 0x{layout.total:X}")
    g = {p.name: p for p in layout.parts}
    for s in ("ota1", "ota2"):
        if g[s].offset % SLOT_ALIGN or g[s].size % SLOT_ALIGN:
            raise LayoutError(f"{s} not 64 KiB aligned")
    if g["ota1"].size != g["ota2"].size:
        raise LayoutError("slots differ in size")
    if g["boot"].offset != 0x4000 or g["ptable"].offset != 0:
        raise LayoutError("ptable must be at 0 and boot at 0x4000 (bootloader/ROM expectation)")


def region(layout, name):
    for p in layout.parts:
        if p.name == name:
            return p
    raise KeyError(name)


def check_fits(layout, image_len, name="ota1"):
    """Hard size gate: the image starts at the slot offset and must not exceed the slot."""
    slot = region(layout, name)
    size = image_len - slot.offset
    if size > slot.size:
        raise LayoutError(f"app image 0x{size:X} bytes does not fit slot {name} (0x{slot.size:X}), over by 0x{size - slot.size:X}")
    return slot.size - size


def board_flash(layout):
    """Regions ltchiptool's elf2bin reads from its board file, taken from our layout."""
    names = {"part_table": "ptable", "system": "system", "calibration": "calibration",
             "boot": "boot", "ota1": "ota1", "ota2": "ota2"}
    out = {}
    for key, name in names.items():
        p = region(layout, name)
        out[key] = f"0x{p.offset:06X}+0x{p.size:X}"
    return out


def verify_flash_image(data, layout):
    """Parse the partition table inside a flash image with ltchiptool's structures and compare it
    with the layout: boot, FW1 and FW2 records must sit at the intended offsets/lengths."""
    import io
    from ltchiptool.soc.ambz2.parse_partition import PT
    pt = PT.parse_stream(io.BytesIO(data)).data
    recs = {str(r.type).split(".")[-1]: (r.start_address, r.length) for r in pt.part_records}
    recs["BOOT"] = (pt.boot_record.start_address, pt.boot_record.length)
    want = {"BOOT": "boot", "FW1": "ota1", "FW2": "ota2"}
    for typ, name in want.items():
        p = region(layout, name)
        if recs.get(typ) != (p.offset, p.size):
            raise LayoutError(f"partition table {typ}={recs.get(typ)} but layout {name}=({p.offset:#x},{p.size:#x})")
    if len(recs) != len(want):
        raise LayoutError(f"unexpected partition records: {sorted(recs)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app")
    ap.add_argument("bootloader")
    ap.add_argument("toolchain")
    ap.add_argument("--layout", default=DEFAULT_LAYOUT)
    ap.add_argument("--board", default="generic-rtl8720cf-2mb-992k",
                    help="ltchiptool board used only for image keys/sections; its flash map is replaced")
    a = ap.parse_args()

    layout = load_layout(a.layout)
    validate_layout(layout)

    from ltchiptool import Board, SocInterface
    from ltchiptool.util.toolchain import Toolchain

    app = os.path.abspath(a.app)
    outdir = os.path.dirname(app)
    boot = os.path.join(outdir, "bootloader.axf")  # ltchiptool looks for it beside the app
    if os.path.abspath(a.bootloader) != boot:
        shutil.copyfile(a.bootloader, boot)

    board = Board(a.board)
    board["flash"] = board_flash(layout)
    board["image"]["ptable"] = {"boot": "BOOT", "ota1": "FW1", "ota2": "FW2"}
    board._toolchain = Toolchain(os.path.join(a.toolchain, "arm-none-eabi-"))
    soc = SocInterface.get(board.family)
    soc.set_board(board)
    wipe_path = os.path.join(outdir, "image_flash_wipe.0x000000.bin")

    def remove_images():
        # images from an earlier build or a half-finished pack must never be flashed as if they were this one
        for name in os.listdir(outdir):
            if name.startswith("image_") and name.endswith(".bin"):
                os.remove(os.path.join(outdir, name))

    remove_images()
    try:
        results = soc.elf2bin(app, ota_idx=1)
        flash_path = next(b.path for b in results if os.path.basename(b.path).startswith("image_flash_is."))
        with open(flash_path, "rb") as f:
            data = f.read()
        spare = check_fits(layout, len(data))
        verify_flash_image(data, layout)
        ota1 = region(layout, "ota1")
        wipe = data + b"\xff" * (layout.total - len(data))
        with open(wipe_path, "wb") as f:
            f.write(wipe)
    except LayoutError as e:
        remove_images()
        sys.exit(f"pack_image: {e}")
    except BaseException:
        remove_images()
        raise
    for b in results:
        print(f"{b.offset:#08x}  {b.path}")
    print(f"app image {len(data) - ota1.offset:#x} bytes, slot {ota1.size:#x}, spare {spare:#x}")


if __name__ == "__main__":
    main()
