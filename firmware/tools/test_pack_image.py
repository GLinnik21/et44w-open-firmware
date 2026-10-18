"""Host tests for the flash map and image packer (no hardware). Run with ltchiptool available:
    ../.venv-flash/bin/python -m unittest tools/test_pack_image.py   (from firmware/)
"""
import glob, io, os, shutil, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pack_image as pi

FW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEF = os.path.join(FW, "platform", "ambz2", "partitions.def")

def tiny_layout_text(ota_size):
    """Valid map with smaller slots (<= 0xE0000; the freed space becomes a 'none' range), for gate tests."""
    t = pi.load_layout(DEF)
    out = [f"FLASH_TOTAL({t.total:#x})"]
    for p in t.parts:
        if p.name == "ota1":
            out.append(f"FLASH_PART(ota1, {p.offset:#x}, {ota_size:#x}, app)")
            out.append(f"FLASH_PART(ota2, {p.offset + ota_size:#x}, {ota_size:#x}, app)")
            pad = pi.region(t, "factory").offset - (p.offset + 2 * ota_size)
            out.append(f"FLASH_PART(slot_pad, {p.offset + 2 * ota_size:#x}, {pad:#x}, none)")
        elif p.name != "ota2":
            out.append(f"FLASH_PART({p.name}, {p.offset:#x}, {p.size:#x}, {p.owner})")
    return "\n".join(out)


class LayoutFile(unittest.TestCase):
    def setUp(self):
        self.layout = pi.load_layout(DEF)

    def test_validates(self):
        pi.validate_layout(self.layout)

    def test_no_overlap_and_tiles_flash(self):
        ps = sorted(self.layout.parts, key=lambda p: p.offset)
        for a, b in zip(ps, ps[1:]):
            self.assertEqual(a.offset + a.size, b.offset, f"{a.name}->{b.name}")
        self.assertEqual(ps[0].offset, 0)
        self.assertEqual(ps[-1].offset + ps[-1].size, self.layout.total)

    def test_alignment(self):
        for p in self.layout.parts:
            self.assertEqual(p.offset % 0x1000, 0, p.name)
            self.assertEqual(p.size % 0x1000, 0, p.name)
        for s in ("ota1", "ota2"):
            self.assertEqual(pi.region(self.layout, s).offset % 0x10000, 0)
            self.assertEqual(pi.region(self.layout, s).size, 0xE0000)

    def test_fits_2mib(self):
        self.assertEqual(self.layout.total, 0x200000)
        self.assertTrue(all(p.offset + p.size <= 0x200000 for p in self.layout.parts))

    def test_sdk_fixed_sectors_not_used_by_us(self):
        reserved = pi.region(self.layout, "sdk_reserved")
        for sector in (0x1F6000, 0x1F7000, 0x1FA000, 0x1FB000, 0x1FC000, 0x1FD000, 0x1FE000, 0x1FF000):
            self.assertTrue(reserved.offset <= sector < reserved.offset + reserved.size, hex(sector))
        for name in ("ota1", "ota2", "factory", "kv"):
            p = pi.region(self.layout, name)
            self.assertLessEqual(p.offset + p.size, reserved.offset, name)
        self.assertEqual(pi.region(self.layout, "sdk_backup").offset, 0x3000)

    def test_kv_holds_dct_modules(self):
        # 9 modules needed (6 HAP + wifi, ota, app); with backup that is 2 x 4 KiB each
        self.assertGreaterEqual(pi.region(self.layout, "kv").size, 9 * 2 * 0x1000)

    def test_factory_is_one_sector(self):
        self.assertEqual(pi.region(self.layout, "factory").size, 0x1000)


class LayoutRejects(unittest.TestCase):
    def check(self, text):
        with self.assertRaises(pi.LayoutError):
            pi.validate_layout(pi.parse_layout(text))

    def base(self):
        return open(DEF).read()

    def test_overlap(self):
        self.check(self.base().replace("FLASH_PART(ota2,         0x0F0000", "FLASH_PART(ota2,         0x0E0000"))

    def test_gap(self):
        self.check(self.base().replace("FLASH_PART(matter,       0x1EA000, 0x00C000", "FLASH_PART(matter,       0x1EA000, 0x00B000"))

    def test_misaligned(self):
        self.check(self.base().replace("0x1D1000, 0x018000", "0x1D1800, 0x017800"))

    def test_slot_not_64k_aligned(self):
        self.check(tiny_layout_text(0x11000))

    def test_bad_line(self):
        with self.assertRaises(pi.LayoutError):
            pi.parse_layout("FLASH_TOTAL(0x200000)\nFLASH_PART(x, 1+2, 3, sdk)\n")


class SizeGate(unittest.TestCase):
    def setUp(self):
        self.layout = pi.load_layout(DEF)

    def test_exact_fit_passes(self):
        ota1 = pi.region(self.layout, "ota1")
        self.assertEqual(pi.check_fits(self.layout, ota1.offset + ota1.size), 0)

    def test_one_byte_over_fails(self):
        ota1 = pi.region(self.layout, "ota1")
        with self.assertRaises(pi.LayoutError) as cm:
            pi.check_fits(self.layout, ota1.offset + ota1.size + 1)
        self.assertIn("does not fit", str(cm.exception))

    def test_small_passes(self):
        self.assertGreater(pi.check_fits(self.layout, 0x10000 + 0x1000), 0)


class PartitionTableRoundTrip(unittest.TestCase):
    """Build the partition table image like elf2bin does and parse it back with ltchiptool."""

    def build_flash(self, layout):
        from ltchiptool import Board
        from ltchiptool.soc.ambz2.util.models.config import ImageConfig
        from ltchiptool.soc.ambz2.util.models.enums import ImageType, PartitionType
        from ltchiptool.soc.ambz2.util.models.headers import ImageHeader, Keyblock
        from ltchiptool.soc.ambz2.util.models.images import FLASH_CALIBRATION, Image
        from ltchiptool.soc.ambz2.util.models.partitions import PartitionRecord, PartitionTable
        from ltchiptool.util.curve25519 import X25519PrivateKey

        board = Board("generic-rtl8720cf-2mb-992k")
        board["flash"] = pi.board_flash(layout)
        config = ImageConfig(**board["image"])
        types = {"boot": "BOOT", "ota1": "FW1", "ota2": "FW2"}
        table = PartitionTable(user_data=b"\xff" * 256)
        for name, typ in types.items():
            off, length, _ = board.region(name)
            table.partitions.append(PartitionRecord(off, length, PartitionType[typ], hash_key=config.keys.hash_keys[name]))
        pub = lambda k: X25519PrivateKey.from_private_bytes(k).public_key()
        image = Image(
            keyblock=Keyblock(decryption=pub(config.keys.decryption), hash=pub(config.keys.keyblock["part_table"])),
            header=ImageHeader(type=ImageType.PARTAB),
            data=table,
        )
        blob = FLASH_CALIBRATION + b"\xff" * 16 + image.pack(
            hash_key=config.keys.hash_keys["part_table"], is_ota=False, is_first=True)
        return blob

    def test_parses_back_to_layout(self):
        layout = pi.load_layout(DEF)
        blob = self.build_flash(layout)
        pi.verify_flash_image(blob, layout)

    def test_verify_detects_wrong_offsets(self):
        layout = pi.load_layout(DEF)
        blob = self.build_flash(layout)
        other = pi.parse_layout(tiny_layout_text(0x20000))
        pi.validate_layout(other)
        with self.assertRaises(pi.LayoutError):
            pi.verify_flash_image(blob, other)


TOOLCHAIN = next((os.path.join(FW, ".toolchain", d, "bin") for d in
                  (os.listdir(os.path.join(FW, ".toolchain")) if os.path.isdir(os.path.join(FW, ".toolchain")) else [])), None)


def built_out():
    """PACK_TEST_OUT, else the newest out*/ or out*/<unit>/ dir holding app.axf and bootloader.axf."""
    if os.environ.get("PACK_TEST_OUT"):
        return os.environ["PACK_TEST_OUT"]
    dirs = [d for d in glob.glob(os.path.join(FW, "out*")) + glob.glob(os.path.join(FW, "out*", "*"))
            if all(os.path.isfile(os.path.join(d, f)) for f in ("app.axf", "bootloader.axf"))]
    return max(dirs, key=lambda d: os.path.getmtime(os.path.join(d, "app.axf")), default=None)


OUT = built_out()


@unittest.skipUnless(TOOLCHAIN and OUT, "needs a build (app.axf + bootloader.axf under out*/; or PACK_TEST_OUT)")
class EndToEnd(unittest.TestCase):
    def run_pack(self, tmp, layout_text=None):
        for f in ("app.axf", "bootloader.axf"):
            shutil.copy(os.path.join(OUT, f), tmp)
        cmd = [sys.executable, os.path.join(FW, "tools", "pack_image.py"),
               os.path.join(tmp, "app.axf"), os.path.join(tmp, "bootloader.axf"), TOOLCHAIN]
        if layout_text:
            lp = os.path.join(tmp, "small.def")
            open(lp, "w").write(layout_text)
            cmd += ["--layout", lp]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_packs_and_wipe_image_is_full_flash(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_pack(tmp)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.path.getsize(os.path.join(tmp, "image_flash_wipe.0x000000.bin")), 0x200000)
            self.assertTrue(os.path.exists(os.path.join(tmp, "image_firmware_is.0x010000.bin")))

    def test_gate_rejects_oversized_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "image_flash_wipe.0x000000.bin")  # from an earlier, good build
            open(stale, "wb").write(b"\xff" * 16)
            r = self.run_pack(tmp, tiny_layout_text(0x10000))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("does not fit", r.stderr)
            self.assertFalse(os.path.exists(os.path.join(tmp, "image_flash_is.0x000000.bin")))
            self.assertFalse(os.path.exists(stale))


if __name__ == "__main__":
    unittest.main()
