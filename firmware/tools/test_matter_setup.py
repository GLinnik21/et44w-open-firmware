"""Host tests for tools/matter_setup.py (no hardware). Run from firmware/:
    python3 -m unittest tools/test_matter_setup.py
Vector sources: connectedhomeip src/setup_payload/tests/TestManualCode.cpp and TestQRCode.cpp (TestBase38),
scripts/tools/spake2p/README.md (published verifier), rs-matter pairing/qr.rs tests, the rs-matter test node's QR code.
"""
import base64, hashlib, os, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import matter_setup as ms

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "matter_setup.py")


class Base38(unittest.TestCase):
    # TestQRCode.cpp TestBase38 (chip).
    VECTORS = [(b"", ""), (bytes([10]), "A0"), (bytes([10, 10]), "OT10"), (bytes([10, 10, 10]), "-N.B0"),
               (bytes([10, 10, 0]), "OT100"), (bytes([10, 10, 40]), "Y6V91"), (bytes([10, 10, 41]), "KL0B1"),
               (bytes([10, 10, 255]), "Q-M08"), (bytes([35]), "Z0"), (bytes([255, 0]), "R600"),
               (bytes([46, 0, 0]), "81000"), (bytes([255]), "R6"), (bytes([255, 255]), "NE71"),
               (bytes([255, 255, 255]), "PLS18"), (b"Hello World!", "KKHF3W2S013OPM3EJX11")]

    def test_encode_decode(self):
        for data, text in self.VECTORS:
            self.assertEqual(ms.base38_encode(data), text)
            self.assertEqual(ms.base38_decode(text), data)

    def test_decode_errors(self):
        for bad in ("S6", "OE71", "QLS18", "A", "@0", " 0"):
            with self.assertRaises(ValueError):
                ms.base38_decode(bad)


class QrCode(unittest.TestCase):
    def test_rs_matter_ble_vector(self):
        # rs-matter pairing/qr.rs can_base38_encode: passcode 34567890, disc 2976, VID 9050, PID 65279, BLE.
        self.assertEqual(ms.qr_payload(34567890, 2976, 9050, 65279, ms.RENDEZVOUS["ble"]), "MT:YNJV7VSC00CMVH7SR00")

    def test_m0_node_qr(self):
        qr = "MT:-24J0AFN00KA064IJ3P0WISA0DK5N1K8SQ1RYCU1O0"  # carries trailing TLV after the 11-byte header
        d = ms.qr_decode(qr)
        self.assertEqual((d["vid"], d["pid"], d["flow"], d["rendezvous"], d["discriminator"], d["passcode"]),
                         (0xFFF1, 0x8001, 0, ms.RENDEZVOUS["onnetwork"], 3840, 20202021))
        self.assertEqual(ms.manual_code_pretty(ms.manual_code(d["passcode"], d["discriminator"])), "3497-011-2332")

    def test_rs_matter_ip_vector_header(self):
        # rs-matter can_base38_encode_with_vendor_data: same header bytes plus TLV; first 9 bytes = 15 chars agree.
        qr = ms.qr_payload(20202021, 3840, 0xFFF1, 0x8001, ms.RENDEZVOUS["onnetwork"])
        self.assertEqual(qr[:18], "MT:-24J0AFN00KA064")
        self.assertEqual(ms.qr_decode(qr)["passcode"], 20202021)

    def test_chip_invalid_passcode_still_decodes(self):
        # TestQRCode.cpp: "MT:M5L90MP500W-GT68D20" parses, passcode 111111111.
        d = ms.qr_decode("MT:M5L90MP500W-GT68D20")
        self.assertEqual(d["passcode"], 111111111)

    def test_roundtrip_random_fields(self):
        for pc, disc, vid, pid, rv, flow in [(1, 0, 0, 0, 0, 0), (99999998, 4095, 0xFFFF, 0xFFFF, 31, 2),
                                             (12345679, 2560, 1, 1, 6, 1)]:
            d = ms.qr_decode(ms.qr_payload(pc, disc, vid, pid, rv, flow))
            self.assertEqual((d["passcode"], d["discriminator"], d["vid"], d["pid"], d["rendezvous"], d["flow"]),
                             (pc, disc, vid, pid, rv, flow))

    def test_decode_rejects_bad_prefix(self):
        with self.assertRaises(ValueError):
            ms.qr_decode("AT:M5L90MP500K64J00000")


def verhoeff_valid(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = ms._D[c][ms._P[i % 8][int(ch)]]
    return c == 0


class ManualCode(unittest.TestCase):
    def test_chip_generator_vectors(self):
        # TestManualCode.cpp: expected strings there are the digits before the Verhoeff digit.
        cases = [((12345679, 2560), "2412950753"),
                 ((12345679, 2560, 1, 1, True), "64129507530000100001"),
                 ((12345679, 2560, 45367, 14526, False), "2412950753"),
                 ((12345679, 2560, 45367, 14526, True), "64129507534536714526")]
        for args, expect in cases:
            code = ms.manual_code(*args)
            self.assertEqual(code[:-1], expect)
            self.assertTrue(verhoeff_valid(code))

    def test_chip_parser_vectors(self):
        # TestPayloadParser_*: chip appends the check digit to these before parsing.
        for body in ("2361087535", "63610875354536714526", "52927623630456200032", "40000100000000100001"):
            self.assertTrue(verhoeff_valid(body + ms.verhoeff_check_digit(body)), body)
        self.assertFalse(verhoeff_valid("02684354589"))  # chip: INTEGRITY_CHECK_FAILED

    def test_pin_discriminator_fields(self):
        # 63610875354536714526: PIN 123456780, disc nibble 0xA, VID 45367, PID 14526 (custom flow).
        code = ms.manual_code(123456780, 0xA00, 45367, 14526, True)
        self.assertEqual(code[:20], "63610875354536714526")
        self.assertEqual(ms.manual_code(123456780, 0xA00)[:10], "2361087535")

    def test_default_dev_code(self):
        self.assertEqual(ms.manual_code(20202021, 3840), "34970112332")
        self.assertEqual(ms.manual_code_pretty("34970112332"), "3497-011-2332")

    def test_check_digit_known(self):
        # Verhoeff: "236" -> 3 (standard worked example).
        self.assertEqual(ms.verhoeff_check_digit("236"), "3")


class Verifier(unittest.TestCase):
    def test_published_default_verifier(self):
        # connectedhomeip scripts/tools/spake2p/README.md: salt "SPAKE2P Key Salt", passcode 20202021, 1000 iters.
        exp = base64.b64decode("uWFwqugDNGiEck/po7KHwwMwwqZgN10XuyBajPGuyzUEV/iree4lOrao5GuwnlQ65CJzbeUB49s31EH+"
                               "NEkg0JVI5MGCQGMMT/SRPFNRODm3wH/MBiehuFc6FJ/NH6Rmzw==")
        self.assertEqual(base64.b64decode("U1BBS0UyUCBLZXkgU2FsdA=="), b"SPAKE2P Key Salt")
        w0, L = ms.verifier(20202021, b"SPAKE2P Key Salt", 1000)
        self.assertEqual(len(exp), 97)
        self.assertEqual(w0 + L, exp)
        self.assertEqual(L[0], 4)

    def test_curve(self):
        self.assertTrue(ms.on_curve(ms.G))
        self.assertIsNone(ms.point_mul(ms.N, ms.G))
        self.assertEqual(ms.point_mul(ms.N - 1, ms.G)[0], ms.G[0])
        two_g = ms.point_add(ms.G, ms.G)
        self.assertEqual(ms.point_mul(2, ms.G), two_g)
        self.assertTrue(ms.on_curve(two_g))

    def test_pbkdf2_rfc_style_vector(self):
        # chip PBKDF2_SHA256_test_vectors.h vector 1 is HMAC-SHA1-sized; sanity check the hashlib call shape.
        self.assertEqual(hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32).hex(),
                         "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")  # RFC 7914 style KAT


class Passcodes(unittest.TestCase):
    def test_invalid(self):
        for pc in [0, 11111111, 22222222, 99999999, 12345678, 87654321, 100000000, 99999999 + 1, -1]:
            self.assertFalse(ms.valid_passcode(pc), pc)
        for pc in [1, 20202021, 12345679, 99999998]:
            self.assertTrue(ms.valid_passcode(pc), pc)

    def test_random_always_valid(self):
        for _ in range(500):
            self.assertTrue(ms.valid_passcode(ms.random_passcode()))


class Cli(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, TOOL, *args], capture_output=True, text=True)

    def test_header_for_default_dev_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = os.path.join(tmp, "m.h")
            r = self.run_tool(h, "--passcode", "20202021", "--discriminator", "3840", "--iterations", "1000",
                              "--salt-hex", b"SPAKE2P Key Salt".hex(), "--rendezvous", "onnetwork")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("3497-011-2332", r.stdout)
            with open(h) as f:
                text = f.read()
            for needle in ("MATTER_DISCRIMINATOR 3840", "MATTER_PASSCODE 20202021", "MATTER_PBKDF_ITERATIONS 1000",
                           "MATTER_VENDOR_ID 0xFFF1", "MATTER_PRODUCT_ID 0x8000", "MATTER_DISCOVERY_CAPABILITIES 0x04",
                           "MATTER_PBKDF_SALT_LEN 16", "0xb9, 0x61, 0x70"):  # w0 starts b9 61 70 (published vector)
                self.assertIn(needle, text)
            self.assertEqual(oct(os.stat(h).st_mode & 0o777), oct(0o600))

    def test_rejects_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = os.path.join(tmp, "m.h")
            self.assertNotEqual(self.run_tool(h, "--passcode", "12345678").returncode, 0)
            self.assertNotEqual(self.run_tool(h, "--discriminator", "4096").returncode, 0)
            self.assertNotEqual(self.run_tool(h, "--iterations", "999").returncode, 0)
            self.assertNotEqual(self.run_tool(h, "--rendezvous", "zigbee").returncode, 0)
            self.assertFalse(os.path.exists(h))

    def test_unit_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = os.path.join(tmp, "u.h")
            r = self.run_tool(h, "--unit", "000000000001", "--passcode", "20202021", "--discriminator", "3840",
                              "--iterations", "1000", "--salt-hex", b"SPAKE2P Key Salt".hex(), "--rendezvous", "onnetwork")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("3497-011-2332", r.stdout)       # the passcode is printed once ...
            with open(h) as f:
                text = f.read()
            self.assertNotIn("PASSCODE", text)               # ... and never written to the header
            self.assertNotIn("20202021", text)
            for needle in ("MATTER_UNIT_H", 'MATTER_SERIAL_NUMBER "000000000001"', "MATTER_UNIQUE_ID \"",
                           "MATTER_DISCRIMINATOR 3840", "0xb9, 0x61, 0x70"):
                self.assertIn(needle, text)
            self.assertEqual(oct(os.stat(h).st_mode & 0o777), oct(0o600))
            r = self.run_tool(h, "--unit", "000000000001")  # never overwrites a unit
            self.assertNotEqual(r.returncode, 0)
            with open(h) as f:
                self.assertEqual(f.read(), text)
            self.assertNotEqual(self.run_tool(os.path.join(tmp, "v.h"), "--unit", "bad serial").returncode, 0)

    def test_reissue_qr(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, txt = os.path.join(tmp, "u.h"), os.path.join(tmp, "setup.txt")
            r = self.run_tool(h, "--unit", "000000000001", "--passcode", "20202021", "--discriminator", "3840",
                              "--iterations", "1000", "--rendezvous", "onnetwork")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(txt, "w") as f:
                f.write(r.stdout)
            with open(h) as f:
                before = f.read()
            r = self.run_tool(h, "--reissue-qr", txt, "--rendezvous", "ble")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("20202021", r.stdout)            # nothing secret on stdout
            self.assertNotIn("MT:", r.stdout)
            with open(txt) as f:
                lines = f.read().splitlines()
            self.assertEqual(lines[-1].split()[:2], ["qr", "(ble):"])
            d = ms.qr_decode(lines[-1].split()[2])
            self.assertEqual((d["passcode"], d["discriminator"], d["rendezvous"], d["vid"], d["pid"]),
                             (20202021, 3840, 2, 0xFFF1, 0x8000))
            with open(h) as f:
                after = f.read()
            self.assertEqual(after, before.replace("CAPABILITIES 0x04", "CAPABILITIES 0x02"))  # only that line
            self.assertEqual(oct(os.stat(h).st_mode & 0o777), oct(0o600))
            # idempotent; a wrong passcode changes nothing
            self.assertEqual(self.run_tool(h, "--reissue-qr", txt, "--rendezvous", "ble").returncode, 0)
            with open(txt) as f:
                self.assertEqual(f.read().splitlines(), lines)
            with open(txt, "w") as f:
                f.write("passcode: 20202022\ndiscriminator: 3840\n")
            r = self.run_tool(h, "--reissue-qr", txt, "--rendezvous", "onnetwork")
            self.assertNotEqual(r.returncode, 0)
            with open(h) as f:
                self.assertEqual(f.read(), after)

    def test_random_run_decodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self.run_tool(os.path.join(tmp, "m.h"), "--rendezvous", "ble,onnetwork", "--iterations", "1000")
            self.assertEqual(r.returncode, 0, r.stderr)
            qr = [l for l in r.stdout.splitlines() if l.startswith("qr:")][0].split()[1]
            d = ms.qr_decode(qr)
            self.assertEqual(d["rendezvous"], 6)
            self.assertTrue(ms.valid_passcode(d["passcode"]))


if __name__ == "__main__":
    unittest.main()
