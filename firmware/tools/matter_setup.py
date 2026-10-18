#!/usr/bin/env python3
"""Generate Matter setup credentials: passcode, discriminator, SPAKE2+ verifier, QR payload, manual code.

Writes a C header with the passcode-derived secrets (w0, L, salt; the verifier lets an attacker brute-force
the 8-digit passcode offline, and the header also holds the passcode itself for the console banner), so keep
it out of version control. The QR string and manual code are printed to stdout; nothing else is.

  tools/matter_setup.py out.h [--rendezvous ble,onnetwork] [--vid 0xFFF1] [--pid 0x8000]
                              [--passcode N] [--discriminator N] [--iterations N] [--salt-hex HEX]
                              [--unit SERIAL]
  tools/matter_setup.py --decode MT:...        decode a QR payload (first 88 bits)
  tools/matter_setup.py UNIT_H --reissue-qr SETUP_TXT --rendezvous ble
                                               new QR for an existing unit (see below)

--unit writes a device unit header instead (apps/thermostat-matter/units/<UNIT>/matter_unit.h): no
MATTER_PASSCODE (the device keeps only the verifier; the passcode exists only in the printed output, so save
that), plus MATTER_SERIAL_NUMBER and a random MATTER_UNIQUE_ID. It refuses to overwrite an existing header,
because a new verifier invalidates the unit's QR code and every printed copy of it.

--reissue-qr recomputes only the QR payload of an existing unit for new rendezvous flags: the passcode and
discriminator come from SETUP_TXT (the saved output of --unit), salt/iterations/VID/PID from UNIT_H. The
verifier is recomputed and must equal UNIT_H's (else nothing changes); then a "qr (<flags>):" line is appended
to SETUP_TXT and only MATTER_DISCOVERY_CAPABILITIES in UNIT_H is rewritten. The verifier, the passcode and the
manual code (rendezvous-independent) stay; nothing secret is printed.

Verifier per Matter Core spec 3.10 / 5.1.1.2: PBKDF2-HMAC-SHA256(passcode as 4 bytes LE, salt, iterations,
80 bytes) = w0s || w1s (40 bytes each), w0 = w0s mod n, w1 = w1s mod n, L = w1 * G (P-256, uncompressed).
Python 3.8+, standard library only (pure-Python P-256 from matter_p256.py; one scalar multiplication).
"""
import argparse, hashlib, os, secrets, sys

from matter_p256 import G, N, on_curve, point_add, point_mul  # point_add: used by the tests

INVALID_PASSCODES = {int(str(d) * 8) for d in range(10)} | {12345678, 87654321}
RENDEZVOUS = {"softap": 1, "ble": 2, "onnetwork": 4, "wifipaf": 8, "nfc": 16}
B38 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."
PAYLOAD_BITS = (("version", 3), ("vid", 16), ("pid", 16), ("flow", 2), ("rendezvous", 8),
                ("discriminator", 12), ("passcode", 27), ("pad", 4))


# ---- SPAKE2+ verifier --------------------------------------------------------------------------------

def valid_passcode(pc):
    return 1 <= pc <= 99999998 and pc not in INVALID_PASSCODES


def verifier(passcode, salt, iterations):
    """Returns (w0 as 32 bytes, L as 65-byte uncompressed point)."""
    w = hashlib.pbkdf2_hmac("sha256", passcode.to_bytes(4, "little"), salt, iterations, 80)
    w0 = int.from_bytes(w[:40], "big") % N
    w1 = int.from_bytes(w[40:], "big") % N
    x, y = point_mul(w1, G)
    return w0.to_bytes(32, "big"), b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---- Base38, QR and manual code ----------------------------------------------------------------------

def base38_encode(data):
    out = ""
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        v = int.from_bytes(chunk, "little")
        for _ in range({1: 2, 2: 4, 3: 5}[len(chunk)]):
            v, r = divmod(v, 38)
            out += B38[r]
    return out


def base38_decode(s):
    out = b""
    i = 0
    while i < len(s):
        n = min(5, len(s) - i)
        size = {2: 1, 4: 2, 5: 3}.get(n)
        if size is None:
            raise ValueError("bad base38 length")
        v = sum(B38.index(c) * 38 ** k for k, c in enumerate(s[i:i + n]))
        if v >> (8 * size):
            raise ValueError("base38 chunk out of range")
        out += v.to_bytes(size, "little")
        i += n
    return out


def qr_payload(passcode, discriminator, vid, pid, rendezvous, flow=0):
    fields = dict(version=0, vid=vid, pid=pid, flow=flow, rendezvous=rendezvous,
                  discriminator=discriminator, passcode=passcode, pad=0)
    v, shift = 0, 0
    for name, bits in PAYLOAD_BITS:
        assert 0 <= fields[name] < 1 << bits, name
        v |= fields[name] << shift
        shift += bits
    return "MT:" + base38_encode(v.to_bytes(shift // 8, "little"))


def qr_decode(s):
    """Fixed 88-bit header of a payload (needs at least 11 bytes); trailing TLV extras are ignored."""
    if not s.startswith("MT:"):
        raise ValueError("missing MT: prefix")
    v = int.from_bytes(base38_decode(s[3:])[:11], "little")
    out = {}
    for name, bits in PAYLOAD_BITS:
        out[name] = v & (1 << bits) - 1
        v >>= bits
    return out


_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check_digit(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def manual_code(passcode, discriminator, vid=0, pid=0, custom_flow=False):
    """11-digit code (21 with vid/pid for the custom flow), check digit appended, no dashes."""
    short_disc = discriminator >> 8
    d1 = (int(custom_flow) << 2) | (short_disc >> 2)
    d2 = ((short_disc & 3) << 14) | (passcode & 0x3FFF)
    digits = "%d%05d%04d" % (d1, d2, passcode >> 14)
    if custom_flow:
        digits += "%05d%05d" % (vid, pid)
    return digits + verhoeff_check_digit(digits)


def manual_code_pretty(code):
    return "%s-%s-%s" % (code[:4], code[4:7], code[7:]) if len(code) == 11 else code


# ---- Output ------------------------------------------------------------------------------------------

def c_bytes(data):
    lines = ["        " + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ", \\" for i in range(0, len(data), 12)]
    return "{ \\\n%s\n    }" % "\n".join(lines)


def header_text(passcode, discriminator, salt, iterations, w0, L, vid, pid, rendezvous, unit=None):
    """unit = (serial, unique_id): a device unit header, without the passcode."""
    if unit:
        head = ("// Generated by tools/matter_setup.py --unit. Contains the SPAKE2+ verifier (lets an attacker brute-force\n"
                "// the passcode offline): do not commit. The passcode itself is not here; it was printed once.\n"
                "#ifndef MATTER_UNIT_H\n#define MATTER_UNIT_H\n\n"
                "#define MATTER_SERIAL_NUMBER \"%s\"\n#define MATTER_UNIQUE_ID \"%s\"\n" % unit)
        pc = ""
    else:
        head = ("// Generated by tools/matter_setup.py. Contains the passcode and its SPAKE2+ verifier: do not commit.\n"
                "#ifndef MATTER_SETUP_INFO_H\n#define MATTER_SETUP_INFO_H\n\n")
        pc = "#define MATTER_PASSCODE %d\n" % passcode
    return (head +
            "#define MATTER_VENDOR_ID 0x%04X\n#define MATTER_PRODUCT_ID 0x%04X\n"
            "#define MATTER_DISCOVERY_CAPABILITIES 0x%02X\n"
            "#define MATTER_DISCRIMINATOR %d\n%s"
            "#define MATTER_PBKDF_ITERATIONS %d\n\n"
            "#define MATTER_PBKDF_SALT_LEN %d\n#define MATTER_PBKDF_SALT %s\n\n"
            "// SPAKE2+ verifier: w0 (32 bytes, big endian) and L (65 bytes, uncompressed SEC1 point).\n"
            "#define MATTER_SPAKE2P_W0 %s\n\n#define MATTER_SPAKE2P_L %s\n\n#endif\n"
            % (vid, pid, rendezvous, discriminator, pc, iterations, len(salt), c_bytes(salt),
               c_bytes(w0), c_bytes(L)))


def random_passcode():
    while True:
        pc = 1 + secrets.randbelow(99999998)
        if valid_passcode(pc):
            return pc


def parse_rendezvous(text):
    flags = 0
    for name in filter(None, text.split(",")):
        if name not in RENDEZVOUS:
            raise SystemExit("unknown rendezvous '%s' (use %s)" % (name, ",".join(RENDEZVOUS)))
        flags |= RENDEZVOUS[name]
    return flags


# ---- --reissue-qr ------------------------------------------------------------------------------------

def parse_header(text):
    """MATTER_* defines of a generated header: ints, and the byte-array macros as bytes."""
    import re
    out = {}
    for m in re.finditer(r"#define (MATTER_\w+) (0x[0-9A-Fa-f]+|\d+)\s*$", text, re.M):
        out[m.group(1)] = int(m.group(2), 0)
    for m in re.finditer(r"#define (MATTER_\w+) \{ \\\n(.*?)\n    \}", text, re.S):
        out[m.group(1)] = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(2)))
    return out


def parse_setup_txt(text):
    vals = {}
    for line in text.splitlines():
        key, _, val = line.partition(":")
        if key in ("passcode", "discriminator") and val.strip().isdigit():
            vals[key] = int(val.strip())
    if set(vals) != {"passcode", "discriminator"}:
        raise SystemExit("setup file: no passcode/discriminator lines")
    return vals["passcode"], vals["discriminator"]


def rendezvous_names(flags):
    return ",".join(n for n, b in RENDEZVOUS.items() if flags & b)


def reissue_qr(header, setup_txt, rendezvous):
    """Returns a status line without secrets; raises SystemExit (nothing changed) on any mismatch."""
    import re
    with open(header) as f:
        htext = f.read()
    with open(setup_txt) as f:
        stext = f.read()
    h = parse_header(htext)
    need = ("MATTER_VENDOR_ID", "MATTER_PRODUCT_ID", "MATTER_DISCOVERY_CAPABILITIES", "MATTER_DISCRIMINATOR",
            "MATTER_PBKDF_ITERATIONS", "MATTER_PBKDF_SALT", "MATTER_SPAKE2P_W0", "MATTER_SPAKE2P_L")
    if any(k not in h for k in need):
        raise SystemExit("%s: missing defines, nothing changed" % header)
    passcode, disc = parse_setup_txt(stext)
    if disc != h["MATTER_DISCRIMINATOR"]:
        raise SystemExit("discriminator differs between the files, nothing changed")
    if not valid_passcode(passcode):
        raise SystemExit("setup file: invalid passcode, nothing changed")
    if verifier(passcode, h["MATTER_PBKDF_SALT"], h["MATTER_PBKDF_ITERATIONS"]) != \
            (h["MATTER_SPAKE2P_W0"], h["MATTER_SPAKE2P_L"]):
        raise SystemExit("verifier mismatch (setup file does not belong to this unit), nothing changed")
    qr = qr_payload(passcode, disc, h["MATTER_VENDOR_ID"], h["MATTER_PRODUCT_ID"], rendezvous)
    dec = qr_decode(qr)
    assert (dec["passcode"], dec["discriminator"], dec["rendezvous"]) == (passcode, disc, rendezvous)
    appended = qr not in stext
    if appended:
        with open(setup_txt, "a") as f:
            f.write("%sqr (%s): %s\n" % ("" if stext.endswith("\n") or not stext else "\n",
                                          rendezvous_names(rendezvous), qr))
    new_h = re.sub(r"(#define MATTER_DISCOVERY_CAPABILITIES )0x[0-9A-Fa-f]+", r"\g<1>0x%02X" % rendezvous, htext)
    if new_h != htext:
        mode = os.stat(header).st_mode & 0o777
        with open(header, "w") as f:
            f.write(new_h)
        os.chmod(header, mode)
    return "ok: verifier matches; QR for rendezvous %s %s; header capabilities 0x%02X" % (
        rendezvous_names(rendezvous), "appended to " + setup_txt if appended else "already in " + setup_txt,
        rendezvous)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("header", nargs="?", help="C header to write")
    ap.add_argument("--rendezvous", default="ble", help="comma list of softap,ble,onnetwork,wifipaf,nfc")
    ap.add_argument("--vid", type=lambda x: int(x, 0), default=0xFFF1)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x8000)
    ap.add_argument("--passcode", type=int, help="default: random")
    ap.add_argument("--discriminator", type=int, help="12 bits, default: random")
    ap.add_argument("--iterations", type=int, default=10000, help="1000..100000")
    ap.add_argument("--salt-hex", help="16..32 bytes, default: 32 random")
    ap.add_argument("--unit", metavar="SERIAL", help="device unit header: serial number, no passcode, no overwrite")
    ap.add_argument("--decode", metavar="QR", help="decode a QR payload and exit")
    ap.add_argument("--reissue-qr", metavar="SETUP_TXT", help="new QR for the unit header (see the notes above)")
    args = ap.parse_args()

    if args.decode:
        print(qr_decode(args.decode))
        return
    if not args.header:
        ap.error("header is required")
    if args.reissue_qr:
        print(reissue_qr(args.header, args.reissue_qr, parse_rendezvous(args.rendezvous)))
        return
    passcode = args.passcode if args.passcode is not None else random_passcode()
    disc = args.discriminator if args.discriminator is not None else secrets.randbelow(4096)
    salt = bytes.fromhex(args.salt_hex) if args.salt_hex else secrets.token_bytes(32)
    if not valid_passcode(passcode):
        raise SystemExit("invalid passcode")
    if not 0 <= disc < 4096 or not 1000 <= args.iterations <= 100000 or not 16 <= len(salt) <= 32:
        raise SystemExit("discriminator/iterations/salt out of range")
    rendezvous = parse_rendezvous(args.rendezvous)
    unit = None
    if args.unit is not None:
        if not 1 <= len(args.unit) <= 32 or not all(c.isalnum() or c in "-_." for c in args.unit):
            raise SystemExit("--unit: serial must be 1..32 of [A-Za-z0-9-_.]")
        if os.path.exists(args.header):
            raise SystemExit("%s exists: a unit keeps its setup code (delete it by hand to re-roll)" % args.header)
        unit = (args.unit, secrets.token_hex(8).upper())
    w0, L = verifier(passcode, salt, args.iterations)
    assert on_curve((int.from_bytes(L[1:33], "big"), int.from_bytes(L[33:], "big")))
    qr = qr_payload(passcode, disc, args.vid, args.pid, rendezvous)
    dec = qr_decode(qr)
    assert (dec["passcode"], dec["discriminator"], dec["rendezvous"]) == (passcode, disc, rendezvous)

    with open(args.header, "w") as f:
        f.write(header_text(passcode, disc, salt, args.iterations, w0, L, args.vid, args.pid, rendezvous, unit))
    os.chmod(args.header, 0o600)
    print("passcode:      %08d\ndiscriminator: %d\nqr:            %s\nmanual code:   %s"
          % (passcode, disc, qr, manual_code_pretty(manual_code(passcode, disc))))


if __name__ == "__main__":
    main()
