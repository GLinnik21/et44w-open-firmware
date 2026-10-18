#!/usr/bin/env python3
"""Sign a packed firmware slot image with the OTA key and upload it to a module.

  tools/ota_push.py out/image_firmware_is.0x010000.bin --host <device-ip> [--port 8267]
                    [--key secrets/ota_signing.key] [--timeout 120] [--legacy] [--sign-only out.sig] [--self-test]

Wire protocol v2 (libs/ota/include/ota.h): TCP; b"AOT2" + u32le length + u32le serial + SHA-512(image) +
64-byte Ed25519 signature, then the image. The signature covers b"ambz2-ota-v2" + the 72 header bytes after the
magic, so the module authenticates the upload before it erases the idle slot. The module replies with one
line, "OK ..." on success.
--legacy speaks v1 (b"AOTA" + u32le length + signature over b"ambz2-ota-v1" + u32le length + SHA-512(image)),
the only format firmware from before v2 accepts; v2 firmware refuses it.
"""
import argparse, hashlib, os, select, socket, struct, sys, tempfile
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("needs the cryptography package: python3 -m pip install cryptography")

MIN_SIZE, MAX_SIZE = 0x1000, 0xE0000
SERIAL_OFFSET = 0xF4  # libs/ota/src/ota_flash.h OTA_SERIAL_OFFSET
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEF_KEY = os.path.join(ROOT, "secrets", "ota_signing.key")


def signed_part(image):
    serial = struct.unpack_from("<I", image, SERIAL_OFFSET)[0]
    return struct.pack("<II", len(image), serial) + hashlib.sha512(image).digest()


def message(image, legacy=False):
    if legacy:
        return b"ambz2-ota-v1" + struct.pack("<I", len(image)) + hashlib.sha512(image).digest()
    return b"ambz2-ota-v2" + signed_part(image)


def header(image, sig, legacy=False):
    if legacy:
        return b"AOTA" + struct.pack("<I", len(image)) + sig
    return b"AOT2" + signed_part(image) + sig


def load_key(path):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(path).read().strip()))


def self_test():
    key = Ed25519PrivateKey.generate()
    image = bytearray(os.urandom(100 * 1024))
    struct.pack_into("<I", image, SERIAL_OFFSET, 7)
    image = bytes(image)
    for legacy in (False, True):
        sig = key.sign(message(image, legacy))
        assert len(sig) == 64 and len(message(image, legacy)) == (84 if not legacy else 80)
        key.public_key().verify(sig, message(image, legacy))
        try:
            key.public_key().verify(sig, message(image[:-1] + b"x", legacy))
            raise SystemExit("self-test failed: tampered image verified")
        except Exception as e:
            if isinstance(e, SystemExit):
                raise
    hdr = header(image, key.sign(message(image)))
    assert len(hdr) == 140 and hdr[:4] == b"AOT2" and hdr[8:12] == struct.pack("<I", 7)
    assert b"ambz2-ota-v2" + hdr[4:76] == message(image)  # the device verifies exactly these bytes
    assert len(header(image, sig, legacy=True)) == 72
    print("self-test ok")


LEGACY_HINT = ("hint: a module running firmware from before OTA v2 (or rolled back to it) answers v2 with "
               "'bad header' or drops the connection: push once with --legacy")
V2_HINT = "hint: firmware with OTA v2 refuses --legacy uploads (it may drop the connection): push without it"


def hint(args):
    print(V2_HINT if args.legacy else LEGACY_HINT, file=sys.stderr)


def push(args, image, sig):
    buf = b""
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
            s.settimeout(args.timeout)
            s.sendall(header(image, sig, args.legacy))
            for off in range(0, len(image), 4096):
                if select.select([s], [], [], 0)[0]:
                    break  # the module replied early (an error): stop sending and read it
                s.sendall(image[off:off + 4096])
                print("\rsending %3d%%" % (100 * min(off + 4096, len(image)) // len(image)), end="",
                      file=sys.stderr)
            print(file=sys.stderr)
            while b"\n" not in buf:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf += chunk
    except (ConnectionResetError, BrokenPipeError) as e:
        print("\n%s" % e, file=sys.stderr)
        hint(args)
        return 1
    if b"\n" not in buf:
        print("connection closed without a reply line", file=sys.stderr)
        hint(args)
        return 1
    line = buf.split(b"\n")[0].decode(errors="replace").strip()
    print(line)
    if line == "ERR bad header" and not args.legacy:
        print(LEGACY_HINT, file=sys.stderr)
    return 0 if line.startswith("OK") else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", nargs="?", help="packed slot image")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=8267)
    ap.add_argument("--key", default=DEF_KEY)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--legacy", action="store_true", help="v1 upload, for firmware from before OTA v2")
    ap.add_argument("--sign-only", metavar="OUT.SIG", help="write the signature and exit")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.image or not (args.host or args.sign_only):
        ap.error("image and --host (or --sign-only) are required")
    image = open(args.image, "rb").read()
    if not MIN_SIZE < len(image) <= MAX_SIZE:
        sys.exit("image size 0x%x outside (0x%x, 0x%x]" % (len(image), MIN_SIZE, MAX_SIZE))
    sig = load_key(args.key).sign(message(image, args.legacy))
    if args.sign_only:
        open(args.sign_only, "wb").write(sig)
        return print("signature written to " + args.sign_only)
    sys.exit(push(args, image, sig))


if __name__ == "__main__":
    main()
