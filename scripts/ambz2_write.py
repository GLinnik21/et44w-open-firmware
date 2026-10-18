"""Write an image to AmbZ2 flash through the Flipper USB-UART, segment by segment.

Usage: ambz2_write.py <image.bin> [--offset 0xNNN] [--verify-only] [--port PATH]

Each 64 KiB segment goes over XMODEM (per-block CRC/retry), then its SHA-256 is
compared with the chip's `hashq`; a mismatching segment is re-sent up to 5 times.
--verify-only compares hashes without writing anything.
"""
import argparse, io, sys, time
from hashlib import sha256
from ltchiptool.soc.ambz2.util.ambz2tool import AmbZ2Tool
from serial_port import find

_pt = AmbZ2Tool.push_timeout
AmbZ2Tool.push_timeout = lambda self, t: _pt(self, max(t, 3.0))

SEG = 64 * 1024

ap = argparse.ArgumentParser()
ap.add_argument("image")
ap.add_argument("--offset", type=lambda s: int(s, 0), default=0)
ap.add_argument("--verify-only", action="store_true")
ap.add_argument("--port")
a = ap.parse_args()

data = open(a.image, "rb").read()
if a.offset < 0 or a.offset % 4096:
    sys.exit("offset must be a non-negative multiple of 4 KiB")
if a.offset + len(data) > 2 * 1024 * 1024:
    sys.exit("image runs past the end of the 2 MiB flash")

t = AmbZ2Tool(port=find(a.port), baudrate=115200, retry_count=20)
t.link(); t.flash_init(); print("linked", flush=True)

def chip_hash(off, n):
    for _ in range(5):
        try:
            return t.flash_read_hash(off, n)
        except Exception as e:
            print(f"  hash retry at 0x{off:X}: {e}", flush=True)
            t.error_flush(); t.link()
    raise RuntimeError(f"cannot read hash at 0x{off:X}")

t0, bad = time.time(), []
for pos in range(0, len(data), SEG):
    seg, off = data[pos:pos + SEG], a.offset + pos
    want = sha256(seg).digest()
    if a.verify_only:
        ok = chip_hash(off, len(seg)) == want
        print(f"0x{off:06X} {'ok' if ok else 'DIFFERS'}", flush=True)
        if not ok:
            bad.append(off)
        continue
    for attempt in range(1, 6):
        try:
            t.flash_transmit(io.BytesIO(seg), off)
            if chip_hash(off, len(seg)) == want:
                break
            print(f"0x{off:06X} hash mismatch (attempt {attempt})", flush=True)
        except Exception as e:
            print(f"0x{off:06X} error (attempt {attempt}): {e}", flush=True)
            t.error_flush(); t.link()
    else:
        sys.exit(f"FAILED at 0x{off:06X}; flash is partially written, re-run to finish")
    print(f"0x{off:06X} written+verified  {time.time() - t0:.0f}s", flush=True)

if bad:
    sys.exit(f"{len(bad)} segment(s) differ")
whole = chip_hash(a.offset, len(data)) == sha256(data).digest()
print("DONE, whole-image SHA", "matches" if whole else "DIFFERS", flush=True)
sys.exit(0 if whole else 1)
