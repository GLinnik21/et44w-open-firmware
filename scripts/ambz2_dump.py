"""Read the whole 2 MiB AmbZ2 flash through a slow USB-UART bridge (e.g. a Flipper), checked on the chip.

Usage: ambz2_dump.py <out.bin> [--port PATH]

4 KiB chunks with >= 3 s timeouts and 20 retries; the chip's SHA-256 is compared every 128 KiB.
Data goes to <out.bin>.part as it arrives, so a failed run keeps what was read; running again
resumes from the last verified 128 KiB block. The .part file becomes <out.bin> when complete.
"""
import argparse, os, time
from ltchiptool.soc.ambz2.util.ambz2tool import AmbZ2Tool
from serial_port import find

_pt = AmbZ2Tool.push_timeout
AmbZ2Tool.push_timeout = lambda self, t: _pt(self, max(t, 3.0))

SIZE, BLOCK = 2 * 1024 * 1024, 128 * 1024

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--port")
a = ap.parse_args()

part = a.out + ".part"
start = os.path.getsize(part) // BLOCK * BLOCK if os.path.exists(part) else 0
t = AmbZ2Tool(port=find(a.port), baudrate=115200, retry_count=20)
t.link(); print('linked', flush=True)
if start:
    print(f'resuming at {start // 1024} KiB', flush=True)
done, t0 = start, time.time()
os.umask(0o077)  # the dump holds Wi-Fi credentials and device keys
with open(part, 'r+b' if start else 'wb') as f:
    f.truncate(start); f.seek(start)
    for chunk in t.memory_read(start, SIZE - start, use_flash=True, hash_check=True,
                               chunk_size=4096, yield_size=4096, hash_check_size=BLOCK):
        f.write(chunk); done += len(chunk)
        if done % (64 * 1024) == 0:
            f.flush()
            print(f'{done // 1024} KiB  {time.time() - t0:.0f}s', flush=True)
assert done == SIZE, done
os.replace(part, a.out)
print('DONE, SHA verified', flush=True)
