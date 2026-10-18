"""Capture the WBR2 Log_Tx boot log through the Flipper USB-UART bridge, with secrets redacted.

Opens the port with DTR/RTS asserted, so the Flipper's RTS/DTR pins (2, 3 -> A13, A_0) are driven low
and the module boots normally instead of into download mode. Power-cycle the module after starting.
Values after passwd/password/psk/key/secret/token/auth are replaced before anything is written or printed.

Usage: .venv-flash/bin/python scripts/bootlog.py <out.log> [--seconds 90] [--baud 115200] [--port ...]
"""
import argparse
import re
import sys
import time

import serial

from serial_port import find

# The value runs to the end of the line (a passphrase may contain spaces), minus a trailing " input:..." echo.
SECRET = re.compile(r"((?:passwd|password|pass|psk|key|secret|token|auth)\w*\s*[:=]\s*)(\S.*?)((?:\s+input:)\S+)?\s*$", re.I)
KEY_LABEL = re.compile(r"key\w*\s*:\s*(<redacted>)?\W*$", re.I)    # "get key:" with the bytes on the next line
HEX_DUMP = re.compile(r"^\s*(?:(?:(?:0x)?[0-9a-f]{1,2}\s+){8,}(?:0x)?[0-9a-f]{0,2}|[0-9a-f]{16,})\s*$", re.I)


def redact(line, after_key_label=False):
    if after_key_label and HEX_DUMP.match(line):
        return "<redacted key bytes>"
    return SECRET.sub(lambda m: m.group(1) + "<redacted>" + (" input:<redacted>" if m.group(3) else ""), line)


ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--seconds", type=float, default=90)
ap.add_argument("--baud", type=int, default=115200)
ap.add_argument("--port")
a = ap.parse_args()

s = serial.Serial()
s.port, s.baudrate, s.timeout = find(a.port), a.baud, 0.2
s.dtr, s.rts = True, True  # pins low: no download-mode strap
s.open()
print(f"capturing {a.seconds:.0f} s on {s.port} @ {a.baud}; power-cycle the module now", file=sys.stderr, flush=True)

buf, end, prev_label = b"", time.time() + a.seconds, False
with open(a.out, "w") as f:
    while time.time() < end:
        buf += s.read(4096)
        *lines, buf = re.split(rb"\r\n|\r|\n", buf)  # Tuya logs also use bare \r mid-line
        for raw in lines:
            text = raw.decode("utf-8", "replace").rstrip("\r")
            line = redact(text, prev_label)
            if text.strip():  # the key bytes can follow the label after a blank line
                prev_label = bool(KEY_LABEL.search(line)) or bool(KEY_LABEL.search(text.strip()))
            f.write("%.3f %s\n" % (time.time(), line))
            f.flush()
            print(line, flush=True)
    if buf:
        f.write(redact(buf.decode("utf-8", "replace"), prev_label) + "\n")
s.close()
