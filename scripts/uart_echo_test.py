"""Check that the Log_Tx/Log_Rx wires aren't bridged (run with the WBR2 unpowered).

Sends bytes out of the serial adapter's TX and listens on its RX. With the module
unpowered nothing should come back; an echo means TX and RX are shorted together.

Usage: .venv/bin/python scripts/uart_echo_test.py [/dev/cu.usbmodemXXXX]
"""
import glob
import sys

import serial

ports = sys.argv[1:] or sorted(glob.glob("/dev/cu.usbmodem*"))
if not ports:
    sys.exit("No /dev/cu.usbmodem* port found - is the Flipper in USB-UART Bridge mode?")
port = ports[0]
probe = bytes(range(0x20, 0x7F))

with serial.Serial(port, 115200, timeout=1) as s:
    s.reset_input_buffer()
    s.write(probe)
    s.flush()
    echo = s.read(len(probe))

print(f"port {port}: sent {len(probe)} bytes, got {len(echo)} back")
if not echo:
    print("OK: no echo - Log_Tx and Log_Rx are not bridged")
elif echo == probe:
    print("BRIDGED: exact echo - Log_Tx and Log_Rx are shorted, fix the joints")
else:
    print(f"UNCLEAR: partial/garbled data came back: {echo[:40]!r}")
