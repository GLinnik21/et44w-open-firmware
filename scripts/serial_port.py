"""Pick the USB-serial port: --port if given, else the only /dev/cu.usbmodem* / ttyACM* / ttyUSB* present."""
import glob
import sys


def find(port=None):
    if port:
        return port
    ports = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
    if len(ports) != 1:
        sys.exit("No USB-serial port found - is the adapter in USB-UART bridge mode? Pass --port."
                 if not ports else "Several serial ports found, pass --port: " + " ".join(ports))
    return ports[0]
