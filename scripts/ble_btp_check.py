#!/usr/bin/env python3
"""Mac-side check for the firmware BLE probe (libs/ble-probe): find the Matter BTP advertisement,
connect, subscribe to C2 and write C1 a few times; the probe echoes each write back as an indication.

    .venv-flash/bin/python scripts/ble_btp_check.py [--scan-seconds 130] [--writes 5]

Start it before or during the probe's 120 s advertising window. Exits non-zero if the device isn't
found or an echo is missing. Not a Matter commissioner: no BTP handshake, just GATT traffic.
"""
import argparse
import asyncio
import sys

from bleak import BleakClient, BleakScanner

SVC_16 = "0000fff6-0000-1000-8000-00805f9b34fb"
C1 = "18ee2ef5-263d-4559-959f-4f9c429f9d11"
C2 = "18ee2ef5-263d-4559-959f-4f9c429f9d12"


def describe(data: bytes) -> str:
    if len(data) < 8:
        return data.hex()
    disc_ver = int.from_bytes(data[1:3], "little")
    vid = int.from_bytes(data[3:5], "little")
    pid = int.from_bytes(data[5:7], "little")
    return f"opcode {data[0]}, discriminator 0x{disc_ver & 0xFFF:03x}, VID 0x{vid:04x}, PID 0x{pid:04x}"


async def main(args) -> int:
    print(f"scanning up to {args.scan_seconds} s for Matter BTP (service data 0xFFF6)...")
    found = asyncio.get_running_loop().create_future()

    def on_adv(device, adv):
        if SVC_16 in adv.service_data and not found.done():
            found.set_result((device, adv))

    async with BleakScanner(on_adv):
        try:
            device, adv = await asyncio.wait_for(found, args.scan_seconds)
        except asyncio.TimeoutError:
            print("not found")
            return 1
    print(f"found {device.name or '?'} [{device.address}] RSSI {adv.rssi} dBm: {describe(adv.service_data[SVC_16])}")

    echoes = asyncio.Queue()
    async with BleakClient(device, timeout=20) as client:
        print(f"connected, MTU {client.mtu_size}")
        await client.start_notify(C2, lambda _, data: echoes.put_nowait(bytes(data)))
        missing = 0
        for i in range(args.writes):
            payload = f"probe-{i}".encode()
            while not echoes.empty():  # a late echo of a timed-out write must not pair with this one
                echoes.get_nowait()
            await client.write_gatt_char(C1, payload, response=True)
            try:
                echo = await asyncio.wait_for(echoes.get(), 5)
                print(f"write {i}: echo {'ok' if echo == payload else 'MISMATCH ' + echo.hex()}")
            except asyncio.TimeoutError:
                print(f"write {i}: no echo")
                missing += 1
            await asyncio.sleep(1)
        await asyncio.sleep(args.hold_seconds)  # keep the link up while the device logs heap
    print("disconnected")
    return 1 if missing else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scan-seconds", type=float, default=130)
    p.add_argument("--writes", type=int, default=5)
    p.add_argument("--hold-seconds", type=float, default=20)
    sys.exit(asyncio.run(main(p.parse_args())))
