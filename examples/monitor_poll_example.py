#!/usr/bin/env python3
"""
TinyTuya Monitor Example — Manual poll mode

Demonstrates using Monitor.poll() from your own loop instead of
the daemon thread mode (Monitor.start()).

This is useful when you want to integrate monitor into an existing
event loop or control the polling yourself.
"""

import time
import tinytuya

# ── Configuration ───────────────────────────────────────────────────
device_list = [
    {
        "id": "your-device-id-here",
        "ip": "10.0.1.99",
        "key": "your-local-key",
        "ver": 3.3,
        "name": "Kitchen Light",
    },
]


def on_status(device, result):
    dps = result.get("dps", {}) if result else {}
    name = getattr(device, "name", device.id)
    print(f"[STATUS] {name}: {dps}")


def main():
    mon = tinytuya.Monitor(on_status=on_status, heartbeat_interval=12)

    # Register and connect devices
    for cfg in device_list:
        d = tinytuya.OutletDevice(
            cfg["id"], cfg["ip"], cfg["key"],
            version=cfg["ver"], persist=True
        )
        d.name = cfg.get("name", cfg["id"][:8])
        result = mon.add(d)
        if result is True:
            print(f"Connected to {d.name}")
        else:
            print(f"Failed to connect to {d.name}: {result}")

    # Manual poll loop — no background thread
    print("Polling... (Ctrl+C to stop)")
    try:
        while True:
            mon.poll(timeout=1.0)
            # You can also send commands directly since we're on the same thread
            # d.set_value(1, True, nowait=True)
    except KeyboardInterrupt:
        print("\nDone.")

    mon.stop()


if __name__ == "__main__":
    main()
