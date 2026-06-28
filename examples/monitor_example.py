#!/usr/bin/env python3
"""
TinyTuya Monitor Example — Single-thread, multi-device status monitoring

This example demonstrates the Monitor class which watches multiple Tuya
devices on a single OS thread using selectors. No asyncio, no per-device
threads, no new dependencies.

Usage:
    python3 monitor_example.py

Requires devices.json in the working directory (from tinytuya wizard),
or edit the device_list below directly.
"""

import json
import signal
import sys
import time

import tinytuya

# ── Configuration ───────────────────────────────────────────────────
# Option 1: Load from devices.json
# DEVICE_FILE = "devices.json"

# Option 2: Hardcode your devices here
device_list = [
    {
        "id": "your-device-id-here",
        "ip": "10.0.1.99",
        "key": "your-local-key",
        "name": "Kitchen Light",
        "ver": 3.3,
    },
]

HEARTBEAT_INTERVAL = 12  # seconds between heartbeats per device


# ── Callbacks ───────────────────────────────────────────────────────

def on_status(device, result):
    """Called when a device sends a status update."""
    dps = result.get("dps", {}) if result else {}
    name = getattr(device, "name", device.id)
    print(f"[STATUS] {name} ({device.id}): {dps}")


def on_connect(device, error):
    """Called when a device connects (or fails to connect)."""
    name = getattr(device, "name", device.id)
    if error:
        print(f"[CONNECT FAIL] {name}: {error}")
    else:
        print(f"[CONNECTED] {name}")


def on_disconnect(device, error):
    """Called when a device disconnects.

    This callback is opt-in — only fires if you pass on_disconnect
    to Monitor(). Use it for custom reconnection logic, alerts, or cleanup.
    """
    name = getattr(device, "name", device.id)
    print(f"[DISCONNECTED] {name}: {error}")
    # Example: attempt manual reconnect after a short delay
    # time.sleep(5)
    # mon.add(device)


# ── Main ────────────────────────────────────────────────────────────

def main():
    # Load devices
    devices = device_list

    # Try loading from devices.json if hardcoded list is defaults
    try:
        with open("devices.json") as f:
            loaded = json.load(f)
            if loaded and device_list[0]["id"] == "your-device-id-here":
                devices = loaded
                print(f"Loaded {len(devices)} devices from devices.json")
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    if not devices or devices[0].get("id") == "your-device-id-here":
        print("No devices configured. Edit device_list in this file or")
        print("place a devices.json in the current directory.")
        print()
        print("Run `python3 -m tinytuya wizard` to discover devices.")
        sys.exit(1)

    # Create the monitor
    mon = tinytuya.Monitor(
        on_status=on_status,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        heartbeat_interval=HEARTBEAT_INTERVAL,
    )

    # Register devices — add() returns a proxy handle for sending commands
    handles = []
    for cfg in devices:
        dev_id = cfg.get("id", cfg.get("gwId", ""))
        ip = cfg.get("ip", cfg.get("address"))
        key = cfg.get("key", cfg.get("local_key", ""))
        ver = float(cfg.get("ver", cfg.get("version", 3.3)))
        name = cfg.get("name", dev_id[:8])

        d = tinytuya.OutletDevice(dev_id, ip, key, version=ver, persist=True)
        d.name = name

        print(f"Connecting to {name} ({ip}) ... ", end="", flush=True)
        result = mon.add(d)
        if isinstance(result, tinytuya.core.Monitor._DeviceProxy):
            print("OK")
            handles.append(result)
        else:
            print(f"FAILED: {result}")

    if not handles:
        print("No devices connected. Exiting.")
        sys.exit(1)

    print(f"\nMonitoring {len(handles)} device(s). Press Ctrl+C to stop.\n")
    print("Send commands via handles, e.g.: handles[0].set_value(1, True)")

    # Start the monitor reactor on a daemon thread
    mon.start()

    # Keep main thread alive until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        mon.stop()
        print("Done.")


if __name__ == "__main__":
    main()
