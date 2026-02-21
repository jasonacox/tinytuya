# examples/Contrib/SoriaInverterDevice-example.py
"""
TinyTuya - Example - SoriaInverterDevice
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script demonstrates how to use the SoriaInverterDevice community
module to monitor a SORIA solar micro-inverter over a local network
using the Tuya v3.5 protocol.

Author  : Markourai (https://github.com/Markourai)
Issue   : https://github.com/jasonacox/tinytuya/issues/658

Setup:
    pip install tinytuya

    Replace DEVICE_ID, DEVICE_IP and LOCAL_KEY with your own device
    credentials. You can retrieve them using the TinyTuya wizard:
        python -m tinytuya wizard
"""

import time
import tinytuya
from tinytuya.Contrib import SoriaInverterDevice

# ---------------------------------------------------------------------------
# Device credentials  --  replace with your own values
# ---------------------------------------------------------------------------
DEVICE_ID  = 'XXXX'
DEVICE_IP  = 'YYYY'
LOCAL_KEY  = 'ZZZZ'
VERSION    = 3.5

# ---------------------------------------------------------------------------
# Helper — pretty-print a report dict
# ---------------------------------------------------------------------------

def print_realtime(data):
    if not data:
        return
    print('-' * 40)
    print('Real-time power (DPS 25)')
    print('  PV power   : %s W'   % data.get('W_PV'))
    print('  AC power : %s VA'  % data.get('W_AC'))

def print_full_report(data):
    if not data:
        return
    print('-' * 40)
    print('Full report (DPS 21)')
    print('  --- DC circuit (solar panel) ---')
    print('  Voltage        : %s V'   % data.get('V1_volts'))
    print('  Current        : %s A'   % data.get('A1_amperes'))
    print('  Power          : %s W'   % data.get('W1_watts'))
    print('  --- AC grid ---')
    print('  Voltage        : %s V'   % data.get('V2_volts'))
    print('  Current        : %s A'   % data.get('A2_amperes'))
    print('  Power          : %s W'   % data.get('W2_watts'))
    print('  Frequency      : %s Hz'  % data.get('Hz'))
    print('  Power factor   : %s'     % data.get('cos_phi'))
    print('  --- Other ---')
    print('  Temperature 1  : %s C'   % data.get('temp1_C'))
    print('  Temperature 2  : %s C'   % data.get('temp2_C'))
    print('  Energy total   : %s kWh' % data.get('energy_kwh'))
    print('  WiFi signal    : %s'     % data.get('wifi_signal'))

def print_status(data):
    if not data:
        return
    print('-' * 40)
    print('Circuit status (DPS 24)')
    for key, val in data.items():
        print('  %s : %s' % (key, 'ON' if val else 'OFF'))

# ---------------------------------------------------------------------------
# Example 1 — simple one-shot read
# Connects, waits for the first real-time update and prints it.
# ---------------------------------------------------------------------------

def example_oneshot():
    print('\n=== Example 1: one-shot read ===\n')

    d = SoriaInverterDevice(
        dev_id    = DEVICE_ID,
        address   = DEVICE_IP,
        local_key = LOCAL_KEY,
        version   = VERSION,
    )

    d.receive()                        # initial handshake
    data = d.receive_and_update()      # wait for first broadcast

    print_realtime(d.get_realtime_power())
    print_full_report(d.get_full_report())
    print_status(d.get_circuit_status())

# ---------------------------------------------------------------------------
# Example 2 — persistent monitoring loop
# Keeps the connection open and prints every update as it arrives.
# The device sends DPS 25 every ~2 s and DPS 21 every ~60 s.
# ---------------------------------------------------------------------------

def example_monitor():
    print('\n=== Example 2: persistent monitor loop ===\n')
    print('Press Ctrl+C to stop.\n')

    d = SoriaInverterDevice(
        dev_id              = DEVICE_ID,
        address             = DEVICE_IP,
        local_key           = LOCAL_KEY,
        version             = VERSION,
        persist             = True,
        connection_timeout  = 1,
        connection_retry_limit = 999,
        connection_retry_delay = 0.1,
    )

    d.receive()   # initial handshake
    print('Connected. Listening for updates...')

    last_heartbeat = time.time()

    try:
        while True:
            data = d.receive_and_update()

            if data and 'dps' in data:
                dps_keys = list(data['dps'].keys())

                # DPS 25 arrives every ~2 s — show real-time power
                if '25' in dps_keys:
                    print_realtime(d.get_realtime_power())

                # DPS 21 arrives every ~60 s — show full report
                if '21' in dps_keys:
                    print_full_report(d.get_full_report())

                # DPS 24 arrives on state changes
                if '24' in dps_keys:
                    print_status(d.get_circuit_status())

            # Send a heartbeat every 20 s to keep the connection alive
            if time.time() - last_heartbeat > 20:
                payload = d.generate_payload(tinytuya.HEART_BEAT)
                d.send(payload)
                last_heartbeat = time.time()

            time.sleep(0.1)

    except KeyboardInterrupt:
        print('\nStopped.')

# ---------------------------------------------------------------------------
# Example 3 — using the cached status() method
# status() returns the last known DPS values without querying the device.
# ---------------------------------------------------------------------------

def example_cached_status():
    print('\n=== Example 3: cached status ===\n')

    d = SoriaInverterDevice(
        dev_id    = DEVICE_ID,
        address   = DEVICE_IP,
        local_key = LOCAL_KEY,
        version   = VERSION,
        persist   = True,
    )

    # Warm up the cache — wait for a few updates
    d.receive()
    for _ in range(5):
        d.receive_and_update()
        time.sleep(0.5)

    # status() now returns cached data without touching the socket
    cached = d.status()
    print('Raw cached DPS keys: %s' % list(cached.get('dps', {}).keys()))

    # Decoded values are always available from the getters
    print_realtime(d.get_realtime_power())
    print_full_report(d.get_full_report())

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Run Example 1 by default.
    # Switch to example_monitor() for continuous monitoring.
    example_oneshot()

    # Uncomment to run continuous monitoring:
    # example_monitor()

    # Uncomment to demonstrate the cached status API:
    # example_cached_status()
