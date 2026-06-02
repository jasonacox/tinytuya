#!/usr/bin/env python3
"""
Example usage of FloorFanDevice from tinytuya

This example shows how to use the FloorFanDevice class to control
a Tuya floor standing fan device locally.
"""

import sys
from tinytuya.Contrib.FloorFanDevice import FloorFanDevice

# Device Configuration
DEVICE_ID = "YOUR_DEVICE_ID"
IP_ADDRESS = "YOUR_DEVICE_IP"
LOCAL_KEY = "YOUR_LOCAL_KEY"
VERSION = 3.3

def main():
    """
    Main example function demonstrating FloorFanDevice usage
    """
    # Initialize the device
    fan = FloorFanDevice(
        DEVICE_ID,
        IP_ADDRESS,
        LOCAL_KEY,
        version=VERSION
    )

    # Enable debug mode to see what's happening
    # fan.set_debug(True)

    try:
        print("=== Floor Standing Fan Control Example ===\n")

        # Get the current status
        print("1. Getting current status...")
        status = fan.status_json()
        print(f"   Status: {status}\n")

        # Control the fan
        print("2. Turning on the fan...")
        fan.set_power(True)
        status = fan.status_json()
        print(f"   Status: {status}\n")

        # Set the mode
        print("3. Setting wind mode to 'nature'...")
        fan.set_mode("nature")
        status = fan.status_json()
        print(f"   Mode: {status['Mode']}\n")

        # Set the speed
        print("4. Setting fan speed to level 3...")
        fan.set_speed(3)
        status = fan.status_json()
        print(f"   Speed: {status['Speed']}\n")

        # Enable oscillation
        print("5. Enabling oscillation...")
        fan.set_oscillation(True)
        status = fan.status_json()
        print(f"   Oscillation: {status['Oscillation']}\n")

        # Set a sleep timer
        print("6. Setting sleep timer to 2 hours...")
        fan.set_timer("2h")
        status = fan.status_json()
        print(f"   Timer: {status['Timer']}\n")

        # Get individual status values
        print("7. Reading individual status values...")
        print(f"   Power: {fan.get_power()}")
        print(f"   Mode: {fan.get_mode()}")
        print(f"   Speed: {fan.get_speed()}")
        print(f"   Oscillation: {fan.get_oscillation()}")
        print(f"   Timer: {fan.get_timer()}\n")

        # Turn off the fan
        print("8. Turning off the fan...")
        fan.set_power(False)
        status = fan.status_json()
        print(f"   Status: {status}\n")

        print("Example completed successfully!")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
