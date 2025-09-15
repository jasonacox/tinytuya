# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Multi-threaded Example 
 
 This demonstrates how to use threading to listen for status updates from multiple
 Tuya devices.

 Setup:
    Set the config for each device and the script will create a thread for each device
    to listen for status updates.  The main thread will continue to run and can be used
    to send commands to the devices.

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""

import threading
import time
import tinytuya

# Define the devices to control
config = {
    "TuyaDevices": [
        {
            "Address": "192.168.1.10",
            "Device ID": "00112233445566778899",
            "Local Key": "1234567890123abc",
            "Version": "3.3",
        },
        {
            "Address": "192.168.1.11",
            "Device ID": "10112233445566778899",
            "Local Key": "1234567890123abc",
            "Version": "3.3",
        },
        {
            "Address": "192.168.1.12",
            "Device ID": "20112233445566778899",
            "Local Key": "1234567890123abc",
            "Version": "3.3",
        },
        {
            "Address": "192.168.1.13",
            "Device ID": "30112233445566778899",
            "Local Key": "1234567890123abc",
            "Version": "3.3",
        }
    ]
}


# Settings
TTL_HEARTBEAT = 12  # Time in seconds between heartbeats

# Create array, devices, that is an array of tinytuya.Device objects
devices = []
for i in config["TuyaDevices"]:
    d = tinytuya.Device(i["Device ID"], i["Address"], i["Local Key"], version=i["Version"])
    devices.append(d)  # Add the device to the devices array

# Function to listen for status updates from each device
def getDeviceStatuses():
    global devices
    global statuses

    def listen_for_status_updates(device, index):
        """
        Thread function to continuously listen for status updates and send heartbeats.
        """
        # Enable persistent connection to the device
        def reconnect():
            time.sleep(5)  # Cool-down before reconnecting
            try:
                print(f"Reconnecting to {device.id}...")
                device.set_socketPersistent(True)
                initial_status = device.status()
                print(f"Reconnected and got status from {device.id}: {initial_status}")
                statuses[index] = {"id": device.id, "status": initial_status["dps"]}
                return True
            except Exception as e:
                print(f"Failed to reconnect to {device.id}: {e}")
                return False

        try:
            # Call status() once to establish connection and get initial status
            device.set_socketPersistent(True)
            initial_status = device.status()
            print(f"INITIAL status from {device.id}: {initial_status}")
            statuses[index] = {"id": device.id, "status": initial_status["dps"]}
        except Exception as e:
            print(f"Error getting initial status from {device.id}: {e}")
            statuses[index] = {"id": device.id, "status": "Disconnected"}
            return

        # Variables to track the last heartbeat
        last_heartbeat_time = time.time()

        # Infinite loop to listen for status updates
        while True:
            try:
                # Send a heartbeat every 5 seconds
                if time.time() - last_heartbeat_time >= TTL_HEARTBEAT:
                    try:
                        device.heartbeat()
                        print(f"Heartbeat sent to {device.id}")
                        last_heartbeat_time = time.time()
                    except Exception as hb_error:
                        print(f"Failed to send heartbeat to {device.id}: {hb_error}")
                        # Try to reconnect if the heartbeat fails
                        if not reconnect():
                            statuses[index]["status"] = "Disconnected"
                            break  # Exit the loop if reconnection fails

                # Listen for updates from the device
                updated_status = device.receive()

                if updated_status:
                    print(f"UPDATE status from {device.id}: {updated_status}")
                    # We may only get one DPS, so just update that one item
                    if "dps" in updated_status:
                        for key in updated_status["dps"]:
                            statuses[index]["status"][key] = updated_status["dps"][key]
                            print(f" - Updated status for {device.id} DPS {key} to {updated_status['dps'][key]}")

                # Small delay to avoid tight loops
                time.sleep(0.1)

            except Exception as e:
                print(f"Error receiving status from {device.id}: {e}")
                statuses[index]["status"] = "Disconnected"
                if not reconnect():
                    break  # Exit the loop if reconnection fails

    threads = []

    # Create and start a thread for each device
    for index, device in enumerate(devices):
        print(f"Starting thread for device {device.id}")
        thread = threading.Thread(target=listen_for_status_updates, args=(device, index))
        thread.daemon = True  # Daemon threads exit with the main program
        threads.append(thread)
        thread.start()

# Example usage
statuses = [None] * len(devices)  # Initialize statuses list to hold results for each device

getDeviceStatuses()

# Optionally, keep the main program running indefinitely
while True:
    time.sleep(1)  # Keep the main thread alive
