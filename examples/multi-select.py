# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Multi-select Example 
 
 This demonstrates how to use pythons socket select() to listen for status updates 
 from multiple Tuya devices.

 Setup:
    Set the config for each device and the script will open a socket connection for
    each device to listen for status updates. 

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import select
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

# Create array, devices, that is an array of tinytuya.Device objects
devices = []
for i in config["TuyaDevices"]:
    print(f"Connecting to {i['Device ID']} at {i['Address']} with key {i['Local Key']}")
    d = tinytuya.Device(i["Device ID"], i["Address"], i["Local Key"], version=i["Version"])
    devices.append(d)  # Add the device to the devices array

def getDeviceStatuses():
    global devices
    global statuses

    # Enable persistent socket connection for each device
    for device in devices:
        device.set_socketPersistent(True)
        # Call status() once to get the initial status and connect
        initial_status = device.status()
        device_id = device.id
        index = devices.index(device)
        print(f"INITIAL status from {device_id}: {initial_status}")
        statuses[index] = {"id": device_id, "status": initial_status["dps"]}

    # Create a list of sockets to monitor
    sockets = [device.socket for device in devices]

    # Infinite loop to listen for status updates using select
    while True:
        # Use select to wait for any of the device sockets to have data
        readable, _, _ = select.select(sockets, [], [], 0.1)

        # Process each socket with incoming data
        for sock in readable:
            # Find the corresponding device for this socket
            device = next(device for device in devices if device.socket == sock)
            updated_status = device.receive()

            if updated_status:
                print(f"UPDATE status from {device.id}: {updated_status}")
                index = devices.index(device)
                # We may only get one DPS, so just update that one item
                if "dps" in updated_status:
                    for key in updated_status["dps"]:
                        statuses[index]["status"][key] = updated_status["dps"][key]
                        print(f" - Updated status for {device.id} DPS {key} to {updated_status['dps'][key]}")

        # Add a small delay (optional) to prevent tight looping
        time.sleep(0.1)

# Example usage
statuses = [None] * len(devices)  # Initialize statuses list to hold results for each device

# Start the status listener
getDeviceStatuses()

