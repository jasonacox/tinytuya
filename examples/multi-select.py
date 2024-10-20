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

# Settings
TTL_HEARTBEAT = 12  # Time in seconds between heartbeats

def create_device(i):
    print(f"Connecting to {i['Device ID']} at {i['Address']} with key {i['Local Key']}")
    device = tinytuya.Device(i["Device ID"], i["Address"], i["Local Key"], version=i["Version"])
    return device

def reconnect_device(device_info, index, statuses, cool_down_time=5):
    """
    Attempts to reconnect the device after a cool-down period and update the statuses.
    """
    time.sleep(cool_down_time)  # Cool-down before reconnection

    try:
        print(f"Reconnecting to {device_info['Device ID']}...")

        device = create_device(device_info)
        device.set_socketPersistent(True)
        initial_status = device.status()

        # Check if we successfully retrieved a valid status
        if "dps" in initial_status:
            print(f"Reconnected and got status from {device.id}: {initial_status}")
            statuses[index] = {"id": device.id, "status": initial_status["dps"]}
        else:
            raise Exception(f"Failed to get valid initial status after reconnect for {device.id}: {initial_status}")

        return device
    except Exception as e:
        print(f"Failed to reconnect to {device_info['Device ID']}: {e}")
        statuses[index] = {"id": device_info["Device ID"], "status": "Disconnected"}
        return None

def send_heartbeat(device):
    """
    Sends a heartbeat packet to keep the device connected.
    """
    try:
        # Send a heartbeat packet
        device.heartbeat(nowait=True)
        print(f"Sent heartbeat to {device.id}")
    except Exception as e:
        print(f"Failed to send heartbeat to {device.id}: {e}")

def getDeviceStatuses(devices, config):
    statuses = [None] * len(devices)  # Initialize statuses list to hold results for each device

    # Enable persistent socket connection for each device
    for index, device in enumerate(devices):
        try:
            device.set_socketPersistent(True)
            initial_status = device.status()
            if "dps" in initial_status:
                print(f"INITIAL status from {device.id}: {initial_status}")
                statuses[index] = {"id": device.id, "status": initial_status["dps"]}
            else:
                print(f"Failed to get initial status from {device.id}")
                statuses[index] = {"id": device.id, "status": {}}
        except Exception as e:
            print(f"Error getting initial status from {device.id}: {e}")
            statuses[index] = {"id": device.id, "status": {}}

    # Create a list of sockets to monitor
    sockets = [device.socket for device in devices]

    last_heartbeat_time = time.time()  # Track the last time a heartbeat was sent

    # Infinite loop to listen for status updates using select
    while True:
        # Send a heartbeat every 5 seconds to all devices
        if time.time() - last_heartbeat_time >= TTL_HEARTBEAT:
            for device in devices:
                send_heartbeat(device)
            last_heartbeat_time = time.time()  # Reset heartbeat timer

            # Use select to wait for any of the device sockets to have data
            try:
                readable, _, _ = select.select(sockets, [], [], 0.1)
            except Exception as e:
                print(f"Device disconnected: {e}")
                # Find the invalid socket and remove it
                for sock in sockets:
                    if sock.fileno() == -1:
                        # reconnect
                        device_info = config["TuyaDevices"][sockets.index(sock)]
                        new_device = reconnect_device(device_info, sockets.index(sock), statuses, cool_down_time=5)
                        if new_device:
                            devices[sockets.index(sock)] = new_device
                            sockets[sockets.index(sock)] = new_device.socket
                        else:
                            # Remove the invalid socket to avoid the negative file descriptor error
                            sockets.remove(sock)
                continue

            if readable:
                # Process each socket with incoming data
                for sock in readable:
                    # Find the corresponding device for this socket
                    device = next((d for d in devices if d.socket == sock), None)
                    if not device:
                        continue

                    updated_status = device.receive()

                    if updated_status:
                        print(f"UPDATE status from {device.id}: {updated_status}")
                        index = devices.index(device)
                        # We may only get one DPS, so just update that one item
                        if "dps" in updated_status:
                            for key in updated_status["dps"]:
                                statuses[index]["status"][key] = updated_status["dps"][key]
                                print(f" - Updated status for {device.id} DPS {key} to {updated_status['dps'][key]}")
                    else:
                        # Check if the device has disconnected
                        if not device.socket or device.socket.fileno() == -1:
                            # Device has disconnected
                            print(f"Device {device.id} has disconnected.")
                            # Reconnect logic with cool-down
                            device_info = config["TuyaDevices"][devices.index(device)]
                            new_device = reconnect_device(device_info, devices.index(device), statuses, cool_down_time=5)
                            if new_device:
                                devices[devices.index(device)] = new_device  # Replace the disconnected device
                                sockets[devices.index(device)] = new_device.socket  # Update the socket list
                            else:
                                # Remove the invalid socket to avoid the negative file descriptor error
                                sockets.remove(sock)
                        else:
                            print(f"Received empty status from {device.id}")

# Initialize devices
devices = [create_device(i) for i in config["TuyaDevices"]]

# Start the status listener
getDeviceStatuses(devices, config)
