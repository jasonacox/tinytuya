# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Multi-asyncio Example

 This demonstrates how to use pythons asyncio to listen for status updates
 from multiple Tuya devices. This is an asyncio-based alternative to the
 original multi-select example.

 Setup:
    Set the config for each device and the script will open a connection for
    each device to listen for status updates.

 Author: Jason A. Cox
 Edited: 3735943886
 For more information see https://github.com/jasonacox/tinytuya

"""
import asyncio
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

async def create_device(i):
    print(f"Connecting to {i['Device ID']} at {i['Address']} with key {i['Local Key']}")
    device = await tinytuya.DeviceAsync.create(i["Device ID"], i["Address"], i["Local Key"], version=i["Version"])
    return device

async def reconnect_device(device_info, cool_down_time=5):
    """
    Attempts to reconnect the device after a cool-down period and update the statuses.
    """
    await asyncio.sleep(cool_down_time)  # Cool-down before reconnection

    try:
        print(f"Reconnecting to {device_info['Device ID']}...")

        device = await create_device(device_info)
        device.set_socketPersistent(True)
        initial_status = await device.status()

        # Check if we successfully retrieved a valid status
        if "dps" in initial_status:
            print(f"Reconnected and got status from {device.id}: {initial_status}")
            status = {"id": device.id, "status": initial_status["dps"]}
        else:
            print(f"Failed to get valid initial status after reconnect for {device.id}: {initial_status}")
            status = {"id": device.id, "status": {}}

        return device, status
    except Exception as e:
        print(f"Failed to reconnect to {device_info['Device ID']}: {e}")
        status = {"id": device_info["Device ID"], "status": "Disconnected"}
        return None, None

async def send_heartbeat(device):
    """
    Sends a heartbeat packet to keep the device connected.
    """
    try:
        # Send a heartbeat packet
        await device.heartbeat(nowait=True)
        print(f"Sent heartbeat to {device.id}")
    except Exception as e:
        print(f"Failed to send heartbeat to {device.id}: {e}")

async def single_device_worker(device_info):
    """
    Manages connection and status updates for a single device.
    """
    # Initialize devices
    device = await create_device(device_info)
    status = {}

    try:
        device.set_socketPersistent(True)
        initial_status = await device.status()
        if "dps" in initial_status:
            print(f"INITIAL status from {device_info['Device ID']}: {initial_status}")
            status = {"id": device_info['Device ID'], "status": initial_status["dps"]}
        else:
            print(f"Failed to get initial status from {device_info['Device ID']}")
            status = {"id": device_info['Device ID'], "status": {}}
    except Exception as e:
        print(f"Error getting initial status from {device_info['Device ID']}: {e}")
        status = {"id": device_info['Device ID'], "status": {}}
        return

    last_heartbeat_time = time.time()  # Track the last time a heartbeat was sent

    # Infinite loop to listen for status updates
    while True:
        try:
            if device:
                # Send a heartbeat
                if time.time() - last_heartbeat_time >= TTL_HEARTBEAT:
                    await send_heartbeat(device)
                    last_heartbeat_time = time.time()  # Reset heartbeat timer

                updated_status = await device.receive()
                if updated_status:
                    print(f"UPDATE status from {device.id}: {updated_status}")
                    # We may only get one DPS, so just update that one item
                    if "dps" in updated_status:
                        for key in updated_status["dps"]:
                            status["status"][key] = updated_status["dps"][key]
                            print(f" - Updated status for {device.id} DPS {key} to {updated_status['dps'][key]}")
                        continue
                print(f"Received empty status from {device.id}")
            else:
                device, status = await reconnect_device(device_info)

        except Exception as e:
            print(f"Device {device_info['Device ID']} disconnected: {e}")
            try:
                await device.close()
            except:
                pass
            device = None

async def getDeviceStatuses(tuyadevices):
    # Create a list of tasks to monitor
    await asyncio.gather(*[single_device_worker(device_info) for device_info in tuyadevices])

# Start the status listener
asyncio.run(getDeviceStatuses(config['TuyaDevices']))
