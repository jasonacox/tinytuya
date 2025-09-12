# -*- coding: utf-8 -*-
"""
TinyTuya - Asynchronous Example

This demonstrates how to use the `tinytuya.DeviceAsync` class to control and
monitor a Tuya device asynchronously. The example shows how to run
concurrent tasks for a device's routine and main control flow, ensuring
non-blocking I/O operations.

Setup:
    Replace 'DEVICEID', 'DEVICEADDRESS', 'DEVICEKEY', and 'DEVICEVERSION'
    with your specific device details. The script will create a background
    task to listen for device status updates and a main task to send
    commands to the device.

Author: 3735943886
For more information, see https://github.com/jasonacox/tinytuya
"""
import asyncio
import tinytuya

# tinytuya.set_debug(True)
d = None

async def device_routine(id, ip, key, ver):
    global d
    # The device object can also be created by calling the 'create' method.
    # d = await tinytuya.DeviceAsync.create(id, ip, key, version=ver, persist=True)
    async with tinytuya.DeviceAsync(id, ip, key, version=ver, persist=True) as d:
        # Asynchronous methods such as 'status', 'receive', and 'heartbeat' must all be called with 'await' to function correctly.
        await d.status(nowait = True)
        while(True):
            data = await d.receive()
            print('Received Payload: %r' % data)
            await d.heartbeat()

async def main():
    global d
    # Example creating an asynchronous task to run the device_routine concurrently.
    # The device_routine will run in the background while the main() function executes its sleep and control commands.
    task = asyncio.create_task(device_routine('DEVICEID', 'DEVICEADDRESS', 'DEVICEKEY', 'DEVICEVERSION'))

    # When sending a control command (payload) while another task (device_routine) is waiting for a packet via 'receive()', 'nowait=True' must be set.
    # This ensures the command is sent without interfering with the ongoing 'receive()' and prevents an unexpected error.
    await asyncio.sleep(5)
    await d.turn_off(1, nowait = True)
    await asyncio.sleep(5)
    await d.turn_on(1, nowait = True)
    await asyncio.sleep(5)

    # If the 'async with' statement was not used, 'd.close()' would need to be called explicitly to properly close the connection.
    # await d.close()

if __name__ == "__main__":
    asyncio.run(main())
