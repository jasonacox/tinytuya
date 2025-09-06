# TinyTuya Cover Device Async
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    CoverDeviceAsync(...)
        See OutletDeviceAsync() for constructor arguments

 Functions
    CoverDeviceAsync:
        async open_cover(switch=1):
        async close_cover(switch=1):
        async stop_cover(switch=1):

    Inherited from DeviceAsync:
        async json = status()                    # returns json payload
        set_version(version)               # 3.1 [default] or 3.3
        set_socketPersistent(False/True)   # False [default] or True
        set_socketNODELAY(False/True)      # False or True [default]
        set_socketRetryLimit(integer)      # retry count limit [default 5]
        set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
        set_dpsUsed(dps_to_request)        # add data points (DPS) to request
        add_dps_to_request(index)          # add data point (DPS) index set to None
        set_retry(retry=True)              # retry if response payload is truncated
        async set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
        async set_value(index, value, nowait)    # Set int value of any index.
        async heartbeat(nowait)                  # Send heartbeat to device
        async updatedps(index=[1], nowait)       # Send updatedps command to device
        async turn_on(switch=1, nowait)          # Turn on device / switch #
        async turn_off(switch=1, nowait)         # Turn off
        async set_timer(num_secs, nowait)        # Set timer for num_secs
        set_debug(toggle, color)           # Activate verbose debugging output
        set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
        detect_available_dps()             # Return list of DPS available from device
        generate_payload(command, data)    # Generate TuyaMessage payload for command with data
        async send(payload)                      # Send payload to device (do not wait for response)
        async receive()
"""

from .core.DeviceAsync import DeviceAsync

class CoverDeviceAsync(DeviceAsync):
    """
    Represents a Tuya based Smart Window Cover (async implementation).
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }

    async def open_cover(self, switch=1, nowait=False):
        """Open the cover"""
        return await self.set_status("on", switch, nowait=nowait)

    async def close_cover(self, switch=1, nowait=False):
        """Close the cover"""
        return await self.set_status("off", switch, nowait=nowait)

    async def stop_cover(self, switch=1, nowait=False):
        """Stop the motion of the cover"""
        return await self.set_status("stop", switch, nowait=nowait)
