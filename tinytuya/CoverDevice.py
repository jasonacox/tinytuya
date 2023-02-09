# TinyTuya Cover Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    CoverDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    CoverDevice:
        open_cover(switch=1):
        close_cover(switch=1):
        stop_cover(switch=1):

    Inherited
        json = status()                    # returns json payload
        set_version(version)               # 3.1 [default] or 3.3
        set_socketPersistent(False/True)   # False [default] or True
        set_socketNODELAY(False/True)      # False or True [default]
        set_socketRetryLimit(integer)      # retry count limit [default 5]
        set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
        set_dpsUsed(dps_to_request)        # add data points (DPS) to request
        add_dps_to_request(index)          # add data point (DPS) index set to None
        set_retry(retry=True)              # retry if response payload is truncated
        set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
        set_value(index, value, nowait)    # Set int value of any index.
        heartbeat(nowait)                  # Send heartbeat to device
        updatedps(index=[1], nowait)       # Send updatedps command to device
        turn_on(switch=1, nowait)          # Turn on device / switch #
        turn_off(switch=1, nowait)         # Turn off
        set_timer(num_secs, nowait)        # Set timer for num_secs
        set_debug(toggle, color)           # Activate verbose debugging output
        set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
        detect_available_dps()             # Return list of DPS available from device
        generate_payload(command, data)    # Generate TuyaMessage payload for command with data
        send(payload)                      # Send payload to device (do not wait for response)
        receive()
"""

from .core import Device

class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }

    def open_cover(self, switch=1, nowait=False):
        """Open the cover"""
        self.set_status("on", switch, nowait=nowait)

    def close_cover(self, switch=1, nowait=False):
        """Close the cover"""
        self.set_status("off", switch, nowait=nowait)

    def stop_cover(self, switch=1, nowait=False):
        """Stop the motion of the cover"""
        self.set_status("stop", switch, nowait=nowait)
