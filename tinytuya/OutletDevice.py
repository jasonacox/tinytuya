# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    OutletDevice(dev_id, address=None, local_key=None, dev_type='default', connection_timeout=5, version=3.1, persist=False
        dev_id (str): Device ID e.g. 01234567891234567890
        address (str, optional): Device Network IP Address e.g. 10.0.1.99, or None to try and find the device
        local_key (str, optional): The encryption key. Defaults to None. If None, key will be looked up in DEVICEFILE if available
        dev_type (str, optional): Device type for payload options (see below)
        connection_timeout (float, optional): The default socket connect and data timeout
        version (float, optional): The API version to use. Defaults to 3.1
        persist (bool, optional): Make a persistant connection to the device

 Functions
    OutletDevice:
        set_dimmer(percentage):
        
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

class OutletDevice(Device):
    """
    Represents a Tuya based Smart Plug or Switch.
    """

    def set_dimmer(self, percentage=None, value=None, dps_id=3, nowait=False):
        """Set dimmer value

        Args:
            percentage (int): percentage dim 0-100
            value (int): direct value for switch 0-255
            dps_id (int): DPS index for dimmer value
            nowait (bool): True to send without waiting for response.
        """

        if percentage is not None:
            level = int(percentage * 255.0 / 100.0)
        else:
            level = value

        if level == 0:
            self.turn_off(nowait=nowait)
        elif level is not None:
            if level < 25:
                level = 25
            if level > 255:
                level = 255
            self.turn_on(nowait=nowait)
            self.set_value(dps_id, level, nowait=nowait)
