# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya Electric Heating Blanket

 Author: Leo Denham (https://github.com/leodenham)
 Tested: Goldair Platinum Electric Blanket GPFAEB-Q

 Local Control Classes
    BlanketDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    BlanketDevice:
        get_feet_level()
        get_body_level()
        set_feet_level()
        set_body_level()
        get_feet_time()
        get_body_time()
        set_feet_time()
        set_body_time()
        get_feet_countdown()
        get_body_countdown()


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

from ..core import Device, error_json, ERR_RANGE


class BlanketDevice(Device):
    """
    Represents a Tuya based Electric Blanket Device
    """
    DPS = 'dps'
    DPS_BODY_LEVEL = '14'
    DPS_FEET_LEVEL = '15'
    DPS_BODY_TIME = '16'
    DPS_FEET_TIME = '17'
    DPS_BODY_COUNTDOWN = '18'
    DPS_FEET_COUNTDOWN = '19'
    LEVEL_PREFIX = 'level_'

    def _number_to_level(self, num):
        return f'{self.LEVEL_PREFIX}{num+1}'
    
    def _level_to_number(self, level):
        return int(level.split(self.LEVEL_PREFIX)[1]) - 1

    def get_feet_level(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = self._level_to_number(status_data[self.DPS][self.DPS_FEET_LEVEL])
        return current

    def get_body_level(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = self._level_to_number(status_data[self.DPS][self.DPS_BODY_LEVEL])
        return current

    def set_feet_level(self, num):
        if (num < 0 or num > 6):
            return error_json(
                ERR_RANGE, "set_feet_level: The value for the level needs to be between 0 and 6."
            )
        return self.set_value(self.DPS_FEET_LEVEL, self._number_to_level(num))

    def set_body_level(self, num):
        if (num < 0 or num > 6):
            return error_json(
                ERR_RANGE, "set_body_level: The value for the level needs to be between 0 and 6."
            )
        return self.set_value(self.DPS_BODY_LEVEL, self._number_to_level(num))

    def get_feet_time(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = status_data[self.DPS][self.DPS_FEET_TIME]
        return current.replace('h', '')

    def get_body_time(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = status_data[self.DPS][self.DPS_BODY_TIME]
        return current.replace('h', '')

    def set_feet_time(self, num):
        if (num < 1 or num > 12):
            return error_json(
                ERR_RANGE, "set_feet_time: The value for the time needs to be between 1 and 12."
            )
        return self.set_value(self.DPS_FEET_TIME, f"{num}h")

    def set_body_time(self, num):
        if (num < 1 or num > 12):
            return error_json(
                ERR_RANGE, "set_body_time: The value for the time needs to be between 1 and 12."
            )
        return self.set_value(self.DPS_BODY_TIME, f"{num}h")

    def get_feet_countdown(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = status_data[self.DPS][self.DPS_FEET_COUNTDOWN]
        return current

    def get_body_countdown(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        
        current = status_data[self.DPS][self.DPS_BODY_COUNTDOWN]
        return current

