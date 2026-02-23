# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya
"""

from ..core import Device

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
