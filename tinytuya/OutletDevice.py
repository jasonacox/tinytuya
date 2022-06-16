# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    OutletDevice(dev_id, address, local_key=None, dev_type='default')

 Functions
    OutletDevice:
        set_dimmer(percentage):
"""

from .core import Device

class OutletDevice(Device):
    """
    Represents a Tuya based Smart Plug or Switch.

    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)

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
