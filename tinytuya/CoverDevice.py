# TinyTuya Cover Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    CoverDevice(dev_id, address, local_key=None, dev_type='default')

 Functions
    CoverDevice:
        open_cover(switch=1):
        close_cover(switch=1):
        stop_cover(switch=1):
"""

from .core import Device

class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.

    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(CoverDevice, self).__init__(dev_id, address, local_key, dev_type)

    def open_cover(self, switch=1, nowait=False):
        """Open the cover"""
        self.set_status("on", switch, nowait=nowait)

    def close_cover(self, switch=1, nowait=False):
        """Close the cover"""
        self.set_status("off", switch, nowait=nowait)

    def stop_cover(self, switch=1, nowait=False):
        """Stop the motion of the cover"""
        self.set_status("stop", switch, nowait=nowait)
