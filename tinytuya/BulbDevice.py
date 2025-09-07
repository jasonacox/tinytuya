# TinyTuya Bulb Device
# -*- coding: utf-8 -*-
"""
 TinyTuya - Bulb Device Wrapper

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 This class provides bulb-specific functionality while inheriting
 all basic device operations from the Device class.
"""

from .BulbDeviceAsync import BulbDeviceAsync
from .core import Device


class BulbDevice(Device):
    """
    Represents a Tuya based Smart Light/Bulb.
    
    Inherits from Device but uses BulbDeviceAsync implementation for bulb-specific functionality.
    Uses the new AsyncWrapper architecture for automatic method delegation.
    """

    def __init__(self, *args, **kwargs):
        """Initialize BulbDevice with BulbDeviceAsync implementation"""
        # Initialize AsyncWrapper directly with BulbDeviceAsync instead of calling super()
        # because super() would create DeviceAsync, but we want BulbDeviceAsync
        from .core.AsyncWrapper import AsyncWrapper
        AsyncWrapper.__init__(self, BulbDeviceAsync, *args, **kwargs)
        
        # Set the attributes that Device/XenonDevice would normally set
        # Extract from args/kwargs for backward compatibility
        if args:
            self.id = args[0]  # dev_id is first argument
        else:
            self.id = kwargs.get('dev_id')
        
        self.address = kwargs.get('address') if 'address' in kwargs else (args[1] if len(args) > 1 else None)
        self.cid = kwargs.get('cid') or kwargs.get('node_id')
        self.port = kwargs.get('port', 6668)
        
        # Initialize the async implementation to handle Auto-IP and device.json lookup
        self._runner.run(self._async_impl.initialize())

    # Static methods (no async conversion needed)
    @staticmethod
    def rgb_to_hexvalue(r, g, b, hexformat):
        return BulbDeviceAsync.rgb_to_hexvalue(r, g, b, hexformat)

    @staticmethod 
    def _rgb_to_hexvalue(r, g, b, bulb="A"):
        return BulbDeviceAsync._rgb_to_hexvalue(r, g, b, bulb)

    @staticmethod
    def hsv_to_hexvalue(h, s, v, hexformat):
        return BulbDeviceAsync.hsv_to_hexvalue(h, s, v, hexformat)

    @staticmethod
    def hexvalue_to_rgb(hexvalue, hexformat=None):
        return BulbDeviceAsync.hexvalue_to_rgb(hexvalue, hexformat)

    @staticmethod
    def _hexvalue_to_rgb(hexvalue, bulb="A"):
        return BulbDeviceAsync._hexvalue_to_rgb(hexvalue, bulb)

    @staticmethod
    def hexvalue_to_hsv(hexvalue, hexformat=None):
        return BulbDeviceAsync.hexvalue_to_hsv(hexvalue, hexformat)

    @staticmethod
    def _hexvalue_to_hsv(hexvalue, bulb="A"):
        return BulbDeviceAsync._hexvalue_to_hsv(hexvalue, bulb)
