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
    
    Inherits all basic device functionality from Device and adds bulb-specific features.
    """

    def __init__(self, *args, **kwargs):
        """Initialize BulbDevice with BulbDeviceAsync implementation"""
        # Create BulbDeviceAsync instead of DeviceAsync for bulb-specific functionality
        self._async_impl = BulbDeviceAsync(*args, **kwargs)
        from .core.async_runner import AsyncRunner
        self._runner = AsyncRunner()
        
        # Initialize parent class attributes manually (since we can't call super().__init__)
        # This is necessary because we need BulbDeviceAsync instead of DeviceAsync
        self.id = self._async_impl.id
        self.address = self._async_impl.address
        self.local_key = self._async_impl.local_key
        self.version = self._async_impl.version
        self.port = self._async_impl.port
        self.connection_timeout = self._async_impl.connection_timeout

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._runner.run(self._async_impl.close())
        return False

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

    # ---- Bulb-Specific Method Overrides ----
    # These methods override Device methods to provide bulb-specific default behavior
    
    def turn_on(self, switch=0, nowait=False):
        """Turn bulb on (bulb-specific default switch=0)"""
        return self._runner.run(self._async_impl.turn_on(switch, nowait))

    def turn_off(self, switch=0, nowait=False):
        """Turn bulb off (bulb-specific default switch=0)"""
        return self._runner.run(self._async_impl.turn_off(switch, nowait))

    # ---- Bulb-Specific Methods ----
    # These methods are unique to bulbs and don't exist in the base Device class
    
    def turn_onoff(self, on, switch=0, nowait=False):
        """Turn bulb on/off (bulb-specific method)"""
        return self._runner.run(self._async_impl.turn_onoff(on, switch, nowait))

    def set_mode(self, mode="white", nowait=False):
        """Set bulb mode (white/colour/scene/music)"""
        return self._runner.run(self._async_impl.set_mode(mode, nowait))

    def set_scene(self, scene, scene_data=None, nowait=False):
        """Set bulb scene"""
        return self._runner.run(self._async_impl.set_scene(scene, scene_data, nowait))

    def set_music_colour(self, transition, red, green, blue, brightness=None, colourtemp=None, nowait=False):
        """Set music colour with transition"""
        return self._runner.run(self._async_impl.set_music_colour(transition, red, green, blue, brightness, colourtemp, nowait))

    def set_colour(self, r, g, b, nowait=False):
        """Set bulb RGB colour"""
        return self._runner.run(self._async_impl.set_colour(r, g, b, nowait))

    def set_hsv(self, h, s, v, nowait=False):
        """Set bulb HSV colour"""
        return self._runner.run(self._async_impl.set_hsv(h, s, v, nowait))

    def set_white_percentage(self, brightness=100, colourtemp=0, nowait=False):
        """Set white mode with percentage values"""
        return self._runner.run(self._async_impl.set_white_percentage(brightness, colourtemp, nowait))

    def set_white(self, brightness=-1, colourtemp=-1, nowait=False):
        """Set white mode with absolute values"""
        return self._runner.run(self._async_impl.set_white(brightness, colourtemp, nowait))

    def set_brightness_percentage(self, brightness=100, nowait=False):
        """Set brightness as percentage"""
        return self._runner.run(self._async_impl.set_brightness_percentage(brightness, nowait))

    def set_brightness(self, brightness, nowait=False):
        """Set brightness as absolute value"""
        return self._runner.run(self._async_impl.set_brightness(brightness, nowait))

    def set_colourtemp_percentage(self, colourtemp=100, nowait=False):
        """Set colour temperature as percentage"""
        return self._runner.run(self._async_impl.set_colourtemp_percentage(colourtemp, nowait))

    def set_colourtemp(self, colourtemp, nowait=False):
        """Set colour temperature as absolute value"""
        return self._runner.run(self._async_impl.set_colourtemp(colourtemp, nowait))

    # ---- Bulb Property/Query Methods ----

    def get_value(self, feature, state=None, nowait=False):
        """Get bulb feature value"""
        return self._runner.run(self._async_impl.get_value(feature, state, nowait))

    def get_mode(self, state=None, nowait=False):
        """Get current bulb mode"""
        return self._runner.run(self._async_impl.get_mode(state, nowait))

    def white_percentage(self, state=None, nowait=False):
        """Get white percentage values"""
        return self._runner.run(self._async_impl.white_percentage(state, nowait))

    def get_brightness_percentage(self, state=None, nowait=False):
        """Get brightness as percentage"""
        return self._runner.run(self._async_impl.get_brightness_percentage(state, nowait))

    def brightness(self, state=None, nowait=False):
        """Get brightness absolute value"""
        return self._runner.run(self._async_impl.brightness(state, nowait))

    def get_colourtemp_percentage(self, state=None, nowait=False):
        """Get colour temperature as percentage"""
        return self._runner.run(self._async_impl.get_colourtemp_percentage(state, nowait))

    def colourtemp(self, state=None, nowait=False):
        """Get colour temperature absolute value"""
        return self._runner.run(self._async_impl.colourtemp(state, nowait))

    def colour_rgb(self, state=None, nowait=False):
        """Get RGB colour values"""
        return self._runner.run(self._async_impl.colour_rgb(state, nowait))

    def colour_hsv(self, state=None, nowait=False):
        """Get HSV colour values"""
        return self._runner.run(self._async_impl.colour_hsv(state, nowait))

    def bulb_has_capability(self, capability, nowait=False):
        """Check if bulb has specific capability"""
        return self._runner.run(self._async_impl.bulb_has_capability(capability, nowait))

    # ---- Configuration Methods (inherited from XenonDevice) ----
    # These methods are missing because BulbDevice doesn't call super().__init__()

    def set_version(self, version):
        """Set protocol version"""
        self._async_impl.set_version(version)

    def set_socketPersistent(self, persist):
        """Set socket persistence"""
        self._async_impl.set_socketPersistent(persist)

    def set_socketNODELAY(self, nodelay):
        """Set socket NODELAY option"""
        self._async_impl.set_socketNODELAY(nodelay)

    def set_socketTimeout(self, timeout):
        """Set socket timeout"""
        self._async_impl.set_socketTimeout(timeout)

    def set_sendWait(self, wait_time):
        """Set send wait time"""
        self._async_impl.set_sendWait(wait_time)

    def set_dpsUsed(self, dps_to_request):
        """Set DPS values to request"""
        self._async_impl.set_dpsUsed(dps_to_request)

    def set_retry(self, retry):
        """Set retry flag"""
        self._async_impl.set_retry(retry)
