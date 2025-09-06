# TinyTuya Bulb Device
# -*- coding: utf-8 -*-
"""
 TinyTuya - Bulb Device Wrapper

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 This is a thin wrapper that provides the original synchronous interface
 while delegating all work to the async implementation using AsyncRunner.
"""

from .BulbDeviceAsync import BulbDeviceAsync
from .core import AsyncRunner


class BulbDevice(object):
    """
    Synchronous wrapper for BulbDeviceAsync.
    
    This class provides the same interface as the original BulbDevice class
    but delegates all operations to BulbDeviceAsync using AsyncRunner.
    """

    def __init__(self, *args, **kwargs):
        self._async_impl = BulbDeviceAsync(*args, **kwargs)
        self._runner = AsyncRunner()

    def __getattr__(self, name):
        """Forward attribute access to the async device."""
        attr = getattr(self._async_impl, name)
        return attr

    def __setattr__(self, name, value):
        if name in ['_async_impl', '_runner']:
            object.__setattr__(self, name, value)
        else:
            setattr(self._async_impl, name, value)

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

    # Synchronous method wrappers
    def status(self, nowait=False):
        return self._runner.run(self._async_impl.status(nowait))

    def turn_on(self, switch=0, nowait=False):
        return self._runner.run(self._async_impl.turn_on(switch, nowait))

    def turn_off(self, switch=0, nowait=False):
        return self._runner.run(self._async_impl.turn_off(switch, nowait))

    def turn_onoff(self, on, switch=0, nowait=False):
        return self._runner.run(self._async_impl.turn_onoff(on, switch, nowait))

    def set_mode(self, mode="white", nowait=False):
        return self._runner.run(self._async_impl.set_mode(mode, nowait))

    def set_scene(self, scene, scene_data=None, nowait=False):
        return self._runner.run(self._async_impl.set_scene(scene, scene_data, nowait))

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        return self._runner.run(self._async_impl.set_timer(num_secs, dps_id, nowait))

    def set_music_colour(self, transition, red, green, blue, brightness=None, colourtemp=None, nowait=False):
        return self._runner.run(self._async_impl.set_music_colour(transition, red, green, blue, brightness, colourtemp, nowait))

    def set_colour(self, r, g, b, nowait=False):
        return self._runner.run(self._async_impl.set_colour(r, g, b, nowait))

    def set_hsv(self, h, s, v, nowait=False):
        return self._runner.run(self._async_impl.set_hsv(h, s, v, nowait))

    def set_white_percentage(self, brightness=100, colourtemp=0, nowait=False):
        return self._runner.run(self._async_impl.set_white_percentage(brightness, colourtemp, nowait))

    def set_white(self, brightness=-1, colourtemp=-1, nowait=False):
        return self._runner.run(self._async_impl.set_white(brightness, colourtemp, nowait))

    def set_brightness_percentage(self, brightness=100, nowait=False):
        return self._runner.run(self._async_impl.set_brightness_percentage(brightness, nowait))

    def set_brightness(self, brightness, nowait=False):
        return self._runner.run(self._async_impl.set_brightness(brightness, nowait))

    def set_colourtemp_percentage(self, colourtemp=100, nowait=False):
        return self._runner.run(self._async_impl.set_colourtemp_percentage(colourtemp, nowait))

    def set_colourtemp(self, colourtemp, nowait=False):
        return self._runner.run(self._async_impl.set_colourtemp(colourtemp, nowait))

    # Property methods that don't need async conversion
    def get_value(self, feature, state=None, nowait=False):
        return self._async_impl.get_value(feature, state, nowait)

    def get_mode(self, state=None, nowait=False):
        return self._async_impl.get_mode(state, nowait)

    def white_percentage(self, state=None, nowait=False):
        return self._async_impl.white_percentage(state, nowait)

    def get_brightness_percentage(self, state=None, nowait=False):
        return self._async_impl.get_brightness_percentage(state, nowait)

    def brightness(self, state=None, nowait=False):
        return self._async_impl.brightness(state, nowait)

    def get_colourtemp_percentage(self, state=None, nowait=False):
        return self._async_impl.get_colourtemp_percentage(state, nowait)

    def colourtemp(self, state=None, nowait=False):
        return self._async_impl.colourtemp(state, nowait)

    def colour_rgb(self, state=None, nowait=False):
        return self._async_impl.colour_rgb(state, nowait)

    def colour_hsv(self, state=None, nowait=False):
        return self._async_impl.colour_hsv(state, nowait)

    def bulb_has_capability(self, capability, nowait=False):
        return self._async_impl.bulb_has_capability(capability, nowait)
