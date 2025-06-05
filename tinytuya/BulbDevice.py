# TinyTuya Bulb Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    BulbDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    BulbDevice Class methods
        rgb_to_hexvalue(r, g, b, hexformat):
        hsv_to_hexvalue(h, s, v, hexformat):
        hexvalue_to_rgb(hexvalue, hexformat=None):
        hexvalue_to_hsv(hexvalue, hexformat=None):

    BulbDevice
        set_mode(self, mode="white", nowait=False):
        set_scene(self, scene, scene_data=None, nowait=False):
        set_timer(self, num_secs, nowait=False):
        set_musicmode(self, transition, modify_settings=True, nowait=False):
        unset_musicmode( self ):
        set_music_colour( self, red, green, blue, brightness=None, colourtemp=None, transition=None, nowait=False ):
        set_colour(r, g, b, nowait):
        set_hsv(h, s, v, nowait):
        set_white_percentage(brightness=100, colourtemp=0, nowait):
        set_brightness_percentage(brightness=100, nowait):
        set_colourtemp_percentage(colourtemp=100, nowait):
        result = get_value(self, feature, state=None, nowait=False):
        result = get_mode(self, state=None, nowait=False):
        result = get_brightness_percentage(self, state=None, nowait=False):
        result = get_colourtemp_percentage(self, state=None, nowait=False):
        (r, g, b) = colour_rgb():
        (h,s,v) = colour_hsv()
        result = state():
        bool = bulb_has_capability( self, feature, nowait=False ):
        detect_bulb(self, response=None, nowait=False):
        set_bulb_type(self, bulb_type=None, mapping=None):
        set_bulb_capabilities(self, mapping):

    Inherited
        Every device function from core.py
"""

import colorsys

from .core import Device, log
from .core import error_json, ERR_JSON, ERR_FUNCTION # ERR_RANGE, ERR_STATE, ERR_TIMEOUT

# pylint: disable=R0904
class BulbDevice(Device):
    """
    Represents a Tuya based Smart Light/Bulb.
    """

    DPS_MODE_WHITE = "white"
    DPS_MODE_COLOUR = "colour"
    DPS_MODE_SCENE = "scene"
    DPS_MODE_MUSIC = "music"
    DPS_MODE_SCENE_1 = "scene_1"  # nature
    DPS_MODE_SCENE_2 = "scene_2"
    DPS_MODE_SCENE_3 = "scene_3"  # rave
    DPS_MODE_SCENE_4 = "scene_4"  # rainbow

    BULB_FEATURE_MODE = 'mode'
    BULB_FEATURE_BRIGHTNESS = 'brightness'
    BULB_FEATURE_COLOURTEMP = 'colourtemp'
    BULB_FEATURE_COLOUR = 'colour'
    BULB_FEATURE_SCENE = 'scene'
    BULB_FEATURE_SCENE_DATA = 'scene_data'
    BULB_FEATURE_TIMER = 'timer'
    BULB_FEATURE_MUSIC = 'music'

    MUSIC_TRANSITION_JUMP = 0
    MUSIC_TRANSITION_FADE = 1

    DEFAULT_DPSET = {}
    DEFAULT_DPSET['A'] = {
        'switch': 1,
        'mode': 2,
        'brightness': 3,
        'colourtemp': 4,
        'colour': 5,
        'scene': 6,
        'scene_data': None, # Type A sets mode to 'scene_N'
        'timer': 7,
        'music': 8,
        'value_min': 25,
        'value_max': 255,
        'value_hexformat': 'rgb8',
    }
    DEFAULT_DPSET['B'] = {
        'switch': 20,
        'mode': 21,
        'brightness': 22,
        'colourtemp': 23,
        'colour': 24,
        'scene': 25,
        'scene_data': 25, # Type B prefixes scene data with idx
        'timer': 26,
        'music': 28,
        'value_min': 10,
        'value_max': 1000,
        'value_hexformat': 'hsv16',
    }
    DEFAULT_DPSET['C'] = {
        'switch': 1,
        'mode': None,
        'brightness': 2,
        'colourtemp': 3,
        'colour': None,
        'scene': None,
        'scene_data': None,
        'timer': None,
        'music': None,
        'value_min': 25,
        'value_max': 255,
        'value_hexformat': 'rgb8',
    }
    DEFAULT_DPSET['None'] = {
        'switch': 1,
        'mode': None,
        'brightness': None,
        'colourtemp': None,
        'colour': None,
        'scene': None,
        'scene_data': None,
        'timer': None,
        'music': None,
        'value_min': 0,
        'value_max': 255,
        'value_hexformat': 'rgb8',
    }


    # These attributes are obsolete and only kept for backwards compatibility
    DPS_INDEX_SETS = [20, 1] # starts at either DP 20 (Type B) or 1 (all others)
    DPS_INDEX_ON = {"A": "1", "B": "20", "C": "1"}
    DPS_INDEX_MODE = {"A": "2", "B": "21", "C": "1"}
    DPS_INDEX_BRIGHTNESS = {"A": "3", "B": "22", "C": "2"}
    DPS_INDEX_COLOURTEMP = {"A": "4", "B": "23", "C": None}
    DPS_INDEX_COLOUR = {"A": "5", "B": "24", "C": None}
    DPS_INDEX_SCENE = {"A": "2", "B": "25", "C": None}
    DPS_INDEX_TIMER = {"A": None, "B": "26", "C": None}
    DPS_INDEX_MUSIC = {"A": None, "B": "27", "C": None}
    DPS = "dps"

    def __init__(self, *args, **kwargs):
        # Set Default Bulb Types
        self.bulb_configured = False
        self.bulb_type = None
        self.has_brightness = None
        self.has_colourtemp = None
        self.has_colour = None
        self.tried_status = False
        self.dpset = {
            'switch': None,
            'mode': None,
            'brightness': None,
            'colourtemp': None,
            'colour': None,
            'scene': None,
            'scene_data': None,
            'timer': None,
            'music': None,
            'value_min': -1,
            'value_max': -1,
            'value_hexformat': 'hsv16',
        }

        # set the default version to None so we do not immediately connect and call status()
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = None
        super(BulbDevice, self).__init__(*args, **kwargs)

    def status(self, nowait=False):
        result = super(BulbDevice, self).status(nowait=nowait)
        self.tried_status = True
        if result and (not self.bulb_configured) and ('dps' in result):
            self.detect_bulb(result, nowait=nowait)
        return result

    @staticmethod
    def rgb_to_hexvalue(r, g, b, hexformat):
        """
        Convert an RGB value to the hex representation expected by Tuya Bulb.

        While r, g and b are just hexadecimal values of the corresponding
        Red, Green and Blue values, the h, s and v values (which are values
        between 0 and 1) are scaled:
            hexformat="rgb8": 360 (h) and 255 (s and v)
            hexformat="hsv16": 360 (h) and 1000 (s and v)

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
            hexformat(str): Selects the return format
                "rgb8": rrggbb0hhhssvv
                "hsv16": hhhhssssvvvv
        """
        err = ''
        if not 0 <= r <= 255.0:
            err += '/red'
        if not 0 <= g <= 255.0:
            err += '/green'
        if not 0 <= b <= 255.0:
            err += '/blue'
        if err:
            raise ValueError('rgb_to_hexvalue: The value for %s needs to be between 0 and 255.' % err[1:])

        hsv = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)

        if hexformat == 'rgb8':
            # r:0-255,g:0-255,b:0-255|rgb|
            hexvalue = '%02x%02x%02x' % (r, g, b)
            # h:0-360,s:0-255,v:0-255|hsv|
            hexvalue += '%04x%02x%02x' % (int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255))
        elif hexformat == 'hsv16':
            # h:0-360,s:0-1000,v:0-1000|hsv|
            hexvalue = '%04x%04x%04x' % (int(hsv[0] * 360), int(hsv[1] * 1000), int(hsv[2] * 1000))
        else:
            raise ValueError('rgb_to_hexvalue: hexformat must be either "rgb8" or "hsv16"')

        return hexvalue

    # Deprecated. Kept for backwards compatibility
    @staticmethod
    def _rgb_to_hexvalue(r, g, b, bulb="A"):
        if bulb == "A":
            hexformat = 'rgb8'
        elif bulb == "B":
            hexformat = 'hsv16'
        else:
            # Unsupported bulb type
            raise ValueError("Unsupported bulb type %r - unable to determine hexvalue." % bulb)

        return BulbDevice.rgb_to_hexvalue(r, g, b, hexformat)

    @staticmethod
    def hsv_to_hexvalue(h, s, v, hexformat):
        """
        Convert an HSV value to the hex representation expected by Tuya Bulb.

        Args:
            h(float): colour Hue as float from 0-1
            s(float): colour Saturation as float from 0-1
            v(float): colour Value as float from 0-1
            hexformat(str): Selects the return format
                "rgb8": rrggbb0hhhssvv
                "hsv16": hhhhssssvvvv
        """
        err = ''
        if not 0 <= h <= 1.0:
            err += '/Hue'
        if not 0 <= s <= 1.0:
            err += '/Saturation'
        if not 0 <= v <= 1.0:
            err += '/Value'

        if err:
            raise ValueError( 'hsv_to_hexvalue: The value for %s needs to be between 0 and 1.' % err[1:])

        if hexformat == 'rgb8':
            (r, g, b) = colorsys.hsv_to_rgb(h, s, v)
            return BulbDevice.rgb_to_hexvalue( r * 255.0, g * 255.0, b * 255.0, hexformat )
        elif hexformat == 'hsv16':
            # h:0-360,s:0-1000,v:0-1000|hsv|
            hexvalue = '%04x%04x%04x' % (int(h * 360), int(s * 1000), int(v * 1000))
            return hexvalue
        else:
            raise ValueError('hsv_to_hexvalue: hexformat must be either "rgb8" or "hsv16"')

    @staticmethod
    def hexvalue_to_rgb(hexvalue, hexformat=None):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an RGB value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice.rgb_to_hexvalue()
            hexformat(str or None):
                "rgb8": The hex is in rrggbb0hhhssvv format
                "hsv16": The hex is in hhhhssssvvvv format
                None: Try to auto-detect the format
        """
        hexvalue_len = len(hexvalue)
        if not hexformat:
            if hexvalue_len == 6 or hexvalue_len == 14:
                hexformat = 'rgb8'
            elif hexvalue_len == 12:
                hexformat = 'hsv16'
            else:
                # Unsupported bulb type
                raise ValueError("Unable to detect hexvalue format. Value string must have 6, 12 or 14 hex digits.")

        if hexformat == 'rgb8':
            if hexvalue_len < 6:
                raise ValueError("RGB value string must have 6 or 14 hex digits.")
            r = int(hexvalue[0:2], 16)
            g = int(hexvalue[2:4], 16)
            b = int(hexvalue[4:6], 16)
        elif hexformat == 'hsv16':
            # hexvalue is in hsv
            if hexvalue_len < 12:
                raise ValueError("HSV value string must have 12 hex digits.")
            h = float(int(hexvalue[0:4], 16) / 360.0)
            s = float(int(hexvalue[4:8], 16) / 1000.0)
            v = float(int(hexvalue[8:12], 16) / 1000.0)
            rgb = colorsys.hsv_to_rgb(h, s, v)
            r = int(rgb[0] * 255)
            g = int(rgb[1] * 255)
            b = int(rgb[2] * 255)
        else:
            raise ValueError('hexvalue_to_rgb: hexformat must be None, "rgb8" or "hsv16"')

        return (r, g, b)

    # Deprecated. Kept for backwards compatibility
    @staticmethod
    def _hexvalue_to_rgb(hexvalue, bulb="A"):
        if bulb == "A":
            hexformat = 'rgb8'
        elif bulb == "B":
            hexformat = 'hsv16'
        else:
            # Unsupported bulb type, attempt to auto-detect format
            hexformat = None
        return BulbDevice.hexvalue_to_rgb(hexvalue, hexformat)

    @staticmethod
    def hexvalue_to_hsv(hexvalue, hexformat=None):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an HSV value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice.rgb_to_hexvalue()
            hexformat(str or None):
                "rgb8": The hex is in rrggbb0hhhssvv format
                "hsv16": The hex is in hhhhssssvvvv format
                None: Try to auto-detect the format
        """
        hexvalue_len = len(hexvalue)
        if not hexformat:
            if hexvalue_len == 6 or hexvalue_len == 14:
                hexformat = 'rgb8'
            elif hexvalue_len == 12:
                hexformat = 'hsv16'
            else:
                # Unsupported bulb type
                raise ValueError("Unable to detetect hexvalue format. Value string must have 6, 12 or 14 hex digits.")

        if hexformat == 'rgb8':
            if hexvalue_len < 6:
                raise ValueError("RGB[HSV] value string must have 6 or 14 hex digits.")
            if hexvalue_len < 14:
                # hexvalue is in rgb
                rgb = BulbDevice.hexvalue_to_rgb(hexvalue, 'rgb8')
                h, s, v = colorsys.rgb_to_hsv(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0)
            else:
                # hexvalue is in rgb+hsv
                h = int(hexvalue[7:10], 16) / 360.0
                s = int(hexvalue[10:12], 16) / 255.0
                v = int(hexvalue[12:14], 16) / 255.0
        elif hexformat == 'hsv16':
            # hexvalue is in hsv
            if hexvalue_len < 12:
                raise ValueError("HSV value string must have 12 hex digits.")
            h = int(hexvalue[0:4], 16) / 360.0
            s = int(hexvalue[4:8], 16) / 1000.0
            v = int(hexvalue[8:12], 16) / 1000.0
        else:
            raise ValueError('hexvalue_to_hsv: hexformat must be None, "rgb8" or "hsv16"')

        return (h, s, v)

    # Deprecated. Kept for backwards compatibility
    @staticmethod
    def _hexvalue_to_hsv(hexvalue, bulb="A"):
        if bulb == "A":
            hexformat = 'rgb8'
        elif bulb == "B":
            hexformat = 'hsv16'
        else:
            # Unsupported bulb type, attempt to auto-detect format
            hexformat = None
        return BulbDevice.hexvalue_to_hsv(hexvalue, hexformat)

    def _set_values_check( self, check_values, nowait=False ):
        dps_values = {}

        # check to see which DPs need to be set
        state = self.cached_status(nowait=nowait)
        if state and 'dps' in state and state['dps']:
            # last state is cached, so check to see if 'mode' needs to be set
            for k in check_values:
                dp = self.dpset[k]
                if dp and ((dp not in state['dps']) or (state['dps'][dp] != check_values[k])):
                    dps_values[dp] = check_values[k]
                elif not dp:
                    log.debug('Device does not support capability, skipping: %r:%r', k, check_values[k])

        if dps_values:
            log.debug('Only sending changed DPs: %r', dps_values)
        else:
            # last state not cached or everything already set, so send them all
            for k in check_values:
                if self.dpset[k]:
                    dps_values[self.dpset[k]] = check_values[k]
                else:
                    log.debug('Device does not support capability, skipping: %r:%r', k, check_values[k])
            log.debug('No DPs have changed, sending full update to refresh: %r', dps_values)

        return self.set_multiple_values( dps_values, nowait=nowait )

    def turn_onoff(self, on, switch=0, nowait=False):
        """Turn the device on or off"""
        if not switch:
            if not self.tried_status:
                self.detect_bulb( nowait=nowait )
            # some people may use BulbDevice as the default even for non-bulb
            #   devices, so default to '1' if we can't detect it
            switch = self.dpset['switch'] if self.dpset['switch'] else 1
        return self.set_status(on, switch, nowait=nowait)

    def turn_on(self, switch=0, nowait=False):
        """Turn the device on"""
        return self.turn_onoff( True, switch=switch, nowait=nowait )

    def turn_off(self, switch=0, nowait=False):
        """Turn the device off"""
        return self.turn_onoff( False, switch=switch, nowait=nowait )

    def set_mode(self, mode="white", nowait=False):
        """
        Set bulb mode

        Args:
            mode(string): white,colour,scene,music
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( 'mode', nowait=nowait ):
            return error_json(ERR_FUNCTION, 'Bulb does not support mode setting.')

        check_values = {
            'mode': mode,
            'switch': True,
        }

        return self._set_values_check( check_values, nowait=nowait )

    def set_scene(self, scene, scene_data=None, nowait=False):
        """
        Set to scene mode

        Args:
            scene(int): Value for the scene as int from 1-4 (Type A bulbs) or 1-N (Type B bulbs).
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( 'scene', nowait=nowait ):
            return error_json(ERR_FUNCTION, 'set_scene: Bulb does not support scenes.')

        # Type A, scene idx is part of the mode
        if (not self.dpset['scene_data']) or (self.dpset['scene_data'] == self.dpset['mode']):
            if (not 1 <= scene <= 4):
                raise ValueError('set_scene: The value for scene needs to be between 1 and 4.')
            dps_values = {
                self.dpset['mode']: self.DPS_MODE_SCENE + '_' + str(scene)
            }
        else:
            scene = '%02x' % int(scene)
            dps_values = {
                'scene': scene,
                'mode': self.DPS_MODE_SCENE,
            }

            if scene_data:
                if (self.dpset['scene_data'] is True) or (self.dpset['scene_data'] == self.dpset['scene']):
                    dps_values['scene'] += scene_data
                else:
                    dps_values['scene_data'] = scene_data

        return self._set_values_check( dps_values, nowait=nowait )

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        """
        Set the timer

        Args:
            num_secs: data to send to bulb
            dps_id: do not use, kept for compatibility with Device.set_timer()
        """
        if dps_id:
            return self.set_value(dps_id, num_secs, nowait=nowait)

        if not self.bulb_has_capability( 'timer', nowait=nowait ):
            return error_json(ERR_FUNCTION, 'set_timer: Bulb does not support timer.')
        return self.set_value(self.dpset['timer'], num_secs, nowait=nowait)

    def set_music_colour( self, transition, red, green, blue, brightness=None, colourtemp=None, nowait=False ):
        """
        Set a colour while in music mode

        Args:
            red(float): red value, 0.0 - 255.0
            green(float): green value, 0.0 - 255.0
            blue(float): blue value, 0.0 - 255.0
            brightness(float): optional white light brightness
            colourtemp(float): optional white light colourtemp
            transition(int): optional transition. will use transition provided in set_musicmode() if not provided
        """
        if not self.bulb_has_capability( 'music', nowait=nowait ):
            return error_json(ERR_FUNCTION, "set_music_colour: Device does not support music mode.")

        colour = '%x' % transition
        colour += self.rgb_to_hexvalue( red, green, blue, self.dpset['value_hexformat'] )

        if (not brightness) or (brightness < 0):
            brightness = 0
        brightness = int(self.dpset['value_max'] * brightness // 100)

        if (not colourtemp) or (colourtemp < 0):
            colourtemp = 0
        colourtemp = int(self.dpset['value_max'] * colourtemp // 100)

        fmt = '%02x' if self.dpset['value_hexformat'] == 'rgb8' else '%04x'
        colour += fmt % brightness
        colour += fmt % colourtemp

        return self.set_value(self.dpset['music'], colour, nowait=nowait)

    def set_colour(self, r, g, b, nowait=False):
        """
        Set colour of an rgb bulb.

        Args:
            r(float): Value for the colour Red from 0.0-255.0.
            g(float): Value for the colour Green from 0.0-255.0.
            b(float): Value for the colour Blue from 0.0-255.0.
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( 'colour', nowait=nowait ):
            return error_json(ERR_FUNCTION, "set_colour: Device does not support color.")

        check_values = {
            'colour': self.rgb_to_hexvalue(r, g, b, self.dpset['value_hexformat']),
            'mode': self.DPS_MODE_COLOUR,
            'switch': True
        }

        return self._set_values_check( check_values, nowait=nowait )

    def set_hsv(self, h, s, v, nowait=False):
        """
        Set colour of an rgb bulb using h, s, v.

        Args:
            h(float): colour Hue as float from 0-1
            s(float): colour Saturation as float from 0-1
            v(float): colour Value as float from 0-1
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( 'colour', nowait=nowait ):
            return error_json(ERR_FUNCTION, "set_colour: Device does not support color.")

        check_values = {
            'colour': self.hsv_to_hexvalue( h, s, v, self.dpset['value_hexformat'] ),
            'mode': self.DPS_MODE_COLOUR,
            'switch': True
        }
        return self._set_values_check( check_values, nowait=nowait )

    def set_white_percentage(self, brightness=100, colourtemp=0, nowait=False):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            colourtemp(int): Value for the colour temperature in percent (0-100)
            nowait(bool): True to send without waiting for response.

        Note: unlike set_colourtemp(), the colour temp will be silently ignored if the bulb does not support it
        """
        err = ''
        if not 0 <= brightness <= 100:
            err += '/Brightness'
        if not 0 <= colourtemp <= 100:
            err += '/Colourtemp'
        if err:
            raise ValueError( 'set_white_percentage: %s percentage needs to be between 0 and 100.' % err[1:])

        b = int(self.dpset['value_max'] * brightness // 100)
        c = int(self.dpset['value_max'] * colourtemp // 100)

        return self.set_white( b, c, nowait=nowait )

    # Deprecated.  Please use set_white_percentage() instead.
    def set_white(self, brightness=-1, colourtemp=-1, nowait=False):
        """
        DEPRECATED Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (A:25-255 or B:10-1000)
            colourtemp(int): Value for the colour temperature (A:0-255, B:0-1000).
            nowait(bool): True to send without waiting for response.

            Default: Max Brightness and Min Colourtemp

        Note: unlike set_colourtemp(), the colour temp will be silently ignored if the bulb does not support it
        """
        if not self.bulb_has_capability( 'brightness', nowait=nowait ):
            return error_json(ERR_FUNCTION, 'set_white: Device does not support brightness.')

        # Brightness (default: Max)
        brightness = int(brightness)
        if brightness < 0:
            brightness = self.dpset['value_max']
        elif brightness > self.dpset['value_max']:
            raise ValueError('set_white: The brightness needs to be between %d and %d.' % (self.dpset['value_min'], self.dpset['value_max']))

        # Colourtemp (default: Min)
        # It will be silently ignored if the bulb does not support it
        if colourtemp is not None:
            colourtemp = int(colourtemp)
            if colourtemp < 0:
                colourtemp = 0
            if colourtemp > self.dpset['value_max']:
                raise ValueError('set_white: The colour temperature needs to be between 0 and %d.' % self.dpset['value_max'])

        # do this the hard way as brightness=0 means we should turn off, but if colourtemp is set then
        #   turn_on() should turn it on at that colourtemp
        check_values = {}
        if brightness >= self.dpset['value_min']:
            check_values['brightness'] = brightness
        if colourtemp is not None:
            check_values['colourtemp'] = colourtemp
        if check_values:
            # we're setting brightness and/or colourtemp
            check_values['mode'] = self.DPS_MODE_WHITE
        check_values['switch'] = bool(brightness >= self.dpset['value_min'])

        # _set_values_check() will skip colourtemp if the bulb does not have it
        return self._set_values_check( check_values, nowait=nowait )

    def set_brightness_percentage(self, brightness=100, nowait=False):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            nowait(bool): True to send without waiting for response.
        """
        if not 0 <= brightness <= 100:
            raise ValueError('set_brightness_percentage: The brightness needs to be between 0 and 100.')
        b = int(self.dpset['value_max'] * brightness // 100)
        return self.set_brightness(b, nowait=nowait)

    # Deprecated.  Please use set_brightness_percentage() instead.
    def set_brightness(self, brightness, nowait=False):
        """
        DEPRECATED Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( 'brightness', nowait=nowait ):
            return error_json(ERR_FUNCTION, 'set_brightness: Device does not support brightness.')

        # Brightness (default Max)
        if brightness < 0:
            brightness = self.dpset['value_max']
        elif brightness < self.dpset['value_min']:
            return self.turn_off(0, nowait=nowait)
        elif brightness > self.dpset['value_max']:
            raise ValueError('set_brightness: The brightness needs to be between %d and %d.' % (self.dpset['value_min'], self.dpset['value_max']))

        # Determine which mode bulb is in and adjust accordingly
        state = self.state(nowait=nowait)

        if ('Error' in state) or ('mode' not in state):
            return state

        if state['mode'] != self.DPS_MODE_COLOUR:
            # use white mode, changing to it if needed
            return self.set_white(brightness=brightness, colourtemp=None, nowait=nowait)
        else:
            # for colour mode use hsv to increase brightness
            value = brightness / float(self.dpset['value_max'])
            (h, s, v) = self.colour_hsv(state=state, nowait=nowait)
            return self.set_hsv(h, s, value, nowait=nowait)

    def set_colourtemp_percentage(self, colourtemp=100, nowait=False):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature in percentage (0-100).
            nowait(bool): True to send without waiting for response.
        """
        if not 0 <= colourtemp <= 100:
            raise ValueError( 'set_colourtemp_percentage: Colourtemp percentage needs to be between 0 and 100.')
        c = int(self.dpset['value_max'] * colourtemp // 100)
        return self.set_colourtemp( c, nowait=nowait )

    # Deprecated.  Please use set_white_percentage() instead.
    def set_colourtemp(self, colourtemp, nowait=False):
        """
        DEPRECATED Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_has_capability( self.BULB_FEATURE_COLOURTEMP, nowait=nowait ):
            return error_json(ERR_FUNCTION, 'set_colourtemp: Device does not support colourtemp.')

        if not 0 <= colourtemp <= self.dpset['value_max']:
            raise ValueError('set_colourtemp: The colour temperature needs to be between 0 and %d.' % self.dpset['value_max'])

        check_values = {
            'colourtemp': colourtemp,
            'mode': self.DPS_MODE_WHITE,
            'switch': True,
        }

        return self._set_values_check( check_values, nowait=nowait )

    def get_value(self, feature, state=None, nowait=False):
        if not state:
            state = self.state(nowait=nowait)
        if 'Error' in state:
            raise RuntimeError('Error getting device current state.')
        if feature not in state:
            raise ValueError("Unknown parameter %r." % feature)
        return state[feature]

    def get_mode(self, state=None, nowait=False):
        """Return current working mode"""
        return self.get_value('mode', state=state, nowait=nowait)

    def white_percentage(self, state=None, nowait=False):
        if not state:
            state = self.state(nowait=nowait)
        return (self.brightness_percentage(state=state, nowait=nowait), self.colourtemp_percentage(state=state, nowait=nowait))

    #def white(self, state=None, nowait=False):
    #    pass

    def get_brightness_percentage(self, state=None, nowait=False):
        if (not self.dpset['value_max']) or (self.dpset['value_max'] < 1):
            raise RuntimeError("Bulb capabilitiy 'value_max' not set, unable to calculate percentage.")
        return self.brightness(state=state, nowait=nowait) / self.dpset['value_max'] * 100.0

    def brightness(self, state=None, nowait=False):
        """Return brightness value"""
        return self.get_value('brightness', state=state, nowait=nowait)

    def get_colourtemp_percentage(self, state=None, nowait=False):
        if (not self.dpset['value_max']) or (self.dpset['value_max'] < 1):
            raise RuntimeError("Bulb capabilitiy 'value_max' not set, unable to calculate percentage.")
        return self.colourtemp(state=state, nowait=nowait) / self.dpset['value_max'] * 100.0

    def colourtemp(self, state=None, nowait=False):
        """Return colour temperature"""
        return self.get_value('colourtemp', state=state, nowait=nowait)

    def colour_rgb(self, state=None, nowait=False):
        """Return colour as RGB value"""
        hexvalue = self.get_value('colour', state=state, nowait=nowait)
        if isinstance( hexvalue, dict ):
            return hexvalue # Error
        return BulbDevice.hexvalue_to_rgb(hexvalue, self.dpset['value_hexformat'])

    def colour_hsv(self, state=None, nowait=False):
        """Return colour as HSV value"""
        hexvalue = self.get_value('colour', state=state, nowait=nowait)
        if isinstance( hexvalue, dict ):
            return hexvalue # Error
        return BulbDevice.hexvalue_to_hsv(hexvalue, self.dpset['value_hexformat'])

    def state(self, nowait=False):
        """Return state of Bulb"""
        if not self.bulb_configured:
            self.detect_bulb(nowait=nowait)
            if not self.bulb_configured:
                raise RuntimeError('Bulb not configured, cannot get device current state.')

        status = self.cached_status(nowait=nowait)
        state = {}
        if not status:
            return error_json(ERR_JSON, "state: empty response")

        if "Error" in status:
            return error_json(ERR_JSON, status["Error"])

        if 'dps' not in status:
            return error_json(ERR_JSON, "state: no data points")

        for key in self.dpset:
            dp = self.dpset[key]
            if '_' in key:
                # skip scene_data, value_min, value_max, etc
                state[key] = None
            elif dp in status['dps']:
                state[key] = status['dps'][dp]
            else:
                state[key] = None

        if 'switch' in state:
            state['is_on'] = state['switch']

        #print( 'state:', state )
        return state

    def bulb_has_capability( self, feature, nowait=False ):
        if not self.bulb_configured:
            self.detect_bulb( nowait=nowait )
            if not self.bulb_configured:
                raise RuntimeError('Bulb not configured, cannot get device capabilities.')
        return bool( self.dpset[feature] )

    def detect_bulb(self, response=None, nowait=False):
        """
        Attempt to determine BulbDevice Type A, B or C based on:
            Type A has keys 1-9
            Type B has keys 20-28
            Type C is basic (non-CCT) and only has 1-2 (i.e Feit type bulbs from Costco)

        Example status data:
          Sylvania BR30 [v3.3, RGB+CCT]:
            {'20': True, '21': 'colour', '22': 750, '23': 278, '24': '00f003e803e8', '25': '000e0d0000000000000000c803e8', '26': 0}

          Geeni BW229 Smart Filament Bulb [v3.3, CCT only]:
            {'1': True, '2': 25, '3': 0}
            1: switch, 2: brightness, 3: colour temperature

          No-name RGB+CCT (LED BULB W5K) [v3.5, RGB+CCT]:
            {'20': True, '21': 'white', '22': 10, '23': 0, '24': '000003e803e8', '25': '000e0d0000000000000000c80000', '26': 0, '34': False}

          Feit soft white Filament [v3.5, 2700K only]:
            {'20': True, '21': 'white', '22': 60, '25': '000e0d0000000000000000c803e8', '26': 0, '34': False, '41': True}
            (No CCT (23) or colour (24), but does support scenes (25) and music mode (28))

          Feit dimmer switch [v3.3, not a bulb]:
            {'1': True, '2': 10, '3': 10, '4': 'incandescent'}
            Note: after a power cycle, only DP 2 is returned!  The rest are not returned until after they are set
            1: switch, 2: brightness, 3: minimum dim %, 4: installed bulb type (LED/incandescent)
        """
        if not response:
            response = self.cached_status(historic=True, nowait=nowait)
            if (not response) or ('dps' not in response):
                if nowait:
                    log.debug('No cached status, but nowait set! detect_bulb() exiting without detecting bulb!')
                else:
                    response = self.status()
                # return here as self.status() will call us again
                return
        if response and 'dps' in response and isinstance(response['dps'], dict):
            # Try to determine type of BulbDevice Type based on DPS indexes
            # 1+2 or 20+21 are required per https://developer.tuya.com/en/docs/iot/product-function-definition?id=K9tp155s4th6b
            #   The rest are optional
            if '20' in response['dps'] and '1' in response['dps']:
                # both 1 and 20 in response, this probably isn't a bulb
                self.bulb_configured = True
                self.bulb_type = 'None'
            elif '20' in response['dps'] and '21' in response['dps']:
                self.bulb_configured = True
                self.bulb_type = 'B'
            elif '1' in response['dps'] and '2' in response['dps']:
                self.bulb_configured = True

                # if DP 2 is a string, it is the mode (Type A).  If it is an int, it is the brightness (Type C)
                self.bulb_type = 'A' if isinstance(response['dps']['2'], str) else 'C'

            if self.bulb_type and self.bulb_type in self.DEFAULT_DPSET:
                # The 'music' DP is not returned in status(), so use the default value
                self.dpset['music'] = self.DEFAULT_DPSET[self.bulb_type]['music']

                self.dpset['value_min'] = self.DEFAULT_DPSET[self.bulb_type]['value_min']
                self.dpset['value_max'] = self.DEFAULT_DPSET[self.bulb_type]['value_max']
                self.dpset['value_hexformat'] = self.DEFAULT_DPSET[self.bulb_type]['value_hexformat']

                for k in self.DEFAULT_DPSET[self.bulb_type]:
                    if k[:6] == 'value_':
                        continue
                    if not self.DEFAULT_DPSET[self.bulb_type][k]:
                        continue
                    dp = str( self.DEFAULT_DPSET[self.bulb_type][k] )
                    if dp in response['dps']:
                        self.dpset[k] = dp

            # set has_* attributes for backwards compatibility
            for k in ('brightness', 'colourtemp', 'colour'):
                setattr( self, 'has_'+k, bool(self.dpset[k]) )

            log.debug("Bulb type set to %r. has brightness: %r, has colourtemp: %r, has colour: %r",
                      self.bulb_type, self.dpset['brightness'], self.dpset['colourtemp'], self.dpset['colour']
                      )
        elif not self.bulb_configured:
            # response has no dps
            log.debug("No DPs in response, cannot detect bulb type!")

    def set_bulb_type(self, bulb_type=None, mapping=None):
        self.bulb_type = bulb_type
        self.set_bulb_capabilities(mapping)

    def set_bulb_capabilities(self, mapping):
        if self.bulb_type in self.DEFAULT_DPSET:
            default_dpset = self.DEFAULT_DPSET[self.bulb_type]
        else:
            default_dpset = {}

        if not isinstance( mapping, dict ):
            mapping = {}

        for k in self.dpset:
            if k in mapping:
                self.dpset[k] = mapping[k]
            elif self.dpset[k] is None:
                dp = default_dpset.get(k, None)
                self.dpset[k] = str(dp) if (dp and k[:6] != 'value_') else dp

        if self.dpset['switch'] and self.dpset['brightness']:
            self.bulb_configured = True
