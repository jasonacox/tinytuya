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
    BulbDevice
        set_colour(r, g, b, nowait):
        set_hsv(h, s, v, nowait):
        set_white(brightness, colourtemp, nowait):
        set_white_percentage(brightness=100, colourtemp=0, nowait):
        set_brightness(brightness, nowait):
        set_brightness_percentage(brightness=100, nowait):
        set_colourtemp(colourtemp, nowait):
        set_colourtemp_percentage(colourtemp=100, nowait):
        set_scene(scene, nowait):             # 1=nature, 3=rave, 4=rainbow
        set_mode(mode='white', nowait):       # white, colour, scene, music
        result = brightness():
        result = colourtemp():
        (r, g, b) = colour_rgb():
        (h,s,v) = colour_hsv()
        result = state():

    Inherited
        Every device function from core.py
"""

import colorsys

from .core import Device, log
from .core import error_json, ERR_JSON, ERR_RANGE, ERR_STATE, ERR_TIMEOUT, ERR_FUNCTION

class BulbDevice(Device):
    """
    Represents a Tuya based Smart Light/Bulb.

    This class supports two types of bulbs with different DPS mappings and functions:
        Type A - Uses DPS index 1-5
        Type B - Uses DPS index 20-27 (no index 1)
        Type C - Uses DPS index 1-2 with DPS 2 being brightness (which ranges from 0-1000).  These are the Feit branded dimmers found at Costco.
    """

    # Two types of Bulbs - TypeA uses DPS 1-5, TypeB uses DPS 20-24
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
    DPS_MODE_WHITE = "white"
    DPS_MODE_COLOUR = "colour"
    DPS_MODE_SCENE = "scene"
    DPS_MODE_MUSIC = "music"
    DPS_MODE_SCENE_1 = "scene_1"  # nature
    DPS_MODE_SCENE_2 = "scene_2"
    DPS_MODE_SCENE_3 = "scene_3"  # rave
    DPS_MODE_SCENE_4 = "scene_4"  # rainbow

    DEFAULT_DPSET = {}
    DEFAULT_DPSET['A'] = {
        'switch': 1,
        'mode': 2,
        'brightness': 3,
        'colourtemp': 4,
        'colour': 5,
        'scene': 7,
        'scene_idx': 2, # Type A sets mode to 'scene_N'
        'timer': None,
        'music': None,
        'value_min': 25,
        'value_max': 255,
    }
    DEFAULT_DPSET['B'] = {
        'switch': 20,
        'mode': 21,
        'brightness': 22,
        'colourtemp': 23,
        'colour': 24,
        'scene': 25,
        'scene_idx': 25, # Type B prefixes scene with idx
        'timer': 26,
        'music': 27,
        'value_min': 10,
        'value_max': 1000,
    }
    DEFAULT_DPSET['C'] = {
        'switch': 1,
        'mode': None,
        'brightness': 2,
        'colourtemp': None,
        'colour': None,
        'scene': None,
        'scene_idx': None,
        'timer': None,
        'music': None,
        'value_min': 25,
        'value_max': 255,
    }

    def __init__(self, *args, **kwargs):
        # Set Default Bulb Types
        self.bulb_type = None
        self.has_brightness = None
        self.has_colourtemp = None
        self.has_colour = None
        self.dpset = {
            'switch': None,
            'mode': None,
            'brightness': None,
            'colourtemp': None,
            'colour': None,
            'scene': None,
            'scene_idx': None,
            'timer': None,
            'music': None,
            'value_min': None,
            'value_max': None,
        }

        # set the default version to None so we do not immediately connect and call status()
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = None
        super(BulbDevice, self).__init__(*args, **kwargs)

    def status(self, nowait=False):
        result = super(BulbDevice, self).status(nowait=nowait)
        if result and (not self.bulb_type) and (self.DPS in result):
            self.detect_bulb(result)
        return result

    @staticmethod
    def _rgb_to_hexvalue(r, g, b, bulb="A", use_rgb=None):
        """
        Convert an RGB value to the hex representation expected by Tuya Bulb.

        Index (DPS_INDEX_COLOUR) is assumed to be in the format:
            (Type A) Index: 5 in hex format: rrggbb0hhhssvv
            (Type B) Index: 24 in hex format: hhhhssssvvvv

        While r, g and b are just hexadecimal values of the corresponding
        Red, Green and Blue values, the h, s and v values (which are values
        between 0 and 1) are scaled:
            Type A: 360 (h) and 255 (s and v)
            Type B: 360 (h) and 1000 (s and v)

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        rgb = [r, g, b]

        for rgb_value in rgb:
            if rgb_value < 0 or rgb_value > 255:
                raise ValueError(f"Bulb type {bulb} must have RGB values 0-255.")

        hsv = colorsys.rgb_to_hsv(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0)
        #print(hsv)
        if use_rgb is None:
            if bulb == "A":
                use_rgb = True
            elif bulb == "B":
                use_rgb = False
            else:
                # Unsupported bulb type
                raise ValueError(f"Unsupported bulb type {bulb} - unable to determine hexvalue.")

        if use_rgb:
            # r:0-255,g:0-255,b:0-255|rgb|
            hexvalue = ""
            for rgb_value in rgb:
                hexvalue += '%02x' % int(rgb_value)
            # h:0-360,s:0-255,v:0-255|hsv|
            hexvalue += '%04x' % int(hsv[0] * 360)
            hexvalue += '%02x' % int(hsv[1] * 255)
            hexvalue += '%02x' % int(hsv[2] * 255)
        else:
            # h:0-360,s:0-1000,v:0-1000|hsv|
            hexvalue = ""
            hsvarray = [int(hsv[0] * 360), int(hsv[1] * 1000), int(hsv[2] * 1000)]
            #print(hsvarray)
            for hsv_value in hsvarray:
                hexvalue += '%04x' % int(hsv_value)

        return hexvalue

    @staticmethod
    def _hexvalue_to_rgb(hexvalue, bulb="A", use_hsv=None):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an RGB value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        hexvalue_len = len(hexvalue)
        if use_hsv is None:
            if hexvalue_len == 6 or hexvalue_len == 14:
                use_hsv = False
            elif hexvalue_len == 12:
                use_hsv = True
            elif bulb == "A":
                use_hsv = False
            elif bulb == "B":
                use_hsv = True
            else:
                # Unsupported bulb type
                raise ValueError(f"Unsupported bulb type {bulb} - unable to determine RGB values.")

        if not use_hsv:
            if hexvalue_len < 6:
                raise ValueError("RGB value string must have 6 or 14 hex digits.")
            r = int(hexvalue[0:2], 16)
            g = int(hexvalue[2:4], 16)
            b = int(hexvalue[4:6], 16)
        else:
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

        return (r, g, b)

    @staticmethod
    def _hexvalue_to_hsv(hexvalue, bulb="A", use_rgb=None):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an HSV value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        hexvalue_len = len(hexvalue)
        if use_rgb is None:
            if hexvalue_len == 6 or hexvalue_len == 14:
                use_rgb = True
            elif hexvalue_len == 12:
                use_rgb = False
            elif bulb == "A":
                use_rgb = True
            elif bulb == "B":
                use_rgb = False
            else:
                # Unsupported bulb type
                raise ValueError(f"Unsupported bulb type {bulb} - unable to determine RGB values.")

        if use_rgb:
            # hexvalue is in rgb+hsv
            if hexvalue_len < 14:
                raise ValueError("RGBHSV value string must have 14 hex digits.")
            h = int(hexvalue[7:10], 16) / 360.0
            s = int(hexvalue[10:12], 16) / 255.0
            v = int(hexvalue[12:14], 16) / 255.0
        else:
            # hexvalue is in hsv
            if hexvalue_len < 12:
                raise ValueError("HSV value string must have 12 hex digits.")
            h = int(hexvalue[0:4], 16) / 360.0
            s = int(hexvalue[4:8], 16) / 1000.0
            v = int(hexvalue[8:12], 16) / 1000.0

        return (h, s, v)

    def turn_on(self, switch=0, nowait=False):
        """Turn the device on"""
        if switch == 0:
            if not self.bulb_type:
                self.detect_bulb()
            switch = self.dpset['switch']
        self.set_status(True, switch, nowait=nowait)

    def turn_off(self, switch=0, nowait=False):
        """Turn the device on"""
        if switch == 0:
            if not self.bulb_type:
                self.detect_bulb()
            switch = self.dpset['switch']
        self.set_status(False, switch, nowait=nowait)

    def set_bulb_type(self, type, **kwargs):
        self.bulb_type = type
        self.set_bulb_capabilities(**kwargs)

    def set_bulb_capabilities(self, **kwargs):
        if self.bulb_type in self.DEFAULT_DPSET:
            default_dpset = self.DEFAULT_DPSET[self.bulb_type]
        else:
            raise ValueError(f"Unsupported bulb type '{self.bulb_type}' - unable to determine DPS set.")

        for k in self.dpset:
            if k in kwargs:
                self.dpset[k] = kwargs[k]
            elif self.dpset[k] is None:
                val = getattr(default_dpset, k, None)
                self.dpset[k] = str(val) if (val and k[:6] != 'value_') else val
        #print('dpset:', self.dpset)

    def set_mode(self, mode="white", nowait=False):
        """
        Set bulb mode

        Args:
            mode(string): white,colour,scene,music
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_type:
            self.detect_bulb()
        if not self.dpset['mode']:
            raise ValueError('Bulb does not support mode setting.')
        return self.set_value( self.dpset['mode'], mode, nowait=nowait )

    def set_scene(self, scene, nowait=False):
        """
        Set to scene mode

        Args:
            scene(int): Value for the scene as int from 1-4 (Type A bulbs) or 1-N (Type B bulbs).
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_type:
            self.detect_bulb()

        if not self.dpset['scene']:
            raise ValueError('Bulb does not support scenes.')

        if( (self.dpset['scene_idx'] == self.dpset['mode']) and (not 1 <= scene <= 4) ):
            raise ValueError('set_scene: The value for scene needs to be between 1 and 4.')

        if self.dpset['scene_idx'] == self.dpset['mode']:
            dps_values = {
                self.dpset['mode']: self.DPS_MODE_SCENE + '_' + str(scene)
            }
        else:
            dps_values = {
                self.dpset['scene']: '%02x' % int(scene),
                self.dpset['mode']: self.DPS_MODE_SCENE,
            }

        return self.set_multiple_values( dps_values, nowait=nowait )

    def set_colour(self, r, g, b, nowait=False):
        """
        Set colour of an rgb bulb.

        Args:
            r(int): Value for the colour Red as int from 0-255.
            g(int): Value for the colour Green as int from 0-255.
            b(int): Value for the colour Blue as int from 0-255.
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_type:
            self.detect_bulb()

        if not self.dpset['colour']:
            return error_json(ERR_FUNCTION, "set_colour: Device does not support color.")
        if not 0 <= r <= 255:
            return error_json(
                ERR_RANGE,
                "set_colour: The value for red needs to be between 0 and 255.",
            )
        if not 0 <= g <= 255:
            return error_json(
                ERR_RANGE,
                "set_colour: The value for green needs to be between 0 and 255.",
            )
        if not 0 <= b <= 255:
            return error_json(
                ERR_RANGE,
                "set_colour: The value for blue needs to be between 0 and 255.",
            )

        dps_values = {}
        check_values = {
            'colour': BulbDevice._rgb_to_hexvalue(r, g, b, self.bulb_type),
            'mode': self.DPS_MODE_COLOUR,
            'switch': True
        }

        # check to see which DPs need to be set
        state = self.cached_status(nowait=True)
        if state and self.DPS in state and state[self.DPS]:
            # last state is cached, so check to see if 'mode' needs to be set
            for k in check_values:
                dp = self.dpset[k]
                if dp and ((dp not in state[self.DPS]) or (state[self.DPS][dp] != check_values[k])):
                    dps_values[dp] = check_values[k]

        if not dps_values:
            # last state not cached or everything already set, so send them all
            for k in check_values:
                if self.dpset[k]:
                    dps_values[self.dpset[k]] = check_values[k]

        return self.set_multiple_values( dps_values, nowait=nowait )

    def set_hsv(self, h, s, v, nowait=False):
        """
        Set colour of an rgb bulb using h, s, v.

        Args:
            h(float): colour Hue as float from 0-1
            s(float): colour Saturation as float from 0-1
            v(float): colour Value as float from 0-1
            nowait(bool): True to send without waiting for response.
        """
        if not 0 <= h <= 1.0:
            return error_json(
                ERR_RANGE, "set_hsv: The value for Hue needs to be between 0 and 1."
            )
        if not 0 <= s <= 1.0:
            return error_json(
                ERR_RANGE,
                "set_hsv: The value for Saturation needs to be between 0 and 1.",
            )
        if not 0 <= v <= 1.0:
            return error_json(
                ERR_RANGE,
                "set_hsv: The value for Value needs to be between 0 and 1.",
            )

        (r, g, b) = colorsys.hsv_to_rgb(h, s, v)
        return self.set_colour( r * 255.0, g * 255.0, b * 255.0, nowait=nowait )

    def set_white_percentage(self, brightness=100, colourtemp=0, nowait=False):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            colourtemp(int): Value for the colour temperature in percent (0-100)
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_type:
            self.detect_bulb()

        # Brightness
        if not 0 <= brightness <= 100:
            return error_json(
                ERR_RANGE,
                "set_white_percentage: Brightness percentage needs to be between 0 and 100.",
            )

        # Colourtemp
        if not 0 <= colourtemp <= 100:
            return error_json(
                ERR_RANGE,
                "set_white_percentage: Colourtemp percentage needs to be between 0 and 100.",
            )

        if brightness < 1.0:
            return self.turn_off(0, nowait=nowait)

        b = int(self.dpset['value_max'] * brightness / 100)
        c = int(self.dpset['value_max'] * colourtemp / 100)

        data = self.set_white(b, c, nowait=nowait)
        return data

    def set_white(self, brightness=-1, colourtemp=-1, nowait=False):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (A:25-255 or B:10-1000)
            colourtemp(int): Value for the colour temperature (A:0-255, B:0-1000).
            nowait(bool): True to send without waiting for response.

            Default: Max Brightness and Min Colourtemp
        """
        if not self.bulb_type:
            self.detect_bulb()

        brightness = int(brightness)
        colourtemp = int(colourtemp)

        # Brightness (default Max)
        if brightness < 0:
            brightness = self.dpset['value_max']
        elif brightness < self.dpset['value_min']:
            return self.turn_off(0, nowait=nowait)
        elif brightness > self.dpset['value_max']:
            return error_json(
                ERR_RANGE, f"set_white: The brightness needs to be between {self.dpset['value_min']} and {self.dpset['value_max']}."
            )

        # Colourtemp (default Min)
        if colourtemp < 0:
            colourtemp = 0
        if colourtemp > self.dpset['value_max']:
            return error_json(
                ERR_RANGE,
                f"set_white: The colour temperature needs to be between 0 and {self.dpset['value_max']}.",
            )

        dps_values = {}
        check_values = {
            'brightness': brightness,
            'colourtemp': colourtemp,
            'mode': self.DPS_MODE_WHITE,
            'switch': True
        }

        # check to see which DPs need to be set
        state = self.cached_status(nowait=True)
        if state and self.DPS in state and state[self.DPS]:
            # last state is cached, so check to see if 'mode' needs to be set
            for k in check_values:
                dp = self.dpset[k]
                if dp and ((dp not in state[self.DPS]) or (state[self.DPS][dp] != check_values[k])):
                    dps_values[dp] = check_values[k]

        if not dps_values:
            # last state not cached or everything already set, so send them all
            for k in check_values:
                if self.dpset[k]:
                    dps_values[self.dpset[k]] = check_values[k]

        return self.set_multiple_values( dps_values, nowait=nowait )

    def set_brightness_percentage(self, brightness=100, nowait=False):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            nowait(bool): True to send without waiting for response.
        """
        if not 0 <= brightness <= 100:
            return error_json(
                ERR_RANGE,
                "set_brightness_percentage: Brightness percentage needs to be between 0 and 100.",
            )

        if not self.bulb_type:
            self.detect_bulb()

        b = int(self.dpset['value_max'] * brightness / 100)
        data = self.set_brightness(b, nowait=nowait)
        return data

    def set_brightness(self, brightness, nowait=False):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
            nowait(bool): True to send without waiting for response.
        """
        if not self.bulb_type:
            self.detect_bulb()

        # Brightness (default Max)
        if brightness < 0:
            brightness = self.dpset['value_max']
        elif brightness < self.dpset['value_min']:
            return self.turn_off(0, nowait=nowait)
        elif brightness > self.dpset['value_max']:
            return error_json(
                ERR_RANGE, f"set_brightness: The brightness needs to be between {self.dpset['value_min']} and {self.dpset['value_max']}."
            )

        # Determine which mode bulb is in and adjust accordingly
        state = self.state()
        #print( 'set_brightness state:', state )
        data = None
        msg = 'set_brightness: '

        if (not self.dpset['mode']) or state['mode'] == self.DPS_MODE_WHITE:
            # for white mode use DPS for brightness
            if not self.dpset['brightness']:
                return error_json(ERR_FUNCTION, "set_brightness: Device does not support brightness.")
            data = self.set_value( self.dpset['brightness'], brightness, nowait=nowait )
            msg += 'No repsonse from bulb.'
        elif state['mode'] == self.DPS_MODE_COLOUR:
            # for colour mode use hsv to increase brightness
            value = brightness / float(self.dpset['value_max'])
            (h, s, v) = self.colour_hsv()
            data = self.set_hsv(h, s, value, nowait=nowait)
            msg += 'No repsonse from bulb.'
        else:
            msg += "Unable to set brightness, device mode needs to be 'white' or 'colour' but reports %r" % state["mode"]
            log.debug( msg )
            return error_json(ERR_STATE, msg)

        if data is not None or nowait is True:
            return data
        else:
            log.debug( msg )
            return error_json(ERR_TIMEOUT, msg)

    def set_colourtemp_percentage(self, colourtemp=100, nowait=False):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature in percentage (0-100).
            nowait(bool): True to send without waiting for response.
        """
        if not 0 <= colourtemp <= 100:
            return error_json(
                ERR_RANGE,
                "set_colourtemp_percentage: Colourtemp percentage needs to be between 0 and 100.",
            )

        if not self.bulb_type:
            self.detect_bulb()

        c = int(self.dpset['value_max'] * colourtemp / 100)
        data = self.set_colourtemp(c, nowait=nowait)
        return data

    def set_colourtemp(self, colourtemp, nowait=False):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
            nowait(bool): True to send without waiting for response.
        """

        if not self.bulb_type:
            self.detect_bulb()

        if not self.dpset['colourtemp']:
            return error_json(ERR_FUNCTION, "set_colourtemp: Device does not support colortemp.")
        if not 0 <= colourtemp <= self.dpset['value_max']:
            return error_json(
                ERR_RANGE,
                f"set_colourtemp: The colour temperature needs to be between 0 and {self.dpset['value_max']}.",
            )

        return self.set_value( self.dpset['colourtemp'], colourtemp, nowait=nowait )

    def get_value(self, idx):
        s = self.state()
        #print( 'get_value state:', state )
        if 'Error' in s:
            return s
        if idx not in s:
            raise ValueError(f"Unknown parameter '{idx}'.")
        return s[idx]

    def mode(self):
        """Return current working mode"""
        return self.get_value('mode')

    def brightness(self):
        """Return brightness value"""
        return self.get_value('brightness')

    def colourtemp(self):
        """Return colour temperature"""
        return self.get_value('colourtemp')

    def colour_rgb(self):
        """Return colour as RGB value"""
        if not self.bulb_type: self.detect_bulb()
        hexvalue = self.cached_status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_rgb(hexvalue, self.bulb_type)

    def colour_hsv(self):
        """Return colour as HSV value"""
        if not self.bulb_type: self.detect_bulb()
        hexvalue = self.cached_status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_hsv(hexvalue, self.bulb_type)

    def state(self, nowait=False):
        """Return state of Bulb"""
        if not self.bulb_type:
            self.detect_bulb()

        status = self.cached_status(nowait=nowait)
        state = {}
        if not status:
            return error_json(ERR_JSON, "state: empty response")

        if "Error" in status:
            return error_json(ERR_JSON, status["Error"])

        if self.DPS not in status:
            return error_json(ERR_JSON, "state: no data points")

        for key in self.dpset:
            dp = self.dpset[key]
            if '_' in key:
                # skip scene_idx, value_min, value_max, etc
                state[key] = None
            elif dp in status[self.DPS]:
                state[key] = status[self.DPS][dp]
            else:
                state[key] = None

        if 'switch' in state:
            state['is_on'] = state['switch']

        #print( 'state:', state )
        return state

    def detect_bulb(self, response=None, default='B'):
        """
        Attempt to determine BulbDevice Type: A, B or C based on:
            Type A has keys 1-5
            Type B has keys 20-29
            Type C is Feit type bulbs from costco
        """
        if not response:
            response = self.cached_status(nowait=True)
            if (not response) or (self.DPS not in response):
                response = self.status()
                # return here as self.status() will call us again
                return
        if response and self.DPS in response:
            # Try to determine type of BulbDevice Type based on DPS indexes
            if self.bulb_type is None:
                if self.DPS_INDEX_ON['B'] in response[self.DPS]:
                    self.bulb_type = "B"
                elif self.DPS_INDEX_ON['A'] in response[self.DPS] and self.DPS_INDEX_BRIGHTNESS['A'] in response[self.DPS]:
                    if self.DPS_INDEX_COLOURTEMP['A'] in response[self.DPS] or self.DPS_INDEX_COLOUR['A'] in response[self.DPS]:
                        self.bulb_type = 'A'
                    else:
                        self.bulb_type = 'C'

            if self.bulb_type:
                if self.has_brightness is None:
                    if self.DPS_INDEX_BRIGHTNESS[self.bulb_type] in response["dps"]:
                        self.has_brightness = True
                if self.DPS_INDEX_COLOURTEMP[self.bulb_type] in response["dps"]:
                    self.has_colourtemp = True
                if self.DPS_INDEX_COLOUR[self.bulb_type] in response["dps"]:
                    self.has_colour = True
                log.debug("Bulb type set to %r. has brightness: %r, has colourtemp: %r, has colour: %r", self.bulb_type, self.has_brightness, self.has_colourtemp, self.has_colour)
            else:
                log.debug("No known DPs, bulb type detection failed!")
                self.bulb_type = default
                self.assume_bulb_attribs()
        else:
            # response has no dps
            log.debug("No DPs in response, cannot detect bulb type!")
            self.bulb_type = default
            self.assume_bulb_attribs()

    def assume_bulb_attribs(self):
        if self.has_brightness is None:
            self.has_brightness = bool(self.DPS_INDEX_BRIGHTNESS[self.bulb_type])
        if self.has_colourtemp is None:
            self.has_colourtemp = bool(self.DPS_INDEX_COLOURTEMP[self.bulb_type])
        if self.has_colour is None:
            self.has_colour = bool(self.DPS_INDEX_COLOUR[self.bulb_type])
