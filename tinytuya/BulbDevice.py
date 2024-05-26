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
        receive()                          # Receive payload from device
"""

import colorsys

from .core import * # pylint: disable=W0401, W0614

class BulbDevice(Device):
    """
    Represents a Tuya based Smart Light/Bulb.

    This class supports two types of bulbs with different DPS mappings and functions:
        Type A - Uses DPS index 1-5
        Type B - Uses DPS index 20-27 (no index 1)
        Type C - Same as Type A except that it is using DPS 2 for brightness, which ranges from 0-1000.  These are the Feit branded dimmers found at Costco.
    """

    # Two types of Bulbs - TypeA uses DPS 1-5, TypeB uses DPS 20-24
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

    DPS_2_STATE = {
        "1": "is_on",
        "2": "mode",
        "3": "brightness",
        "4": "colourtemp",
        "5": "colour",
        "20": "is_on",
        "21": "mode",
        "22": "brightness",
        "23": "colourtemp",
        "24": "colour",
    }

    # Set Default Bulb Types
    bulb_type = "A"
    has_brightness = False
    has_colourtemp = False
    has_colour = False

    def __init__(self, *args, **kwargs):
        # set the default version to None so we do not immediately connect and call status()
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = None
        super(BulbDevice, self).__init__(*args, **kwargs)

    @staticmethod
    def _rgb_to_hexvalue(r, g, b, bulb="A"):
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
        hsv = colorsys.rgb_to_hsv(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0)

        # Bulb Type A
        if bulb == "A":
            # h:0-360,s:0-255,v:0-255|hsv|
            hexvalue = ""
            for value in rgb:
                temp = str(hex(int(value))).replace("0x", "")
                if len(temp) == 1:
                    temp = "0" + temp
                hexvalue = hexvalue + temp

            hsvarray = [int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255)]
            hexvalue_hsv = ""
            for value in hsvarray:
                temp = str(hex(int(value))).replace("0x", "")
                if len(temp) == 1:
                    temp = "0" + temp
                hexvalue_hsv = hexvalue_hsv + temp
            if len(hexvalue_hsv) == 7:
                hexvalue = hexvalue + "0" + hexvalue_hsv
            else:
                hexvalue = hexvalue + "00" + hexvalue_hsv

        # Bulb Type B
        if bulb == "B":
            # h:0-360,s:0-1000,v:0-1000|hsv|
            hexvalue = ""
            hsvarray = [int(hsv[0] * 360), int(hsv[1] * 1000), int(hsv[2] * 1000)]
            for value in hsvarray:
                temp = str(hex(int(value))).replace("0x", "")
                while len(temp) < 4:
                    temp = "0" + temp
                hexvalue = hexvalue + temp

        return hexvalue

    @staticmethod
    def _hexvalue_to_rgb(hexvalue, bulb="A"):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an RGB value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        if bulb == "A":
            r = int(hexvalue[0:2], 16)
            g = int(hexvalue[2:4], 16)
            b = int(hexvalue[4:6], 16)
        elif bulb == "B":
            # hexvalue is in hsv
            h = float(int(hexvalue[0:4], 16) / 360.0)
            s = float(int(hexvalue[4:8], 16) / 1000.0)
            v = float(int(hexvalue[8:12], 16) / 1000.0)
            rgb = colorsys.hsv_to_rgb(h, s, v)
            r = int(rgb[0] * 255)
            g = int(rgb[1] * 255)
            b = int(rgb[2] * 255)
        else:
            # Unsupported bulb type
            raise ValueError(f"Unsupported bulb type {bulb} - unable to determine RGB values.")

        return (r, g, b)

    @staticmethod
    def _hexvalue_to_hsv(hexvalue, bulb="A"):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an HSV value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        if bulb == "A":
            h = int(hexvalue[7:10], 16) / 360.0
            s = int(hexvalue[10:12], 16) / 255.0
            v = int(hexvalue[12:14], 16) / 255.0
        elif bulb == "B":
            # hexvalue is in hsv
            h = int(hexvalue[0:4], 16) / 360.0
            s = int(hexvalue[4:8], 16) / 1000.0
            v = int(hexvalue[8:12], 16) / 1000.0
        else:
            # Unsupported bulb type
            raise ValueError(f"Unsupported bulb type {bulb} - unable to determine HSV values.")
        
        return (h, s, v)

    def set_version(self, version): # pylint: disable=W0621
        """
        Set the Tuya device version 3.1 or 3.3 for BulbDevice
        Attempt to determine BulbDevice Type: A or B based on:
            Type A has keys 1-5 (default)
            Type B has keys 20-29
            Type C is Feit type bulbs from costco
        """
        super(BulbDevice, self).set_version(version)

        # Try to determine type of BulbDevice Type based on DPS indexes
        status = self.status()
        if status is not None:
            if "dps" in status:
                if "1" not in status["dps"]:
                    self.bulb_type = "B"
                if self.DPS_INDEX_BRIGHTNESS[self.bulb_type] in status["dps"]:
                    self.has_brightness = True
                if self.DPS_INDEX_COLOURTEMP[self.bulb_type] in status["dps"]:
                    self.has_colourtemp = True
                if self.DPS_INDEX_COLOUR[self.bulb_type] in status["dps"]:
                    self.has_colour = True
            else:
                self.bulb_type = "B"
        else:
            # response has no dps
            self.bulb_type = "B"
        log.debug("bulb type set to %s", self.bulb_type)

    def turn_on(self, switch=0, nowait=False):
        """Turn the device on"""
        if switch == 0:
            switch = self.DPS_INDEX_ON[self.bulb_type]
        self.set_status(True, switch, nowait=nowait)

    def turn_off(self, switch=0, nowait=False):
        """Turn the device on"""
        if switch == 0:
            switch = self.DPS_INDEX_ON[self.bulb_type]
        self.set_status(False, switch, nowait=nowait)

    def set_bulb_type(self, type):
        self.bulb_type = type

    def set_mode(self, mode="white", nowait=False):
        """
        Set bulb mode

        Args:
            mode(string): white,colour,scene,music
            nowait(bool): True to send without waiting for response.
        """
        payload = self.generate_payload(
            CONTROL, {self.DPS_INDEX_MODE[self.bulb_type]: mode}
        )
        data = self._send_receive(payload, getresponse=(not nowait))
        return data

    def set_scene(self, scene, nowait=False):
        """
        Set to scene mode

        Args:
            scene(int): Value for the scene as int from 1-4.
            nowait(bool): True to send without waiting for response.
        """
        if not 1 <= scene <= 4:
            return error_json(
                ERR_RANGE, "set_scene: The value for scene needs to be between 1 and 4."
            )

        if scene == 1:
            s = self.DPS_MODE_SCENE_1
        elif scene == 2:
            s = self.DPS_MODE_SCENE_2
        elif scene == 3:
            s = self.DPS_MODE_SCENE_3
        else:
            s = self.DPS_MODE_SCENE_4

        payload = self.generate_payload(
            CONTROL, {self.DPS_INDEX_MODE[self.bulb_type]: s}
        )
        data = self._send_receive(payload, getresponse=(not nowait))
        return data

    def set_colour(self, r, g, b, nowait=False):
        """
        Set colour of an rgb bulb.

        Args:
            r(int): Value for the colour Red as int from 0-255.
            g(int): Value for the colour Green as int from 0-255.
            b(int): Value for the colour Blue as int from 0-255.
            nowait(bool): True to send without waiting for response.
        """
        if not self.has_colour:
            log.debug("set_colour: Device does not appear to support color.")
            # return error_json(ERR_FUNCTION, "set_colour: Device does not support color.")
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

        hexvalue = BulbDevice._rgb_to_hexvalue(r, g, b, self.bulb_type)

        payload = self.generate_payload(
            CONTROL,
            {
                self.DPS_INDEX_MODE[self.bulb_type]: self.DPS_MODE_COLOUR,
                self.DPS_INDEX_COLOUR[self.bulb_type]: hexvalue,
            },
        )
        data = self._send_receive(payload, getresponse=(not nowait))
        return data

    def set_hsv(self, h, s, v, nowait=False):
        """
        Set colour of an rgb bulb using h, s, v.

        Args:
            h(float): colour Hue as float from 0-1
            s(float): colour Saturation as float from 0-1
            v(float): colour Value as float from 0-1
            nowait(bool): True to send without waiting for response.
        """
        if not self.has_colour:
            log.debug("set_hsv: Device does not appear to support color.")
            # return error_json(ERR_FUNCTION, "set_hsv: Device does not support color.")
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
        hexvalue = BulbDevice._rgb_to_hexvalue(
            r * 255.0, g * 255.0, b * 255.0, self.bulb_type
        )

        payload = self.generate_payload(
            CONTROL,
            {
                self.DPS_INDEX_MODE[self.bulb_type]: self.DPS_MODE_COLOUR,
                self.DPS_INDEX_COLOUR[self.bulb_type]: hexvalue,
            },
        )
        data = self._send_receive(payload, getresponse=(not nowait))
        return data

    def set_white_percentage(self, brightness=100, colourtemp=0, nowait=False):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            colourtemp(int): Value for the colour temperature in percent (0-100)
            nowait(bool): True to send without waiting for response.
        """
        # Brightness
        if not 0 <= brightness <= 100:
            return error_json(
                ERR_RANGE,
                "set_white_percentage: Brightness percentage needs to be between 0 and 100.",
            )

        b = int(25 + (255 - 25) * brightness / 100)

        if self.bulb_type == "B":
            b = int(10 + (1000 - 10) * brightness / 100)

        # Colourtemp
        if not 0 <= colourtemp <= 100:
            return error_json(
                ERR_RANGE,
                "set_white_percentage: Colourtemp percentage needs to be between 0 and 100.",
            )

        c = int(255 * colourtemp / 100)

        if self.bulb_type == "B":
            c = int(1000 * colourtemp / 100)

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
        # Brightness (default Max)
        if brightness < 0:
            brightness = 255
            if self.bulb_type == "B":
                brightness = 1000
        if self.bulb_type == "A" and not 25 <= brightness <= 255:
            return error_json(
                ERR_RANGE, "set_white: The brightness needs to be between 25 and 255."
            )
        if self.bulb_type == "B" and not 10 <= brightness <= 1000:
            return error_json(
                ERR_RANGE, "set_white: The brightness needs to be between 10 and 1000."
            )

        # Colourtemp (default Min)
        if colourtemp < 0:
            colourtemp = 0
        if self.bulb_type == "A" and not 0 <= colourtemp <= 255:
            return error_json(
                ERR_RANGE,
                "set_white: The colour temperature needs to be between 0 and 255.",
            )
        if self.bulb_type == "B" and not 0 <= colourtemp <= 1000:
            return error_json(
                ERR_RANGE,
                "set_white: The colour temperature needs to be between 0 and 1000.",
            )

        payload = self.generate_payload(
            CONTROL,
            {
                self.DPS_INDEX_MODE[self.bulb_type]: self.DPS_MODE_WHITE,
                self.DPS_INDEX_BRIGHTNESS[self.bulb_type]: brightness,
                self.DPS_INDEX_COLOURTEMP[self.bulb_type]: colourtemp,
            },
        )

        data = self._send_receive(payload, getresponse=(not nowait))
        return data

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
        b = int(25 + (255 - 25) * brightness / 100)
        if self.bulb_type == "B":
            b = int(10 + (1000 - 10) * brightness / 100)

        data = self.set_brightness(b, nowait=nowait)
        return data

    def set_brightness(self, brightness, nowait=False):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
            nowait(bool): True to send without waiting for response.
        """
        if self.bulb_type == "A" and not 25 <= brightness <= 255:
            return error_json(
                ERR_RANGE,
                "set_brightness: The brightness needs to be between 25 and 255.",
            )
        if self.bulb_type == "B" and not 10 <= brightness <= 1000:
            return error_json(
                ERR_RANGE,
                "set_brightness: The brightness needs to be between 10 and 1000.",
            )

        # Determine which mode bulb is in and adjust accordingly
        state = self.state()
        data = None

        if "mode" in state:
            if state["mode"] == "white":
                # for white mode use DPS for brightness
                if not self.has_brightness:
                    log.debug("set_brightness: Device does not appear to support brightness.")
                    # return error_json(ERR_FUNCTION, "set_brightness: Device does not support brightness.")
                payload = self.generate_payload(
                    CONTROL, {self.DPS_INDEX_BRIGHTNESS[self.bulb_type]: brightness}
                )
                data = self._send_receive(payload, getresponse=(not nowait))

            if state["mode"] == "colour":
                # for colour mode use hsv to increase brightness
                if self.bulb_type == "A":
                    value = brightness / 255.0
                else:
                    value = brightness / 1000.0
                (h, s, v) = self.colour_hsv()
                data = self.set_hsv(h, s, value, nowait=nowait)

        if data is not None or nowait is True:
            return data
        else:
            return error_json(ERR_STATE, "set_brightness: Unknown bulb state.")

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
        c = int(255 * colourtemp / 100)
        if self.bulb_type == "B":
            c = int(1000 * colourtemp / 100)

        data = self.set_colourtemp(c, nowait=nowait)
        return data

    def set_colourtemp(self, colourtemp, nowait=False):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
            nowait(bool): True to send without waiting for response.
        """
        if not self.has_colourtemp:
            log.debug("set_colourtemp: Device does not appear to support colortemp.")
            # return error_json(ERR_FUNCTION, "set_colourtemp: Device does not support colortemp.")
        if self.bulb_type == "A" and not 0 <= colourtemp <= 255:
            return error_json(
                ERR_RANGE,
                "set_colourtemp: The colour temperature needs to be between 0 and 255.",
            )
        if self.bulb_type == "B" and not 0 <= colourtemp <= 1000:
            return error_json(
                ERR_RANGE,
                "set_colourtemp: The colour temperature needs to be between 0 and 1000.",
            )

        payload = self.generate_payload(
            CONTROL, {self.DPS_INDEX_COLOURTEMP[self.bulb_type]: colourtemp}
        )
        data = self._send_receive(payload, getresponse=(not nowait))
        return data

    def brightness(self):
        """Return brightness value"""
        return self.status()[self.DPS][self.DPS_INDEX_BRIGHTNESS[self.bulb_type]]

    def colourtemp(self):
        """Return colour temperature"""
        return self.status()[self.DPS][self.DPS_INDEX_COLOURTEMP[self.bulb_type]]

    def colour_rgb(self):
        """Return colour as RGB value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_rgb(hexvalue, self.bulb_type)

    def colour_hsv(self):
        """Return colour as HSV value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_hsv(hexvalue, self.bulb_type)

    def state(self):
        """Return state of Bulb"""
        status = self.status()
        state = {}
        if not status:
            return error_json(ERR_JSON, "state: empty response")

        if "Error" in status.keys():
            return error_json(ERR_JSON, status["Error"])

        if self.DPS not in status.keys():
            return error_json(ERR_JSON, "state: no data points")

        for key in status[self.DPS].keys():
            if key in self.DPS_2_STATE:
                state[self.DPS_2_STATE[key]] = status[self.DPS][key]

        return state
