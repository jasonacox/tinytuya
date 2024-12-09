# TinyTuya LED Music Controller Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya Colorful-X7:
 Tuya Smart WiFi Zigbee BT Colorful X7 LED Music Controller SP107E 
 Matrix 1024 Pixels LED Panel Light Music Spectrum Controller

 Author: Ahmed Chehaibi (https://github.com/CheAhMeD)

 Local Control Classes
    ColorfulX7Device(...)
        See OutletDevice() for constructor arguments

 Functions
    ColorfulX7Device:
        is_on()                            # returns the state of the device (True=On, False=Off)
        switch_off()                       # turns off the device
        switch_on()                        # turns on the device
        set_mode(mode)                     # sets the mode to white | colour | scene | music | screen
        set_color(r, g, b)                 # sets the colour 
        set_countdown(value)               # sets the countdown timer value (max 86400)
        set_segments_number(number)        # sets the number of segments in led strip|matrix (1 to 64)
        set_leds_PerSegment(number)        # sets the number of leds per segment in led strip|matrix (1 to 150)
        set_rgb_order(order)               # sets the RGB order of the leds to  ORDER_RGB | ORDER_RBG | ORDER_GRB | ORDER_GBR | ORDER_BRG | ORDER_BGR
        set_work_mode(mode)                # sets the work mode to CLOSE | FIX_COLOR | DYNAMIC | MUSIC | SCREEN
        set_color_rgb(r, g, b)             # sets the colour in CLOSE | FIX_COLOR | DYNAMIC work modes
        set_brightness(value)              # sets the brightness in CLOSE | FIX_COLOR | DYNAMIC work modes
        set_speed(value)                   # sets the speed in DYNAMIC work mode
        set_dynamic_mode(mode)             # sets the scene type in DYNAMIC work mode
        set_music_mode(mode)               # sets the scene type in MUSIC work mode
        set_sensitivity(value)             # sets the MIC sensitivity in MUSIC | SCREEN work modes
        set_music_RGBColor(r, g, b)        # sets the colour in some scenes in MUSIC | SCREEN work modes
        set_led_brand(brand)               # sets the Leds brand to WS2811 | DMX512 | FW1935
        set_screen_mode(mode)              # sets the scene type in SCREEN work mode
        set_fallingDot_color(r, g, b)      # sets the falling dot color in some scenes in MUSIC work mode

    Inherited
        json = status()                    # returns json payload
        set_version(version)               # 3.1 [default] or 3.5
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

from ..core import *
import colorsys

class ColorfulX7Device(Device):
    """
    Represents a Tuya based LED Music Controller
    """
    DPS_MODEL = "Colorful-X7"
    DPS = 'dps'
    DPS_INDEX_ON             = "20"
    DPS_INDEX_MODE           = "21"
    DPS_INDEX_MODE_ENUM      = ["white","colour","scene","music","screen"]
    DPS_INDEX_COLOUR         = "24"
    DPS_INDEX_COUNTDOWN      = "26"
    DPS_INDEX_SEG_NUM        = "101"
    DPS_INDEX_SEG_LED_NUM    = "102"
    DPS_INDEX_RGB_ORDER      = "103"
    DPS_INDEX_RGB_ORDER_ENUM = ["ORDER_RGB","ORDER_RBG","ORDER_GRB","ORDER_GBR","ORDER_BRG","ORDER_BGR"]
    DPS_INDEX_WORKMODE       = "104"
    DPS_INDEX_WORKMODE_ENUM  = ["CLOSE","FIX_COLOR","DYNAMIC","MUSIC","SCREEN"]
    DPS_INDEX_COLOUR_RGB     = "105"
    DPS_INDEX_BRIGHTNESS     = "106"
    DPS_INDEX_DYNAMIC_INTV   = "107"
    DPS_INDEX_DYNAMIC_MODE   = "108"
    DPS_INDEX_MUSIC_MODE     = "109"
    DPS_INDEX_SENSITIVITY    = "110"
    DPS_INDEX_MUSIC_COLOR    = "111"
    DPS_INDEX_LED_BRAND      = "112"
    #NOTE: the Brand ENUM should contain more brands but Tuya Smart App only shows
    #the following brands:
    DPS_INDEX_LED_BRAND_ENUM = ["WS2811","DMX512","FW1935"]
    DPS_INDEX_SCREEN_POINT_COLOR = "113"
    DPS_INDEX_SCREEN_MODE    = "114"
    DPS_INDEX_MUSIC_DATA     = "27"

    def __init__(self, *args, **kwargs):
        # set the default version to None so we do not immediately connect and call status()
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = None
        super(ColorfulX7Device, self).__init__(*args, **kwargs)

    @staticmethod
    def _hsv_to_hexValue(hsvValue):
        '''
        Convert an HSV value to the hex representation expected by Colorful-X7
        in hhhhssssvvvv format.

        '''
        hexValue = ""
        hsvArray = [int(hsvValue[0] * 360), int(hsvValue[1] * 1000), int(hsvValue[2] * 1000)]
        for value in hsvArray:
            temp = str(hex(int(value))).replace("0x", "")
            while len(temp) < 4:
                temp = "0" + temp
            hexValue = hexValue + temp
        return hexValue

    @staticmethod
    def _rgb_to_hexValue(r, g, b):
        '''
        Convert an RGB value to the hex representation expected by Colorful-X7
        in #RRGGBB format.

        '''
        return '#{:02x}{:02x}{:02x}'.format(r, g, b)
    
    def switch_off(self):
        self.turn_off(self.DPS_INDEX_ON)

    def switch_on(self):
        self.turn_on(self.DPS_INDEX_ON)
        
    def is_on(self):
        data = self.status()
        return data[self.DPS][self.DPS_INDEX_ON]

    def set_mode(self, mode):
        if mode not in self.DPS_INDEX_MODE_ENUM:
            log.error(
                "set_mode: Unsupporetd mode {}. Supported modes {}".format(mode, self.DPS_INDEX_MODE_ENUM)
            )
            return None
        
        self.set_value(self.DPS_INDEX_MODE, mode)
    
    def set_color(self, r, g, b):
        if not 0 <= r <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for red needs to be between 0 and 255.",
            )
        if not 0 <= g <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for green needs to be between 0 and 255.",
            )
        if not 0 <= b <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for blue needs to be between 0 and 255.",
            )

        hsv = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)

        self.set_value(self.DPS_INDEX_COLOUR, ColorfulX7Device._hsv_to_hexValue(hsv))
    
    def set_countdown(self, value):
        if not 0 <= value <= 86400:
            return error_json(
                ERR_RANGE,
                "set_countdown: The value for countdown needs to be between 0 and 86400 (s)."
            )
        self.set_value(self.DPS_INDEX_COUNTDOWN, value)
    
    def set_segments_number(self, number):
        if not 1 <= number <= 64:
            return error_json(
                ERR_RANGE,
                "set_segments_number: The number of segments needs to be between 1 and 64."
            )
        self.set_value(self.DPS_INDEX_SEG_NUM, number)
    
    def set_leds_PerSegment(self, number):
        if not 1 <= number <= 150:
            return error_json(
                ERR_RANGE,"set_leds_PerSegment: The number of Leds per segment needs to be between 1 and 150."
            )
        self.set_value(self.DPS_INDEX_SEG_LED_NUM, number)
    
    def set_rgb_order(self, order):
        if order not in self.DPS_INDEX_RGB_ORDER_ENUM:
            log.error(
                "set_rgb_order: Unsupporetd RGB Order {}. Supported RGB Orders {}".format(order, self.DPS_INDEX_RGB_ORDER_ENUM)
            )
            return
        self.set_value(self.DPS_INDEX_RGB_ORDER, order)

    def set_work_mode(self, mode):
        if mode not in self.DPS_INDEX_WORKMODE_ENUM:
            log.error(
                "set_work_mode: Unsupporetd work mode {}. Supported modes {}".format(mode, self.DPS_INDEX_WORKMODE_ENUM)
            )
            return
        
        self.set_value(self.DPS_INDEX_WORKMODE, mode)
    
    def set_color_rgb(self, r, g, b):
        if not 0 <= r <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for red needs to be between 0 and 255.",
            )
        if not 0 <= g <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for green needs to be between 0 and 255.",
            )
        if not 0 <= b <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for blue needs to be between 0 and 255.",
            )
        
        rgbHexValue = ColorfulX7Device._rgb_to_hexValue(r, g, b)
        self.set_value(self.DPS_INDEX_COLOUR_RGB, rgbHexValue)

    def set_brightness(self, value):
        if not 0 <= value <= 100:
            return error_json(
                ERR_RANGE,
                "set_brightness: The value for brightness needs to be between 0 and 100 (%)."
            )
            
        self.set_value(self.DPS_INDEX_BRIGHTNESS, value)

    def set_speed(self, value):
        if not 0 <= value <= 100:
            return error_json(
                ERR_RANGE,
                "set_speed: The value for speed needs to be between 0 and 100 (ms)."
            )
        self.set_value(self.DPS_INDEX_DYNAMIC_INTV, value)

    def set_dynamic_mode(self, mode):
        '''
        Dynamic Mode:
        choose between 180 available modes (in the App)
        modes don't have a name they are represented by numbers (1 to 180)

        If dynamic mode is enabled (workmode = DYNAMIC)
        you can use set_dynamic_mode, set_speed and set_brightness
        using the other functions won't have any effect

        '''
        if not 1 <= mode <= 180:
            return error_json(
                ERR_RANGE,
                "set_dynamic_mode: The dynamic mode needs to be between 1 and 180."
            )
        self.set_value(self.DPS_INDEX_DYNAMIC_MODE, mode)

    def set_music_mode(self, mode):
        '''
        Music Mode:
        chooses between 22 available strip modes
        modes don't have a name they are represented by numbers

        If music mode is enabled (workmode = MUSIC)
        we can use set_music_mode, set_sensitivity and set_music_RGBColor (only for some modes!!)
        using the other functions won't have any effect

        '''
        if not 1 <= mode <= 22:
            return error_json(
                ERR_RANGE,
                "set_music_mode: The music mode needs to be between 1 and 22."
            )
        self.set_value(self.DPS_INDEX_MUSIC_MODE, mode)

    def set_sensitivity(self, value):
        if not 0 <= value <= 100:
            return error_json(
                ERR_RANGE,
                "set_sensitivity: The music sensitivity needs to be between 0 and 100."
            )
        self.set_value(self.DPS_INDEX_SENSITIVITY, value)

    def set_music_RGBColor(self, r, g, b):
        if not 0 <= r <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for red needs to be between 0 and 255.",
            )
        if not 0 <= g <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for green needs to be between 0 and 255.",
            )
        if not 0 <= b <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for blue needs to be between 0 and 255.",
            )
        
        rgbHexValue = ColorfulX7Device._rgb_to_hexValue(r, g, b)
        self.set_value(self.DPS_INDEX_MUSIC_COLOR, rgbHexValue)

    def set_led_brand(self, brand):
        if brand not in self.DPS_INDEX_LED_BRAND_ENUM:
            log.error(
                "set_led_brand: Unsupporetd LED brand {}. Supported brands {}".format(brand, self.DPS_INDEX_LED_BRAND)
            )
            return
        self.set_value(self.DPS_INDEX_LED_BRAND, brand)

    def set_screen_mode(self, mode):
        '''
        Screen Mode: 
        Like Music mode but for matrix display
        choose between 30 available matrix modes
        modes don't have a name they are represented by numbers

        If Screen mode is enabled (workmode = SCREEN)
        we can use set_screen_mode, set_sensitivity and set_fallingDot_color
        using the other functions won't have any effect

        '''
        if not 1 <= mode <= 30:
            return error_json(
                ERR_RANGE,
                "set_screen_mode: The screen mode needs to be between 1 and 30."
            )
        self.set_value(self.DPS_INDEX_SCREEN_MODE, mode)

    def set_fallingDot_color(self, r, g, b):
        if not 0 <= r <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for red needs to be between 0 and 255.",
            )
        if not 0 <= g <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for green needs to be between 0 and 255.",
            )
        if not 0 <= b <= 255:
            return error_json(
                ERR_RANGE,
                "set_color: The value for blue needs to be between 0 and 255.",
            )

        hsv = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
        self.set_value(self.DPS_INDEX_SCREEN_POINT_COLOR, ColorfulX7Device._hsv_to_hexValue(hsv))
