# TinyTuya Doorbell Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: JonesMeUp
 Tested: LSC-Bell 8S(AKV300_8M)
 Note: Without hack the device can't be used offline. 
       With hack the DoorbellDevice is useless.
        
 For more information see https://github.com/jasonacox/tinytuya
    https://github.com/jasonacox/tinytuya/issues/162 

Offline Device
    This DoorbellDevice works only if the device is online. Most stay
    offline to preserve the battery.

 Local Control Classes
    DoorbellDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    DoorbellDevice:
        set_basic_indicator(bool):
        set_volume(1-10):
        set_motion_area(x,y,lenX, lenY)
        set_motion_area_switch(bool)
"""

from ..core import Device

class DoorbellDevice(Device):
    """
    Represents a Tuya based Video-Doorbell.
    """
    DPS_2_STATE = {
        "101": "basic_indicator",     # Boolean                                                (status indicator)
        "103": "basic_flip",          # Boolean                                                (flip video vertically)
        "104": "basic_osd",           # Boolean                                                (timestap on video)
        "106": "motion_sensitivity",  # Enum ["0","1","2"]                                     (low, medium, high)
        "108": "basic_nightvision",   # Enum ["0","1","2"]                                     (auto, off, on)
        "109": "sd_storge",           # String ["maxlen":255]                                  (capacity|used|free) e.g: '258048|50176|207872'
        "110": "sd_status",           # Integer ["min":1,"max": 5,"scale":1,"step":1]
        "111": "sd_format",           # Boolean
        "115": "movement_detect_pic", # Raw
        "117": "sd_format_state",     # Integer ["min":-20000,"max":20000,"scale":1,"step":1]
        "134": "motion_switch",       # Boolean                                               (alarm on motion detection)
        "136": "doorbell_active",     # String ["maxlen":255]                                 (doorbell was pressed)
        "150": "record_switch",       # Boolean                                               (false = no recording)
        "151": "record_mode",         # Enum ["1","2"]                                        (1=on event, 2=always)
        "154": "doorbell_pic",        # Raw                                                   (picture of the device)
        "155": "doorbell_ring_exist", # Enum ["0","1"]
        "156": "chime_ring_tune",     # Enum ["1","2","3","4"]
        "157": "chime_ring_volume",   # Integer ["min":0,"max":100,"scale":1,"step":1]        (chime is an extrenal gong [433MhZ])
        "160": "basic_device_volume", # Integer ["min":1,"max": 10,"scale":0,"step":1]
        "165": "chime_settings",      # Enum ["0","2","3"]
        "168": "motion_area_switch",  # Boolean                                               (false = use full area)
        "169": "motion_area",         # String ["maxlen":255]                                 (x, y, xlen, ylen)
        "185": "alarm_message",       # String
    }
    DPS_2_FUNC = {
        "101": "basic_indicator",     # Boolean
        "103": "basic_flip",          # Boolean
        "104": "basic_osd",           # Boolean
        "106": "motion_sensitivity",  # Enum ["0","1","2"]
        "108": "basic_nightvision",   # Enum ["0","1","2"]
        "111": "sd_format",           # Boolean
        "134": "motion_switch",       # Boolean
        "150": "record_switch",       # Boolean
        "151": "record_mode",         # Enum ["1","2"]
        "155": "doorbell_ring_exist", # Enum ["0","1"]
        "156": "chime_ring_tune",     # Enum ["1","2","3","4"]
        "157": "chime_ring_volume",   # Integer ["min":0,"max":100,"scale":1,"step":1]
        "160": "basic_device_volume", # Integer ["min":1,"max": 10,"scale":0,"step":1]
        "165": "chime_settings",      # Enum ["0","2","3"]
        "168": "motion_area_switch",  # Boolean
        "169": "motion_area",         # String ["maxlen":255]
    }

    def set_basic_indicator(self, val=True, nowait=False):
        """ Set the basic incicator """
        self.set_value(101, bool(val), nowait)

    def set_volume(self, vol=10, nowait=False):
        """ Set the doorbell volume """
        if vol < 3:
            vol = 3 # Nothing to hear below 3
        if vol > 10:
            vol = 10        
        self.set_value(160, int(vol), nowait)

    def set_motion_area(self, x=0,y=0,xlen=50, ylen=100, nowait=False):
        """ set the area of motion detection [%] """
        if x <   0: x = 0
        if y <   0: y = 0
        if x > 100: x = 100
        if y > 100: y = 100
        if xlen <   0: xlen =   0
        if ylen <   0: ylen =   0
        if xlen > 100: xlen = 100
        if ylen > 100: ylen = 100
        if x+xlen >100: 
           x    = 25
           xlen = 75
        if y+ylen >100: 
           y    = 25
           ylen = 75
        data = '{"num":1,"region0":{"x":'+str(x)+',"y":'+str(y)+',"xlen":'+str(xlen)+',"ylen":'+str(ylen)+'}}'
        self.set_value(169, data, nowait)

    def set_motion_area_switch(self, useArea=False, nowait=False):
        """ use the area of motion detection on/off """
        self.set_value(168, bool(useArea), nowait)
