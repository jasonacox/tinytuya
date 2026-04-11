# TinyTuya IRRemoteControlDevice Example
# -*- coding: utf-8 -*-
"""
 Example script using the community-contributed Python module for Tuya WiFi smart universal remote control simulators

 Author: uzlonewolf (https://github.com/uzlonewolf)
 For more information see https://github.com/jasonacox/tinytuya

"""
import sys
import tinytuya
from tinytuya.Contrib import IRRemoteControlDevice
from time import sleep

# Optional: enable debugging
#tinytuya.set_debug(toggle=True, color=True)


# Create the device.
# This will automatically call detect_control_type() which connects
#   to the device to try and determine which DPS to use.  As such
#   the version must be set here and not later via set_version()
ir = IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc', version=3.3, persist=True )


# Send a learned key via a base64 blob.  Note: when using a blob taken from
#   the device log of a DP 201 device, the leading '1' must be removed.  I.e.
#  "1yOvEToCZ...QI5AkoCO" should be entered as
#  "yOvEToCZ...QI5AkoCO"
b64 = "yOvEToCZ...QI5AkoCO"
ir.send_button( b64 )


# Send a key via a head+key1 pair.  Note: when using a key1 taken from
#   the device log, the leading '0' in key1 must be removed.  I.e.
#  "002$000CA900" should be entered as
#  "02$000CA900"
head = "010fbb00000000000f001900320064032c0313044c041a03450433046502fa0401035e02e1047e"
key1 = "02$000CA900"
ir.send_key( head, key1 )

