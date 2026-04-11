# TinyTuya IRRemoteControlDevice Example
# -*- coding: utf-8 -*-
"""
 Example script using the community-contributed Python module for Tuya WiFi smart universal remote control simulators

 Author: Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)
 Rewritten by: uzlonewolf (https://github.com/uzlonewolf)
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


# learn a new remote
print("Press button on your remote control")
button = ir.receive_button(timeout=15)
if (button == None):
    print("Timeout, button code is not received")
    sys.exit(1)

print("Received button:", button)
pulses = ir.base64_to_pulses(button)
print( IRRemoteControlDevice.print_pulses( pulses ) )

# See if we can decode it into head+key
headkey = IRRemoteControlDevice.pulses_to_head_key( pulses )
if headkey:
    head, key = headkey
    print( 'Parsed button into head+key:' )
    print( 'Head:', head )
    print( 'Key:', key )

    for i in range(10):
        if i > 0: sleep(1)
        print("Simulating button press...")
        ir.send_key( head, key )

else:
    print( 'Could not parse button into head+key, keeping as base64.' )

    for i in range(10):
        if i > 0: sleep(1)
        print("Simulating button press...")
        ir.send_button(button)

