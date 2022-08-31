
# TinyTuya IRRemoteControlDevice Example
# -*- coding: utf-8 -*-
"""
 Example script using the community-contributed Python module for Tuya WiFi smart universal remote control simulators

 Author: Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)
 For more information see https://github.com/jasonacox/tinytuya

"""
import sys
import tinytuya
from tinytuya import Contrib
from time import sleep

# tinytuya.set_debug(toggle=True, color=True)

# discrete on/off codes for Samsung
pronto_samsung_on = '0000 006D 0000 0022 00AC 00AC 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0689'
pronto_samsung_off = '0000 006D 0000 0022 00AC 00AC 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0689'
pulses_samsung_on = Contrib.IRRemoteControlDevice.pronto_to_pulses( pronto_samsung_on )
pulses_samsung_off = Contrib.IRRemoteControlDevice.pronto_to_pulses( pronto_samsung_off )
print( 'Samsung on code:', Contrib.IRRemoteControlDevice.pulses_to_samsung( pulses_samsung_on )[0] )
print( 'Samsung off code:', Contrib.IRRemoteControlDevice.pulses_to_samsung( pulses_samsung_off )[0] )

# discrete on/off codes for LG
hex_lg_on = 0x20DF23DC
hex_lg_off = 0x20DFA35C
pulses_lg_on = Contrib.IRRemoteControlDevice.nec_to_pulses( hex_lg_on )
pulses_lg_off = Contrib.IRRemoteControlDevice.nec_to_pulses( hex_lg_off )
print( 'LG on code:', Contrib.IRRemoteControlDevice.pulses_to_nec( pulses_lg_on )[0] )
print( 'LG off code:', Contrib.IRRemoteControlDevice.pulses_to_nec( pulses_lg_off )[0] )

ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )

# turn the Samsung tv on
ir.send_button( ir.pulses_to_base64( pulses_samsung_on ) )
# turn the LG tv on
ir.send_button( ir.pulses_to_base64( pulses_lg_on ) )

print("Press button on your remote control")
button = ir.receive_button(timeout=15)
if (button == None):
    print("Timeout, button code is not received")
    sys.exit(1)

print("Received button:", button)
pulses = ir.base64_to_pulses(button)
print("Pulses and gaps (microseconds): " + 
    ' '.join([f'{"p" if i % 2 == 0 else "g"}{pulses[i]}' for i in range(len(pulses))]))

for i in range(10):
    print("Simulating button press...")
    ir.send_button(button)
    sleep(1)
