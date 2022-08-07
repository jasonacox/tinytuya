
# TinyTuya IRRemoteControlDevice- Example
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

ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )

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
