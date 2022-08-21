# TinyTuya IRRemoteControlDevice Example
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: JonesMeUp
 Tested: LSC-Bell 8S(AKV300_8M)
 Note: Without hack the device can't be used offline. 
       With hack the DoorbellDevice is useless.
        
 For more information see https://github.com/jasonacox/tinytuya
    https://github.com/jasonacox/tinytuya/issues/162 
    
"""
import tinytuya
from tinytuya.Contrib import DoorbellDevice

d = DoorbellDevice('abcdefghijklmnop123456', '192.168.178.25', 
    '1234567890123abc', 'device22')
d.set_version(3.3)
d.set_socketPersistent(True) # Keep socket connection open between commands

d.set_volume(3)
d.set_motion_area(0, 5, 50, 50)
d.set_motion_area_switch(True)

print(" > Begin Monitor Loop <")
while(True):
    # See if any data is available
    data = d.receive()
    print('Data: %r' % data)
    # Send keyalive heartbeat
    print(" > Send Heartbeat Ping < ")
    payload = d.generate_payload(tinytuya.HEART_BEAT)
    d.send(payload)