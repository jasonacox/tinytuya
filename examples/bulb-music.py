# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Smart Bulb RGB Music Test

 TODO: Figure out what strings to send to the bulb to 
       represent real music data, beats, note, fades, etc.

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import tinytuya
import time

#tinytuya.set_debug()

# SmartBulb
DEVICEID = "01234567891234567890"
DEVICEIP = "10.0.1.99"
DEVICEKEY = "0123456789abcdef"
DEVICEVERS = "3.3"

print("TinyTuya - Smart Bulb Music Test [%s]\n" % tinytuya.__version__)
print('TESTING: Device %s at %s with key %s version %s' %
      (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

# Connect to Tuya BulbDevice
d = tinytuya.BulbDevice(DEVICEID, DEVICEIP, DEVICEKEY)
if(DEVICEVERS == '3.3'):    # IMPORTANT to always set version 
    d.set_version(3.3)
else:
    d.set_version(3.1)
# Keep socket connection open between commands
d.set_socketPersistent(True)  

# Show status of device
data = d.status()
print('\nCurrent Status of Bulb: %r' % data)

# Music Test
print('Setting to Music')
d.set_mode('music')
data = d.status()

# Send example music data to bulb 
#  TODO: Figure out what the value does and how to use it to 
#        represent real music data, beats, colors, fades
x = 0
while (x<20):
    value = "%02d01" % x
    print (" > Sending %s" % value)
    payload = d.generate_payload(tinytuya.CONTROL, {"27": value})
    d.send(payload)
    if (x % 3):
        time.sleep(1)  # extend every 3 beat
    time.sleep(0.2)
    x = x + 1

# Done
print('\nDone')
d.set_white()
