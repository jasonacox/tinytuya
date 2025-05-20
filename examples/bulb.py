# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Smart Bulb RGB Test

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import tinytuya
import time
import os
import random

#tinytuya.set_debug()

DEVICEID = "01234567891234567890"
DEVICEIP = "Auto" # Will try to discover the bulb on the network
DEVICEKEY = ""    # Leave blank to read from devices.json
DEVICEVERS = 3.3  # Must be set correctly unless IP=Auto

# Check for environmental variables and always use those if available
DEVICEID = os.getenv("DEVICEID", DEVICEID)
DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

print("TinyTuya - Smart Bulb RGB Test [%s]\n" % tinytuya.__version__)
print('TESTING: Device %s at %s with key %s version %s' %
      (DEVICEID, DEVICEIP, DEVICEKEY, DEVICEVERS))

# Connect to Tuya BulbDevice
d = tinytuya.BulbDevice(DEVICEID, address=DEVICEIP, local_key=DEVICEKEY, version=DEVICEVERS, persist=True)

if (not DEVICEIP) or (DEVICEIP == 'Auto') or (not DEVICEKEY) or (not DEVICEVERS):
    print('Device %s found at %s with key %r version %s' %
          (d.id, d.address, d.local_key, d.version))

# Show status of device
data = d.status()
print('\nCurrent Status of Bulb: %r' % data)

# NOTE: the capabilities of the bulb are auto-detected when status() is called.  If auto-detection
#   fails or you do not call status, you must manually set the capability:DP mapping with either:
#d.set_bulb_type('B') # 'A' 'B' or 'C'
# or
"""
mapping = {
    'switch': 20,       # Required
    #'mode': None,      # Optional
    'brightness': 22,   # Required
    #'colourtemp': None,# Optional
    #'colour': None,    # Optional
    'scene': 25,        # Optional
    'scene_data': 25,   # Optional.  Type B prefixes scene data with idx
    'timer': 26,        # Optional
    'music': 28,        # Optional
    'value_min': 10,    # Required.  Minimum brightness value
    'value_max': 1000,  # Required.  Maximum brightness and colourtemp value
    'value_hexformat': 'hsv16', # Required.  'hsv16' or 'rgb8'
}
d.set_bulb_capabilities(mapping)
"""

# Set to full brightness warm white
# set_white_percentage() will ignore the colour temperature if the bulb does not support it
print('\nWarm White Test')
d.set_white_percentage(100.0, 0.0) # 100% brightness, 0% colour temperature
time.sleep(2)

# Power Control Test
print('\nPower Control Test')
print('    Turn off lamp')
d.turn_off()
time.sleep(2)
print('    Turn on lamp')
d.turn_on()
time.sleep(2)

# Dimmer Test
print('\nDimmer Control Test')
for level in range(11):
    level *= 10
    if not level: level = 1
    print('    Level: %d%%' % level)
    d.set_brightness_percentage(level)
    time.sleep(1)

# Colortemp Test
# An error JSON will be returned if the bulb does not support colour temperature
if d.bulb_has_capability( d.BULB_FEATURE_COLOURTEMP ):
    print('\nColortemp Control Test (Warm to Cool)')
    for level in range(11):
        print('    Level: %d%%' % (level*10))
        d.set_colourtemp_percentage(level*10)
        time.sleep(1)
else:
    # set_colourtemp_percentage() will return an error JSON if the bulb does not support colour temperature
    print('\nBulb does not have colour temp control, skipping Colortemp Control Test')

# Flip through colors of rainbow - set_colour(r, g, b):
if d.bulb_has_capability( d.BULB_FEATURE_COLOUR ):
    print('\nColor Test - Cycle through rainbow')
    rainbow = {"red": [255, 0, 0], "orange": [255, 127, 0], "yellow": [255, 200, 0],
               "green": [0, 255, 0], "blue": [0, 0, 255], "indigo": [46, 43, 95],
               "violet": [139, 0, 255]}
    for x in range(2):
        for i in rainbow:
            r = rainbow[i][0]
            g = rainbow[i][1]
            b = rainbow[i][2]
            print('    %s (%d,%d,%d)' % (i, r, g, b))
            d.set_colour(r, g, b)
            time.sleep(2)
        print('')

    # Turn off
    d.turn_off()
    time.sleep(1)

    # Random Color Test
    d.turn_on()
    print('\nRandom Color Test')
    for x in range(10):
        r = random.randint(0, 255)
        g = random.randint(0, 255)
        b = random.randint(0, 255)
        print('    RGB (%d,%d,%d)' % (r, g, b))
        d.set_colour(r, g, b)
        time.sleep(2)
else:
    print('\nBulb does not do colours, skipping Color Test')

# Test Modes
if d.bulb_has_capability( d.BULB_FEATURE_MODE ):
    print('\nTesting Bulb Modes')
    print('    White')
    d.set_mode('white')
    time.sleep(2)
    print('    Colour')
    d.set_mode('colour')
    time.sleep(2)
    print('    Scene')
    d.set_mode('scene')
    time.sleep(2)
    print('    Music')
    d.set_mode('music')
    time.sleep(2)
else:
    print('\nBulb does not support modes, skipping Bulb Mode Test')

# Done
print('\nDone')
d.turn_off()
