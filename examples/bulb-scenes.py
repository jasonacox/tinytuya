# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - RGB SmartBulb - Scene Test for Bulbs

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import tinytuya
import time
import os


DEVICEID = "01234567891234567890"
DEVICEIP = "Auto" # Will try to discover the bulb on the network
DEVICEKEY = ""    # Leave blank to read from devices.json
DEVICEVERS = 3.3  # Must be set correctly unless IP=Auto

# Check for environmental variables and always use those if available
DEVICEID = os.getenv("DEVICEID", DEVICEID)
DEVICEIP = os.getenv("DEVICEIP", DEVICEIP)
DEVICEKEY = os.getenv("DEVICEKEY", DEVICEKEY)
DEVICEVERS = os.getenv("DEVICEVERS", DEVICEVERS)

print("TinyTuya - Smart Bulb String Scenes Test [%s]\n" % tinytuya.__version__)
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

# Set Mode to Scenes
print('\nSetting bulb mode to Scenes')
d.set_mode('scene')

if d.bulb_has_capability(d.BULB_FEATURE_SCENE_DATA):
    print('\n   String based scenes compatible smartbulb detected.')
    # Example: Color rotation 
    print('    Switch to Scene 7 - Color Rotation')
    d.set_scene( 7, '464602000003e803e800000000464602007803e803e80000000046460200f003e803e800000000464602003d03e803e80000000046460200ae03e803e800000000464602011303e803e800000000')
    time.sleep(10)

    # Example: Read scene
    print('    Switch to Scene 1 - Reading Light')
    d.set_scene( 1, '0e0d0000000000000003e803e8')
    time.sleep(5)

    # You can pull the scene strings from your smartbulb by running the async_send_receive.py script
    # and using the SmartLife app to change between scenes.  
else:
    print('\n   Your smartbulb does not appear to support string based scenes.')
    # Rotate through numeric scenes
    for n in range(1, 5):
        print('    Scene - %d' % n)
        d.set_scene(n)
        time.sleep(5)

# Done
print('\nDone')
d.turn_off()
