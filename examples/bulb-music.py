# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Smart Bulb RGB Music Test

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import tinytuya
import time
import random
import os

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

print("TinyTuya - Smart Bulb Music Test [%s]\n" % tinytuya.__version__)
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

# Music Test
print('Setting to Music')
d.set_mode('music')
data = d.status()

d.set_socketPersistent( True )

# Devices respond with a command ACK, but do not send DP updates.
# Setting the 2 options below causes it to wait for a response but
#   return immediately after an ACK.
d.set_sendWait( None )
d.set_retry( False )

for x in range(100):
    # Value is 0 1111 2222 3333 4444 5555
    # see: https://developer.tuya.com/en/docs/iot/solarlight-function-definition?id=K9tp16f086d5h#title-10-DP27(8)%3A%20music
    red = random.randint(0,255)
    green = random.randint(0,255)
    blue = random.randint(0,255)

    if (x % 6 == 0):
        # extend every 6 beat
        d.set_music_colour( d.MUSIC_TRANSITION_FADE, red, green, blue )
        time.sleep(2)
    else:
        # Jump!
        d.set_music_colour( d.MUSIC_TRANSITION_JUMP, red, green, blue )
        time.sleep(0.1) # the bulbs seem to get upset if updates are faster than 0.1s (100ms)

# Done
print('\nDone')
d.turn_off()
