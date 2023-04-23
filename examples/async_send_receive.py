# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Example showing async persistent connection to device with
 continual loop watching for device updates.

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import time
import tinytuya

# tinytuya.set_debug(True)

d = tinytuya.OutletDevice('DEVICEID', 'DEVICEIP', 'DEVICEKEY')
d.set_version(3.3)
d.set_socketPersistent(True)

# Devices will close the connection if they do not receve data every 30 seconds
# Sending heartbeat packets every 9 seconds gives some wiggle room for lost packets or loop lag
PING_TIME = 9

# Option - also poll
POLL_TIME = 60

print(" > Send Request for Status < ")
d.status(nowait=True)

print(" > Begin Monitor Loop <")
pingtime = time.time() + PING_TIME
polltime = time.time() + POLL_TIME
while(True):
    # See if any data is available
    data = d.receive()
    if data:
        print('Received Payload: %r' % data)

    if( pingtime <= time.time() ):
        pingtime = time.time() + PING_TIME
        # Send keep-alive heartbeat
        print(" > Send Heartbeat Ping < ")
        d.heartbeat(nowait=True)

    # Option - Poll for status
    if( polltime <= time.time() ):
        polltime = time.time() + POLL_TIME

        # Option - Some plugs require an UPDATEDPS command to update their power data points
        if False:
            print(" > Send DPS Update Request < ")

            # # Some Tuya devices require a list of DPs to update
            # payload = d.generate_payload(tinytuya.UPDATEDPS,['18','19','20'])
            # data = d.send(payload)
            # print('Received Payload: %r' % data)

            # # Other devices will not accept the DPS index values for UPDATEDPS - try:
            # payload = d.generate_payload(tinytuya.UPDATEDPS)
            # data = d.send(payload)
            # print('Received Payload: %r' % data)

        print(" > Send Request for Status < ")
        data = d.status()
        print('Received Payload: %r' % data)
