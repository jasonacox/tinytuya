# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Example script to monitor state changes with Tuya devices.

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

"""
import tinytuya
import time

# tinytuya.set_debug(True)

d = tinytuya.OutletDevice('DEVICEID', 'DEVICEIP', 'DEVICEKEY', version=3.3, persist=True)

STATUS_TIMER = 30
KEEPALIVE_TIMER = 12

print(" > Send Request for Status < ")
data = d.status()
print('Initial Status: %r' % data)

print(" > Begin Monitor Loop <")
heartbeat_time = time.time() + KEEPALIVE_TIMER
status_time =  None

# Uncomment if you want the monitor to constantly request status - otherwise you
# will only get updates when state changes
#status_time = time.time() + STATUS_TIMER

while(True):
    if status_time and time.time() >= status_time:
        # Uncomment if your device provides power monitoring data but it is not updating
        # Some devices require a UPDATEDPS command to force measurements of power.
        # print(" > Send DPS Update Request < ")
        # Most devices send power data on DPS indexes 18, 19 and 20
        # d.updatedps(['18','19','20'], nowait=True)
        # Some Tuya devices will not accept the DPS index values for UPDATEDPS - try:
        # payload = d.generate_payload(tinytuya.UPDATEDPS)
        # d.send(payload)

        # poll for status
        print(" > Send Request for Status < ")
        data = d.status()
        status_time = time.time() + STATUS_TIMER
        heartbeat_time = time.time() + KEEPALIVE_TIMER
    elif time.time() >= heartbeat_time:
        # send a keep-alive
        data = d.heartbeat(nowait=False)
        heartbeat_time = time.time() + KEEPALIVE_TIMER
    else:
        # no need to send anything, just listen for an asynchronous update
        data = d.receive()

    print('Received Payload: %r' % data)
