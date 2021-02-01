# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Example to fetch status of Tuya device

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

""" 
import tinytuya

# Connect to the device - replace with real values
d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY)
d.set_version(3.3)

# Alternative connection - for some devices with 22 character IDs they require a special handling
#    d=tinytuya.OutletDevice(DEVICEID, DEVICEIP, DEVICEKEY, 'device22')
#    d.set_dpsUsed({"1": None}) 
#    d.set_version(3.3)

# Get the status of the device 
# e.g. {'devId': '0071299988f9376255b', 'dps': {'1': True, '3': 208, '101': False}}
data = d.get_status()
print(data)