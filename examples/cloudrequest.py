# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - CloudRequest

 This examples uses the Tinytuya Cloud class and the cloudrequest function
 to access the Tuya Cloud to control a door lock.


 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

""" 
import tinytuya

# Turn on Debug Mode
tinytuya.set_debug(True)

# You can have tinytuya pull the API credentials
# from the tinytuya.json file created by the wizard
# c = tinytuya.Cloud()
# Alternatively you can specify those values here:
# Connect to Tuya Cloud
c = tinytuya.Cloud(
        apiRegion="us", 
        apiKey="xxxxxxxxxxxxxxxxxxxx", 
        apiSecret="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 
        apiDeviceID="xxxxxxxxxxxxxxxxxxID")

# Example: Door Lock
device_id = "xxxxxxxxxxxxxxxxxxID"

# Get a password ticket
ticket = c.cloudrequest( f'/v1.0/smart-lock/devices/{device_id}/password-ticket' )

# Unlock the door
unlock = c.cloudrequest( f'/v1.1/devices/{device_id}/door-lock/password-free/open-door', 
                        post={'ticket_id': ticket} )
