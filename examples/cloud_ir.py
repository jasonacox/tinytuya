# TinyTuya Example
# -*- coding: utf-8 -*-
"""
 TinyTuya - Tuya Cloud IR Functions

 This example uses the Tinytuya Cloud class and functions
 to send IR blaster commands

 Author: uzlonewolf
 For more information see https://github.com/jasonacox/tinytuya

""" 
import tinytuya
import colorsys
import time
import json

#tinytuya.set_debug()

# Set this to the actual blaster device, not a virtual remote
device_id = DEVICEID

# Connect to Tuya Cloud - uses tinytuya.json
c = tinytuya.Cloud()




# Raw IR commands can be sent directly
ir_cmd = {
    "control":"send_ir",
    "head":"010ed20000000000040015004000ad0730",
    "key1":"002$$0020E0E0E01F@%",
    "type":0,
    "delay":300
}

cloud_cmd = {
    "commands": [
        {
            "code": "ir_send",
            "value": json.dumps(ir_cmd)
        },
    ]
}

print('Send Raw result:')
res = c.sendcommand(device_id, cloud_cmd)
print( json.dumps(res, indent=2) )




# Keys from a virtual remote can also be sent
#
# See https://developer.tuya.com/en/docs/cloud/ir-control-hub-open-service?id=Kb3oe2mk8ya72
#   for API documentation


# First, get a listing of all programmed remotes
print('List of remotes:')
remote_list = c.cloudrequest( '/v2.0/infrareds/' + device_id + '/remotes' )
print( json.dumps(remote_list, indent=2) )

# Next, get a list of keys for a remote using remote_id from the list returned by the previous command
print('List of keys on 1st remote:')
remote_id = remote_list['result'][0]['remote_id'] # Grab the first remote for this example
remote_key_list = c.cloudrequest( '/v2.0/infrareds/%s/remotes/%s/keys' % (device_id, remote_id) )
print( json.dumps(remote_key_list, indent=2) )

# Finally, send the 'Power' key
post_data = {
    "key": "OK", #"Power",
    "category_id": remote_key_list['result']['category_id'],
    "remote_index": remote_key_list['result']['remote_index']
}
print('Send key result:')
res = c.cloudrequest( '/v2.0/infrareds/%s/remotes/%s/command' % (device_id, remote_id), post=post_data )
print( json.dumps(res, indent=2) )



# The actual value sent by the above key can be found by checking the device logs
print('Device logs:')
logs = c.getdevicelog(device_id, evtype='5', size=3, max_fetches=1)
print( json.dumps(logs, indent=2) )
