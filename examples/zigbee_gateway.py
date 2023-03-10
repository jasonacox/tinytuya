import tinytuya
import time

# Zigbee Gateway support uses a parent/child model where a parent gateway device is
#  connected and then one or more children are added.

# configure the parent device
#   address=None will cause it to search the network for the device
gw = tinytuya.Device( 'eb...4', address=None, local_key='aabbccddeeffgghh', persist=True, version=3.3 )

print( 'GW IP found:', gw.address )

# configure one or more children.  Every dev_id must be unique!
#   cid is the "node_id" from devices.json
#   node_id can be used as an alias for cid
zigbee1 = tinytuya.OutletDevice( 'eb14...w', cid='0011223344556601', parent=gw )
zigbee2 = tinytuya.OutletDevice( 'eb04...l', cid='0011223344556689', parent=gw )

print(zigbee1.status())
print(zigbee2.status())

print(" > Begin Monitor Loop <")
pingtime = time.time() + 9

while(True):
    if( pingtime <= time.time() ):
        payload = gw.generate_payload(tinytuya.HEART_BEAT)
        gw.send(payload)
        pingtime = time.time() + 9

    # receive from the gateway object to get updates for all sub-devices
    print('recv:')
    data = gw.receive()
    print( data )

    # data['device'] contains a reference to the device object
    if data and 'device' in data and data['device'] == zigbee1:
        print('toggling device state')
        time.sleep(1)
        if data['dps']['1']:
            data['device'].turn_off(nowait=True)
        else:
            data['device'].turn_on(nowait=True)
