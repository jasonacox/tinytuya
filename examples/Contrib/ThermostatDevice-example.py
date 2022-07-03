
# TinyTuya ThermostatDevice Example
# -*- coding: utf-8 -*-
"""
 Example script using the community-contributed Python module for Tuya WiFi smart thermostats

 Author: uzlonewolf (https://github.com/uzlonewolf)
 For more information see https://github.com/jasonacox/tinytuya

"""
from tinytuya import Contrib
import time

tstatdev = Contrib.ThermostatDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )

## we do not need to set persistant or v3.3 as ThermostatDevice() does that for us

data = tstatdev.status()
print('Device status: %r' % data)

print(" > Begin Monitor Loop <")

# the thermostat will close the connection if it doesn't get a heartbeat message every ~28 seconds, so make sure to ping it.
# every 9 seconds, or roughly 3x that limit, is a good number to make sure we don't miss it due to received messages resetting the socket timeout
pingtime = time.time() + 9

show_all_attribs = True

while(True):
    if( pingtime <= time.time() ):
        tstatdev.sendPing()
        pingtime = time.time() + 9

    data = tstatdev.receive()

    if data:
        if show_all_attribs:
            show_all_attribs = False
            print( 'Data:', data )
            print( '' )
            print( 'All attribs:', dict(tstatdev) )
            print( '' )

            if tstatdev.isSingleSetpoint():
                print( 'Single Setpoint (Mode is "cool" or "heat")' )
            else:
                print( 'Dual Setpoints (Mode is "auto")' )

            print( 'Temperature is degrees C or F:', '°' + tstatdev.getCF().upper() )
            print( '' )

            ## hexadecimal dump of all sensors in a DPS:
            #for s in tstatdev.sensorlists:
            #    print( 'DPS', s.dps, '=', str(s) )

            ## Base64 dump of all sensors in a DPS:
            #for s in tstatdev.sensorlists:
            #    print( 'DPS', s.dps, '=', s.b64() )

            ## display info for every sensor:
            for s in tstatdev.sensors():
                ## print the DPS containing the sensor, the sensor ID, name, and temperature
                print( 'Sensor: DPS:%s ID:%s Name:"%s" Temperature:%r' % (s.parent_sensorlist.dps, s.id, s.name, s.temperature) )

                ## dump all data as a hexadecimal string
                print( str(s) )

        if 'changed_sensors' in data and len(data['changed_sensors']) > 0:
            for s in data['changed_sensors']:
                print( 'Sensor Changed! DPS:%s ID:%s Name:"%s" Changed:%r' % (s.parent_sensorlist.dps, s.id, s.name, s.changed) )
                #print(repr(s))
                #print(vars(s))

                for changed in s.changed:
                    print( 'Changed:', repr(changed), 'New Value:', getattr( s, changed ) )

                if( 'sensor_added' in s.changed ):
                    print( 'New sensor was added!' )
                    #print(repr(s.parent_sensorlist))
                    #print(str(s))

                if( 'sensor_added' in s.changed and s.id == '01234567' ):
                    print('Changing data for sensor', s.id)

                    ## by default every change will be sent immediately.  if multiple values are to be changed, it is much faster
                    ##  to call s.delayUpdates() first, make the changes, and then call s.sendUpdates() to send them
                    s.delayUpdates( )

                    ## make some changes
                    #s.setName( 'Bedroom Sensor 1' )
                    s.setEnabled( True )
                    #s.setEnabled( False )
                    #s.setOccupied( True )
                    s.setParticipation( 'wake', True )
                    #s.setParticipation( 'sleep', True )
                    #s.setParticipation( 0x0F )
                    #s.setUnknown2( 0x0A )

                    ## send the queued changes
                    s.sendUpdates( )

                    show_all_attribs = True

                if 'name' in s.changed:
                    print( 'Sensor was renamed!  New name:', s.name )

        if 'changed' in data and len(data['changed']) > 0:
            print( 'Changed:', data['changed'] )
            for c in data['changed']:
                print( 'Changed:', repr(c), 'New Value:', getattr( tstatdev, c ) )

            if 'cooling_setpoint_f' in data['changed']:
                if tstatdev.mode != 'heat' and tstatdev.cooling_setpoint_f < 65:
                    print( 'Cooling setpoint was set below 65, increasing to 72' )
                    tstatdev.setCoolSetpoint( 72 )

            if 'system' in data['changed'] and tstatdev.system == 'coolfanon':
                print( 'System now cooling to', tstatdev.cooling_setpoint_f )
