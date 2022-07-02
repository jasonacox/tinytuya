# TinyTuya Contrib ThermostatDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart thermostats

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Local Control Classes
    ThermostatDevice(dev_id, address, local_key=None, dev_type='default', persist=True)
        This class automatically sets the version to 3.3 and enables persistance so we can catch temperature updates

 Additional Classes
    ThermostatSensorList(dps, parent_device)
        Mainly used internally, exposed in case it's useful elsewhere
        The 'dps' argument should be the DPS ID of the list so it knows what DPS to send when updating a sensor option
        The 'parent_device' argument should be the ThermostatDevice() this sensor list belongs to


    Sensor related functions:
        tstatdev = ThermostatDevice(...)
        tstatdev.sensors() 
            -> returns an iterable list of all the sensors
              sensors have the following attributes:
                  id -> ID # of the sensor as a hex string
                  raw_id -> ID # of the sensor as a integer
                  name -> decoded and trimmed name of the sensor
                  raw_name -> NUL-padded name of the sensor as a byte array
                  enabled -> sensor enabled flag True/False
                  occupied -> sensor detected occupancy flag True/False
                  temperature -> temperature in degrees C as a float
                  raw_temperature -> temperature as reported by the sensor (degrees C * 100)
                  online -> sensor online flag True/False
                  participation -> schedule participation bitmask ['wake', 'away', 'home', 'sleep']
                  battery -> battery percentage remaining
                  unknown2 -> value of unknown field, integer 0-255
                  firmware_version -> firmware version * 10 (01 = v0.1)
                  averaging -> sensor currently participation in the temperature averaging (occupied is True and participation flag for the current schedule mode is set)
                  unknown3 -> value of unknown field, 8 byte long byte array
                  changed -> list of attributes which have changed since last update

        When sensor values change, the sensor object is also available in data['changed_sensors'].  i.e.
            data = tstatdev.receive()
            if data and 'changed_sensors' in data:
                for sensor in data['changed_sensors']:
                    if 'temperature' in sensor['changed'] and sensor.online:
                        ...do something with sensor.temperature or whatever...

        sensor.setName( new_name )
        sensor.setEnabled( enabled )
        sensor.setOccupied( occupied )
            -> not really useful for remote sensors as they get overwritten on the next update
        sensor.setParticipation( flag, val=True )
            -> flag can be either a string in ['wake', 'away', 'home', 'sleep'] or an integer bitmask
               when it's a string, val sets (True) or clears (False) that particular flag
               when it's a integer, the bitmask is set to val
        sensor.getParticipation( flag )
            -> flag can be either a string in ['wake', 'away', 'home', 'sleep'] or an integer bitmask
               returns True if (string) flag is set or (integer) bitmask matches exactly, otherwise returns False
            -> if the current value of all flags is wanted, the sensor.participation field can be read directly instead of using this function
        sensor.setUnknown2( val )
            -> sets the second unknown field to val.  'val' should be an integer in the range 0-255
        sensor.setUnknown3( val )
            -> sets the third unknown field to val.  'val' should be a 8 byte long byte array

    If multiple sensor options are going to be changed at the same time, it is much quicker to queue the updates and send them all at once:
        sensor.delayUpdates()
        ... call sensor.setName() or whatever here ...
        sensor.sendUpdates()



    Thermostat related functions:
        delayUpdates()
            -> when changing multiple settings, calling this first will cause them to be queued and sent all at once later
        sendUpdates()
            -> sends all queued updates at once and disables queueing (delayUpdates() will need to be called again if you want to queue things)

        setSetpoint( setpoint, cf=None )
            -> tried to auto-detect which setpoint you want to set (cooling or heating)) using the system mode and sets it
               if cf is None it assumes the given setpoint is the same temperature unit (degrees C or F) as the system temperature unit
        setCoolSetpoint( setpoint, cf=None )
            -> sets the cooling setpoint, for when the system mode is 'cool' or 'auto'
        setHeatSetpoint( setpoint, cf=None )
            -> sets the heating setpoint, for when the system mode is 'heat' or 'auto'
        setMiddleSetpoint( setpoint, cf=None )
            -> you should not need to call this, the thermostat handles it
               matches the cool or heat setpoint if the system is in those modes, or the midpoint between them if the mode is 'auto'

        setMode( mode )
            -> sets the system mode.  mode should be a string in ['cool', 'heat', 'auto', 'off']
        setFan( fan )
            -> sets the fan mode.  fan should be True (on), False (auto), or a string in ['on', 'auto', 'circ']
        setFanRuntime( runtime )
            -> when the fan mode is 'circ' this sets how many minutes per hour the fan is run to circulate the air
        setUnits( cf )
            -> sets the system temperature units.  cf should be a string in ['c', 'f']
        setSchedule( schedule )
            -> enables or disables the previously-created schedule.  creating a new schedule is not yet implemented
        setHold( hold )
            -> sets the temperature hold.  hold should be True (permhold), False (followschedule), or a string in ['permhold', 'temphold', 'followschedule']

        getCF(cf=None)
            -> parses the given cf value and returns either 'c' or 'f', or returns the system temperature units if cf is None
        isSingleSetpoint()
            -> returns True if the system is expecting a single temperature (mode is 'cool' or 'heat'), or False if it is expecting separate cool and heat setpoints

        sendPing()
            -> sends a async heartbeat packet
        sendStatusRequest()
            -> sends a async status request packet
        status()
            -> sends a synchronous status request packet and returns the result after parsing it
        receive()
            -> receives a single packet and returns the result after parsing it

        setValue( key, val )
            -> directly set a key in the dict.  you probably do not need to call this directly
        setValues( dict )
            -> directly set multiple keys in the dict.  you probably do not need to call this directly
        parseValue( key, val )
            -> converts a value to the format the DPS is expecting for that particular key.  you probably do not need to call this directly

    attributes:
        mode -> ['auto', 'cool', 'heat', 'off']
        fan -> ['auto', 'cycle', 'on']
        system -> current system state, ['fanon', 'coolfanon', 'alloff', 'heatfanon', 'heaton']
        setpoint_c -> either the setpoint when system is not in 'auto' mode, or the midpoint between the heating and cooling setpoints
        temp_set -> alias for setpoint_c
        setpoint_f and temp_set_f -> same as setpoint_c but in degrees F
        cooling_setpoint_c and upper_temp
        cooling_setpoint_f and upper_temp_f
        heating_setpoint_c and lower_temp
        heating_setpoint_f and lower_temp_f
        units and temp_unit_convert -> system temperature units, either 'c' or 'f'
        temp_correction -> offset to adjust displayed sensor temperatures
        temperature_c and temp_current -> current temperature in degrees C
        temperature_f and temp_current_f -> current temperature in degrees F
        humidity -> RH%
        fault -> fault flags, [e1, e2, e3]
        system_type -> '4'=heatpump
        home -> ??
        schedule -> binary blob
        schedule_enabled -> flag True/False
        hold -> ['permhold', 'temphold', 'followschedule']
        vacation -> binary blob
        fan_run_time -> when the fan mode is 'circ' this is how many minutes per hour the fan is run to circulate the air
        weather_forcast -> ??

    status() and receive() both return a dict containing both the raw DPS dict as well as a list of changed attributes in 'changed' and a list of changed sensors in 'changed_sensors'
     these can be used like:

            data = tstatdev.receive()
            if data and 'changed' in data:
                if 'system' in data['changed']:
                    print( 'System State changed, current temperature is:', tstatdev.temperature_c )
                for changed in data['changed']:
                    print( 'Changed:', changed, 'New Value:', getattr( tstatdev, changed ) )
            if data and 'changed_sensors' in data:
                for sensor in data['changed_sensors']:
                    print( 'Sensor Changed! Changed Attribs:%r DPS:%s ID:%s Name:"%s" Current Temperature: %r' % (sensor.changed, sensor.dps, sensor.id, sensor.name, sensor.temperature) )
                    if 'sensor_added' in sensor.changed:
                        print( 'New sensor was added!' )
                    if 'name' in sensor.changed:
                        print( 'Sensor was renamed!' )
                    for changed in sensor.changed:
                        print( 'Changed:', changed, 'New Value:', getattr( sensor, changed ) )

"""

import struct
import base64

from ..core import Device, log, HEART_BEAT, DP_QUERY, CONTROL


class ThermostatDevice(Device):
    """
    Represents a Tuya based 24v Thermostat.

    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """

    high_resolution = None
    delay_updates = False
    delayed_updates = { }
    sensorlists = [ ]
    sensor_dps = ('122', '125', '126', '127', '128')
    dps_data = {
        '2' : { 'name': 'mode', 'enum': ['auto', 'cool', 'heat', 'off'] },
        '16': { 'name': 'temp_set', 'alt': 'setpoint_c', 'scale': 100 },
        '17': { 'name': 'temp_set_f', 'alt': 'setpoint_f' },
        '18': { 'name': 'upper_temp_f', 'alt': 'cooling_setpoint_f', 'high_resolution': False },
        '19': { 'name': 'upper_temp', 'alt': 'cooling_setpoint_c', 'high_resolution': False },
        '20': { 'name': 'lower_temp_f', 'alt': 'heating_setpoint_f', 'high_resolution': False },
        '23': { 'name': 'temp_unit_convert', 'alt': 'units', 'enum': ['f','c'] },
        '24': { 'name': 'temp_current', 'alt': 'temperature_c', 'scale': 100 },
        '26': { 'name': 'lower_temp', 'alt': 'heating_setpoint_c', 'high_resolution': False },
        '27': { 'name': 'temp_correction', 'high_resolution': False },
        '29': { 'name': 'temp_current_f', 'alt': 'temperature_f' },
        '34': { 'name': 'humidity' },
        '45': { 'name': 'fault' },
        '107': { 'name': 'system_type' },
        '108': { 'name': 'upper_temp', 'alt': 'cooling_setpoint_c', 'scale': 100, 'high_resolution': True },
        '109': { 'name': 'lower_temp', 'alt': 'heating_setpoint_c', 'scale': 100, 'high_resolution': True },
        '110': { 'name': 'upper_temp_f', 'alt': 'cooling_setpoint_f', 'high_resolution': True },
        '111': { 'name': 'lower_temp_f', 'alt': 'heating_setpoint_f', 'high_resolution': True },
        '115': { 'name': 'fan', 'enum': ['auto', 'cycle', 'on'] },
        '116': { 'name': 'home' },
        '118': { 'name': 'schedule', 'base64': True },
        '119': { 'name': 'schedule_enabled' },
        '120': { 'name': 'hold', 'enum': ['permhold', 'temphold', 'followschedule'] },
        '121': { 'name': 'vacation', 'base64': True },
        #'122': { 'name': 'sensor_list_1', 'base64': True },
        '123': { 'name': 'fan_run_time' }, # presumably for when fan='circ'
        #'125': { 'name': 'sensor_list_2', 'base64': True },
        #'126': { 'name': 'sensor_list_3', 'base64': True },
        #'127': { 'name': 'sensor_list_4', 'base64': True },
        #'128': { 'name': 'sensor_list_5', 'base64': True },
        '129': { 'name': 'system', 'enum': ['fanon', 'coolfanon', 'alloff', 'heatfanon', 'heaton'] },
        '130': { 'name': 'weather_forcast' }
        }

    def __init__(self, dev_id, address, local_key="", dev_type="default", persist=True):
        super(ThermostatDevice, self).__init__(dev_id, address, local_key, dev_type)
        self.set_version(3.3)
        # set persistant so we can receive sensor broadcasts
        if persist:
            self.set_socketPersistent(True)

        for k in self.sensor_dps:
            self.sensorlists.append(ThermostatSensorList(k, self))

        for k in self.dps_data:
            setattr(self, self.dps_data[k]['name'], None)
            if 'alt' in self.dps_data[k]:
                setattr(self, self.dps_data[k]['alt'], None)

            if( ('scale' in self.dps_data[k]) or (('base64' in self.dps_data[k]) and self.dps_data[k]['base64']) ):
                setattr(self, 'raw_' + self.dps_data[k]['name'], None)

    def sensors( self ):
        for l in self.sensorlists:
            for s in l:
                yield s

    def delayUpdates( self ):
        self.delay_updates = True

    def setSetpoint( self, setpoint, cf=None ):
        if self.mode == 'cool':
            return self.setCoolSetpoint( self, setpoint, cf )
        elif self.mode == 'heat':
            return self.setHeatSetpoint( self, setpoint, cf )
        else:
            # no idea, let the thermostat figure it out
            return self.setMiddleSetpoint( self, setpoint, cf )

    def setCoolSetpoint( self, setpoint, cf=None ):
        k = 'cooling_setpoint_' + self.getCF( cf )
        return self.setValue( k, setpoint )

    def setHeatSetpoint( self, setpoint, cf=None ):
        k = 'heating_setpoint_' + self.getCF( cf )
        return self.setValue( k, setpoint )

    def setMiddleSetpoint( self, setpoint, cf=None ):
        k = 'setpoint_' + self.getCF( cf )
        return self.setValue( k, setpoint )

    def setMode( self, mode ):
        return self.setValue( 'mode', mode )

    def setFan( self, fan ):
        if not fan:
            fan = 'auto'
        elif fan is True:
            fan = 'on'
        return self.setValue( 'fan', fan )

    def setUnits( self, cf ):
        cf = self.getCF( cf )
        return self.setValue( 'temp_unit_convert', cf )

    def setSchedule( self, sch ):
        # FIXME set schedule data?
        if sch:
            return self.setValue( 'schedule_enabled', True )
        return self.setValue( 'schedule_enabled', False )

    def setHold( self, hold ):
        if hold is True:
            return self.setValue( 'hold', 'permhold' )

        if hold	is False:
            return self.setValue( 'hold', 'followschedule' )

        return self.setValue( 'hold', hold )

    def setFanRuntime( self, rt ):
        return self.setValue( 'fan_runtime', int(rt) )

    def setValue( self, key, val ):
        dps, val = self.parseValue( key, val )

        if not self.delay_updates:
            return self.set_value( dps, val, nowait=True )

        self.delayed_updates[dps] = val
        return True

    def setValues( self, val_dict ):
        for key in val_dict:
            dps, val = self.parseValue( key, val_dict[key] )
            self.delayed_updates[dps] = val

        if not self.delay_updates:
            payload = self.generate_payload(CONTROL, self.delayed_updates)
            self.delayed_updates = { }
            return self.send(payload)

        return True

    def parseValue( self, key, val ):
        dps = None
        for k in self.dps_data:
            if( (key == self.dps_data[k]['name']) or (('alt' in self.dps_data[k]) and (key == self.dps_data[k]['alt'])) ):
                if( ('high_resolution' not in self.dps_data[k]) or (self.dps_data[k]['high_resolution'] == self.high_resolution) ):
                    dps = k
                    break

        if not dps:
            log.warn( 'Requested key %r not found!' % key )
            return False

        ddata = self.dps_data[dps]

        if 'scale' in ddata:
            val = int( val * ddata['scale'] )

        if 'enum' in ddata:
            if val not in ddata['enum']:
                log.warn( 'Requested value %r for key %r/%r not in enum list %r !  Setting anyway...' % (val, dps, key, ddata['enum']) )

        if 'base64' in ddata:
            val = base64.b64encode( val ).decode('ascii')

        return ( dps, val )

    def sendUpdates( self ):
        self.delay_updates = False

        if len(self.delayed_updates) > 0:
            payload = self.generate_payload(CONTROL, self.delayed_updates)
            self.delayed_updates = { }
            return self.send(payload)

        return False

    def getCF( self, cf=None ):
        if cf is None:
            cf = getattr(self, 'temp_unit_convert', 'c')
        if cf == 'f':
            return 'f'
        return 'c'

    def isSingleSetpoint( self ):
        if self.mode == 'auto':
            return False

        return True

    def sendPing( self ):
        payload = self.generate_payload( HEART_BEAT )
        return self.send(payload)

    def sendStatusRequest( self ):
        payload = self.generate_payload( DP_QUERY )
        return self.send(payload)

    def status(self):
        data = super(ThermostatDevice, self).status()
        return self._inspect_data( data )

    def receive(self):
        data = self._send_receive(None)
        return self._inspect_data( data )

    def _inspect_data( self, data ):
        if not data:
            return data

        if 'dps' not in data:
            return data

        data['changed'] = [ ]
        data['changed_sensors'] = [ ]

        for i in range( len(self.sensor_dps) ):
            k = self.sensor_dps[i]
            if k in data['dps']:
                data['changed_sensors'] += self.sensorlists[i].update( data['dps'][k] )

        if self.high_resolution is None:
            for k in self.dps_data:
                if k in data['dps'] and 'high_resolution' in self.dps_data[k]:
                    self.high_resolution = self.dps_data[k]['high_resolution']
                    log.info('ThermostatDevice: high-resolution is now %r' % self.high_resolution)
                    break

        for k in data['dps']:
            if k in self.dps_data:
                name = checkname = self.dps_data[k]['name']
                val = data['dps'][k]
                if( ('scale' in self.dps_data[k]) or (('base64' in self.dps_data[k]) and self.dps_data[k]['base64']) ):
                    checkname = 'raw_' + name

                if getattr(self, checkname) != val:
                    data['changed'].append( name )
                    setattr(self, checkname, val)

                    if ('base64' in self.dps_data[k]) and self.dps_data[k]:
                        val = base64.b64decode( val )
                        data['changed'].append( checkname )
                        setattr(self, name, val)

                    if 'enum' in self.dps_data[k]:
                        if val not in self.dps_data[k]['enum']:
                            log.warn( 'Received value %r for key %r/%r not in enum list %r !  Perhaps enum list needs to be updated?' % (val, k, name, self.dps_data[k]['enum']) )

                    if 'scale' in self.dps_data[k]:
                        val /= self.dps_data[k]['scale']
                        data['changed'].append( checkname )
                        setattr(self, name, val)

                    if 'alt' in self.dps_data[k]:
                        data['changed'].append( self.dps_data[k]['alt'] )
                        setattr(self, self.dps_data[k]['alt'], val)

        return data

    def __iter__(self):
        for k in self.dps_data:
            if 'alt' in self.dps_data[k]:
                yield (self.dps_data[k]['alt'], getattr(self, self.dps_data[k]['alt']))
            yield (self.dps_data[k]['name'], getattr(self, self.dps_data[k]['name']))


class ThermostatSensorList(object):
    """
    Represents a list of sensors such as what gets returned in DPS 122

    Args:
        dps: the DPS of this sensor list
        parent_device: the ThermostatDevice which this sensor list is attached to


    The .update(sensordata_list) method parses an update
      Args:
        sensordata_list: either a base64-encoded string such as what DPS 122 contains, or an already-decoded byte string

    The .b64() method returns a base64-encoded string ready for sending
    The str() method returns a hexidecimal string to make it easier to visualize the data

    This class is iterable so you can easily loop through the individual sensors

    I.e.
        ## create a new list
        sensor_list_object = ThermostatSensorList( '122', self ) # for DPS 122

        ## populate the sensor data
        sensor_list_object.update( 'base64 string here' )

        ## send an update after changing a sensor value
        send_dps = { '122': sensor_list_object.b64() }
        payload = d.generate_payload(tinytuya.CONTROL, data)
        d.send(payload)
    """

    stated_count = 0
    actual_count = 0

    def __init__( self, dps, parent_device ):
        self.sensors = [ ]
        self.parent_device = parent_device

        if isinstance(dps, int):
            dps = str(dps)

        self.dps = dps

    def update(self, sensordata_list):
        changed = [ ]
        if isinstance(sensordata_list, str):
            sensordata_list = base64.b64decode( sensordata_list )
        elif not isinstance(sensordata_list, bytes):
            raise TypeError( 'Unhandled Thermostat Sensor List data type' )

        if( len(sensordata_list) < 1 ):
            self.stated_count = self.actual_count = 0
            self.sensors = [ ]
            return

        if ((len(sensordata_list) - 1) % 52) != 0:
            raise TypeError( 'Unhandled Thermostat Sensor List data length' )

        self.stated_count = sensordata_list[0]
        self.actual_count = int((len(sensordata_list) - 1) / 52)

        for i in range( self.actual_count ):
            if i < len(self.sensors):
                if self.sensors[i].parse(sensordata_list[(i*52)+1:((i+1)*52)+1]):
                    changed.append(self.sensors[i])
            else:
                self.sensors.append( self.ThermostatSensorData( self ) )
                self.sensors[i].parse(sensordata_list[(i*52)+1:((i+1)*52)+1])
                # instead of listing every field, just say it was added
                self.sensors[i].changed = [ 'sensor_added' ]
                self.sensors[i].sensor_added = True
                changed.append(self.sensors[i])

            # FIXME should we delete removed sensors?

        return changed

    def __repr__( self ):
        out = '%02X' % self.stated_count
        for s in self.sensors:
            out += str(s)
        return out

    def b64(self):
        b = bytearray( [self.stated_count] )
        for s in self.sensors:
            b += bytearray( bytes( s ) )
        return base64.b64encode( b ).decode('ascii')

    def __iter__(self):
        for s in self.sensors:
            yield s

    class ThermostatSensorData(object):
        # unpack the 52-byte long binary blob
        struct_format = '>I30s??h?BBBB?8s'
        keys = ('raw_id', 'raw_name', 'enabled', 'occupied', 'raw_temperature', 'online', 'participation', 'battery', 'firmware_version', 'unknown2', 'averaging', 'unknown3')
        parent_sensorlist = None
        raw_id = 0
        raw_name = b'\x00' * 30
        name = ''
        enabled = True
        occupied = True
        raw_temperature = 0
        temperature = 0.0
        online = True
        participation = 0
        battery = 0
        unknown2 = 0
        firmware_version = 0
        averaging = True
        unknown3 = b'\x00' * 8
        changed = [ ]
        want_update = [ ]
        sensor_added = True
        delay_updates = False

        def __init__( self, parent_sensorlist ):
            self.parent_sensorlist = parent_sensorlist

        def parse( self, sensordata ):
            new = struct.unpack( self.struct_format, sensordata )
            self.changed = [ ]
            self.sensor_added = False
            self.delay_updates = False

            for i in range(len(self.keys)):
                k = self.keys[i]

                if (k in self.want_update) or (getattr(self, k) != new[i]):
                    self.changed.append( k )
                    setattr(self, k, new[i])

            if 'raw_id' in self.changed:
                self.changed.remove('raw_id')
                self.changed.append('id')
                self.id = '%08x' % self.raw_id

            if 'raw_name' in self.changed:
                self.changed.remove('raw_name')
                self.changed.append('name')
                self.name = self.raw_name.strip(b'\x00').decode('utf8')

            if 'raw_temperature' in self.changed:
                self.changed.remove('raw_temperature')
                self.changed.append('temperature')
                self.temperature = self.raw_temperature / 100.0

            self.want_update = [ ]

            return (len(self.changed) != 0)

        def delayUpdates( self ):
            self.delay_updates = True

        def setName( self, name ):
            self.name = name
            # the app limits the length to 20 chars, so lets do the same
            self.raw_name = name[:20].encode('utf8').rjust( 30, b'\0' )
            self.want_update.append( 'raw_name' )
            self.sendUpdates(False)

        def setEnabled( self, ena ):
            self.enabled = ena
            self.want_update.append( 'enabled' )
            self.sendUpdates(False)

        def setOccupied( self, occ ):
            self.occupied = occ
            self.want_update.append( 'occupied' )
            self.sendUpdates(False)

        def setParticipation( self, flag, val=True ):
            self.want_update.append( 'participation' )

            if isinstance( flag, str ):
                mask = 1 << ( 'wake', 'away', 'home', 'sleep' ).index( flag )
                if val:
                    self.participation |= mask
                else:
                    self.participation &= ~mask
            elif isinstance( flag, int ):
                self.participation = flag

            self.sendUpdates(False)

        #def clearParticipation( self, flag ):
        #    return self.setParticipation( 0, False )

        def getParticipation( self, flag ):
            if isinstance( flag, str ):
                mask = 1 << ( 'wake', 'away', 'home', 'sleep' ).index( flag )
                if (self.participation & mask) == mask:
                    return True
                return False
            elif isinstance( flag, int ):
                if (self.participation & flag) == flag:
                    return True
                return False

            return False

        ## technically the battery level and firmware version can also be changed, no idea why someone would want to do that though
        #def setBattery( self, new_battery ):
        #def setFirmware( self, new_firmware ):

        def setUnknown2( self, u2 ):
            self.unknown2 = u2
            self.want_update.append( 'unknown2' )
            self.sendUpdates(False)

        def setUnknown3( self, u3 ):
            if not isinstance( u3, bytes ):
                u3 = bytes( u3 )

            if len( u3 ) < 8:
                u3 = u3 + (b'\x00' * (8 - len( u3 )))

            self.unknown3 = u3[:8]
            self.want_update.append( 'unknown3' )
            self.sendUpdates(False)

        def sendUpdates( self, force=True ):
            if (not force) and self.delay_updates:
                return

            self.delay_updates = False
            idx = self.parent_sensorlist.parent_device.sensor_dps.index( self.parent_sensorlist.dps )
            self.parent_sensorlist.parent_device.set_value( self.parent_sensorlist.dps, self.parent_sensorlist.b64(), nowait=True )

        def __repr__( self ):
            return bytearray( bytes(self) ).hex().upper()

        def __bytes__( self ):
            try:
                return struct.pack( self.struct_format, *(getattr(self, k) for k in self.keys) )
            except:
                log.exception( 'Error while attempting to pack %s with %r/%r/%r/%r/%r/%r/%r/%r/%r/%r/%r/%r', self.struct_format, *(getattr(self, k) for k in self.keys) )
                raise

