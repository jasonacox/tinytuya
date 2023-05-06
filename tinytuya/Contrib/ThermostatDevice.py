# TinyTuya Contrib ThermostatDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart thermostats

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Module Author: uzlonewolf (https://github.com/uzlonewolf)

 Local Control Classes
    ThermostatDevice(..., version=3.3, persist=True)
        This class uses a default version of 3.3 and enables persistance so we can catch temperature updates
        See OutletDevice() for the other constructor arguments

 Additional Classes
    ThermostatSensorList(dps, parent_device)
        Mainly used internally, exposed in case it's useful elsewhere
        The 'dps' argument should be the DPS ID of the list so it knows what DPS to send when updating a sensor option
        The 'parent_device' argument should be the ThermostatDevice() this sensor list belongs to


    Sensor related functions:
        tstatdev = ThermostatDevice(...)
        tstatdev.sensors
            -> an iterable list of all the sensors that can also be acessed like a dict:

              for sensor in tstatdev.sensors:
                  if not sensor.online:
                      print( 'Sensor %r offline!' % sensor.name )

              if tstatdev.sensors['12345678'].battery < 10:
                  print( 'Sensor %r low battery!' % tstatdev.sensors['12345678'].name )
              else:
                  print( 'Sensor %r battery %d%%' % (tstatdev.sensors['12345678'].name, tstatdev.sensors['12345678'].battery ) )

            dict access matches against both name and id:
              tstatdev.sensors['name'] and tstatdev.sensors['id'] both work

        When sensor values change, the sensor object is also available in data['changed_sensors'].  i.e.
            data = tstatdev.receive()
            if data and 'changed_sensors' in data:
                for sensor in data['changed_sensors']:
                    if 'temperature' in sensor['changed'] and sensor.online:
                        ...do something with sensor.temperature or whatever...

        sensors have the following attributes:
          id -> ID # of the sensor as a hex string
          raw_id -> ID # of the sensor as a integer
          name -> decoded and trimmed name of the sensor
          raw_name -> NUL-padded name of the sensor as a byte array
          enabled -> sensor enabled flag True/False
          occupied -> sensor detected occupancy flag True/False
          temperature -> temperature in degrees C as a float
          raw_temperature -> temperature as reported by the sensor (degrees C * 100)
          temperature_used -> the rounded temperature used in averaging calculations
          raw_temperature_used -> the rounded temperature used in averaging calculations (degrees C * 100)
          online -> sensor online flag True/False
          participation -> schedule participation bitmask ['wake', 'away', 'home', 'sleep']
          battery -> battery percentage remaining
          unknown2 -> value of unknown field, integer 0-255
          firmware_version -> firmware version * 10 (01 = v0.1)
          averaging -> sensor currently participation in the temperature averaging (occupied is True and participation flag for the current schedule mode is set)
          unknown3 -> value of unknown field, 8 byte long byte array
          changed -> list of attributes which have changed since last update

        sensors also have the following methods:
          sensor.setName( new_name )
          sensor.setEnabled( enabled )
          sensor.setOccupied( occupied )
              -> not really useful for remote sensors as they get overwritten on the next update
          sensor.setParticipation( flag, val=True )
              -> flag can be either a string in ['wake', 'away', 'home', 'sleep'] or an integer bitmask
                 when it's a string, val sets (True) or clears (False) that particular flag
                 when it's a integer, the bitmask is set to flag and val is ignored
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
        mode -> ['auto', 'cool', 'heat', 'emergencyheat', 'off']
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
        system_type -> '4'=heatpump, '5'=2-stage heatpump?
        home -> ??
        schedule -> ThermostatSchedule() class
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
                    print( 'Sensor Changed! Changed Attribs:%r DPS:%s ID:%s Name:"%s" Current Temperature: %r' % (sensor.changed, sensor.parent_sensorlist.dps, sensor.id, sensor.name, sensor.temperature) )
                    if 'sensor_added' in sensor.changed:
                        print( 'New sensor was added!' )
                    if 'name' in sensor.changed:
                        print( 'Sensor was renamed!' )
                    for changed in sensor.changed:
                        print( 'Changed:', changed, 'New Value:', getattr( sensor, changed ) )

    ThermostatSchedule class:

        !! WARNING !! The thermostat does NOT send the current schedule when you request the status, it only sends it when it has changed.  So, you
            must either a) set the entire schedule or b) change it in the app or on the thermostat itself while tinytuya is running.  Changes to a
            single day/period/value can only be made once this has been done.

        'day' is a case-insensitive string starting with su, m, tu, w, th, f, sa or an integer in the range 0-6
        'period' is a case-insensitive string starting with w[ake], a[way], h[ome], s[leep], e[xtra] or an integer in the range 0-4
            -> Only periods 0-3 (wake-sleep) show up in the app or on the thermostat! (4 (extra) is hidden)

        Schedule parameters can be accessed directly by dict via name or index:
            tstatdev.schedule[1][0].coolto = 25.0 or
            tstatdev.schedule['monday']['wake'].coolto = 25.0 or
            tstatdev.schedule['m']['w'].coolto = 25.0 or
            tstatdev.schedule['MoNdAySsUcK']['WakeMeUp'].coolto = 25.0
        all mean the same thing.  Parameters can also be set using the .setPeriod method:
            tstatdev.schedule.setPeriod( day_of_week, period, coolto=25.0, heatto=10.0, time=0, participation=(period & 3) )
        To disable a schedule period (set the time to 0xFFFF) you can:
            tstatdev.schedule.setPeriod( day, 4, delete=True)

        Once a day is set you can copy it to a different day with:
            # copy sunday (0) to monday-saturday (1-6)
            for i in range(6):
                tstatdev.schedule.copyDay( 0, i+1 )

        Individual periods can also be copied:
            tstatdev.schedule.copyPeriod( src_day, src_period, dst_day, dst_period )
"""

import struct
import base64

from ..core import Device, log, HEART_BEAT, DP_QUERY, CONTROL

class ThermostatDevice(Device):
    """
    Represents a Tuya based 24v Thermostat.
    """

    sensor_dps = ('122', '125', '126', '127', '128')
    dps_data = {
        '2' : { 'name': 'mode', 'enum': ['auto', 'cool', 'heat', 'emergencyheat', 'off'] },
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
        '107': { 'name': 'system_type', 'decode': int },
        '108': { 'name': 'upper_temp', 'alt': 'cooling_setpoint_c', 'scale': 100, 'high_resolution': True },
        '109': { 'name': 'lower_temp', 'alt': 'heating_setpoint_c', 'scale': 100, 'high_resolution': True },
        '110': { 'name': 'upper_temp_f', 'alt': 'cooling_setpoint_f', 'high_resolution': True },
        '111': { 'name': 'lower_temp_f', 'alt': 'heating_setpoint_f', 'high_resolution': True },
        '115': { 'name': 'fan', 'enum': ['auto', 'cycle', 'on'] },
        '116': { 'name': 'home' },
        '118': { 'name': 'schedule', 'base64': True, 'selfclass': 'ThermostatSchedule' },
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

    def __init__(self, *args, **kwargs):
        # set the default version to 3.3 as there are no 3.1 devices
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.3
        # set persistant so we can receive sensor broadcasts
        if 'persist' not in kwargs:
            kwargs['persist'] = True
        super(ThermostatDevice, self).__init__(*args, **kwargs)

        self.high_resolution = None
        self.schedule = None
        self.delay_updates = False
        self.delayed_updates = { }
        self.sensorlists = [ ]
        self.sensors = self.SensorList( self )

        for k in self.sensor_dps:
            self.sensorlists.append(ThermostatSensorList(k, self))

        for k in self.dps_data:
            val = None

            if 'selfclass' in self.dps_data[k]:
                val = getattr( self, self.dps_data[k]['selfclass'] )( self, k )

            setattr( self, self.dps_data[k]['name'], val )
            if 'alt' in self.dps_data[k]:
                setattr( self, self.dps_data[k]['alt'], val )

            if( ('scale' in self.dps_data[k]) or (('base64' in self.dps_data[k]) and self.dps_data[k]['base64']) or ('selfclass' in self.dps_data[k]) or ('decode' in self.dps_data[k]) ):
                self.dps_data[k]['check_raw'] = True

            if 'check_raw' in self.dps_data[k] and self.dps_data[k]['check_raw']:
                setattr( self, 'raw_' + self.dps_data[k]['name'], None )

    def delayUpdates( self ):
        self.delay_updates = True

    def setSetpoint( self, setpoint, cf=None ):
        if self.mode == 'cool':
            return self.setCoolSetpoint( setpoint, cf )
        elif self.mode == 'heat' or self.mode == 'emergencyheat':
            return self.setHeatSetpoint( setpoint, cf )
        else:
            # no idea, let the thermostat figure it out
            return self.setMiddleSetpoint( setpoint, cf )

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

        if hold is False:
            return self.setValue( 'hold', 'followschedule' )

        return self.setValue( 'hold', hold )

    def setFanRuntime( self, rt ):
        return self.setValue( 'fan_run_time', int(rt) )

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

        if 'encode' in ddata:
            val = ddata['encode']( val )

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
        return super(ThermostatDevice, self).status()

    def receive(self):
        return self._send_receive(None)

    def _process_response( self, data ):
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
                name = self.dps_data[k]['name']
                checkname = ('raw_' + name) if 'check_raw' in self.dps_data[k] and self.dps_data[k]['check_raw'] else name
                val = data['dps'][k]

                if getattr( self, checkname ) == val:
                    continue

                data['changed'].append( name )
                if name != checkname: data['changed'].append( checkname )
                setattr( self, checkname, val )

                if ('base64' in self.dps_data[k]) and self.dps_data[k]:
                    val = base64.b64decode( val )

                if 'selfclass' in self.dps_data[k]:
                    getattr( self, name ).update( val )

                    if 'alt' in self.dps_data[k]:
                        data['changed'].append( self.dps_data[k]['alt'] )
                        setattr( self, self.dps_data[k]['alt'], getattr( self, name ) )
                else:
                    if 'decode' in self.dps_data[k]:
                        val = self.dps_data[k]['decode']( val )

                    if 'scale' in self.dps_data[k]:
                        val /= self.dps_data[k]['scale']

                    setattr(self, name, val)

                    if 'enum' in self.dps_data[k]:
                        if val not in self.dps_data[k]['enum']:
                            log.warn( 'Received value %r for key %r/%r not in enum list %r !  Perhaps enum list needs to be updated?' % (val, k, name, self.dps_data[k]['enum']) )

                    if 'alt' in self.dps_data[k]:
                        data['changed'].append( self.dps_data[k]['alt'] )
                        setattr( self, self.dps_data[k]['alt'], val )

        return data

    def __iter__(self):
        for k in self.dps_data:
            if 'alt' in self.dps_data[k]:
                yield (self.dps_data[k]['alt'], getattr(self, self.dps_data[k]['alt']))
            yield (self.dps_data[k]['name'], getattr(self, self.dps_data[k]['name']))

    class SensorList:
        def __init__( self, parent ):
            self.parent = parent

        def find_sensor( self, name ):
            for l in self.parent.sensorlists:
                for s in l:
                    if s.id == name or s.name == name:
                        return s

            return None

        def __getitem__( self, key ):
            if isinstance( key, str ):
                return self.find_sensor( key )
            elif not isinstance( key, int ):
                return getattr( self, key )

            i = 0
            for l in self.parent.sensorlists:
                for s in l:
                    if i == key:
                        return s
                    i += 1

            return None

        def __len__( self ):
            i = 0
            for l in self.parent.sensorlists:
                for s in l:
                    i += 1
            return i

        def __iter__( self ):
            for l in self.parent.sensorlists:
                for s in l:
                    yield s

        def __call__( self ):
            for l in self.parent.sensorlists:
                for s in l:
                    yield s


    class ThermostatSchedule(object):
        class ScheduleDay:
            class SchedulePeriod:
                def __init__( self, sched ):
                    self.sched = sched
                    self.participation = 0xFF
                    self.time = 0xFFFF
                    self.heatto = -32768
                    self.coolto = -32768

                def __setitem__( self, key, data ):
                    if not isinstance( key, int ):
                        setattr( self, key, data )

                    if key == 0: self.participation = data
                    elif key == 1: self.time = data
                    elif key == 2: self.heatto = data
                    elif key == 3: self.coolto = data
                    else: raise IndexError('Numeric index must be an integer 0-3')

                def __getitem__( self, key ):
                    if not isinstance( key, int ):
                        return getattr(self, key)

                    if key == 0: return self.participation
                    elif key == 1: return self.time
                    elif key == 2: return self.heatto
                    elif key == 3: return self.coolto
                    else: raise IndexError('Numeric index must be an integer 0-3')

                def __len__( self ):
                    return 4

                def __iter__( self ):
                    yield self.participation
                    yield self.time
                    yield self.heatto
                    yield self.coolto

                def __bytes__( self ):
                    cf = self.sched.parent.getCF( self.sched.cf )

                    if self.heatto < -100 or self.heatto > 100:
                        heatto = round(self.heatto)
                    else:
                        heatto = self.heatto
                        # schedule is in C, so convert from F
                        if cf == 'f':
                            heatto = (heatto - 32) / 1.8
                        heatto = round(heatto * 100)
                        heatmod = heatto % 50
                        heatto -= heatmod
                        if heatmod >= 25: heatto += 50

                    if self.coolto < -100 or self.coolto > 100:
                        coolto = round(self.coolto)
                    else:
                        coolto = self.coolto
                        # schedule is in C, so convert from F
                        if cf == 'f':
                            coolto = (coolto - 32) / 1.8
                        coolto = round(coolto * 100)
                        coolmod = coolto % 50
                        coolto -= coolmod
                        if coolmod >= 25: coolto += 50

                    log.info( 'CF is: %r %r %r cool: %r %r %r', cf, self.heatto, heatto / 100, self.coolto, coolto / 100, self.time )

                    # if self.time is a string then it needs to be in 24-hour HH:MM[:SS] format!
                    if isinstance( self.time, str ):
                        tparts = self.time.split( ':' )
                        if len(tparts) >= 2:
                            ptime = (int(tparts[0]) * 60) + int(tparts[1])
                        else:
                            ptime = int(tparts[0])
                    elif isinstance( self.time, int ):
                        ptime = self.time
                    else:
                        ptime = int(self.time)

                    return struct.pack( '>BHhh', self.participation, ptime, heatto, coolto )

                def __repr__( self ):
                    return bytes(self).hex().upper()

            def __init__( self, sched ):
                self.sched = sched
                self.periods = [ ]
                for i in range( 5 ):
                    sp = self.SchedulePeriod( sched )
                    self.periods.append( sp )

            def period_to_idx( self, period ):
                if isinstance( period, int ):
                    if period >= 0 and period < 5:
                        return period
                    raise ValueError('"period" must be an integer in the range 0-4 or a string containing the period name')

                if not isinstance( period, str ):
                    raise ValueError('"period" must be an integer in the range 0-4 or a string containing the period name')

                period = period[0].lower()
                if period == 'w': return 0 # wake
                if period == 'a': return 1 # away
                if period == 'h': return 2 # home
                if period == 's': return 3 # sleep
                if period == 'e': return 4 # extra

                raise ValueError('"period" must be an integer in the range 0-4 or a string containing the period name')

            def __setitem__( self, key, data ):
                if isinstance( key, str ):
                    key = self.period_to_idx( key )
                elif not isinstance( key, int ):
                    setattr( self, key, data )

                if key < 0 or key > 4:
                    raise IndexError('Numeric index must be an integer 0-4')

                self.periods[key] = data

            def __getitem__( self, key ):
                if isinstance( key, str ):
                    key = self.period_to_idx( key )
                elif not isinstance( key, int ):
                    return getattr( self, key )

                if key < 0 or key > 4:
                    raise IndexError('Numeric index must be an integer 0-4')

                return self.periods[key]

            def __len__( self ):
                return 5

            def __iter__( self ):
                for p in self.periods:
                    yield p

            def __bytes__( self ):
                ret = bytearray()
                for period in self.periods:
                    ret += bytearray( bytes( period ) )
                return bytes(ret)

            def __repr__( self ):
                return bytes(self).hex().upper()


        def __init__( self, parent, dps ):
            self.parent = parent
            self.dps = dps
            self.have_data = False
            self.cf = None

            self.day_data = [ ]

            for i in range( 7 ):
                sd = self.ScheduleDay( self )
                self.day_data.append( sd )

        def day_to_idx( self, day ):
            if isinstance( day, int ):
                if day >= 0 and day < 7:
                    return day
                raise ValueError('"day" must be an integer in the range 0-6 or a string containing the day name')

            if not isinstance( day, str ):
                raise ValueError('"day" must be an integer in the range 0-6 or a string containing the day name')

            day = day[:2].lower()
            if day == 'su':   return 0
            if day[0] == 'm': return 1
            if day == 'tu':   return 2
            if day[0] == 'w': return 3
            if day == 'th':   return 4
            if day[0] == 'f': return 5
            if day == 'sa':   return 6

            raise ValueError('"day" must be an integer in the range 0-6 or a string containing the day name')

        def copyDay( self, src, dst ):
            src = self.day_to_idx( src )
            dst = self.day_to_idx( dst )

            for period in range( len(self.day_data[src]) ):
                for itm in range( len(self.day_data[src][period]) ):
                    self.day_data[dst][period][itm] = self.day_data[src][period][itm]

            return self.have_data

        def copyPeriod( self, src_day, src_period, dst_day, dst_period ):
            src_day = self.day_to_idx( src_day )
            #src_period = self.period_to_idx( src_period )
            dst_day = self.day_to_idx( dst_day )
            #dst_period = self.period_to_idx( dst_period )

            for itm in range( len(self.day_data[src_day][src_period]) ):
                self.day_data[dst_day][dst_period][itm] = self.day_data[src_day][src_period][itm]

            return self.have_data

        def setPeriod( self, day, period, **kwargs ):
            day = self.day_to_idx( day )
            #period = self.period_to_idx( period )

            if 'delete' in kwargs:
                self.day_data[day][period] = self.ScheduleDay.SchedulePeriod( self )

            if 'participation' in kwargs:
                self.day_data[day][period].participation = kwargs['participation']

            if 'time' in kwargs:
                self.day_data[day][period].time = kwargs['time']

            if 'heatto' in kwargs:
                self.day_data[day][period].heatto = kwargs['heatto']

            if 'coolto' in kwargs:
                self.day_data[day][period].coolto = kwargs['coolto']

            if self.day_data[day][period][0] > 3 and self.day_data[day][period][1] < 1440:
                if self.day_data[day][period][0] != 0xFF:
                    log.warn('Selected participation flag is out of range, setting to %d', period)
                self.day_data[day][period][0] = period & 3

        def setCF( self, cf ):
            self.cf = cf

        def update( self, data ):
            self.have_data = False

            if len(data) % 7 != 0:
                log.warn( 'Schedule data is in an unknown format, ignoring schedule' )
                return False

            cf = self.parent.getCF( self.cf )
            daylen = int(len(data) / 7)
            for dow in range( 7 ):
                offset = dow * daylen
                day = data[offset:offset+daylen]

                if len(day) % 7 != 0:
                    log.warn( 'Schedule day data for day %d is in an unknown format, ignoring schedule' % dow )
                    return False

                periods = len(day) / 7
                period = -1

                for dayoffset in range( 0, len(day), 7 ):
                    period += 1
                    perioddata = day[dayoffset:dayoffset+7]

                    if len(perioddata) != 7:
                        log.warn( 'Schedule period data for period %d on day %d is in an unknown format, ignoring schedule' % (period, dow) )
                        return False

                    newdata = struct.unpack( '>BHhh', perioddata )

                    for i in range( len(newdata) ):
                        self.day_data[dow][period][i] = newdata[i]

                    # display the time as 24-hour HH:MM
                    if self.day_data[dow][period].time < 1440:
                        hrs = int(self.day_data[dow][period].time / 60)
                        mins = self.day_data[dow][period].time % 60
                        self.day_data[dow][period].time = '%d:%02d' % (hrs,mins)

                    if self.day_data[dow][period].heatto > -10000 and self.day_data[dow][period].heatto < 10000:
                        self.day_data[dow][period].heatto /= 100
                        if cf == 'f':
                            self.day_data[dow][period].heatto = round((self.day_data[dow][period].heatto * 1.8) + 32)

                    if self.day_data[dow][period].coolto > -10000 and self.day_data[dow][period].coolto < 10000:
                        self.day_data[dow][period].coolto /= 100
                        if cf == 'f':
                            self.day_data[dow][period].coolto = round((self.day_data[dow][period].coolto * 1.8) + 32)

            self.have_data = True

        def save( self ):
            return self.parent.set_value( self.dps, self.b64(), nowait=True )

        def __bytes__( self ):
            ret = bytearray()
            for daydata in self.day_data:
                ret += bytearray( bytes( daydata ) )

            return bytes(ret)

        def __repr__( self ):
            #if not self.have_data:
            #    return ''
            return bytes(self).hex().upper()

        def b64(self):
            return base64.b64encode( bytes(self) ).decode('ascii')

        def __iter__(self):
            for d in self.day_data:
                yield d

        def __setitem__( self, key, data ):
            if isinstance( key, str ):
                if key == 'cf':
                    self.cf = data
                    return
                key = self.day_to_idx( key )
            elif not isinstance( key, int ):
                setattr( self, key, data )

            if key < 0 or key > 6:
                raise IndexError('Numeric index must be an integer 0-6')

            self.day_data[key] = data

        def __getitem__( self, key ):
            if isinstance( key, str ):
                key = self.day_to_idx( key )
            elif not isinstance( key, int ):
                return getattr( self, key )

            if key < 0 or key > 6:
                raise IndexError('Numeric index must be an integer 0-6')

            return self.day_data[key]


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

    def __init__( self, dps, parent_device ):
        self.stated_count = 0
        self.actual_count = 0
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

        lenmod = len(sensordata_list) % 52

        if lenmod == 1:
            self.stated_count = sensordata_list[0]
        elif lenmod == 0:
            self.stated_count = None
        else:
            raise TypeError( 'Unhandled Thermostat Sensor List data length' )

        self.actual_count = int((len(sensordata_list) - lenmod) / 52)

        for i in range( self.actual_count ):
            if i < len(self.sensors):
                if self.sensors[i].parse(sensordata_list[(i*52)+lenmod:((i+1)*52)+lenmod]):
                    changed.append(self.sensors[i])
            else:
                self.sensors.append( self.ThermostatSensorData( self ) )
                self.sensors[i].parse(sensordata_list[(i*52)+lenmod:((i+1)*52)+lenmod])
                # instead of listing every field, just say it was added
                self.sensors[i].changed = [ 'sensor_added' ]
                self.sensors[i].sensor_added = True
                changed.append(self.sensors[i])

            # FIXME should we delete removed sensors?

        return changed

    def __repr__( self ):
        if self.stated_count is not None:
            out = '%02X' % self.stated_count
        else:
            out = ''

        for s in self.sensors:
            out += str(s)

        return out

    def b64(self):
        if self.stated_count is not None:
            b = bytearray( [self.stated_count] )
        else:
            b = bytearray()

        for s in self.sensors:
            b += bytearray( bytes( s ) )
        return base64.b64encode( b ).decode('ascii')

    def __iter__(self):
        for s in self.sensors:
            yield s

    class ThermostatSensorData(object):
        # unpack the 52-byte long binary blob
        struct_format = '>I30s??h?BBBB?h6s'
        keys = ('raw_id', 'raw_name', 'enabled', 'occupied', 'raw_temperature_used', 'online', 'participation', 'battery', 'firmware_version', 'unknown2', 'averaging', 'raw_temperature', 'unknown3')
        raw_temperature_used_idx = keys.index( 'raw_temperature_used' )
        raw_temperature_idx = keys.index( 'raw_temperature' )

        def __init__( self, parent_sensorlist ):
            self.parent_sensorlist = parent_sensorlist
            self.raw_id = 0
            self.raw_name = b'\x00' * 30
            self.name = ''
            self.enabled = True
            self.occupied = True
            self.raw_temperature = 0
            self.temperature = 0.0
            self.raw_temperature_used = 0
            self.temperature_used = 0.0
            self.online = True
            self.participation = 0
            self.battery = 0
            self.unknown2 = 0
            self.firmware_version = 0
            self.averaging = True
            self.unknown3 = b'\x00' * 8
            self.changed = [ ]
            self.want_update = [ ]
            self.sensor_added = True
            self.delay_updates = False


        def parse( self, sensordata ):
            new = struct.unpack( self.struct_format, sensordata )
            self.changed = [ ]
            self.sensor_added = False
            self.delay_updates = False

            if new[self.raw_temperature_idx] == 0:
                new = list(new)
                new[self.raw_temperature_idx] = new[self.raw_temperature_used_idx]
                # "int( N / 50 ) * 50" does a pretty good job of matching what the thermostat does
                new[self.raw_temperature_used_idx] = int(new[self.raw_temperature_used_idx] / 50) * 50

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

            if 'raw_temperature_used' in self.changed:
                self.changed.remove('raw_temperature_used')
                self.changed.append('temperature_used')
                self.temperature_used = self.raw_temperature_used / 100.0

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
            return bytes(self).hex().upper()

        def __bytes__( self ):
            try:
                return struct.pack( self.struct_format, *(getattr(self, k) for k in self.keys) )
            except:
                log.exception( 'Error while attempting to pack %s with %r/%r/%r/%r/%r/%r/%r/%r/%r/%r/%r/%r', self.struct_format, *(getattr(self, k) for k in self.keys) )
                raise

