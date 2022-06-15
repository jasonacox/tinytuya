
import struct
import base64

from .core import Device
from .core import log
#from .core import *

class ThermostatDevice(Device):
    """
    Represents a Tuya based 24v Thermostat.

    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """

    high_resolution = None
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
        '123': { 'name': 'fan_runtime' },
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
            self.sensorlists.append(self.ThermostatSensorList(k))

        for k in self.dps_data:
            setattr(self, self.dps_data[k]['name'], None)
            if 'alt' in self.dps_data[k]:
                setattr(self, self.dps_data[k]['alt'], None)

            if( ('scale' in self.dps_data[k]) or (('base64' in self.dps_data[k]) and self.dps_data[k]['base64']) ):
                setattr(self, 'raw_' + self.dps_data[k]['name'], None)

    class ThermostatSensorList(object):
        """
        Represents a list of sensors such as what gets returned in DPS 122

        Args:
            sensordata_list: either a base64-encoded string such as what DPS 122 contains, or an already-decoded byte string
            dps: the DPS of this sensor list

        The str() method returns a base64-encoded string ready for sending
        The repr() method returns a hexidecimal string to make it easier to see the data

        This class is iterable so you can easily loop through the individual sensors

        I.e.
            sensor_list_object = ThermostatSensorList( '122' ) # for DPS 122
            sensor_list_object.update( 'base64 string here' )
            send_dps = { '122': sensor_list_object.b64() }
            payload = d.generate_payload(tinytuya.CONTROL, data)
            d.send(payload)
        """

        stated_count = 0
        actual_count = 0

        def __init__( self, dps ):
            self.sensors = [ ]
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
                    if self.sensors[i].update(sensordata_list[(i*52)+1:((i+1)*52)+1]):
                        changed.append(self.sensors[i])
                else:
                    self.sensors.append( self.ThermostatSensorData( self.dps ) )
                    self.sensors[i].update(sensordata_list[(i*52)+1:((i+1)*52)+1])
                    # instead of listing every field, just say it was added
                    self.sensors[i].changed = [ 'sensor_added' ]
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
            struct_format = '>I30sB?h?BBBB?8s'
            dps = None
            raw_id = 0
            raw_name = b'\x00' * 30
            unknown1 = 0
            occupied = False
            raw_temperature = 0
            temperature = 0
            online = False
            participation = 0
            battery = 0
            unknown2 = 0
            firmware_version = 0
            averaging = False
            unknown3 = b'\x00' * 8
            changed = [ ]

            def __init__( self, dps ):
                self.dps = dps

            def update( self, sensordata ):
                keys = ('raw_id', 'raw_name', 'unknown1', 'occupied', 'raw_temperature', 'online', 'participation', 'battery', 'firmware_version', 'unknown2', 'averaging', 'unknown3')
                new = struct.unpack( self.struct_format, sensordata )
                self.changed = [ ]

                for i in range(len(keys)):
                    k = keys[i]

                    if getattr(self, k) != new[i]:
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

                return (len(self.changed) != 0)

            def setName( self, name ):
                self.name = name
                # the app limits the length to 20 chars, so lets do the same
                self.raw_name = name[:20].encode('utf8').rjust( 30, b'\0' )

            def __repr__( self ):
                return bytearray( bytes(self) ).hex().upper()

            def __bytes__( self ):
                return struct.pack( self.struct_format, self.raw_id, self.raw_name, self.unknown1, self.occupied, int(self.temperature*100), self.online, self.participation, self.battery, self.firmware_version, self.unknown2, self.averaging, self.unknown3 )

    def sensors( self ):
        for l in self.sensorlists:
            for s in l:
                yield s

    def setSensorOccupied( self, sen, occ ):
        sen.occupied = occ
        idx = self.sensor_dps.index( sen.dps )
        self.set_value( sen.dps, self.sensorlists[idx].b64(), nowait=True )
        # delete the old value so we'll get a occupancy-updated message
        sen.occupied = None

    def setSensorName( self, sen, name ):
        oldname = sen.name
        oldraw = sen.raw_name
        sen.setName( name )
        idx = self.sensor_dps.index( sen.dps )
        self.set_value( sen.dps, self.sensorlists[idx].b64(), nowait=True )
        # delete the old name so we'll get a name-updated message
        sen.raw_name = sen.name = None

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
        return self.setValue( 'hold', hold )

    def setFanRuntime( self, rt ):
        return self.setValue( 'fan_runtime', int(rt) )

    def setValue( self, key, val ):
        dps = None
        for k in self.dps_data:
            if( (key == k['name']) or ('alt' in k and key == k['alt']) ):
                if( ('high_resolution' not in k) or (k['high_resolution'] == self.high_resolution) ):
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

        return self.set_value( dps, val, nowait=True )

    def getCF( self, cf=None ):
        if cf is None:
            cf = getattr(self, 'temp_unit_convert', 'c')
        if cf == 'f':
            return 'f'
        return 'c'

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
