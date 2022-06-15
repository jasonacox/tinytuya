
import struct
import base64

from .core import Device
#from .core import log
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

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(ThermostatDevice, self).__init__(dev_id, address, local_key, dev_type)
        self.set_version(3.3)
        # set persistant so we can receive sensor broadcasts
        self.set_socketPersistent(True)
        # load the initial data
        #self.status()

        for k in self.sensor_dps:
            self.sensorlists.append(self.ThermostatSensorList(k))

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
                    self.sensors[i].changed = [ 'sensor_added' ]
                    changed.append(self.sensors[i])

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

        data['changed'] = { }

        data['changed']['sensors'] = [ ]
        for i in range( len(self.sensor_dps) ):
            k = self.sensor_dps[i]
            if k in data['dps']:
                data['changed']['sensors'] += self.sensorlists[i].update( data['dps'][k] )

        if len(data['changed']['sensors']) < 1:
            del data['changed']['sensors']









        if len(data['changed']) < 1:
            del data['changed']

        return data
