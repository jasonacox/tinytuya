# TinyTuya Mapped Device
# -*- coding: utf-8 -*-
"""
 Python module to map Tuya DPs to names

 Author: uzlonewolf https://github.com/uzlonewolf
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    MappedDevice(..., product_id="...", mappingfile=DPMAPPINGSFILE, mapping=None, cloud=None)
        product_id (str): Product ID string to match in mapping file
        mappingfile (str, optional): Name of JSON file to load mapping data from.  Default: 
        mapping (dict, optional): Additional mapping data to use in addition to loaded file
        cloud (Cloud object): Initilized tinytuya.Cloud object to use to download the mapping if needed

        See OutletDevice() for common constructor arguments

        At least one of product_id+mappingfile, mapping, or cloud must be provided!
        If product_id is not provied, a lookup for it in DEVICEFILE will be attempted

 Functions
    MappedDevice
        set_mapping(mapping_dict)

    Inherited
        See OutletDevice()

 Attributes
    .dps
        Set or Get mapped values
            val = MappedDevice.dps.some_dp_name
              or
            val = MappedDevice.dps['some_dp_name']
              or
            MappedDevice.dps.some_dp_name = new_value
              or
            MappedDevice.dps['some_dp_name'] = new_value
"""

import json
from .core import Device, log, device_info

class _dp_type_raw():
    def __init__( self, data ):
        if data and type(data) == dict and 'values' in data and type(data['values']) == dict:
            self.values = data['values']
        else:
            self.values = {}

        if 'unit' in self.values:
            self.unit = self.values['unit']
        else:
            self.unit = None

    def parse_value( self, val ):
        return val

    def encode_value( self, val ):
        return val

class _dp_type_bitmap( _dp_type_raw ):
    def __init__( self, data ):
        super( _dp_type_bitmap, self ).__init__( data )
        opts = []

        if 'label' in self.values and type(self.values['label']) == list:
            opts = self.values['label']

        if 'maxlen' in self.values and type(self.values['maxlen']) == int:
            maxlen = int(self.values['maxlen'])
        else:
            maxlen = len(opts)

        if maxlen > len(opts):
            for i in range( len(opts), maxlen ):
                opts.append( 'opt-%d' % i )
        elif len(opts) > maxlen:
            maxlen = len(opts)

        self.bitmap = tuple(opts)
        self.bitmap_maxlen = maxlen

    def parse_value( self, val ):
        newval = []
        i = 0
        while (val > 0) and (i < self.bitmap_maxlen):
            if (val & 1):
                newval.append( self.bitmap[i] )
            i += 1
            val >>= 1
        return tuple(newval)

    def encode_value( self, val ):
        if type(val) == int:
            maxlen = (1 << self.bitmap_maxlen) - 1
            if (val < 0) or (val > maxlen):
                raise ValueError( 'Bitmap value out of range, max value is %d' % maxlen )
            return val
        newval = 0
        for i in val:
            idx = self.bitmap.index( i )
            newval |= (1 << idx)
        return newval

class _dp_type_boolean( _dp_type_raw ):
    def parse_value( self, val ):
        return bool( val )

    def encode_value( self, val ):
        return bool( val )

class _dp_type_enum( _dp_type_raw ):
    def __init__( self, data ):
        super( _dp_type_enum, self ).__init__( data )
        self.enum_range = []

        if 'range' in self.values and type(self.values['range']) == list:
            self.enum_range = tuple(self.values['range'])

    def parse_value( self, val ):
        if val not in self.enum_range:
            self.enum_range = self.enum_range + (val,)
        return val

    def encode_value( self, val ):
        if val in self.enum_range:
            return val
        if type(val) != str and str(val) in self.enum_range:
            return str(val)
        raise ValueError( '%r is not a valid enum option (valid options are: %r)' % val, self.enum_range )

class _dp_type_integer( _dp_type_raw ):
    def __init__( self, data ):
        super( _dp_type_integer, self ).__init__( data )
        for k in ('min', 'max', 'step'):
            if k in self.values:
                setattr( self, 'int_' + k, int( self.values[k] ) )
            else:
                setattr( self, 'int_' + k, None )

        if 'scale' in self.values:
            self.int_scale = 10 ** int( self.values['scale'] )
        else:
            self.int_scale = 1

    def parse_value( self, val ):
        val = int( val )
        if self.int_scale > 1:
            return val / self.int_scale

        return val

    def encode_value( self, val ):
        val = int( val )

        if self.int_scale > 1:
            val *= self.int_scale
            val = int( val )

        if self.int_min is not None and val < self.int_min:
            raise ValueError( 'Integer is below minimum value %d' % self.int_min )

        if self.int_max is not None and val > self.int_max:
            raise ValueError( 'Integer is above maximum value %d' % self.int_max )

        if self.int_step is not None and self.int_step > 1:
            # value must be a multiple of 'step'
            r = val % self.int_step
            if r != 0:
                midpoint = self.int_step >> 1
                if r >= midpoint:
                    # round up
                    val += (self.int_step - r)
                else:
                    # round down
                    val -= r

        return val

class _dp_type_json( _dp_type_raw ):
    # FIXME
    pass

class _dp_type_string( _dp_type_raw ):
    def __init__( self, data ):
        super( _dp_type_string, self ).__init__( data )
        if 'maxlen' in self.values:
            self.string_maxlen = int( self.values['maxlen'] )
        else:
            self.string_maxlen = None

    def parse_value( self, val ):
        return str( val )

    def encode_value( self, val ):
        val = str(val)

        if self.string_maxlen is not None and len( val ) > self.string_maxlen:
            raise ValueError( 'Attempted to set string %r (length: %d) which is longer than maxlen %r' % (val, len( val ), self.string_maxlen) )

        return val

class _dp_object( object ):
    EXPOSE_ITEMS = ( 'unit', 'enum_range', 'int_min', 'int_max', 'int_step', 'int_scale', 'bitmap', 'bitmap_maxlen', 'string_maxlen' )
    def __init__( self, device, dp ):
        super( _dp_object, self ).__setattr__( 'device', device )
        super( _dp_object, self ).__setattr__( 'dp', dp )
        super( _dp_object, self ).__setattr__( 'name', None )
        super( _dp_object, self ).__setattr__( 'names', [dp] )
        super( _dp_object, self ).__setattr__( 'obj', None )
        self._update_value( None )

    def encode_value( self, new_value ):
        return self.obj.encode_value( new_value )

    #def _update_attr( self, attr, new_value ):
    #    super( _dp_object, self ).__setattr__( attr, new_value )

    def _update_value( self, new_value ):
        super( _dp_object, self ).__setattr__( 'raw_value', new_value )
        if self.obj:
            new_value = self.obj.parse_value( new_value )
        super( _dp_object, self ).__setattr__( 'value', new_value )

    def _update_obj( self, new_obj ):
        super( _dp_object, self ).__setattr__( 'obj', new_obj )
        for k in self.EXPOSE_ITEMS:
            super( _dp_object, self ).__setattr__( k, getattr( self.obj, k, None ) )

    def __setattr__( self, key, data, *args, **kwargs ):
        if key == 'value':
            #print( 'in _dp_object __setattr__()' )
            self.device.set_value( self.dp, data )
        elif key in ('name', 'names'):
            return super( _dp_object, self ).__setattr__( key, data, *args, **kwargs )
        else:
            #return super( _dp_object, self ).__setattr__( key, data, *args, **kwargs )
            raise AttributeError( 'Attempted to set %r but only "value" can be set!' % key )

    def __repr__( self ):
        d = {}
        for k in ( 'dp', 'name', 'names', 'raw_value', 'value' ) + self.EXPOSE_ITEMS:
            d[k] = getattr( self, k, None )
        return repr(d)

class mapped_dps_object( object ):
    def __init__( self, device ):
        self.device = device
        self._dp_data = {}

    def set_mappings( self, mappings ):
        # delete DP IDs we have not received values for and all names
        dels = []
        for k in self._dp_data:
            if k != self._dp_data[k].dp or self._dp_data[k].raw_value is None:
                dels.append( k )
        for k in dels:
            del self._dp_data[k]

        # loop through the mapping list and add entries for the DP ID and all names
        #  the primary name is in the 'code' key, and an (optional) alternate name can be in 'alt'
        for dp_id in mappings:
            map_item = mappings[dp_id]
            dp_id = str(dp_id)

            if dp_id not in self._dp_data:
                # add new DP ID
                self._dp_data[dp_id] = _dp_object( self.device, dp_id )

            # reset all names
            dst = self._dp_data[dp_id]
            dst.name = None
            dst.names = [dp_id]

            # add primary name
            if 'code' in map_item and map_item['code']:
                dst.name = map_item['code']
                if dst.name not in self._dp_data:
                    self._dp_data[dst.name] = dst
                    dst.names.append( dst.name )
            else:
                print( 'no name!', map_item)

            # add an alternate name if provided
            if 'alt' in map_item and map_item['alt']:
                name = map_item['alt']
                if name not in self._dp_data:
                    self._dp_data[name] = dst
                    dst.names.append( name )
                if not dst.name:
                    dst.name = name

            # set the mapping
            if 'type' not in map_item or (not map_item['type']) or type(map_item['type']) != str:
                # default to 'raw' if no type provided
                map_item['type'] = 'Raw'

            # normalize the 'values' key
            if ('values' not in map_item) or (not map_item['values']):
                map_item['values'] = {}
            elif type(map_item['values']) != dict:
                if type(map_item['values']) == str and map_item['values'][0] == '{' and map_item['values'][-1] == '}':
                    map_item['values'] = json.loads( map_item['values'] )

            # ignore case
            type_lower = map_item['type'].lower()

            try:
                obj = globals()['_dp_type_'+type_lower]
            except KeyError:
                # default to 'raw' if type is unknown
                obj = _dp_type_raw

            dst._update_obj( obj( map_item ) )

    # received update from device so parse the value
    def _update_value( self, dp_id, new_raw_val ):
        if dp_id not in self._dp_data:
            # no mapping for this DP ID??
            #print( 'adding missing dp', dp_id )
            self._dp_data[dp_id] = _dp_object( self.device, dp_id )
            self._dp_data[dp_id]._update_obj( _dp_type_raw( None ) )

        dst = self._dp_data[dp_id]
        changed = new_raw_val != self._dp_data[dp_id].raw_value
        dst._update_value( new_raw_val )
        return changed, dst

    # accessing as dict returns the _dp_object
    def __getitem__( self, key ):
        key = str(key)
        if key in self._dp_data:
            return self._dp_data[key]
        return None

    #def __setattr__( self, key, data, *args, **kwargs ):
    #    pass

    #def __getattr__( self, key, *args, **kwargs ):
    #    if key[0] == '_':
    #        return super( _dps_object, self ).__getattr__( key, *args, **kwargs )

    # when looping through DPs, only return one object per DP no matter how many names are set
    def __iter__( self ):
        for i in self._dp_data:
            if i == self._dp_data[i].name or not self._dp_data[i].name:
                # prefer primary name, or DP ID if no name set
                yield self._dp_data[i]

class MappedDevice(Device):
    def __init__(self, dev_id, *args, **kwargs):
        mapping = None
        product_id = None
        self.nowait = False

        # XenonDevice is not going to like the 'mapping' or 'product_id' keys, so remove them from kwargs
        if 'mapping' in kwargs:
            mapping = kwargs['mapping']
            del kwargs['mapping']

        if 'product_id' in kwargs:
            product_id = kwargs['product_id']
            del kwargs['product_id']

        super(MappedDevice, self).__init__( dev_id, *args, **kwargs )

        # initialize the mapping machine
        self.dps = mapped_dps_object( self )

        if not mapping:
            # no mapping provided, attempt to look it up in devices.json
            devinfo = device_info( self.id )
            if devinfo:
                if 'mapping' in devinfo:
                    mapping = devinfo['mapping']
                if (not product_id) and ('product_id' in devinfo):
                    product_id = devinfo['product_id']

        if (not mapping) and self.cloud:
            # no devices.json, or mapping not found in devices.json, so use the Cloud if available
            mapping = self.cloud.getmapping( product_id, self.id )

        if mapping:
            # apply the mappings
            self.dps.set_mappings( mapping )

    # parse the response from the device, mapping DP IDs to names
    def _process_response( self, data ):
        #print('processing response:', data)
        if not data:
            return data

        if 'dps' not in data:
            return data

        new_dps = {}
        changed = []
        for dp_id in data['dps']:
            has_changed, dst = self.dps._update_value( dp_id, data['dps'][dp_id] )

            if dst.name:
                # set both primary and alt names
                for name in dst.names[1:]:
                    new_dps[name] = dst.value
                if has_changed:
                    changed += dst.names[1:]
            else:
                # no name, so use DP ID
                if has_changed:
                    changed += dst.names
                new_dps[dst.dp] = dst.value

        data['dps'] = new_dps
        data['changed'] = changed
        return data

    # quick-n-dirty access as dict returns the DPS value
    def __getitem__( self, key ):
        obj = self.dps[key]
        if obj:
            return obj.value
        return obj

    # quick-n-dirty set as dict
    def __setitem__( self, key, new_value ):
        #print('main __setitem__()')
        return self.set_value( key, new_value )

    # when looping through DPs, only return one name per DP no matter how many are set
    def __iter__( self ):
        for i in self.dps:
            # prefer primary name, or DP ID if no name set
            yield i.name if i.name else i.dp

    def set_nowait( self, nowait ):
        self.nowait = nowait

    #def updatedps(self, index=None, nowait=False):
    #    pass

    def set_value( self, index, value, nowait=None ):
        obj = self.dps[index]
        if not obj:
            return None
        if nowait is None:
            nowait = self.nowait
        new_value = obj.encode_value( value )
        return super(MappedDevice, self).set_value( obj.dp, new_value, nowait=nowait )

    def set_multiple_values(self, data, nowait=False):
        newdata = {}
        for k in data:
            obj = self.dps[k]
            if not obj:
                # FIXME should we throw an error instead?
                continue
            newdata[obj.dp] = obj.encode_value( data[k] )
        if nowait is None:
            nowait = self.nowait
        return super(MappedDevice, self).set_multiple_values( newdata, nowait=nowait )

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        # FIXME
        raise NotImplementedError( 'set_timer() is not implemented yet' )
