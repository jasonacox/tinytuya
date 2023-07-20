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
import base64
from sys import hexversion
from .core import Device, log, device_info

# dict key order can only be relied upon with python v3.7 and above
if hexversion < 0x3070000:
    from collections import OrderedDict
    USE_ORDEREDDICT = True
else:
    USE_ORDEREDDICT = False

MAPPING_FIXUPS = [
    {
        "match_keys": {'h': {'max': 360}, 's': {'max': 1000}, 'v': {'max': 1000}},
        "mapping": {
            "type": "Json",
            "values": "{\"h\":{\"min\":0,\"scale\":0,\"unit\":\"°\",\"max\":360,\"step\":1},\"s\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1},\"v\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1}}"
        },
    },
    {
        "dp_id": "24",
        "code": ("colour_data","colour_data_v2"),
        "mapping": {
            "type": "Json",
            "values": "{\"h\":{\"min\":0,\"scale\":0,\"unit\":\"°\",\"max\":360,\"step\":1},\"s\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1},\"v\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1}}"
        },
    },
    {
        "dp_id": "25",
        "code": ("scene_data_v2","scene_data"),
        "mapping": {
            "type": "Json",
            "raw_values": "{\"scene_num\":{\"min\":1,\"scale\":0,\"max\":8,\"step\":1},\"scene_units\": {\"step_duration\":{\"min\":0,\"scale\":0,\"max\":100,\"step\":1},\"unit_gradient_duration\":{\"min\":0,\"scale\":0,\"max\":100,\"step\":1},\"unit_change_mode\":{\"range\":[\"static\",\"jump\",\"gradient\"]},\"h\":{\"min\":0,\"scale\":0,\"unit\":\"°\",\"max\":360,\"step\":1},\"s\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1},\"v\":{\"min\":0,\"scale\":0,\"unit\":\"%\",\"max\":1000,\"step\":1},\"bright\":{\"min\":0,\"scale\":0,\"max\":1000,\"step\":1},\"temperature\":{\"min\":0,\"scale\":0,\"max\":1000,\"step\":1}}}"
        }
    },
]

def _build_obj( map_item, dp_id=None ):
    if 'type' not in map_item or (not map_item['type']):
        # default to 'base_class' if no type provided
        map_item['type'] = 'base_class'
    elif type(map_item['type']) == bytes:
        map_item['type'] = map_item['type'].decode( 'utf8' )
    elif type(map_item['type']) != str:
        try:
            map_item['type'] = map_item['type'].encode( 'utf8' )
        except:
            map_item['type'] = 'base_class'

    # ignore case
    type_lower = map_item['type'].lower()

    # fix some known mapping errors
    for fixup in MAPPING_FIXUPS:
        if 'dp_id' in fixup:
            if fixup['dp_id'] != dp_id:
                continue
        if 'code' in fixup:
            if 'code' not in map_item:
                continue
            if isinstance( fixup['code'], tuple ) or isinstance( fixup['code'], list ):
                if map_item['code'] not in fixup['code']:
                    continue
            elif fixup['code'] != map_item['code']:
                continue

        if 'values' in fixup['mapping']:
            values = fixup['mapping']['values']
        else:
            values = json.loads( fixup['mapping']['raw_values'] )

        if 'match_keys' in fixup:
            if len(map_item['values']) != len(fixup['match_keys']):
                continue
            matches = True
            for k in fixup['match_keys']:
                if k not in map_item['values']:
                    matches = False
                    break
                if isinstance( fixup['match_keys'], dict ) and isinstance( fixup['match_keys'][k], dict ):
                    if k not in map_item['values']:
                        matches = False
                        break
                    for mkey in fixup['match_keys'][k]:
                        if (mkey not in map_item['values'][k]) or (fixup['match_keys'][k][mkey] != map_item['values'][k][mkey]):
                            matches = False
                            break
            if not matches:
                continue

        map_item = fixup['mapping']
        map_item['values'] = values
        break

    if USE_ORDEREDDICT and 'raw_values' in map_item and map_item['raw_values']:
        # python < v3.7.0 needs to use OrderedDict
        map_item['values'] = json.loads( map_item['raw_values'], object_pairs_hook=OrderedDict )

    # normalize the 'values' key
    if ('values' not in map_item) or (not map_item['values']):
        map_item['values'] = {}
    elif not isinstance( map_item['values'], dict ):
        if type(map_item['values']) == str and map_item['values'][0] == '{' and map_item['values'][-1] == '}':
            map_item['values'] = json.loads( map_item['values'] )
        elif type_lower != 'string':
            map_item['values'] = {}

    if type_lower == 'string':
        # FIXME detect bulb/scene data
        pass

    try:
        obj = globals()['_dp_type_'+type_lower]
    except KeyError:
        # default to 'raw' if type is unknown
        obj = _dp_type_base_class

    return obj( map_item, type_lower )

def _detect_json_array( values ):
    if not isinstance( values, dict ):
        return False

    for k in values:
        if not isinstance( values[k], dict ):
            return False

    return True

def _detect_json_subtype( values ):
    if _detect_json_array( values ):
        return 'Array'
    if 'range' in values and isinstance( values['range'], list ):
        return 'Enum_Integer'
    if 'label' in values and isinstance( values['range'], list ):
        return Bitmask
    is_int = True
    for k in ('min', 'max', 'scale', 'step'):
        if k not in values:
            is_int = False
            break
    if is_int:
        return 'Integer'

    # no good way of detecting Bool or Raw
    return 'String'

class _dp_type_base_class( object ):
    def __init__( self, data, type_lower ):
        self.value_type = type_lower
        self.value_len = 0
        self.array_decode_int = False

        if data and isinstance(data, dict) and 'values' in data and isinstance(data['values'], dict):
            self.values = data['values']
        else:
            self.values = {}

        if 'unit' in self.values:
            self.unit = self.values['unit']
        else:
            self.unit = None

        if 'maxlen' in self.values:
            self.maxlen = int( self.values['maxlen'] )
        else:
            self.maxlen = None

    def _calc_valuelen( self ):
        valmin = getattr( self, 'int_min', None )
        valmax = getattr( self, 'int_max', None )

        if (valmin is None) or (valmax is None):
            self.value_len = 0
            return

        span = valmax - valmin
        if span < 256:
            self.value_len = 1
        elif span < 65536:
            self.value_len = 2
        else:
            self.value_len = 4

        self.array_decode_int = True

    def _unpack_int( self, val ):
        if isinstance( val, str ):
            vlen = self.value_len if self.value_len else 1
            vlen *= 2
            return int( val[:vlen], 16 ), val[vlen:]

        return int(val), None

    def _pack_int( self, val ):
        fmt = '%0' + str((self.value_len * 2) if self.value_len else 2) + 'x'
        val = fmt % val
        return val

    def parse_value( self, val ):
        return val, None

    def encode_value( self, val, pack=False ):
        return val


class _dp_type_array( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        #print('parsing Array', type_lower, data)
        super( _dp_type_array, self ).__init__( data, type_lower )
        #if 'elementTypeSpec' in self.values and isinstance( self.values['elementTypeSpec'], dict ) and 'type' in self.values['elementTypeSpec']:
        #    self.subtype = self.values['elementTypeSpec']['type'].lower()
        #    self.subvals = {}
        #else:
        #    self.subtype = 'json'
        #    self.subvals = {}
        self.subobj = _build_obj( {'type':'Json', 'values':self.values} )
        self.value_len = None

    def parse_value( self, val ):
        parsed = []
        while val:
            data, val = self.subobj.parse_value( val )
            parsed.append( data )
        return parsed, val

    def encode_value( self, val, pack=False ):
        if isinstance( val, str ):
            # assume the user already encoded it
            return val

        final = ''
        for data in val:
            final += self.subobj.encode_value( data, True )

        return final

class _dp_type_bitmap( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        super( _dp_type_bitmap, self ).__init__( data, type_lower )
        opts = []

        if 'label' in self.values and type(self.values['label']) == list:
            opts = self.values['label']

        if 'maxlen' in self.values and type(self.values['maxlen']) == int:
            maxlen = int(self.values['maxlen'])
        else:
            maxlen = len(opts)

        # max 32-bit
        if maxlen > 32:
            maxlen = 32

        if maxlen > len(opts):
            for i in range( len(opts), maxlen ):
                opts.append( 'opt-%d' % i )
        elif len(opts) > maxlen:
            maxlen = len(opts)
            if maxlen > 32:
                maxlen = 32

        self.bitmap = tuple(opts)
        self.maxlen = maxlen
        self.int_min = 0
        self.int_max = (1 << maxlen) - 1
        self._calc_valuelen()

    def parse_value( self, val ):
        val, remain = self._unpack_int( val )
        newval = []
        maxlen = self.int_max
        i = 0
        while (val > 0) and (maxlen):
            if (val & 1):
                newval.append( self.bitmap[i] )
            maxlen >>= 1
            val >>= 1
            i += 1
        return tuple(newval), remain

    def encode_value( self, val, pack=False ):
        if type(val) == int:
            if (val < 0) or (val > self.maxlen):
                raise ValueError( 'Bitmap value out of range, max value is %d' % self.maxlen )
            return val
        newval = 0
        for i in val:
            idx = self.bitmap.index( i )
            newval |= (1 << idx)
        return newval if not pack else self._pack_int( newval )

class _dp_type_boolean( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        super( _dp_type_boolean, self ).__init__( data, type_lower )
        self.int_min = 0
        self.int_max = 1
        self._calc_valuelen()

    def parse_value( self, val ):
        val, remain = self._unpack_int( val )
        return bool( val ), remain

    def encode_value( self, val, pack=False ):
        return bool( val ) if not pack else self._pack_int( int(bool( val )) )

class _dp_type_enum( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        super( _dp_type_enum, self ).__init__( data, type_lower )
        self.enum_range = []

        if 'range' in self.values and type(self.values['range']) == list:
            self.enum_range = tuple(self.values['range'])

    def parse_value( self, val ):
        if val not in self.enum_range:
            self.enum_range = self.enum_range + (val,)
        return val, None

    def encode_value( self, val, pack=False ):
        if val in self.enum_range:
            return val
        if type(val) != str and str(val) in self.enum_range:
            return str(val)
        raise ValueError( '%r is not a valid enum option (valid options are: %r)' % val, self.enum_range )

class _dp_type_enum_integer( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        super( _dp_type_enum_integer, self ).__init__( data, type_lower )
        self.enum_range = []

        if 'range' in self.values and type(self.values['range']) == list:
            self.enum_range = tuple(self.values['range'])

        self.int_min = 0
        self.int_max = len(self.enum_range) - 1
        self._calc_valuelen()

    def parse_value( self, val ):
        val, remain = self._unpack_int( val )
        while val >= len(self.enum_range):
            self.enum_range = self.enum_range + (val,)
        return val, remain

    def encode_value( self, val, pack=False ):
        if str(val) in self.enum_range:
            val = self.enum_range.index( str(val) )
        else:
            val = int( val )
        return val if not pack else self._pack_int( val )

class _dp_type_integer( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        super( _dp_type_integer, self ).__init__( data, type_lower )
        for k in ('min', 'max', 'step'):
            if k in self.values:
                setattr( self, 'int_' + k, int( self.values[k] ) )
                setattr( self, 'raw_' + k, int( self.values[k] ) )
            else:
                setattr( self, 'int_' + k, None )
                setattr( self, 'raw_' + k, None )

        if 'scale' in self.values:
            self.int_scale = 10 ** int( self.values['scale'] )
        else:
            self.int_scale = 1

        self._calc_valuelen()

        # override scale and map "10 - 1000" to "1.0 - 100.0"
        if (self.int_min == 10 or self.int_min == 0) and self.int_max == 1000 and self.int_step == 1 and self.int_scale == 1:
            self.int_scale = 10

        # scale min/max/step if needed
        if self.int_scale > 1:
            for k in ('int_min', 'int_max', 'int_step'):
                v = getattr( self, k, None )
                if v is not None:
                    setattr( self, k, float(v)/self.int_scale )

    def parse_value( self, val ):
        val, remain = self._unpack_int( val )
        if self.int_scale > 1:
            return float(val) / self.int_scale, remain
        return val, remain

    def encode_value( self, val, pack=False ):
        if self.int_scale == 1:
            val = int( val )
        else:
            val = float( val )

        if self.int_min is not None and val < self.int_min:
            raise ValueError( 'Integer is below minimum value %d' % self.int_min )

        if self.int_max is not None and val > self.int_max:
            raise ValueError( 'Integer is above maximum value %d' % self.int_max )

        if self.int_scale != 1:
            val *= self.int_scale
            val = round( val )

        if self.raw_step is not None and self.raw_step > 1:
            # value must be a multiple of 'step'
            r = val % self.raw_step
            if r != 0:
                midpoint = self.raw_step >> 1
                if r >= midpoint:
                    # round up
                    val += (self.raw_step - r)
                else:
                    # round down
                    val -= r

        return val if not pack else self._pack_int( val )

class _dp_type_json( _dp_type_base_class ):
    def __init__( self, data, type_lower ):
        #print('parsing JSON', type_lower, data)
        super( _dp_type_json, self ).__init__( data, type_lower )
        self.items = {}
        self.value_len = 0
        for k in self.values:
            vtype = _detect_json_subtype( self.values[k] )
            #print('JSON key', k, 'subtype', vtype)
            self.items[k] = _build_obj( {'type': vtype, 'values': self.values[k]} )
            if not self.items[k].value_len:
                self.value_len = None
            elif self.value_len is not None:
                self.value_len += (self.items[k].value_len * 2)
        if not self.value_len:
            self.value_len = 0
        #print( 'Value len:', self.value_len, data )

    def parse_value( self, val ):
        parsed = {}
        #print( '_dp_type_json(): parsing:', val, 'into', self.values )
        for k in self.values:
            if val is None:
                print( '_dp_type_json(): not enough input to parse', k )
                continue
            parsed[k], val = self.items[k].parse_value( val )
            #print( k, type(self.items[k]).__name__, self.items[k].value_len, '=', parsed[k], 'remain:', val )
        return parsed, val

    def encode_value( self, val, pack=False ):
        if isinstance( val, str ):
            # assume the user already encoded it
            return val
        final = ''
        for k in self.values:
            final += self.items[k].encode_value( val[k], True )
        return final


class _dp_type_raw( _dp_type_base_class ):
    # type "Raw" is encoded as a base64 string
    def parse_value( self, val ):
        return base64.b64decode( val ), None

    def encode_value( self, val, pack=False ):
        b64val = base64.b64encode( val )
        if self.maxlen is not None and len( val ) > self.maxlen:
            # display value as b64 even though the length is for raw bytes
            raise ValueError( 'Attempted to set string %r (length: %d) which is longer than maxlen %r' % (b64val, len( val ), self.maxlen) )
        return b64val


class _dp_type_string( _dp_type_base_class ):
    # type "String" can be base64, hex, quoted JSON, or anything else
    def parse_value( self, val ):
        return str( val ), None

    def encode_value( self, val, pack=False ):
        val = str(val)
        if self.maxlen is not None and len( val ) > self.maxlen:
            raise ValueError( 'Attempted to set string %r (length: %d) which is longer than maxlen %r' % (val, len( val ), self.maxlen) )
        return val

class _dp_object( object ):
    COMMON_ITEMS = ( 'dp', 'name', 'alt_name', 'names', 'valid', 'added', 'changed', 'raw_value', 'value' )
    OPTION_ITEMS = ( 'value_type', 'unit', 'enum_range', 'int_min', 'int_max', 'int_step', 'int_scale', 'bitmap', 'maxlen' )
    def __init__( self, device, dp ):
        super( _dp_object, self ).__setattr__( 'device', device )
        super( _dp_object, self ).__setattr__( 'dp', dp )
        super( _dp_object, self ).__setattr__( 'name', None )
        super( _dp_object, self ).__setattr__( 'alt_name', None )
        super( _dp_object, self ).__setattr__( 'names', [dp] )
        super( _dp_object, self ).__setattr__( 'obj', None )
        self._update_value( None, added=True )

    def encode_value( self, new_value ):
        return self.obj.encode_value( new_value, False )

    def clear_changed( self ):
        if self.valid:
            super( _dp_object, self ).__setattr__( 'changed', False )
            super( _dp_object, self ).__setattr__( 'added', False )

    #def _update_attr( self, attr, new_value ):
    #    super( _dp_object, self ).__setattr__( attr, new_value )

    def _update_value( self, new_value, added=False ):
        #print( 'updating val:', self.names, new_value )
        if added:
            super( _dp_object, self ).__setattr__( 'added', False )
            super( _dp_object, self ).__setattr__( 'valid', False )
            super( _dp_object, self ).__setattr__( 'changed', False )
        else:
            super( _dp_object, self ).__setattr__( 'added', not self.valid )
            super( _dp_object, self ).__setattr__( 'valid', True )
            super( _dp_object, self ).__setattr__( 'changed', new_value != self.raw_value )

        super( _dp_object, self ).__setattr__( 'raw_value', new_value )
        if self.obj:
            new_value, _ = self.obj.parse_value( new_value )
        super( _dp_object, self ).__setattr__( 'value', new_value )

    def _update_obj( self, new_obj ):
        super( _dp_object, self ).__setattr__( 'obj', new_obj )
        for k in self.OPTION_ITEMS:
            super( _dp_object, self ).__setattr__( k, getattr( self.obj, k, None ) )

    def __setattr__( self, key, data, *args, **kwargs ):
        if key == 'value':
            #print( 'in _dp_object __setattr__()' )
            return self.device.set_value( self.dp, data )
        elif key in ('added', 'changed'):
            return super( _dp_object, self ).__setattr__( key, bool(data), *args, **kwargs )
        elif key in ('name', 'alt_name'):
            if not data:
                # replace "" with None
                data = None
            ret = super( _dp_object, self ).__setattr__( key, data, *args, **kwargs )
            # if there is no primary name, use alt name
            if (not self.name) and (key == 'alt_name'):
                super( _dp_object, self ).__setattr__( 'name', data )
            names = [self.dp]
            if self.name: names.append( self.name )
            if (self.alt_name) and (self.name != self.alt_name): names.append( self.alt_name )
            super( _dp_object, self ).__setattr__( 'names', names )
            return ret
        else:
            #return super( _dp_object, self ).__setattr__( key, data, *args, **kwargs )
            raise AttributeError( 'Attempted to set %r but only "value" can be set!' % key )

    def _as_dict( self ):
        d = {}
        for k in self.COMMON_ITEMS + self.OPTION_ITEMS:
            d[k] = getattr( self, k, None )
        return d

    # override __dict__ (and vars())
    @property
    def __dict__(self):
        return self._as_dict()

    def __repr__( self ):
        return repr(self._as_dict())

    # allows dict()
    def __iter__( self ):
        for k in self.COMMON_ITEMS + self.OPTION_ITEMS:
            yield (k, getattr( self, k, None ))

    #def __getitem__( self, key ):
    #    return getattr( self, key, None )

    #def __dir__( self ):
    #    return list(self.COMMON_ITEMS + self.OPTION_ITEMS)

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
        del dels

        # loop through the mapping list and add entries for the DP ID and all names
        #  the primary name is in the 'code' key, and an (optional) alternate name can be in 'alt'
        for dp_id in mappings:
            map_item = mappings[dp_id]
            dp_id = str(dp_id)

            if dp_id not in self._dp_data:
                # add new DP ID
                dst = _dp_object( self.device, dp_id )
                self._dp_data[dp_id] = dst
            else:
                # reset all names
                dst = self._dp_data[dp_id]
                dst.name = None
                dst.alt_name = None

            # add primary name
            if 'code' in map_item and map_item['code']:
                dst.name = map_item['code']
                if (dst.name not in self._dp_data) or (not dst.name.isnumeric()):
                    self._dp_data[dst.name] = dst
            else:
                print( 'no name!', map_item)
                map_item['code'] = dp_id

            # add an alternate name if provided
            if 'alt' in map_item and map_item['alt']:
                dst.alt_name = map_item['alt']
                if dst.alt_name not in self._dp_data:
                    self._dp_data[dst.alt_name] = dst
                if not dst.name:
                    dst.name = dst.alt_name

            # set the mapping
            dst._update_obj( _build_obj( map_item, dp_id ) )

    # received update from device so parse the value
    def _update_value( self, dp_id, new_raw_val ):
        if dp_id not in self._dp_data:
            # no mapping for this DP ID??
            #print( 'adding missing dp', dp_id )
            self._dp_data[dp_id] = _dp_object( self.device, dp_id )
            self._dp_data[dp_id]._update_obj( _dp_type_base_class( None, None ) )

        dst = self._dp_data[dp_id]
        dst._update_value( new_raw_val )
        return dst

    # accessing as dict returns the _dp_object
    def __getitem__( self, key ):
        key = str(key)
        if key in self._dp_data:
            return self._dp_data[key]
        return None

    def __contains__( self, key ):
        return str(key) in self._dp_data

    #def __setattr__( self, key, data, *args, **kwargs ):
    #    pass

    #def __getattr__( self, key, *args, **kwargs ):
    #    if key[0] == '_':
    #        return super( _dps_object, self ).__getattr__( key, *args, **kwargs )

    # when looping through DPs, only return one object per DP no matter how many names are set
    def __iter__( self ):
        for i in self._dp_data:
            # prefer alt name
            if self._dp_data[i].alt_name:
                if i == self._dp_data[i].alt_name:
                    yield self._dp_data[i]
            elif i == self._dp_data[i].name or not self._dp_data[i].name:
                # else use primary name, or DP ID if no name set
                yield self._dp_data[i]

    def __repr__( self ):
        return repr( [i for i in self] )

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

        if 'data' in data and isinstance( data['data'], dict ):
            if 'dps' in data['data']:
                del data['data']['dps']
            if not data['data']:
                del data['data']

        for obj in self.dps:
            obj.clear_changed()

        dps_values = {}
        dps_printable = {}
        dps_objects = []
        for dp_id in data['dps']:
            dp_id_s = str(dp_id)
            dst = self.dps._update_value( dp_id_s, data['dps'][dp_id] )
            dps_objects.append( dst )

            # set both primary and alt names
            if dst.name:
                dps_values[dst.name] = dst.value
                dps_printable[dst.name] = str(dst.value) + (dst.unit if dst.unit else '')
                if (dst.alt_name) and (dst.alt_name != dst.name):
                    dps_values[dst.alt_name] = dst.value
                    dps_printable[dst.alt_name] = dps_printable[dst.name]
            else:
                # no name, so use DP ID
                dps_values[dst.dp] = dst.value
                dps_printable[dst.dp] = str(dst.value) + (dst.unit if dst.unit else '')

        data['raw_dps'] = data['dps']
        data['dps'] = dps_values
        data['dps_printable'] = dps_printable
        data['dps_objects'] = dps_objects
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

    def __contains__( self, key ):
        return key in self.dps

    # when looping through DPs, only return one name per DP no matter how many are set
    def __iter__( self ):
        for i in self.dps:
            # prefer alt name, then primary name, then DP ID if no name set
            if i.alt_name:
                yield i.alt_name
            else:
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
        new_value = obj.encode_value( value, False )
        return super(MappedDevice, self).set_value( obj.dp, new_value, nowait=nowait )

    def set_multiple_values(self, data, nowait=False):
        newdata = {}
        for k in data:
            ks = str(k)
            obj = self.dps[ks]
            if not obj:
                # FIXME should we throw an error instead?
                if ks.isnumeric():
                    obj = self.dps._update_value( ks, data[k] )
                else:
                    # FIXME what do we do here?
                    continue
            newdata[obj.dp] = obj.encode_value( data[k], False )
        if nowait is None:
            nowait = self.nowait
        return super(MappedDevice, self).set_multiple_values( newdata, nowait=nowait )

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        if dps_id == 0:
            # try and find the DP ID for the timer
            found = False
            possible = False
            for obj in self.dps:
                if ('countdown' in obj.names) or ('countdown_1' in obj.names):
                    found = obj
                    break
                for n in obj.names:
                    if n.startswith( 'countdown' ):
                        possible = obj
                        break
            if not found:
                if possible:
                    found = possible
                else:
                    # set_timer() in tinytuya.core says last DP ID is probably the timer, so use it
                    for obj in self.dps:
                        found = obj
            dps_id = found.dp

        return self.set_value( dps_id, num_secs, nowait=nowait )
