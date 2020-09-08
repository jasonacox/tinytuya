# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Classes
    OutletDevice(dev_id, address, local_key=None, dev_type='default')
    CoverDevice(dev_id, address, local_key=None, dev_type='default')
    BulbDevice(dev_id, address, local_key=None, dev_type='default')

        dev_id (str): Device ID e.g. 01234567891234567890
        address (str): Device Network IP Address e.g. 10.0.1.99
        local_key (str, optional): The encryption key. Defaults to None.
        dev_type (str): Device type for payload options (see below)

 Functions 
    json = status()          # returns json payload
    set_version(version)     #  3.1 [default] or 3.3
    set_dpsUsed(dpsUsed)     # set data points (DPs)
    set_retry(retry=True)    # retry if response payload is truncated
    set_status(on, switch=1) # Set status of the device to 'on' or 'off' (bool)
    set_value(index, value)  # Set int value of any index.
    turn_on(switch=1):
    turn_off(switch=1):
    set_timer(num_secs):

    CoverDevice:
        open_cover(switch=1):  
        close_cover(switch=1):
        stop_cover(switch=1):

    BulbDevice
        set_colour(r, g, b):
        set_white(brightness, colourtemp):
        set_brightness(brightness):
        set_colourtemp(colourtemp):
        result = brightness():
        result = colourtemp():
        (r, g, b) = colour_rgb():
        (h,s,v) = colour_hsv()
        result = state():
        
 Credits
  * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    For protocol reverse engineering 
  * PyTuya https://github.com/clach04/python-tuya by clach04
    The origin of this python module (now abandoned)
  * LocalTuya https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
    Updated pytuya to support devices with Device IDs of 22 characters
    
"""

import base64
from hashlib import md5
import json
import logging
import socket
import sys
import time
import colorsys
import binascii

# Required module: pycryptodome
try:
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes

version_tuple = (1, 0, 2)
version = __version__ = '%d.%d.%d' % version_tuple
__author__ = 'jasonacox'

log = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG) # Uncomment to Debug 

log.debug('%s version %s', __name__, __version__)
log.debug('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.debug('Using pyaes version %r', pyaes.VERSION)
    log.debug('Using pyaes from %r', pyaes.__file__)
else:
    log.debug('Using PyCrypto %r', Crypto.version_info)
    log.debug('Using PyCrypto from %r', Crypto.__file__)

## Tuya Command Types
UDP = 0
AP_CONFIG = 1
ACTIVE = 2
BIND = 3
RENAME_GW = 4
RENAME_DEVICE = 5
UNBIND = 6
CONTROL = 7         # set values
STATUS = 8
HEART_BEAT = 9
DP_QUERY = 10       # get data points
QUERY_WIFI = 11
TOKEN_BIND = 12
CONTROL_NEW = 13
ENABLE_WIFI = 14
DP_QUERY_NEW = 16
SCENE_EXECUTE = 17
UDP_NEW = 19
AP_CONFIG_NEW = 20
LAN_GW_ACTIVE = 240
LAN_SUB_DEV_REQUEST = 241
LAN_DELETE_SUB_DEV = 242
LAN_REPORT_SUB_DEV = 243
LAN_SCENE = 244
LAN_PUBLISH_CLOUD_CONFIG = 245
LAN_PUBLISH_APP_CONFIG = 246
LAN_EXPORT_APP_CONFIG = 247
LAN_PUBLISH_SCENE_PANEL = 248
LAN_REMOVE_GW = 249
LAN_CHECK_GW_UPDATE = 250
LAN_GW_UPDATE = 251
LAN_SET_GW_CHANNEL = 252

## Protocol Versions
PROTOCOL_VERSION_BYTES_31 = b'3.1'
PROTOCOL_VERSION_BYTES_33 = b'3.3'

## Python 2 Support
IS_PY2 = sys.version_info[0] == 2

## Cryptography Helpers
class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = key
    def encrypt(self, raw, use_base64 = True):
        if Crypto:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)
        else:
            _ = self._pad(raw)
            cipher = pyaes.blockfeeder.Encrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            crypted_text = cipher.feed(raw)
            crypted_text += cipher.feed()  # flush final block

        if use_base64:
            return base64.b64encode(crypted_text)
        else:
            return crypted_text
            
    def decrypt(self, enc, use_base64=True):
        if use_base64:
            enc = base64.b64decode(enc)

        if Crypto:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            return self._unpad(raw).decode('utf-8')

        else:
            cipher = pyaes.blockfeeder.Decrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            plain_text = cipher.feed(enc)
            plain_text += cipher.feed()  # flush final block
            return plain_text

    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def bin2hex(x, pretty=False):
    if pretty:
        space = ' '
    else:
        space = ''
    if IS_PY2:
        result = ''.join('%02X%s' % (ord(y), space) for y in x)
    else:
        result = ''.join('%02X%s' % (y, space) for y in x)
    return result

def hex2bin(x):
    if IS_PY2:
        return x.decode('hex')
    else:
        return bytes.fromhex(x)

# Tuya Device Dictionary - Commands and Payload Template
# See requests.json payload at https://github.com/codetheweb/tuyapi

payload_dict = {
  # Default Device
  "default": {
    CONTROL: {   # Set Control Values on Device
      "hexByte": "07",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    STATUS: {    # Get Status from Device
      "hexByte": "08",
      "command": {"gwId": "", "devId": ""}
    },    
    HEART_BEAT: {
      "hexByte": "09",
      "command": {}
    },
    DP_QUERY: {  # Get Data Points from Device
      "hexByte": "0a",
      "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
    },
    CONTROL_NEW: {
      "hexByte": "0d",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    DP_QUERY_NEW: {
      "hexByte": "0f",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    "prefix": "000055aa00000000000000",    
        # Next byte is command "hexByte" + length of remaining payload + command + suffix 
        # (unclear if multiple bytes used for length, zero padding implies could be more 
        # than one byte)
    "suffix": "000000000000aa55"
  },
  # Special Case Device 
  "device22": {
    DP_QUERY: {  # Get Data Points from Device
      "hexByte": "0d",  # Uses CONTROL_NEW command for some reason
      "command": {"devId": "", "uid": "", "t": ""}
    },
    CONTROL: {   # Set Control Values on Device
      "hexByte": "07",
      "command": {"devId": "", "uid": "", "t": ""}
    },
    "prefix": "000055aa00000000000000", 
    "suffix": "000000000000aa55"
  }
}

class XenonDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type="default", connection_timeout=10):
        """
        Represents a Tuya device.
        
        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            
        Attributes:
            port (int): The port to connect to.
        """

        self.id = dev_id
        self.address = address
        self.local_key = local_key
        self.local_key = local_key.encode('latin1')
        self.connection_timeout = connection_timeout
        self.version = 3.1
        self.retry = True
        self.dev_type = dev_type
        self.port = 6668  # default - do not expect caller to pass in

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    def _send_receive(self, payload):
        """
        Send single buffer `payload` and receive a single buffer.
        
        Args:
            payload(bytes): Data to send.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(self.connection_timeout)
        s.connect((self.address, self.port))
        s.send(payload)
        data = s.recv(1024)
        # Some devices fail to send full payload in first response
        if self.retry and len(data) < 40:  
            time.sleep(0.1)
            data = s.recv(1024)  # try again
        s.close()
        return data

    def set_version(self, version):
        self.version = version

    def set_dpsUsed(self, dpsUsed):
        self.dpsUsed = dpsUsed
        
    def set_retry(self, retry):
        self.retry = retry

    def generate_payload(self, command, data=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to send.
                This is what will be passed via the 'dps' entry
        """
        json_data = payload_dict[self.dev_type][command]['command']
        command_hb = payload_dict[self.dev_type][command]['hexByte']

        if 'gwId' in json_data:
            json_data['gwId'] = self.id
        if 'devId' in json_data:
            json_data['devId'] = self.id
        if 'uid' in json_data:
            json_data['uid'] = self.id  # use device ID
        if 't' in json_data:
            json_data['t'] = str(int(time.time()))

        if data is not None:
            json_data['dps'] = data
        if command_hb == '0d':   # CONTROL_NEW
            json_data['dps'] = self.dpsUsed

        # Create byte buffer from hex data
        json_payload = json.dumps(json_data)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if self.version == 3.3:
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload, False)
            self.cipher = None
            if command_hb != '0a':
                # add the 3.3 header
                json_payload = PROTOCOL_VERSION_BYTES_33 + b"\0\0\0\0\0\0\0\0\0\0\0\0" + json_payload
        elif command == CONTROL:  
            # need to encrypt
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            preMd5String = b'data=' + json_payload + b'||lpv=' + PROTOCOL_VERSION_BYTES_31 + b'||' + self.local_key
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()
            json_payload = PROTOCOL_VERSION_BYTES_31 + hexdigest[8:][:16].encode('latin1') + json_payload
            self.cipher = None  # expect to connect and then disconnect to set new

        postfix_payload = hex2bin(bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])

        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(postfix_payload)  # single byte 0-255 (0x00-0xff)
        buffer = hex2bin( payload_dict[self.dev_type]['prefix'] +
                          payload_dict[self.dev_type][command]['hexByte'] +
                          '000000' +
                          postfix_payload_hex_len ) + postfix_payload

        # calc the CRC of everything except where the CRC goes and the suffix
        hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
        buffer = buffer[:-8] + hex2bin(hex_crc) + buffer[-4:]
        return buffer
    
class Device(XenonDevice):
    def __init__(self, dev_id, address, local_key=None, dev_type="default"):
        super(Device, self).__init__(dev_id, address, local_key, dev_type)
    
    def status(self):
        log.debug('status() entry (dev_type is %s)', self.dev_type)
        # open device, send request, then close connection
        payload = self.generate_payload(DP_QUERY)

        data = self._send_receive(payload)
        log.debug('status received data=%r', data)

        result = data[20:-8]  # hard coded offsets
        if self.dev_type != 'default':
            result = result[15:]

        log.debug('result=%r', result)

        if result.startswith(b'{'):
            # this is the regular expected code path
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        elif result.startswith(PROTOCOL_VERSION_BYTES_31):
            # got an encrypted payload, happens occasionally
            # expect resulting json to look similar to:: {"devId":"ID","dps":{"1":true,"2":0},"t":EPOCH_SECS,"s":3_DIGIT_NUM}
            # NOTE dps.2 may or may not be present
            result = result[len(PROTOCOL_VERSION_BYTES_31):]  # remove version header
            result = result[16:]  # Remove 16-bytes appears to be MD5 hexdigest of payload
            cipher = AESCipher(self.local_key)
            result = cipher.decrypt(result)
            log.debug('decrypted result=%r', result)
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        elif self.version == 3.3:
            cipher = AESCipher(self.local_key)
            result = cipher.decrypt(result, False)
            log.debug('decrypted result=%r', result)
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        else:
            log.error('Unexpected status() payload=%r', result)

        return result

    def set_status(self, on, switch=1):
        """
        Set status of the device to 'on' or 'off'.
        
        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
        """
        # open device, send request, then close connection
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(SET, {switch:on})

        data = self._send_receive(payload)
        log.debug('set_status received data=%r', data)

        return data
    
    def set_value(self, index, value):
        """
        Set int value of any index.

        Args:
            index(int): index to set
            value(int): new value for the index
        """
        # open device, send request, then close connection
        if isinstance(index, int):
            index = str(index)  # index and payload is a string

        payload = self.generate_payload(SET, {
            index: value})
        
        data = self._send_receive(payload)
        
        return data
    
    def turn_on(self, switch=1):
        """Turn the device on"""
        self.set_status(True, switch)

    def turn_off(self, switch=1):
        """Turn the device off"""
        self.set_status(False, switch)

    def set_timer(self, num_secs):
        """
        Set a timer.
        
        Args:
            num_secs(int): Number of seconds
        """

        # Query status, pick last device id as that is probably the timer
        status = self.status()
        devices = status['dps']
        devices_numbers = list(devices.keys())
        devices_numbers.sort()
        dps_id = devices_numbers[-1]

        payload = self.generate_payload(SET, {dps_id:num_secs})

        data = self._send_receive(payload)
        log.debug('set_timer received data=%r', data)
        return data

class OutletDevice(Device):
    """
    Represents a Tuya based Smart Plug or Switch.
    
    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """
    def __init__(self, dev_id, address, local_key=None, dev_type="default"):
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)

class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.
    
    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """
    DPS_INDEX_MOVE       = '1'
    DPS_INDEX_BL         = '101'

    DPS_2_STATE = {
                '1':'movement',
                '101':'backlight',
                }

    def __init__(self, dev_id, address, local_key=None, dev_type="default"):
        super(CoverDevice, self).__init__(dev_id, address, local_key, dev_type)
    
    def open_cover(self, switch=1):
        """Open the cover"""
        self.set_status('on', switch)

    def close_cover(self, switch=1):
        """Close the cover"""
        self.set_status('off', switch)

    def stop_cover(self, switch=1):
        """Stop the motion of the cover"""
        self.set_status('stop', switch)

class BulbDevice(Device):
    """
    Represents a Tuya based Smart Light/Bulb.
    
    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """
    DPS_INDEX_ON         = '1'
    DPS_INDEX_MODE       = '2'
    DPS_INDEX_BRIGHTNESS = '3'
    DPS_INDEX_COLOURTEMP = '4'
    DPS_INDEX_COLOUR     = '5'

    DPS             = 'dps'
    DPS_MODE_COLOUR = 'colour'
    DPS_MODE_WHITE  = 'white'
    
    DPS_2_STATE = {
                '1':'is_on',
                '2':'mode',
                '3':'brightness',
                '4':'colourtemp',
                '5':'colour',
                }

    def __init__(self, dev_id, address, local_key=None, dev_type="default"):
        super(BulbDevice, self).__init____init__(dev_id, address, local_key, dev_type)

    @staticmethod
    def _rgb_to_hexvalue(r, g, b):
        """
        Convert an RGB value to the hex representation expected by tuya.
        
        Index '5' (DPS_INDEX_COLOUR) is assumed to be in the format:
        rrggbb0hhhssvv
        
        While r, g and b are just hexadecimal values of the corresponding
        Red, Green and Blue values, the h, s and v values (which are values
        between 0 and 1) are scaled to 360 (h) and 255 (s and v) respectively.
        
        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        rgb = [r,g,b]
        hsv = colorsys.rgb_to_hsv(rgb[0]/255, rgb[1]/255, rgb[2]/255)

        hexvalue = ""
        for value in rgb:
            temp = str(hex(int(value))).replace("0x","")
            if len(temp) == 1:
                temp = "0" + temp
            hexvalue = hexvalue + temp

        hsvarray = [int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255)]
        hexvalue_hsv = ""
        for value in hsvarray:
            temp = str(hex(int(value))).replace("0x","")
            if len(temp) == 1:
                temp = "0" + temp
            hexvalue_hsv = hexvalue_hsv + temp
        if len(hexvalue_hsv) == 7:
            hexvalue = hexvalue + "0" + hexvalue_hsv
        else:
            hexvalue = hexvalue + "00" + hexvalue_hsv

        return hexvalue

    @staticmethod
    def _hexvalue_to_rgb(hexvalue):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an RGB value.
        
        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        r = int(hexvalue[0:2], 16)
        g = int(hexvalue[2:4], 16)
        b = int(hexvalue[4:6], 16)

        return (r, g, b)

    @staticmethod
    def _hexvalue_to_hsv(hexvalue):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an HSV value.
        
        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        h = int(hexvalue[7:10], 16) / 360
        s = int(hexvalue[10:12], 16) / 255
        v = int(hexvalue[12:14], 16) / 255

        return (h, s, v)

    def set_colour(self, r, g, b):
        """
        Set colour of an rgb bulb.

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        if not 0 <= r <= 255:
            raise ValueError("The value for red needs to be between 0 and 255.")
        if not 0 <= g <= 255:
            raise ValueError("The value for green needs to be between 0 and 255.")
        if not 0 <= b <= 255:
            raise ValueError("The value for blue needs to be between 0 and 255.")

        #print(BulbDevice)
        hexvalue = BulbDevice._rgb_to_hexvalue(r, g, b)

        payload = self.generate_payload(SET, {
            self.DPS_INDEX_MODE: self.DPS_MODE_COLOUR,
            self.DPS_INDEX_COLOUR: hexvalue})
        data = self._send_receive(payload)
        return data

    def set_white(self, brightness, colourtemp):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
            colourtemp(int): Value for the colour temperature (0-255).
        """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")
        if not 0 <= colourtemp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        payload = self.generate_payload(SET, {
            self.DPS_INDEX_MODE: self.DPS_MODE_WHITE,
            self.DPS_INDEX_BRIGHTNESS: brightness,
            self.DPS_INDEX_COLOURTEMP: colourtemp})

        data = self._send_receive(payload)
        return data

    def set_brightness(self, brightness):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
        """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")

        payload = self.generate_payload(SET, {self.DPS_INDEX_BRIGHTNESS: brightness})
        data = self._send_receive(payload)
        return data

    def set_colourtemp(self, colourtemp):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
        """
        if not 0 <= colourtemp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        payload = self.generate_payload(SET, {self.DPS_INDEX_COLOURTEMP: colourtemp})
        data = self._send_receive(payload)
        return data

    def brightness(self):
        """Return brightness value"""
        return self.status()[self.DPS][self.DPS_INDEX_BRIGHTNESS]

    def colourtemp(self):
        """Return colour temperature"""
        return self.status()[self.DPS][self.DPS_INDEX_COLOURTEMP]

    def colour_rgb(self):
        """Return colour as RGB value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR]
        return BulbDevice._hexvalue_to_rgb(hexvalue)

    def colour_hsv(self):
        """Return colour as HSV value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR]
        return BulbDevice._hexvalue_to_hsv(hexvalue)

    def state(self):
        """Return state of Bulb"""
        status = self.status()
        state = {}

        for key in status[self.DPS].keys():
            if(int(key)<=5):
                state[self.DPS_2_STATE[key]]=status[self.DPS][key]

        return state
