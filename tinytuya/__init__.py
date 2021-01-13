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
    json = status()                    # returns json payload
    set_version(version)               # 3.1 [default] or 3.3
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]
    set_socketRetryLimit(integer)      # retry count limit [default 5]
    set_dpsUsed(dpsUsed)               # set data points (DPs)
    set_retry(retry=True)              # retry if response payload is truncated
    set_status(on, switch=1)           # Set status of the device to 'on' or 'off' (bool)
    set_value(index, value)            # Set int value of any index.
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
        set_scene(scene):             # 1=nature, 3=rave, 4=rainbow
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

# Modules
from __future__ import print_function   # python 2.7 support
import base64
from hashlib import md5
import json
import logging
import socket
import sys
import time
import colorsys
import binascii
import requests
import hmac
import hashlib

# Backward compatability for python2
try:
    input = raw_input
except NameError:
    pass

# Required module: pycryptodome
try:
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes

version_tuple = (1, 1, 3)
version = __version__ = '%d.%d.%d' % version_tuple
__author__ = 'jasonacox'

log = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG) # Uncomment to Debug

log.debug('%s version %s', __name__, __version__)
log.debug('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.debug('Using pyaes version %r', pyaes.VERSION)
    log.debug('Using pyaes from %r', pyaes.__file__)
else:
    log.debug('Using PyCrypto %r', Crypto.version_info)
    log.debug('Using PyCrypto from %r', Crypto.__file__)

# Tuya Command Types
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

# Protocol Versions
PROTOCOL_VERSION_BYTES_31 = b'3.1'
PROTOCOL_VERSION_BYTES_33 = b'3.3'

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

# Cryptography Helpers

class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = key

    def encrypt(self, raw, use_base64=True):
        if Crypto:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)
        else:
            _ = self._pad(raw)
            cipher = pyaes.blockfeeder.Encrypter(
                pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
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
            cipher = pyaes.blockfeeder.Decrypter(
                pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
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
            "command": {"gwId": "", "devId": ""}
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
    # Special Case Device with 22 character ID - Some of these devices
    # Require the 0d command as the DP_QUERY status request and the list of
    # dps requested payload
    "device22": {
        DP_QUERY: {  # Get Data Points from Device
            "hexByte": "0d",  # Uses CONTROL_NEW command for some reason
            "command": {"devId": "", "uid": "", "t": ""}
        },
        CONTROL: {   # Set Control Values on Device
            "hexByte": "07",
            "command": {"devId": "", "uid": "", "t": ""}
        },
        HEART_BEAT: {
            "hexByte": "09",
            "command": {"gwId": "", "devId": ""}
        },
        "prefix": "000055aa00000000000000",
        "suffix": "000000000000aa55"
    }
}


class XenonDevice(object):
    def __init__(self, dev_id, address, local_key="", dev_type="default", connection_timeout=10):
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
        self.socket = None
        self.socketPersistent = False
        self.socketNODELAY = True
        self.socketRetryLimit = 5
        if(address == None or address == 'Auto' or address == '0.0.0.0'):
            # try to determine IP address automatically 
            (addr, ver) = self.find(dev_id)
            if(addr == None):
                raise Exception('Unable to find device on network (specify IP address)')
            self.address = addr
            if(ver == "3.3"):
                self.version = 3.3

    def __del__(self):
        # In case we have a lingering socket connection, close it
        if self.socket != None:
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None

    def __repr__(self):
        # FIXME can do better than this
        return '%r' % ((self.id, self.address),)

    def _get_socket(self, renew):
        if(renew and self.socket != None):
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None
        if(self.socket == None):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if(self.socketNODELAY):
                self.socket.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.settimeout(self.connection_timeout)
            self.socket.connect((self.address, self.port))

    def _send_receive(self, payload):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send.
        """
        success = False
        retries = 0
        while not success:
            # make sure I have a socket (may already exist)
            self._get_socket(False)
            try:
                self.socket.send(payload)
                data = self.socket.recv(1024)
                # Some devices fail to send full payload in first response
                # At minimum requires: prefix (4), sequence (4), command (4), length (4),
                # CRC (4), and suffix (4) for 24 total bytes
                # Messages from the device also include return code (4), for 28 total bytes
                if self.retry and len(data) <= 28:  
                    time.sleep(0.1)
                    data = self.socket.recv(1024)  # try again
                success = True
                # Legacy/default mode avoids persisting socket across commands
                if(not self.socketPersistent):
                    self.socket.close()
                    self.socket = None
            except:
                retries = retries+1
                log.debug('Exception with low level TinyTuya socket!!! retry ' +
                          str(retries)+'/'+str(self.socketRetryLimit))
                # if we exceed the limit of retries then lets get out of here
                if(retries > self.socketRetryLimit):
                    if(self.socket != None):
                        self.socket.close()
                        self.socket = None
                    log.exception(
                        'Exceeded tinytuya retry limit ('+str(self.socketRetryLimit)+')')
                    # goodbye
                    raise
                # retry:  wait a bit, toss old socket and get new one
                time.sleep(0.1)
                self._get_socket(True)
            # except
        # while
        # signal we are done reading
        return data

    def set_version(self, version):
        self.version = version

    def set_socketPersistent(self, persist):
        self.socketPersistent = persist

    def set_socketNODELAY(self, nodelay):
        self.socketNODELAY = nodelay

    def set_socketRetryLimit(self, limit):
        self.socketRetryLimit = limit

    def set_dpsUsed(self, dpsUsed):
        self.dpsUsed = dpsUsed

    def set_retry(self, retry):
        self.retry = retry
    
    def find(self, did=None):
        """Scans network for Tuya devices with ID = did
            
        Parameters:
            did = The specific Device ID you are looking for (returns only IP and Version)

        Response: 
            (ip, version)
        """
        if(did == None):
            return(None, None)
        # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
        client = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.bind(("", UDPPORT))
        client.settimeout(TIMEOUT)
        # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
        clients = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        clients.bind(("", UDPPORTS))
        clients.settimeout(TIMEOUT)

        count = 0
        counts = 0
        maxretry = 30
        ret = (None, None)

        while (count + counts) <= maxretry:
            if (count <= counts):  # alternate between 6666 and 6667 ports
                try:
                    data, addr = client.recvfrom(4048)
                    count = count + 1
                except:
                    # Timeout
                    count = count + 1
                    continue
            else:
                try:
                    data, addr = clients.recvfrom(4048)
                    counts = counts + 1
                except:
                    # Timeout
                    counts = counts + 1
                    continue
            ip = addr[0]
            gwId = version = ""
            result = data
            try:
                result = data[20:-8]
                try:
                    result = decrypt_udp(result)
                except:
                    result = result.decode()

                result = json.loads(result)
                ip = result['ip']
                gwId = result['gwId']
                version = result['version']
            except:
                result = {"ip": ip}

            # Check to see if we are only looking for one device
            if(gwId == did):
                # We found it!
                ret = (ip, version)
                break

        # while
        clients.close()
        client.close()
        return(ret)

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
        # if spaces are not removed device does not respond!
        json_payload = json_payload.replace(' ', '')
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if self.version == 3.3:
            # expect to connect and then disconnect to set new
            self.cipher = AESCipher(self.local_key)
            json_payload = self.cipher.encrypt(json_payload, False)
            self.cipher = None
            if command_hb != '0a':
                # add the 3.3 header
                json_payload = PROTOCOL_VERSION_BYTES_33 + \
                    b"\0\0\0\0\0\0\0\0\0\0\0\0" + json_payload
        elif command == CONTROL:
            # need to encrypt
            # expect to connect and then disconnect to set new
            self.cipher = AESCipher(self.local_key)
            json_payload = self.cipher.encrypt(json_payload)
            preMd5String = b'data=' + json_payload + b'||lpv=' + \
                PROTOCOL_VERSION_BYTES_31 + b'||' + self.local_key
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()
            # some tuya libraries strip 8: to :24
            json_payload = PROTOCOL_VERSION_BYTES_31 + \
                hexdigest[8:][:16].encode('latin1') + json_payload
            self.cipher = None  

        postfix_payload = hex2bin(
            bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])

        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(
            postfix_payload)  # single byte 0-255 (0x00-0xff)
        buffer = hex2bin(payload_dict[self.dev_type]['prefix'] +
                         payload_dict[self.dev_type][command]['hexByte'] +
                         '000000' +
                         postfix_payload_hex_len) + postfix_payload

        # calc the CRC of everything except where the CRC goes and the suffix
        hex_crc = format(binascii.crc32(buffer[:-8]) & 0xffffffff, '08X')
        buffer = buffer[:-8] + hex2bin(hex_crc) + buffer[-4:]
        return buffer


class Device(XenonDevice):
    def __init__(self, dev_id, address, local_key="", dev_type="default"):
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
            # Remove 16-bytes appears to be MD5 hexdigest of payload
            result = result[16:]
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
        payload = self.generate_payload(CONTROL, {switch: on})

        data = self._send_receive(payload)
        log.debug('set_status received data=%r', data)

        return data

    def heartbeat(self):
        """
        Send a simple HEART_BEAT command to device.

        """
        # open device, send request, then close connection
        payload = self.generate_payload(HEART_BEAT)
        data = self._send_receive(payload)
        log.debug('heartbeat received data=%r', data)
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

        payload = self.generate_payload(CONTROL, {
            index: value})

        data = self._send_receive(payload)

        return data

    def turn_on(self, switch=1):
        """Turn the device on"""
        self.set_status(True, switch)

    def turn_off(self, switch=1):
        """Turn the device off"""
        self.set_status(False, switch)

    def set_timer(self, num_secs, dps_id=0):
        """
        Set a timer.

        Args:
            num_secs(int): Number of seconds
            dps_id(int): DPS Index for Timer
        """

        # Query status, pick last device id as that is probably the timer
        if(dps_id==0):
            status = self.status()
            devices = status['dps']
            devices_numbers = list(devices.keys())
            devices_numbers.sort()
            dps_id = devices_numbers[-1]

        payload = self.generate_payload(CONTROL, {dps_id: num_secs})

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

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(OutletDevice, self).__init__(
            dev_id, address, local_key, dev_type)


class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.

    Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.
    """
    DPS_INDEX_MOVE = '1'
    DPS_INDEX_BL = '101'

    DPS_2_STATE = {
        '1': 'movement',
        '101': 'backlight',
    }

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
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

    This class supports two types of bulbs with different DPS mappings and functions:
        Type A - Uses DPS index 1-5
        Type B - Uses DPS index 20-27 (no index 1)

    Init Args:
        dev_id (str): The device id.
        address (str): The network address.
        local_key (str, optional): The encryption key. Defaults to None.

    """
    # Two types of Bulbs - TypeA uses DPS 1-5, TypeB uses DPS 20-24
    DPS_INDEX_ON = {'A': '1', 'B': '20'}         
    DPS_INDEX_MODE = {'A': '2', 'B': '21'}
    DPS_INDEX_BRIGHTNESS = {'A': '3', 'B': '22'}
    DPS_INDEX_COLOURTEMP = {'A': '4', 'B': '23'}
    DPS_INDEX_COLOUR = {'A': '5', 'B': '24'}
    DPS_INDEX_SCENE = {'A': '2', 'B': '25'}
    DPS_INDEX_TIMER = {'A': None, 'B': '26'}
    DPS_INDEX_MUSIC = {'A': None, 'B': '27'}
    
    DPS = 'dps'
    DPS_MODE_WHITE = 'white'
    DPS_MODE_COLOUR = 'colour'
    DPS_MODE_SCENE = 'scene'
    DPS_MODE_MUSIC = 'music'
    #
    DPS_MODE_SCENE_1 = 'scene_1'  # nature
    DPS_MODE_SCENE_2 = 'scene_2'
    DPS_MODE_SCENE_3 = 'scene_3'  # rave
    DPS_MODE_SCENE_4 = 'scene_4'  # rainbow

    DPS_2_STATE = {
        '1': 'is_on',
        '2': 'mode',
        '3': 'brightness',
        '4': 'colourtemp',
        '5': 'colour',
        '20': 'is_on',
        '21': 'mode',
        '22': 'brightness',
        '23': 'colourtemp',
        '24': 'colour',
    }

    # Default Bulb Type
    bulb_type = 'A'

    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(BulbDevice, self).__init__(dev_id, address, local_key, dev_type)

    @staticmethod
    def _rgb_to_hexvalue(r, g, b, bulb='A'):
        """
        Convert an RGB value to the hex representation expected by Tuya Bulb.

        Index (DPS_INDEX_COLOUR) is assumed to be in the format:
            (Type A) Index: 5 in hex format: rrggbb0hhhssvv 
            (Type B) Index: 24 in hex format: hhhhssssvvvv 

        While r, g and b are just hexadecimal values of the corresponding
        Red, Green and Blue values, the h, s and v values (which are values
        between 0 and 1) are scaled:
            Type A: 360 (h) and 255 (s and v)
            Type B: 360 (h) and 1000 (s and v)

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        rgb = [r, g, b]
        hsv = colorsys.rgb_to_hsv(rgb[0]/255, rgb[1]/255, rgb[2]/255)

        # Bulb Type A
        if(bulb == 'A'):
            hexvalue = ""
            for value in rgb:
                hsvarray = [int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255)]
                temp = str(hex(int(value))).replace("0x", "")
                if len(temp) == 1:
                    temp = "0" + temp
                hexvalue = hexvalue + temp

            hsvarray = [int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255)]
            hexvalue_hsv = ""
            for value in hsvarray:
                temp = str(hex(int(value))).replace("0x", "")
                if len(temp) == 1:
                    temp = "0" + temp
                hexvalue_hsv = hexvalue_hsv + temp
            if len(hexvalue_hsv) == 7:
                hexvalue = hexvalue + "0" + hexvalue_hsv
            else:
                hexvalue = hexvalue + "00" + hexvalue_hsv

        # Bulb Type B
        if(bulb == 'B'):
            # h:0-360,s:0-1000,v:0-1000|hsv|
            hexvalue = ""
            hsvarray = [int(hsv[0] * 360), int(hsv[1] * 1000), int(hsv[2] * 1000)]
            for value in hsvarray:
                temp = str(hex(int(value))).replace("0x", "")
                while len(temp) < 4:
                    temp = "0" + temp
                hexvalue = hexvalue + temp

        return hexvalue

    @staticmethod
    def _hexvalue_to_rgb(hexvalue, bulb='A'):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an RGB value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        if(bulb == 'A'):
            r = int(hexvalue[0:2], 16)
            g = int(hexvalue[2:4], 16)
            b = int(hexvalue[4:6], 16)
        if(bulb == 'B'):
            # hexvalue is in hsv
            h = float(int(hexvalue[0:4], 16)/360.0)
            s = float(int(hexvalue[4:8], 16)/1000.0)
            v = float(int(hexvalue[8:12], 16)/1000.0)
            rgb = colorsys.hsv_to_rgb(h,s,v)
            r = int(rgb[0]*255)
            g = int(rgb[1]*255)
            b = int(rgb[2]*255)
            
        return (r, g, b)

    @staticmethod
    def _hexvalue_to_hsv(hexvalue, bulb='A'):
        """
        Converts the hexvalue used by Tuya for colour representation into
        an HSV value.

        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        if(bulb == 'A'):
            h = int(hexvalue[7:10], 16) / 360
            s = int(hexvalue[10:12], 16) / 255
            v = int(hexvalue[12:14], 16) / 255
        if(bulb == 'B'):
            # hexvalue is in hsv
            print(hexvalue + " - " + hexvalue[0:4])
            h = int(hexvalue[0:4], 16)/360.0
            s = int(hexvalue[4:8], 16)/1000.0
            v = int(hexvalue[8:12], 16)/1000.0 

        return (h, s, v)

    def set_version(self, version):
        """
        Set the Tuya device version 3.1 or 3.3 for BulbDevice
        Attempt to determine BulbDevice Type: A or B based on:
            Type A has keys 1-5
            Type B has keys 20-29
        """
        self.version = version
        # Try to determine type of BulbDevice Type based on switch DPS
        status = self.status()
        if '1' not in status['dps']:
            self.bulb_type = 'B'

    def turn_on(self, switch=0):
        """Turn the device on"""
        if switch==0:
            switch = self.DPS_INDEX_ON[self.bulb_type]
        self.set_status(True, switch)

    def turn_off(self, switch=0):
        """Turn the device on"""
        if switch==0:
            switch = self.DPS_INDEX_ON[self.bulb_type]
        self.set_status(False, switch)

    def set_mode(self, mode='white'):
        """
        Set bulb mode

        Args:
            mode(string): white,colour,scene,music
        
        """
        payload = self.generate_payload(CONTROL, {
            self.DPS_INDEX_MODE[self.bulb_type]: mode
        })
        data = self._send_receive(payload)
        return data
        
    def set_scene(self, scene):
        """
        Set to scene mode

        Args:
            scene(int): Value for the scene as int from 1-4.
        """
        if not 1 <= scene <= 4:
            raise ValueError(
                "The value for scene needs to be between 1 and 4.")

        if(scene == 1):
            s = self.DPS_MODE_SCENE_1
        elif(scene == 2):
            s = self.DPS_MODE_SCENE_2
        elif(scene == 3):
            s = self.DPS_MODE_SCENE_3
        else:
            s = self.DPS_MODE_SCENE_4

        payload = self.generate_payload(CONTROL, {
            self.DPS_INDEX_MODE[self.bulb_type]: s
        })
        data = self._send_receive(payload)
        return data

    def set_colour(self, r, g, b):
        """
        Set colour of an rgb bulb.

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        if not 0 <= r <= 255:
            raise ValueError(
                "The value for red needs to be between 0 and 255.")
        if not 0 <= g <= 255:
            raise ValueError(
                "The value for green needs to be between 0 and 255.")
        if not 0 <= b <= 255:
            raise ValueError(
                "The value for blue needs to be between 0 and 255.")

        hexvalue = BulbDevice._rgb_to_hexvalue(r, g, b, self.bulb_type)

        payload = self.generate_payload(CONTROL, {
            self.DPS_INDEX_MODE[self.bulb_type]: self.DPS_MODE_COLOUR,
            self.DPS_INDEX_COLOUR[self.bulb_type]: hexvalue})
        data = self._send_receive(payload)
        return data

    def set_white_percentage(self, brightness=100, colourtemp=0):
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
            colourtemp(int): Value for the colour temperature in percent (0-100)
        """
        # Brightness
        if not (0 <= brightness <= 100):
            raise ValueError("Brightness percentage needs to be between 0 and 100.")
        b = int(25 + (255-25)*brightness/100)
        if self.bulb_type == 'B':
            b = int(10 + (1000-10)*brightness/100)

        # Colourtemp
        if not (0 <= colourtemp <= 100):
            raise ValueError("Colourtemp percentage needs to be between 0 and 100.")
        c = colourtemp = int(255*colourtemp/100)
        if self.bulb_type == 'B':
            c = int(1000*colourtemp/100)

        data = set_white(b,c)
        return data

    def set_white(self, brightness=-1, colourtemp=-1): 
        """
        Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (A:25-255 or B:10-1000)
            colourtemp(int): Value for the colour temperature (A:0-255, B:0-1000).

            Default: Max Brightness and Min Colourtemp
        """
        # Brightness (default Max)
        if brightness < 0:
            brightness = 255
            if self.bulb_type == 'B':
                brightness = 1000
        if self.bulb_type == 'A' and not (25 <= brightness <= 255):
                raise ValueError("The brightness needs to be between 25 and 255.")
        if self.bulb_type == 'B' and not (10 <= brightness <= 1000):
                raise ValueError("The brightness needs to be between 10 and 1000.")

        # Colourtemp (default Min)
        if colourtemp < 0:
            colourtemp = 0
        if self.bulb_type == 'A' and not (0 <= colourtemp <= 255):
            raise ValueError(
                "The colour temperature needs to be between 0 and 255.")
        if self.bulb_type == 'B' and not (0 <= colourtemp <= 1000):
            raise ValueError(
                "The colour temperature needs to be between 0 and 1000.")

        payload = self.generate_payload(CONTROL, {
            self.DPS_INDEX_MODE[self.bulb_type]: self.DPS_MODE_WHITE,
            self.DPS_INDEX_BRIGHTNESS[self.bulb_type]: brightness,
            self.DPS_INDEX_COLOURTEMP[self.bulb_type]: colourtemp})

        data = self._send_receive(payload)
        return data

    def set_brightness_percentage(self, brightness=100):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness in percent (0-100)
        """
        if not (0 <= brightness <= 100):
            raise ValueError("Brightness percentage needs to be between 0 and 100.")
        b = int(25 + (255-25)*brightness/100)
        if self.bulb_type == 'B':
            b = int(10 + (1000-10)*brightness/100)

        data = self.set_brightness(b)
        return data

    def set_brightness(self, brightness):
        """
        Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
        """
        if self.bulb_type == 'A' and not (25 <= brightness <= 255):
                raise ValueError("The brightness needs to be between 25 and 255.")
        if self.bulb_type == 'B' and not (10 <= brightness <= 1000):
                raise ValueError("The brightness needs to be between 10 and 1000.")

        payload = self.generate_payload(
            CONTROL, {self.DPS_INDEX_BRIGHTNESS[self.bulb_type]: brightness})
        data = self._send_receive(payload)
        return data

    def set_colourtemp_percentage(self, colourtemp=100):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature in percentage (0-100).
        """
        if not (0 <= colourtemp <= 100):
            raise ValueError("Colourtemp percentage needs to be between 0 and 100.")
        c = int(255*colourtemp/100)
        if self.bulb_type == 'B':
            c = int(1000*colourtemp/100)
        
        data = self.set_colourtemp(c)
        return data

    def set_colourtemp(self, colourtemp):
        """
        Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
        """
        if self.bulb_type == 'A' and not (0 <= colourtemp <= 255):
            raise ValueError(
                "The colour temperature needs to be between 0 and 255.")
        if self.bulb_type == 'B' and not (0 <= colourtemp <= 1000):
            raise ValueError(
                "The colour temperature needs to be between 0 and 1000.")

        payload = self.generate_payload(
            CONTROL, {self.DPS_INDEX_COLOURTEMP[self.bulb_type]: colourtemp})
        data = self._send_receive(payload)
        return data

    def brightness(self):
        """Return brightness value"""
        return self.status()[self.DPS][self.DPS_INDEX_BRIGHTNESS[self.bulb_type]]

    def colourtemp(self):
        """Return colour temperature"""
        return self.status()[self.DPS][self.DPS_INDEX_COLOURTEMP[self.bulb_type]]

    def colour_rgb(self):
        """Return colour as RGB value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_rgb(hexvalue, self.bulb_type)

    def colour_hsv(self):
        """Return colour as HSV value"""
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR[self.bulb_type]]
        return BulbDevice._hexvalue_to_hsv(hexvalue, self.bulb_type)

    def state(self):
        """Return state of Bulb"""
        status = self.status()
        state = {}

        for key in status[self.DPS].keys():
            if(key in self.DPS_2_STATE):
                state[self.DPS_2_STATE[key]] = status[self.DPS][key]

        return state


# Utility Functions

# SCAN network for Tuya devices
MAXCOUNT = 15       # How many tries before stopping
UDPPORT = 6666      # Tuya 3.1 UDP Port
UDPPORTS = 6667     # Tuya 3.3 encrypted UDP Port
TIMEOUT = 3.0       # Seconds to wait for a broadcast

# UDP packet payload decryption - credit to tuya-convert


def pad(s): return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
def unpad(s): return s[:-ord(s[len(s) - 1:])]


def encrypt(msg, key): return AES.new(
    key, AES.MODE_ECB).encrypt(pad(msg).encode())
def decrypt(msg, key): return unpad(
    AES.new(key, AES.MODE_ECB).decrypt(msg)).decode()


udpkey = md5(b"yGAdlopoPVldABfn").digest()
def decrypt_udp(msg): return decrypt(msg, udpkey)

# Return positive number or zero


def floor(x):
    if x > 0:
        return x
    else:
        return 0


def appenddevice(newdevice, devices):
    if(newdevice['ip'] in devices):
        return True
    """
    for i in devices:
        if i['ip'] == newdevice['ip']:
                return True
    """
    devices[newdevice['ip']] = newdevice
    return False

# Scan function shortcut


def scan(maxretry=MAXCOUNT, color=True):
    """Scans your network for Tuya devices with output to stdout
    """
    d = deviceScan(True, maxretry, color)

# Scan function


def deviceScan(verbose=False, maxretry=MAXCOUNT, color=True):
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        maxretry = The number of loops to wait to pick up UDP from all devices
        color = True or False, print output in color [Default: True]

    Response: 
        devices = Dictionary of all devices found

    To unpack data, you can do something like this:

        devices = tinytuya.deviceScan()
        for ip in devices:
            id = devices[ip]['gwId']
            key = devices[ip]['productKey']
            vers = devices[ip]['version']
            dps = devices[ip]['dps']

    """
    DEVICEFILE = 'devices.json'
    havekeys = False
    tuyadevices = []

    # Lookup Tuya device info by (id) returning (name, key)
    def tuyaLookup(deviceid):
        for i in tuyadevices:
            if (i['id'] == deviceid):
                return (i['name'], i['key'])
        return ("", "")

    # Check to see if we have additional Device info
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tuyadevices = json.load(f)
            havekeys = True
    except:
        # No Device info
        pass

    # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
    client = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", UDPPORT))
    client.settimeout(TIMEOUT)
    # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
    clients = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clients.bind(("", UDPPORTS))
    clients.settimeout(TIMEOUT)

    if(verbose):
        if(color == False):
            # Disable Terminal Color Formatting
            bold = subbold = normal = dim = alert = alertdim = ""
        else:
            # Terminal Color Formatting
            bold = "\033[0m\033[97m\033[1m"
            subbold = "\033[0m\033[32m"
            normal = "\033[97m\033[0m"
            dim = "\033[0m\033[97m\033[2m"
            alert = "\033[0m\033[91m\033[1m"
            alertdim = "\033[0m\033[91m\033[2m"

        print("\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"%(bold,normal,dim,__version__))
        if(havekeys):
            print("%s[Loaded devices.json - %d devices]\n" % (dim,len(tuyadevices)))
        print("%sScanning on UDP ports %s and %s for devices (%s retries)...%s\n" %
              (subbold, UDPPORT, UDPPORTS, maxretry, normal))

    # globals
    devices = {}
    count = 0
    counts = 0
    spinnerx = 0
    spinner = "|/-\\|"

    while (count + counts) <= maxretry:
        note = 'invalid'
        if(verbose):
            print("%sScanning... %s\r" % (dim, spinner[spinnerx]), end='')
            spinnerx = (spinnerx + 1) % 4

        if (count <= counts):  # alternate between 6666 and 6667 ports
            try:
                data, addr = client.recvfrom(4048)
            except:
                # Timeout
                count = count + 1
                continue
        else:
            try:
                data, addr = clients.recvfrom(4048)
            except:
                # Timeout
                counts = counts + 1
                continue
        ip = addr[0]
        gwId = productKey = version = dname = dkey = ""
        result = data
        try:
            result = data[20:-8]
            try:
                result = decrypt_udp(result)
            except:
                result = result.decode()

            result = json.loads(result)

            note = 'Valid'
            ip = result['ip']
            gwId = result['gwId']
            productKey = result['productKey']
            version = result['version']
        except:
            if(verbose):
                print(alertdim + "*  Unexpected payload=%r\n" + normal, result)
            result = {"ip": ip}
            note = "Unknown"

        # check to see if we have seen this device before and add to devices array
        if appenddevice(result, devices) == False:
            
            # new device found - back off count if we keep getting new devices
            if(version == '3.1'):
                count = floor(count - 1)
            else:
                counts = floor(counts - 1)
            if(havekeys):
                try:
                    # Try to pull name and key data
                    (dname, dkey) = tuyaLookup(gwId)
                except:
                    pass
            if(verbose):
                if(dname == ""):    
                    print("%s%s Device Found%s [%s payload]: %s%s%s\n    ID = %s, Product ID = %s, Version = %s" % (
                    normal, version, dim, note, subbold, ip, dim, gwId, productKey, version))
                else:
                    print("%s%s%s [%s payload]: %s%s%s\n    ID = %s, Product ID = %s, Version = %s" % (
                    normal, dname, dim, note, subbold, ip, dim, gwId, productKey, version))
            try:
                if(version == '3.1'):
                    # Version 3.1 - no device key requires - poll for status data points
                    d = OutletDevice(gwId, ip, dkey)
                    d.set_version(3.1)
                    dpsdata = d.status()
                    devices[ip]['dps'] = dpsdata
                    if(verbose):
                        print("    Status: %s" % dpsdata['dps'])
                else:
                    # Version 3.3+ requires device key
                    if(dkey != ""):
                        d = OutletDevice(gwId, ip, dkey)
                        d.set_version(3.3)
                        dpsdata = d.status()
                        devices[ip]['dps'] = dpsdata
                        if(verbose):
                            print(dim + "    Status: %s" % dpsdata['dps'])      
                    else:                      
                        if(verbose):
                            print(alertdim + "    No Stats - Device Key required to poll for status" + dim)
            except:
                if(verbose):
                    print(alertdim + "    No Stats for %s: Unable to poll" % ip)
                devices[ip]['err'] = 'Unable to poll'
            if(dname != ""):
                devices[ip]['name'] = dname
                devices[ip]['key'] = dkey
        else:
            if(version == '3.1'):
                count = count + 1
            else:
                counts = counts + 1

    if(verbose):
        print("                    \n%sScan Complete!  Found %s devices.\n" %
              (normal, len(devices)))

    clients.close()
    client.close()
    return(devices)


# TinyTuya Setup Wizard

def tuyaPlatform(apiRegion, apiKey, apiSecret, uri, token=None):
    """Tuya IoT Platform Data Access

    Parameters:
        * region     Tuya API Server Region: us, eu, cn, in
        * apiKey     Tuya Platform Developer ID
        * apiSecret  Tuya Platform Developer secret 
        * uri        Tuya Platform URI for this call
        * token      Tuya OAuth Token

    Playload Construction - Header Data:
        Parameter 	  Type    Required	Description
        client_id	  String     Yes	client_id
        signature     String     Yes	HMAC-SHA256 Signature (see below)
        sign_method	  String	 Yes	Message-Digest Algorithm of the signature: HMAC-SHA256.
        t	          Long	     Yes	13-bit standard timestamp (now in milliseconds).
        lang	      String	 No	    Language. It is zh by default in China and en in other areas.
        access_token  String     *      Required for service management calls

    Signature Details:
        * OAuth Token Request: signature = HMAC-SHA256(KEY + t, SECRET).toUpperCase()
        * Service Management: signature = HMAC-SHA256(KEY + access_token + t, SECRET).toUpperCase()

    URIs:
        * Get Token = https://openapi.tuyaus.com/v1.0/token?grant_type=1
        * Get UserID = https://openapi.tuyaus.com/v1.0/devices/{DeviceID}
        * Get Devices = https://openapi.tuyaus.com/v1.0/users/{UserID}/devices

    """
    url = "https://openapi.tuya%s.com/v1.0/%s" % (apiRegion,uri)
    now = int(time.time()*1000)
    if(token==None):
        payload = apiKey + str(now)
    else:
        payload = apiKey + token + str(now)

    # Sign Payload
    signature = hmac.new(
        apiSecret.encode('utf-8'),
        msg=payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

    # Create Header Data
    headers = {}
    headers['client_id'] = apiKey
    headers['sign_method'] = 'HMAC-SHA256'
    headers['t'] = str(now)
    headers['sign'] = signature
    if(token != None):
        headers['access_token'] = token

    # Get Token
    response = requests.get(url, headers=headers)
    try:
        response_dict = json.loads(response.content.decode())
    except:
        try:
            response_dict = json.loads(response.content)
        except:
            print("Failed to get valid JSON response")

    return(response_dict)

def wizard(color=True):
    """
    TinyTuya Setup Wizard Tuya based WiFi smart devices

    Parameter:
        color = True or False, print output in color [Default: True]

    Description
        Setup Wizard will prompt user for Tuya IoT Developer credentials and will gather all of
        the Device IDs and their Local KEYs.  It will save the credentials and the device
        data in the tinytuya.json and devices.json configuration files respectively.

        HOW to set up your Tuya IoT Developer account: iot.tuya.com:
        https://github.com/jasonacox/tinytuya#get-the-tuya-device-local-key

    Credits
    * Tuya API Documentation
        https://developer.tuya.com/en/docs/iot/open-api/api-list/api?id=K989ru6gtvspg
    * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
        The TuyAPI/CLI wizard inspired and informed this python version.
    """

    # Get Configuration Data
    CONFIGFILE = 'tinytuya.json'
    DEVICEFILE = 'devices.json'
    SNAPSHOTFILE = 'snapshot.json'
    config = {}
    config['apiKey'] = ''
    config['apiSecret'] = ''
    config['apiRegion'] = ''
    config['apiDeviceID'] = ''
    needconfigs = True
    try:
        # Load defaults
        with open(CONFIGFILE) as f:
            config = json.load(f)
    except:
        # First Time Setup
        pass
    
    if(color == False):
        # Disable Terminal Color Formatting
        bold = subbold = normal = dim = alert = alertdim = ""
    else:
        # Terminal Color Formatting
        bold = "\033[0m\033[97m\033[1m"
        subbold = "\033[0m\033[32m"
        normal = "\033[97m\033[0m"
        dim = "\033[0m\033[97m\033[2m"
        alert = "\033[0m\033[91m\033[1m"
        alertdim = "\033[0m\033[91m\033[2m"

    print(bold + 'TinyTuya Setup Wizard' + dim + ' [%s]' % (version) + normal)
    print('')

    if(config['apiKey'] != '' and config['apiSecret'] != '' and
            config['apiRegion'] != '' and config['apiDeviceID'] != ''):
        needconfigs = False
        print("    " + subbold + "Existing settings:" + dim +
              "\n        API Key=%s \n        Secret=%s\n        DeviceID=%s\n        Region=%s" %
              (config['apiKey'], config['apiSecret'], config['apiDeviceID'],
               config['apiRegion']))
        print('')
        answer = input(subbold + '    Use existing credentials ' +
                       normal + '(Y/n): ')
        if(answer[0:1].lower() == 'n'):
            needconfigs = True

    if(needconfigs):
        # Ask user for config settings
        print('')
        config['apiKey'] = input(subbold + "    Enter " + bold + "API Key" + subbold +
                                 " from tuya.com: " + normal)
        config['apiSecret'] = input(subbold + "    Enter " + bold + "API Secret" + subbold +
                                    " from tuya.com: " + normal)
        config['apiDeviceID'] = input(subbold +
                                      "    Enter " + bold + "any Device ID" + subbold +
                                      " currently registered in Tuya App (used to pull full list): " + normal)
        # TO DO - Determine apiRegion based on Device - for now, ask
        config['apiRegion'] = input(subbold + "    Enter " + bold + "Your Region" + subbold +
                                    " (Options: us, eu, cn or in): " + normal)
        # Write Config
        json_object = json.dumps(config, indent=4)
        with open(CONFIGFILE, "w") as outfile:
            outfile.write(json_object)
        print(bold + "\n>> Configuration Data Saved to " + CONFIGFILE)
        print(dim + json_object)

    KEY = config['apiKey']
    SECRET = config['apiSecret']
    DEVICEID = config['apiDeviceID']
    REGION = config['apiRegion']        # us, eu, cn, in
    LANG = 'en'                         # en or zh

    # Get Oauth Token from tuyaPlatform
    uri = 'token?grant_type=1'
    response_dict = tuyaPlatform(REGION, KEY, SECRET,uri)
    token = response_dict['result']['access_token']

    # Get UID from sample Device ID 
    uri = 'devices/%s' % DEVICEID
    response_dict = tuyaPlatform(REGION, KEY, SECRET, uri, token)
    uid = response_dict['result']['uid']

    # Use UID to get list of all Devices for User
    uri = 'users/%s/devices' % uid
    json_data = tuyaPlatform(REGION, KEY, SECRET, uri, token)
 
    # Filter to only Name, ID and Key
    tuyadevices = []
    for i in json_data['result']:
        item = {}
        item['name'] = i['name'].strip()
        item['id'] = i['id']
        item['key'] = i['local_key']
        tuyadevices.append(item)

    # Display device list
    print("\n\n" + bold + "Device Listing\n" + dim)
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    print(output)

    # Save list to devices.json
    print(bold + "\n>> " + normal + "Saving list to " + DEVICEFILE)
    with open(DEVICEFILE, "w") as outfile:
        outfile.write(output)
    print(dim + "    %d registered devices saved" % len(tuyadevices))

    # Find out if we should poll all devices
    answer = input(subbold + '\nPoll local devices? ' +
                   normal + '(Y/n): ')
    if(answer[0:1].lower() != 'n'):
        # Scan network for devices and provide polling data
        print(normal + "\nScanning local network for Tuya devices...")
        devices = deviceScan(False, 20)
        print("    %s%s local devices discovered%s" %
              (dim, len(devices), normal))
        print("")

        def getIP(d, gwid):
            for ip in d:
                if (gwid == d[ip]['gwId']):
                    return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("Polling local devices...")
        for i in tuyadevices:
            item = {}
            name = i['name']
            (ip, ver) = getIP(devices, i['id'])
            item['name'] = name
            item['ip'] = ip
            item['ver'] = ver
            item['id'] = i['id']
            item['key'] = i['key']
            if (ip == 0):
                print("    %s[%s] - %s%s - %sError: No IP found%s" %
                      (subbold, name, dim, ip, alert, normal))
            else:
                try:
                    d = OutletDevice(i['id'], ip, i['key'])
                    if ver == "3.3":
                        d.set_version(3.3)
                    data = d.status()
                    if data:
                        item['dps'] = data
                        state = alertdim + "Off" + dim
                        # print(data)
                        try:
                            if(data['dps']['1'] == True):
                                state = bold + "On" + dim
                            print("    %s[%s] - %s%s - %s - DPS: %r" %
                                  (subbold, name, dim, ip, state, data['dps']))
                        except:
                            print("    %s[%s] - %s%s - %sNo Response" %
                                  (subbold, name, dim, ip, alertdim))
                    else:
                        print("    %s[%s] - %s%s - %sNo Response" %
                              (subbold, name, dim, ip, alertdim))
                except:
                    print("    %s[%s] - %s%s - %sNo Response" %
                          (subbold, name, dim, ip, alertdim))
            polling.append(item)
        # for loop

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4) 
        print(bold + "\n>> " + normal + "Saving device snapshot data to " + SNAPSHOTFILE)
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

    print("\nDone.\n")
    return
