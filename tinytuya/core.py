# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Core Classes and Helper Functions

 Classes
  * AESCipher - Cryptography Helpers
  * XenonDevice(object) - Base Tuya Objects and Functions
  * Device(dev_id, address, local_key="", dev_type="default") - Tuya Class for Devices

 Functions
    json = status()                    # returns json payload
    set_version(version)               # 3.1 [default] or 3.3
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]
    set_socketRetryLimit(integer)      # retry count limit [default 5]
    set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
    set_dpsUsed(dps_to_request)        # add data points (DPS) to request
    add_dps_to_request(index)          # add data point (DPS) index set to None
    set_retry(retry=True)              # retry if response payload is truncated
    set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
    set_value(index, value, nowait)    # Set int value of any index.
    heartbeat(nowait)                  # Send heartbeat to device
    updatedps(index=[1], nowait)       # Send updatedps command to device
    turn_on(switch=1, nowait)          # Turn on device / switch #
    turn_off(switch=1, nowait)         # Turn off
    set_timer(num_secs, nowait)        # Set timer for num_secs
    set_debug(toggle, color)           # Activate verbose debugging output
    set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
    detect_available_dps()             # Return list of DPS available from device
    generate_payload(command, data)    # Generate TuyaMessage payload for command with data
    send(payload)                      # Send payload to device (do not wait for response)
    receive()                          # Receive payload from device
    
 Credits
  * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    For protocol reverse engineering
  * PyTuya https://github.com/clach04/python-tuya by clach04
    The origin of this python module (now abandoned)
  * LocalTuya https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
    Updated pytuya to support devices with Device IDs of 22 characters

"""

# Modules
from __future__ import print_function  # python 2.7 support
import binascii
from collections import namedtuple
import base64
from hashlib import md5
import json
import logging
import socket
import struct
import sys
import time
from colorama import init

# Backward compatibility for python2
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

# Colorama terminal color capability for all platforms
init()

version_tuple = (1, 6, 5)
version = __version__ = "%d.%d.%d" % version_tuple
__author__ = "jasonacox"

log = logging.getLogger(__name__)
# Uncomment the following to set debug mode or call set_debug()
# logging.basicConfig(level=logging.DEBUG)

log.debug("%s version %s", __name__, __version__)
log.debug("Python %s on %s", sys.version, sys.platform)
if Crypto is None:
    log.debug("Using pyaes version %r", pyaes.VERSION)
    log.debug("Using pyaes from %r", pyaes.__file__)
else:
    log.debug("Using PyCrypto %r", Crypto.version_info)
    log.debug("Using PyCrypto from %r", Crypto.__file__)

# Globals Network Settings
MAXCOUNT = 15       # How many tries before stopping
UDPPORT = 6666      # Tuya 3.1 UDP Port
UDPPORTS = 6667     # Tuya 3.3 encrypted UDP Port
TCPPORT = 6668      # Tuya TCP Local Port
TIMEOUT = 3.0       # Seconds to wait for a broadcast
TCPTIMEOUT = 0.4    # Seconds to wait for socket open for scanning
DEFAULT_NETWORK = '192.168.0.0/24'

# Configuration Files
CONFIGFILE = 'tinytuya.json'
DEVICEFILE = 'devices.json'
RAWFILE = 'tuya-raw.json'
SNAPSHOTFILE = 'snapshot.json'

# Tuya Command Types
# Reference: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h
AP_CONFIG       = 1  # FRM_TP_CFG_WF      # only used for ap 3.0 network config
ACTIVE          = 2  # FRM_TP_ACTV (discard) # WORK_MODE_CMD
BIND            = 3  # FRM_SECURITY_TYPE3 # WIFI_STATE_CMD - wifi working status
RENAME_GW       = 4  # FRM_SECURITY_TYPE4 # WIFI_RESET_CMD - reset wifi
RENAME_DEVICE   = 5  # FRM_SECURITY_TYPE5 # WIFI_MODE_CMD - Choose smartconfig/AP mode
UNBIND          = 6  # FRM_TP_UNBIND_DEV  # DATA_QUERT_CMD - issue command
CONTROL         = 7  # FRM_TP_CMD         # STATE_UPLOAD_CMD
STATUS          = 8  # FRM_TP_STAT_REPORT # STATE_QUERY_CMD
HEART_BEAT      = 9  # FRM_TP_HB
DP_QUERY        = 0x0a # 10 # FRM_QUERY_STAT      # UPDATE_START_CMD - get data points
QUERY_WIFI      = 0x0b # 11 # FRM_SSID_QUERY (discard) # UPDATE_TRANS_CMD
TOKEN_BIND      = 0x0c # 12 # FRM_USER_BIND_REQ   # GET_ONLINE_TIME_CMD - system time (GMT)
CONTROL_NEW     = 0x0d # 13 # FRM_TP_NEW_CMD      # FACTORY_MODE_CMD
ENABLE_WIFI     = 0x0e # 14 # FRM_ADD_SUB_DEV_CMD # WIFI_TEST_CMD
WIFI_INFO       = 0x0f # 15 # FRM_CFG_WIFI_INFO
DP_QUERY_NEW    = 0x10 # 16 # FRM_QUERY_STAT_NEW
SCENE_EXECUTE   = 0x11 # 17 # FRM_SCENE_EXEC
UPDATEDPS       = 0x12 # 18 # FRM_LAN_QUERY_DP    # Request refresh of DPS
UDP_NEW         = 0x13 # 19 # FR_TYPE_ENCRYPTION
AP_CONFIG_NEW   = 0x14 # 20 # FRM_AP_CFG_WF_V40
BOARDCAST_LPV34 = 0x23 # 35 # FR_TYPE_BOARDCAST_LPV34
LAN_EXT_STREAM  = 0x40 # 64 # FRM_LAN_EXT_STREAM

# Protocol Versions and Headers
PROTOCOL_VERSION_BYTES_31 = b"3.1"
PROTOCOL_VERSION_BYTES_33 = b"3.3"
PROTOCOL_33_HEADER = PROTOCOL_VERSION_BYTES_33 + 12 * b"\x00"
MESSAGE_HEADER_FMT = ">4I"  # 4*uint32: prefix, seqno, cmd, length [, retcode]
MESSAGE_RETCODE_FMT = ">I"  # retcode for received messages
MESSAGE_END_FMT = ">2I"  # 2*uint32: crc, suffix
PREFIX_VALUE = 0x000055AA
PREFIX_BIN = b"\x00\x00U\xaa"
SUFFIX_VALUE = 0x0000AA55
SUFFIX_BIN = b"\x00\x00\xaaU"

# Tuya Packet Format
TuyaHeader = namedtuple('TuyaHeader', 'prefix seqno cmd length')
TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc")

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

# TinyTuya Error Response Codes
ERR_JSON = 900
ERR_CONNECT = 901
ERR_TIMEOUT = 902
ERR_RANGE = 903
ERR_PAYLOAD = 904
ERR_OFFLINE = 905
ERR_STATE = 906
ERR_FUNCTION = 907
ERR_DEVTYPE = 908
ERR_CLOUDKEY = 909
ERR_CLOUDRESP = 910
ERR_CLOUDTOKEN = 911
ERR_PARAMS = 912
ERR_CLOUD = 913

error_codes = {
    ERR_JSON: "Invalid JSON Response from Device",
    ERR_CONNECT: "Network Error: Unable to Connect",
    ERR_TIMEOUT: "Timeout Waiting for Device",
    ERR_RANGE: "Specified Value Out of Range",
    ERR_PAYLOAD: "Unexpected Payload from Device",
    ERR_OFFLINE: "Network Error: Device Unreachable",
    ERR_STATE: "Device in Unknown State",
    ERR_FUNCTION: "Function Not Supported by Device",
    ERR_DEVTYPE: "Device22 Detected: Retry Command",
    ERR_CLOUDKEY: "Missing Tuya Cloud Key and Secret",
    ERR_CLOUDRESP: "Invalid JSON Response from Cloud",
    ERR_CLOUDTOKEN: "Unable to Get Cloud Token",
    ERR_PARAMS: "Missing Function Parameters",
    ERR_CLOUD: "Error Response from Tuya Cloud",
    None: "Unknown Error",
}

class DecodeError(Exception):
    pass

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
                pyaes.AESModeOfOperationECB(self.key)
            )  # no IV, auto pads to 16
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
            return self._unpad(raw).decode("utf-8")

        else:
            cipher = pyaes.blockfeeder.Decrypter(
                pyaes.AESModeOfOperationECB(self.key)
            )  # no IV, auto pads to 16
            plain_text = cipher.feed(enc)
            plain_text += cipher.feed()  # flush final block
            return plain_text

    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1 :])]


# Misc Helpers
def bin2hex(x, pretty=False):
    if pretty:
        space = " "
    else:
        space = ""
    if IS_PY2:
        result = "".join("%02X%s" % (ord(y), space) for y in x)
    else:
        result = "".join("%02X%s" % (y, space) for y in x)
    return result

def hex2bin(x):
    if IS_PY2:
        return x.decode("hex")
    else:
        return bytes.fromhex(x)

def set_debug(toggle=True, color=True):
    """Enable tinytuya verbose logging"""
    if toggle:
        if color:
            logging.basicConfig(
                format="\x1b[31;1m%(levelname)s:%(message)s\x1b[0m", level=logging.DEBUG
            )
        else:
            logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.DEBUG)
        log.setLevel(logging.DEBUG)
        log.debug("TinyTuya [%s]\n", __version__)
    else:
        log.setLevel(logging.NOTSET)

def pack_message(msg):
    """Pack a TuyaMessage into bytes."""
    # Create full message excluding CRC and suffix
    buffer = (
        struct.pack(
            MESSAGE_HEADER_FMT,
            PREFIX_VALUE,
            msg.seqno,
            msg.cmd,
            len(msg.payload) + struct.calcsize(MESSAGE_END_FMT),
        )
        + msg.payload
    )
    # Calculate CRC, add it together with suffix
    buffer += struct.pack(
        MESSAGE_END_FMT, binascii.crc32(buffer) & 0xFFFFFFFF, SUFFIX_VALUE
    )
    return buffer

def unpack_message(data, header=None):
    """Unpack bytes into a TuyaMessage."""
    # 4-word header plus return code
    header_len = struct.calcsize(MESSAGE_HEADER_FMT)
    retcode_len = struct.calcsize(MESSAGE_RETCODE_FMT)
    end_len = struct.calcsize(MESSAGE_END_FMT)
    headret_len = header_len + retcode_len

    if len(data) < headret_len+end_len:
        log.debug('unpack_message(): not enough data to unpack header! need %d but only have %d', headret_len+end_len, len(data))
        raise DecodeError('Not enough data to unpack header')

    if header is None:
        header = parse_header(data)

    if len(data) < header_len+header.length:
        log.debug('unpack_message(): not enough data to unpack payload! need %d but only have %d', header_len+header.length, len(data))
        raise DecodeError('Not enough data to unpack payload')

    retcode = struct.unpack(MESSAGE_RETCODE_FMT, data[header_len:headret_len])
    payload = data[headret_len:headret_len+header.length]
    crc, suffix = struct.unpack(MESSAGE_END_FMT, payload[-end_len:])
    have_crc = binascii.crc32(data[:(header_len+header.length)-end_len]) & 0xFFFFFFFF

    if suffix != SUFFIX_VALUE:
        log.debug('Suffix prefix wrong! %08X != %08X', suffix, SUFFIX_VALUE)

    if crc != have_crc:
        log.debug('CRC wrong! %08X != %08X', have_crc, crc)

    return TuyaMessage(header.seqno, header.cmd, retcode, payload[:-end_len], crc)

def parse_header(data):
    header_len = struct.calcsize(MESSAGE_HEADER_FMT)

    if len(data) < header_len:
        raise DecodeError('Not enough data to unpack header')

    prefix, seqno, cmd, payload_len = struct.unpack(
        MESSAGE_HEADER_FMT, data[:header_len]
    )

    if prefix != PREFIX_VALUE:
        #log.debug('Header prefix wrong! %08X != %08X', prefix, PREFIX_VALUE)
        raise DecodeError('Header prefix wrong! %08X != %08X' % (prefix, PREFIX_VALUE))

    # sanity check. currently the max payload length is somewhere around 300 bytes
    if payload_len > 1000:
        raise DecodeError('Header claims the packet size is over 1000 bytes!  It is most likely corrupt.  Claimed size: %d bytes' % payload_len)

    return TuyaHeader(prefix, seqno, cmd, payload_len)

def has_suffix(payload):
    """Check to see if payload has valid Tuya suffix"""
    if len(payload) < 4:
        return False
    log.debug("buffer %r = %r", payload[-4:], SUFFIX_BIN)
    return payload[-4:] == SUFFIX_BIN

def error_json(number=None, payload=None):
    """Return error details in JSON"""
    try:
        spayload = json.dumps(payload)
        # spayload = payload.replace('\"','').replace('\'','')
    except:
        spayload = '""'

    vals = (error_codes[number], str(number), spayload)
    log.debug("ERROR %s - %s - payload: %s", *vals)

    return json.loads('{ "Error":"%s", "Err":"%s", "Payload":%s }' % vals)


# Tuya Device Dictionary - Command and Payload Overrides
#
# 'default' devices require the 0a command for the DP_QUERY request
# 'device22' devices require the 0d command for the DP_QUERY request and a list of
#            dps used set to Null in the request payload
#
# Any command not defined in payload_dict will be sent as-is with a
#  payload of {"gwId": "", "devId": "", "uid": "", "t": ""}

payload_dict = {
    # Default Device
    "default": {
        AP_CONFIG: {  # [BETA] Set Control Values on Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CONTROL: {  # Set Control Values on Device
            "command": {"devId": "", "uid": "", "t": ""},
        },
        STATUS: {  # Get Status from Device
            "command": {"gwId": "", "devId": ""},
        },
        HEART_BEAT: {"command": {"gwId": "", "devId": ""}},
        DP_QUERY: {  # Get Data Points from Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CONTROL_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        DP_QUERY_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        UPDATEDPS: {"command": {"dpId": [18, 19, 20]}},
    },
    # Special Case Device with 22 character ID - Some of these devices
    # Require the 0d command as the DP_QUERY status request and the list of
    # dps requested payload
    "device22": {
        DP_QUERY: {  # Get Data Points from Device
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command for some reason
            "command": {"devId": "", "uid": "", "t": ""},
        },
    },
}


########################################################
#             Core Classes and Functions
########################################################

class XenonDevice(object):
    def __init__(
        self, dev_id, address, local_key="", dev_type="default", connection_timeout=5
    ):
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
        self.local_key = local_key.encode("latin1")
        self.connection_timeout = connection_timeout
        self.version = 3.1
        self.retry = True
        self.dev_type = dev_type
        self.disabledetect = False  # if True do not detect device22
        self.port = TCPPORT  # default - do not expect caller to pass in
        self.socket = None
        self.socketPersistent = False
        self.socketNODELAY = True
        self.socketRetryLimit = 5
        self.cipher = AESCipher(self.local_key)
        self.dps_to_request = {}
        self.seqno = 0
        self.sendWait = 0.01
        self.dps_cache = {}
        if address is None or address == "Auto" or address == "0.0.0.0":
            # try to determine IP address automatically
            (addr, ver) = self.find(dev_id)
            if addr is None:
                log.debug("Unable to find device on network (specify IP address)")
                raise Exception("Unable to find device on network (specify IP address)")
            self.address = addr
            if ver == "3.3":
                self.version = 3.3
            time.sleep(0.5)

    def __del__(self):
        # In case we have a lingering socket connection, close it
        if self.socket is not None:
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None

    def __repr__(self):
        # FIXME can do better than this
        return "%r" % ((self.id, self.address),)

    def _get_socket(self, renew):
        if renew and self.socket is not None:
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None
        if self.socket is None:
            # Set up Socket
            retries = 0
            while retries < self.socketRetryLimit:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.socketNODELAY:
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.settimeout(self.connection_timeout)
                try:
                    retries = retries + 1
                    self.socket.connect((self.address, self.port))
                    return True
                except socket.timeout as err:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect - retry %d/%d",
                        retries, self.socketRetryLimit
                    )
                    self.socket.close()
                    time.sleep(0.1)
                except Exception as err:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect - retry %d/%d",
                        retries, self.socketRetryLimit
                    )
                    self.socket.close()
                    time.sleep(5)
            # unable to get connection
            return False
        # existing socket active
        return True

    def _recv_all(self, length):
        tries = 2
        data = b''

        while length > 0:
            newdata = self.socket.recv(length)
            if not newdata or len(newdata) == 0:
                # connection closed?
                tries -= 1
                if tries == 0:
                    raise DecodeError('No data received - connection closed?')
                continue
            data += newdata
            length -= len(newdata)
            tries = 2
        return data

    def _receive(self):
        # message consists of header + retcode + data + footer
        header_len = struct.calcsize(MESSAGE_HEADER_FMT)
        retcode_len = struct.calcsize(MESSAGE_RETCODE_FMT)
        end_len = struct.calcsize(MESSAGE_END_FMT)
        ret_end_len = retcode_len + end_len
        prefix_len = len(PREFIX_BIN)

        data = self._recv_all(header_len+ret_end_len)

        # search for the prefix.  if not found, delete everything except
        # the last (prefix_len - 1) bytes and recv more to replace it
        prefix_offset = data.find(PREFIX_BIN)
        while prefix_offset != 0:
            log.debug('Message prefix not at the beginning of the received data!')
            log.debug('Offset: %d, Received data: %r', prefix_offset, data)
            if prefix_offset < 0:
                data = data[1-prefix_len:]
            else:
                data = data[prefix_offset:]

            data += self._recv_all(header_len+ret_end_len-len(data))
            prefix_offset = data.find(PREFIX_BIN)

        header = parse_header(data)
        remaining = header_len + header.length - len(data)
        if remaining > 0:
            data += self._recv_all(remaining)

        log.debug("received data=%r", binascii.hexlify(data))
        return unpack_message(data, header=header)

    def _send_receive(self, payload, minresponse=28, getresponse=True):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send. Set to 'None' to receive only.
            minresponse(int): Minimum response size expected (default=28 bytes)
            getresponse(bool): If True, wait for and return response.
        """
        success = False
        partial_success = False
        retries = 0
        recv_retries = 0
        #max_recv_retries = 0 if not self.retry else 2 if self.socketRetryLimit > 2 else self.socketRetryLimit
        max_recv_retries = 0 if not self.retry else self.socketRetryLimit
        dev_type = self.dev_type
        do_send = True
        while not success:
            # open up socket if device is available
            if not self._get_socket(False):
                # unable to get a socket - device likely offline
                if self.socket is not None:
                    self.socket.close()
                self.socket = None
                return error_json(ERR_OFFLINE)
            # send request to device
            try:
                if payload is not None and do_send:
                    self.socket.sendall(payload)
                    time.sleep(self.sendWait)  # give device time to respond
                if getresponse is True:
                    do_send = False
                    msg = self._receive()
                    # device may send null ack (28 byte) response before a full response
                    # consider it an ACK and do not retry the send even if we do not get a full response
                    if msg:
                        payload = None
                        partial_success = True
                    if (not msg or len(msg.payload) == 0) and recv_retries <= max_recv_retries:
                        log.debug("received null payload (%r), fetch new one - retry %s / %s", msg, recv_retries, max_recv_retries)
                        recv_retries += 1
                        if recv_retries > max_recv_retries:
                            success = True
                    else:
                        success = True
                        log.debug("received message=%r", msg)
                # legacy/default mode avoids persisting socket across commands
                if not self.socketPersistent:
                    self.socket.close()
                    self.socket = None
                if getresponse is False:
                    return None
            except (KeyboardInterrupt, SystemExit) as err:
                log.debug("Keyboard Interrupt - Exiting")
                raise
            except socket.timeout as err:
                # a socket timeout occurred
                if payload is None:
                    # Receive only mode - return None
                    return None
                do_send = True
                retries += 1
                log.debug(
                    "Timeout in _send_receive() - retry %s / %s",
                    retries, self.socketRetryLimit
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    if self.socket is not None:
                        self.socket.close()
                        self.socket = None
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    # timeout reached - return error
                    json_payload = error_json(
                        ERR_TIMEOUT, "Check device key or version"
                    )
                    return json_payload
                # retry:  wait a bit, toss old socket and get new one
                time.sleep(0.1)
                self._get_socket(True)
            except DecodeError as err:
                log.debug("Error decoding received data - read retry %s/%s", recv_retries, max_recv_retries, exc_info=True)
                recv_retries += 1
                if recv_retries > max_recv_retries:
                    # we recieved at least 1 valid message with a null payload, so the send was successful
                    if partial_success:
                        return None
                    # no valid messages received
                    return error_json(ERR_PAYLOAD)
            except Exception as err:
                # likely network or connection error
                do_send = True
                retries += 1
                log.debug(
                    "Network connection error in _send_receive() - retry %s/%s",
                    retries, self.socketRetryLimit, exc_info=True
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    if self.socket is not None:
                        self.socket.close()
                        self.socket = None
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    log.debug("Unable to connect to device ")
                    # timeout reached - return error
                    json_payload = error_json(ERR_CONNECT)
                    return json_payload
                # retry:  wait a bit, toss old socket and get new one
                time.sleep(0.1)
                self._get_socket(True)
            # except
        # while

        # null packet, nothing to decode
        if not msg or len(msg.payload) == 0:
            log.debug("raw unpacked message = %r", msg)
            return None

        # option - decode Message with hard coded offsets
        # result = self._decode_payload(data[20:-8])

        # Unpack Message into TuyaMessage format
        # and return payload decrypted
        try:
            # Data available: seqno cmd retcode payload crc
            log.debug("raw unpacked message = %r", msg)
            result = self._decode_payload(msg.payload)

            if result is None:
                log.debug("_decode_payload() failed!")
        except:
            log.debug("error unpacking or decoding tuya JSON payload")
            result = error_json(ERR_PAYLOAD)

        # Did we detect a device22 device? Return ERR_DEVTYPE error.
        if dev_type != self.dev_type:
            log.debug(
                "Device22 detected and updated (%s -> %s) - Update payload and try again",
                dev_type,
                self.dev_type,
            )
            result = error_json(ERR_DEVTYPE)

        return result

    def _decode_payload(self, payload):
        log.debug("decode payload=%r", payload)
        cipher = AESCipher(self.local_key)

        if payload.startswith(PROTOCOL_VERSION_BYTES_31):
            # Received an encrypted payload
            # Remove version header
            payload = payload[len(PROTOCOL_VERSION_BYTES_31) :]
            # Decrypt payload
            # Remove 16-bytes of MD5 hexdigest of payload
            payload = cipher.decrypt(payload[16:])
        elif self.version == 3.3:
            # Trim header for non-default device type
            if self.dev_type != "default" or payload.startswith(
                PROTOCOL_VERSION_BYTES_33
            ):
                payload = payload[len(PROTOCOL_33_HEADER) :]
                log.debug("removing 3.3=%r", payload)
            try:
                log.debug("decrypting=%r", payload)
                payload = cipher.decrypt(payload, False)
            except:
                log.debug("incomplete payload=%r (len:%d)", payload, len(payload), exc_info=True)
                return error_json(ERR_PAYLOAD)

            log.debug("decrypted 3.3 payload=%r", payload)
            # Try to detect if device22 found
            log.debug("payload type = %s", type(payload))
            if not isinstance(payload, str):
                try:
                    payload = payload.decode()
                except:
                    log.debug("payload was not string type and decoding failed")
                    return error_json(ERR_JSON, payload)
            if not self.disabledetect and "data unvalid" in payload:
                self.dev_type = "device22"
                # set at least one DPS
                self.dps_to_request = {"1": None}
                log.debug(
                    "'data unvalid' error detected: switching to dev_type %r",
                    self.dev_type,
                )
                return None
        elif not payload.startswith(b"{"):
            log.debug("Unexpected payload=%r", payload)
            return error_json(ERR_PAYLOAD, payload)

        if not isinstance(payload, str):
            payload = payload.decode()
        log.debug("decoded results=%r", payload)
        try:
            json_payload = json.loads(payload)
        except:
            json_payload = error_json(ERR_JSON, payload)
        return json_payload

    def receive(self):
        """
        Poll device to read any payload in the buffer.  Timeout results in None returned.
        """
        return self._send_receive(None)

    def send(self, payload):
        """
        Send single buffer `payload`.

        Args:
            payload(bytes): Data to send.
        """
        return self._send_receive(payload, 0, getresponse=False)

    def detect_available_dps(self):
        """Return which datapoints are supported by the device."""
        # device22 devices need a sort of bruteforce querying in order to detect the
        # list of available dps experience shows that the dps available are usually
        # in the ranges [1-25] and [100-110] need to split the bruteforcing in
        # different steps due to request payload limitation (max. length = 255)
        self.dps_cache = {}
        ranges = [(2, 11), (11, 21), (21, 31), (100, 111)]

        for dps_range in ranges:
            # dps 1 must always be sent, otherwise it might fail in case no dps is found
            # in the requested range
            self.dps_to_request = {"1": None}
            self.add_dps_to_request(range(*dps_range))
            try:
                data = self.status()
            except Exception as ex:
                log.exception("Failed to get status: %s", ex)
                raise
            if "dps" in data:
                self.dps_cache.update(data["dps"])

            if self.dev_type == "default":
                return self.dps_cache
        log.debug("Detected dps: %s", self.dps_cache)
        return self.dps_cache

    def add_dps_to_request(self, dp_indicies):
        """Add a datapoint (DP) to be included in requests."""
        if isinstance(dp_indicies, int):
            self.dps_to_request[str(dp_indicies)] = None
        else:
            self.dps_to_request.update({str(index): None for index in dp_indicies})

    def set_version(self, version):
        self.version = version

    def set_socketPersistent(self, persist):
        self.socketPersistent = persist
        if self.socket and not persist:
            self.socket.close()
            self.socket = None

    def set_socketNODELAY(self, nodelay):
        self.socketNODELAY = nodelay
        if self.socket:
            if nodelay:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

    def set_socketRetryLimit(self, limit):
        self.socketRetryLimit = limit

    def set_socketTimeout(self, s):
        self.connection_timeout = s
        if self.socket:
            self.socket.settimeout(s)

    def set_dpsUsed(self, dps_to_request):
        self.dps_to_request = dps_to_request

    def set_retry(self, retry):
        self.retry = retry

    def set_sendWait(self, s):
        self.sendWait = s

    def close(self):
        self.__del__()

    def find(self, did=None):
        """Scans network for Tuya devices with ID = did

        Parameters:
            did = The specific Device ID you are looking for (returns only IP and Version)

        Response:
            (ip, version)
        """
        if did is None:
            return (None, None)
        log.debug("Listening for device %s on the network", did)
        # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.bind(("", UDPPORT))
        client.settimeout(TIMEOUT)
        # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
        clients = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        clients.bind(("", UDPPORTS))
        clients.settimeout(TIMEOUT)

        count = 0
        counts = 0
        maxretry = 30
        ret = (None, None)

        while (count + counts) <= maxretry:
            if count <= counts:  # alternate between 6666 and 6667 ports
                count = count + 1
                try:
                    data, addr = client.recvfrom(4048)
                except:
                    # Timeout
                    continue
            else:
                counts = counts + 1
                try:
                    data, addr = clients.recvfrom(4048)
                except:
                    # Timeout
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
                ip = result["ip"]
                gwId = result["gwId"]
                version = result["version"]
            except:
                result = {"ip": ip}

            # Check to see if we are only looking for one device
            if gwId == did:
                # We found it!
                ret = (ip, version)
                break

        # while
        clients.close()
        client.close()
        log.debug(ret)
        return ret

    def generate_payload(self, command, data=None, gwId=None, devId=None, uid=None):
        """
        Generate the payload to send.

        Args:
            command(str): The type of command.
                This is one of the entries from payload_dict
            data(dict, optional): The data to send.
                This is what will be passed via the 'dps' entry
            gwId(str, optional): Will be used for gwId
            devId(str, optional): Will be used for devId
            uid(str, optional): Will be used for uid
        """
        json_data = command_override = None

        if command in payload_dict[self.dev_type]:
            if 'command' in payload_dict[self.dev_type][command]:
                json_data = payload_dict[self.dev_type][command]['command']
            if 'command_override' in payload_dict[self.dev_type][command]:
                command_override = payload_dict[self.dev_type][command]['command_override']

        if self.dev_type != 'default':
            if json_data is None and command in payload_dict['default'] and 'command' in payload_dict['default'][command]:
                json_data = payload_dict['default'][command]['command']
            if command_override is None and command in payload_dict['default'] and 'command_override' in payload_dict['default'][command]:
                command_override = payload_dict['default'][command]['command_override']

        if command_override is None:
            command_override = command
        if json_data is None:
            # I have yet to see a device complain about included but unneeded attribs, but they *will*
            # complain about missing attribs, so just include them all unless otherwise specified
            json_data = {"gwId": "", "devId": "", "uid": "", "t": ""}

        if "gwId" in json_data:
            if gwId is not None:
                json_data["gwId"] = gwId
            else:
                json_data["gwId"] = self.id
        if "devId" in json_data:
            if devId is not None:
                json_data["devId"] = devId
            else:
                json_data["devId"] = self.id
        if "uid" in json_data:
            if uid is not None:
                json_data["uid"] = uid
            else:
                json_data["uid"] = self.id
        if "t" in json_data:
            json_data["t"] = str(int(time.time()))

        if data is not None:
            if "dpId" in json_data:
                json_data["dpId"] = data
            else:
                json_data["dps"] = data
        if command_override == CONTROL_NEW:
            json_data["dps"] = self.dps_to_request

        # Create byte buffer from hex data
        payload = json.dumps(json_data)
        # if spaces are not removed device does not respond!
        payload = payload.replace(" ", "")
        payload = payload.encode("utf-8")
        log.debug("building command %s payload=%r", command, payload)

        if self.version == 3.3:
            # expect to connect and then disconnect to set new
            self.cipher = AESCipher(self.local_key)
            payload = self.cipher.encrypt(payload, False)
            self.cipher = None
            if command_override != DP_QUERY and command_override != UPDATEDPS:
                # add the 3.3 header
                payload = PROTOCOL_33_HEADER + payload
        elif command == CONTROL:
            # need to encrypt
            self.cipher = AESCipher(self.local_key)
            payload = self.cipher.encrypt(payload)
            preMd5String = (
                b"data="
                + payload
                + b"||lpv="
                + PROTOCOL_VERSION_BYTES_31
                + b"||"
                + self.local_key
            )
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()
            # some tuya libraries strip 8: to :24
            payload = (
                PROTOCOL_VERSION_BYTES_31
                + hexdigest[8:][:16].encode("latin1")
                + payload
            )
            self.cipher = None

        # create Tuya message packet
        msg = TuyaMessage(self.seqno, command_override, 0, payload, 0)
        self.seqno += 1  # increase message sequence number
        buffer = pack_message(msg)
        log.debug("payload generated=%r",binascii.hexlify(buffer))
        return buffer


class Device(XenonDevice):
    def __init__(self, dev_id, address, local_key="", dev_type="default"):
        super(Device, self).__init__(dev_id, address, local_key, dev_type)

    def status(self):
        """Return device status."""
        log.debug("status() entry (dev_type is %s)", self.dev_type)
        payload = self.generate_payload(DP_QUERY)

        data = self._send_receive(payload)
        log.debug("status() received data=%r", data)
        # Error handling
        if data and "Err" in data:
            if data["Err"] == str(ERR_DEVTYPE):
                # Device22 detected and change - resend with new payload
                log.debug("status() rebuilding payload for device22")
                payload = self.generate_payload(DP_QUERY)
                data = self._send_receive(payload)

        return data

    def set_status(self, on, switch=1, nowait=False):
        """
        Set status of the device to 'on' or 'off'.

        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
            nowait(bool): True to send without waiting for response.
        """
        # open device, send request, then close connection
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(CONTROL, {switch: on})

        data = self._send_receive(payload, getresponse=(not nowait))
        log.debug("set_status received data=%r", data)

        return data

    def product(self):
        """
        Request AP_CONFIG Product Info from device. [BETA]

        """
        # open device, send request, then close connection
        payload = self.generate_payload(AP_CONFIG)
        data = self._send_receive(payload, 0)
        log.debug("product received data=%r", data)
        return data

    def heartbeat(self, nowait=False):
        """
        Send a simple HEART_BEAT command to device.

        Args:
            nowait(bool): True to send without waiting for response.
        """
        # open device, send request, then close connection
        payload = self.generate_payload(HEART_BEAT)
        data = self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("heartbeat received data=%r", data)
        return data

    def updatedps(self, index=None, nowait=False):
        """
        Request device to update index.

        Args:
            index(array): list of dps to update (ex. [4, 5, 6, 18, 19, 20])
            nowait(bool): True to send without waiting for response.
        """
        if index is None:
            index = [1]

        log.debug("updatedps() entry (dev_type is %s)", self.dev_type)
        # open device, send request, then close connection
        payload = self.generate_payload(UPDATEDPS, index)
        data = self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("updatedps received data=%r", data)
        return data

    def set_value(self, index, value, nowait=False):
        """
        Set int value of any index.

        Args:
            index(int): index to set
            value(int): new value for the index
            nowait(bool): True to send without waiting for response.
        """
        # open device, send request, then close connection
        if isinstance(index, int):
            index = str(index)  # index and payload is a string

        payload = self.generate_payload(CONTROL, {index: value})

        data = self._send_receive(payload, getresponse=(not nowait))

        return data

    def turn_on(self, switch=1, nowait=False):
        """Turn the device on"""
        self.set_status(True, switch, nowait)

    def turn_off(self, switch=1, nowait=False):
        """Turn the device off"""
        self.set_status(False, switch, nowait)

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        """
        Set a timer.

        Args:
            num_secs(int): Number of seconds
            dps_id(int): DPS Index for Timer
            nowait(bool): True to send without waiting for response.
        """

        # Query status, pick last device id as that is probably the timer
        if dps_id == 0:
            status = self.status()
            if "dps" in status:
                devices = status["dps"]
                devices_numbers = list(devices.keys())
                devices_numbers.sort()
                dps_id = devices_numbers[-1]
            else:
                log.debug("set_timer received error=%r", status)
                return status

        payload = self.generate_payload(CONTROL, {dps_id: num_secs})

        data = self._send_receive(payload, getresponse=(not nowait))
        log.debug("set_timer received data=%r", data)
        return data

# Utility Functions

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


def encrypt(msg, key):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(msg).encode())


def decrypt(msg, key):
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(msg)).decode()


# UDP packet payload decryption - credit to tuya-convert
udpkey = md5(b"yGAdlopoPVldABfn").digest()


def decrypt_udp(msg):
    return decrypt(msg, udpkey)


# Return positive number or zero
def floor(x):
    if x > 0:
        return x
    else:
        return 0


def appenddevice(newdevice, devices):
    if newdevice["ip"] in devices:
        return True
    """
    for i in devices:
        if i['ip'] == newdevice['ip']:
                return True
    """
    devices[newdevice["ip"]] = newdevice
    return False

# Terminal color helper
def termcolor(color=True):
    if color is False:
        # Disable Terminal Color Formatting
        bold = subbold = normal = dim = alert = alertdim = cyan = red = yellow = ""
    else:
        # Terminal Color Formatting
        bold = "\033[0m\033[97m\033[1m"
        subbold = "\033[0m\033[32m"
        normal = "\033[97m\033[0m"
        dim = "\033[0m\033[97m\033[2m"
        alert = "\033[0m\033[91m\033[1m"
        alertdim = "\033[0m\033[91m\033[2m"
        cyan = "\033[0m\033[36m"
        red = "\033[0m\033[31m"
        yellow = "\033[0m\033[33m"
    return bold,subbold,normal,dim,alert,alertdim,cyan,red,yellow


# Scan function shortcut
def scan(maxretry=None, color=True, forcescan=False):
    """Scans your network for Tuya devices with output to stdout"""
    from . import scanner
    scanner.scan(maxretry=maxretry, color=color, forcescan=forcescan)


# Scan function
def deviceScan(verbose=False, maxretry=None, color=True, poll=True, forcescan=False, byID=False):
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        maxretry = The number of loops to wait to pick up UDP from all devices
        color = True or False, print output in color [Default: True]
        poll = True or False, poll dps status for devices if possible
        forcescan = True or False, force network scan for device IP addresses

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
    from . import scanner
    return scanner.devices(verbose=verbose, maxretry=maxretry, color=color, poll=poll, forcescan=forcescan, byID=byID)
