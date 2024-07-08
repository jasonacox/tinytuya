# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Core Classes and Helper Functions

 Classes
  * AESCipher - Cryptography Helpers
  * XenonDevice(...) - Base Tuya Objects and Functions
        XenonDevice(dev_id, address=None, local_key="", dev_type="default", connection_timeout=5, 
            version="3.1", persist=False, cid/node_id=None, parent=None, connection_retry_limit=5, 
            connection_retry_delay=5)
  * Device(XenonDevice) - Tuya Class for Devices

 Module Functions
    set_debug(toggle, color)                    # Activate verbose debugging output
    pack_message(msg, hmac_key=None)            # Packs a TuyaMessage() into a network packet, encrypting or adding a CRC if protocol requires
    unpack_message(data, hmac_key=None, header=None, no_retcode=False)
                                                # Unpacks a TuyaMessage() from a network packet, decrypting or checking the CRC if protocol requires
    parse_header(data)                          # Unpacks just the header part of a message into a TuyaHeader()
    find_device(dev_id=None, address=None)      # Scans network for Tuya devices with either ID = dev_id or IP = address
    device_info(dev_id)                         # Searches DEVICEFILE (usually devices.json) for devices with ID = dev_id and returns just that device
    assign_dp_mappings(tuyadevices, mappings)   # Adds mappings to all the devices in the tuyadevices list
    decrypt_udp(msg)                            # Decrypts a UDP network broadcast packet

 Device Functions
    json = status()                    # returns json payload
    subdev_query(nowait)               # query sub-device status (only for gateway devices)
    set_version(version)               # 3.1 [default], 3.2, 3.3 or 3.4
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]
    set_socketRetryLimit(integer)      # retry count limit [default 5]
    set_socketRetryDelay(integer)      # retry delay [default 5]
    set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
    set_dpsUsed(dps_to_request)        # add data points (DPS) to request
    add_dps_to_request(index)          # add data point (DPS) index set to None
    set_retry(retry=True)              # retry if response payload is truncated
    set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
    set_value(index, value, nowait)    # Set int value of any index.
    set_multiple_values(index_value_dict, nowait)
                                       # Set multiple values with a single request
    heartbeat(nowait)                  # Send heartbeat to device
    updatedps(index=[1], nowait)       # Send updatedps command to device
    turn_on(switch=1, nowait)          # Turn on device / switch #
    turn_off(switch=1, nowait)         # Turn off
    set_timer(num_secs, nowait)        # Set timer for num_secs
    set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
    detect_available_dps()             # Return list of DPS available from device
    generate_payload(command, data,...)# Generate TuyaMessage payload for command with data
    send(payload)                      # Send payload to device (do not wait for response)
    receive()                          # Receive payload from device

 Credits
  * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    For protocol reverse engineering
  * PyTuya https://github.com/clach04/python-tuya by clach04
    The origin of this python module (now abandoned)
  * LocalTuya https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
    Updated pytuya to support devices with Device IDs of 22 characters
  * Tuya Protocol 3.4 and 3.5 Support by uzlonewolf
    Enhancement to TuyaMessage logic for multi-payload messages

"""

# Modules
from __future__ import print_function  # python 2.7 support
import binascii
from collections import namedtuple
import base64
from hashlib import md5,sha256
import hmac
import json
import logging
import socket
import select
import struct
import sys
import time
from colorama import init

# Backward compatibility for python2
try:
    input = raw_input
except NameError:
    pass

for clib in ('pyca/cryptography', 'PyCryptodomex', 'PyCrypto', 'pyaes'):
    Crypto = Crypto_modes = AES = CRYPTOLIB = None
    try:
        if clib == 'pyca/cryptography': # https://cryptography.io/en/latest/
            from cryptography import __version__ as Crypto_version
            if (Crypto_version[:2] in ('0.', '1.', '2.')) or (Crypto_version == '3.0'):
                # cryptography <= 3.0 requires a backend= parameter
                continue
            from cryptography.hazmat.primitives.ciphers import Cipher as Crypto
            from cryptography.hazmat.primitives.ciphers import modes as Crypto_modes
            from cryptography.hazmat.primitives.ciphers.algorithms import AES
        elif clib == 'PyCryptodomex': # https://pycryptodome.readthedocs.io/en/latest/
            # PyCryptodome is installed as "Cryptodome" when installed by
            #  `apt install python3-pycryptodome` or `pip install pycryptodomex`
            import Cryptodome as Crypto
            from Cryptodome.Cipher import AES
        elif clib == 'PyCrypto': # https://www.pycrypto.org/
            import Crypto
            from Crypto.Cipher import AES
            # v1/v2 is PyCrypto, v3 is PyCryptodome
            clib = 'PyCrypto' if Crypto.version_info[0] < 3 else 'PyCryptodome'
        elif clib == 'pyaes':
            import pyaes  # https://github.com/ricmoo/pyaes
        else:
            continue
        CRYPTOLIB = clib
        break
    except ImportError:
        continue
if CRYPTOLIB is None:
    raise ModuleNotFoundError('No crypto library found, please "pip install" cryptography, pycryptodome, or pyaes')

# Colorama terminal color capability for all platforms
init()

version_tuple = (1, 15, 0)
version = __version__ = "%d.%d.%d" % version_tuple
__author__ = "jasonacox"

log = logging.getLogger(__name__)

# Globals Network Settings
MAXCOUNT = 15       # How many tries before stopping
SCANTIME = 18       # How many seconds to wait before stopping device discovery
UDPPORT = 6666      # Tuya 3.1 UDP Port
UDPPORTS = 6667     # Tuya 3.3 encrypted UDP Port
UDPPORTAPP = 7000   # Tuya app encrypted UDP Port
TCPPORT = 6668      # Tuya TCP Local Port
TIMEOUT = 3.0       # Seconds to wait for a broadcast
TCPTIMEOUT = 0.4    # Seconds to wait for socket open for scanning
DEFAULT_NETWORK = '192.168.0.0/24'

# Configuration Files
CONFIGFILE = 'tinytuya.json'
DEVICEFILE = 'devices.json'
RAWFILE = 'tuya-raw.json'
SNAPSHOTFILE = 'snapshot.json'

DEVICEFILE_SAVE_VALUES = ('category', 'product_name', 'product_id', 'biz_type', 'model', 'sub', 'icon', 'version', 'last_ip', 'uuid', 'node_id', 'sn', 'mapping')

# Tuya Command Types
# Reference: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h
AP_CONFIG       = 1  # FRM_TP_CFG_WF      # only used for ap 3.0 network config
ACTIVE          = 2  # FRM_TP_ACTV (discard) # WORK_MODE_CMD
SESS_KEY_NEG_START  = 3  # FRM_SECURITY_TYPE3 # negotiate session key
SESS_KEY_NEG_RESP   = 4  # FRM_SECURITY_TYPE4 # negotiate session key response
SESS_KEY_NEG_FINISH = 5  # FRM_SECURITY_TYPE5 # finalize session key negotiation
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
REQ_DEVINFO     = 0x25 # broadcast to port 7000 to get v3.5 devices to send their info
LAN_EXT_STREAM  = 0x40 # 64 # FRM_LAN_EXT_STREAM

# Protocol Versions and Headers
PROTOCOL_VERSION_BYTES_31 = b"3.1"
PROTOCOL_VERSION_BYTES_33 = b"3.3"
PROTOCOL_VERSION_BYTES_34 = b"3.4"
PROTOCOL_VERSION_BYTES_35 = b"3.5"
PROTOCOL_3x_HEADER = 12 * b"\x00"
PROTOCOL_33_HEADER = PROTOCOL_VERSION_BYTES_33 + PROTOCOL_3x_HEADER
PROTOCOL_34_HEADER = PROTOCOL_VERSION_BYTES_34 + PROTOCOL_3x_HEADER
PROTOCOL_35_HEADER = PROTOCOL_VERSION_BYTES_35 + PROTOCOL_3x_HEADER
MESSAGE_HEADER_FMT = MESSAGE_HEADER_FMT_55AA = ">4I"  # 4*uint32: prefix, seqno, cmd, length [, retcode]
MESSAGE_HEADER_FMT_6699 = ">IHIII"  # 4*uint32: prefix, unknown, seqno, cmd, length
MESSAGE_RETCODE_FMT = ">I"  # retcode for received messages
MESSAGE_END_FMT = MESSAGE_END_FMT_55AA = ">2I"  # 2*uint32: crc, suffix
MESSAGE_END_FMT_HMAC = ">32sI"  # 32s:hmac, uint32:suffix
MESSAGE_END_FMT_6699 = ">16sI"  # 16s:tag, suffix
PREFIX_VALUE = PREFIX_55AA_VALUE = 0x000055AA
PREFIX_BIN = PREFIX_55AA_BIN = b"\x00\x00U\xaa"
SUFFIX_VALUE = SUFFIX_55AA_VALUE = 0x0000AA55
SUFFIX_BIN = SUFFIX_55AA_BIN = b"\x00\x00\xaaU"
PREFIX_6699_VALUE = 0x00006699
PREFIX_6699_BIN = b"\x00\x00\x66\x99"
SUFFIX_6699_VALUE = 0x00009966
SUFFIX_6699_BIN = b"\x00\x00\x99\x66"

NO_PROTOCOL_HEADER_CMDS = [DP_QUERY, DP_QUERY_NEW, UPDATEDPS, HEART_BEAT, SESS_KEY_NEG_START, SESS_KEY_NEG_RESP, SESS_KEY_NEG_FINISH, LAN_EXT_STREAM ]

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

# Tuya Packet Format
TuyaHeader = namedtuple('TuyaHeader', 'prefix seqno cmd length total_length')
MessagePayload = namedtuple("MessagePayload", "cmd payload")
try:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv", defaults=(True,0x55AA,None))
except:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv")

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
ERR_KEY_OR_VER = 914

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
    ERR_KEY_OR_VER: "Check device key or version",
    None: "Unknown Error",
}

class DecodeError(Exception):
    pass

# Cryptography Helpers
class _AESCipher_Base(object):
    def __init__(self, key):
        self.key = key

    @classmethod
    def get_encryption_iv( cls, iv ):
        if not cls.CRYPTOLIB_HAS_GCM:
            raise NotImplementedError( 'Crypto library does not support GCM' )
        if iv is True:
            if log.isEnabledFor( logging.DEBUG ):
                iv = b'0123456789ab'
            else:
                iv = str(time.time() * 10)[:12].encode('utf8')
        return iv

    @classmethod
    def get_decryption_iv( cls, iv, data ):
        if not cls.CRYPTOLIB_HAS_GCM:
            raise NotImplementedError( 'Crypto library does not support GCM' )
        if iv is True:
            iv = data[:12]
            data = data[12:]
        return iv, data

    @staticmethod
    def _pad(s, bs):
        padnum = bs - len(s) % bs
        return s + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(s, verify_padding=False):
        padlen = ord(s[-1:])
        if padlen < 1 or padlen > 16:
            raise ValueError("invalid padding length byte")
        if verify_padding and s[-padlen:] != (padlen * chr(padlen).encode()):
            raise ValueError("invalid padding data")
        return s[:-padlen]

class _AESCipher_pyca(_AESCipher_Base):
    def encrypt(self, raw, use_base64=True, pad=True, iv=False, header=None): # pylint: disable=W0621
        if iv: # initialization vector or nonce (number used once)
            iv = self.get_encryption_iv( iv )
            encryptor = Crypto( AES(self.key), Crypto_modes.GCM(iv) ).encryptor()
            if header:
                encryptor.authenticate_additional_data(header)
            crypted_text = encryptor.update(raw) + encryptor.finalize()
            crypted_text = iv + crypted_text + encryptor.tag
        else:
            if pad: raw = self._pad(raw, 16)
            encryptor = Crypto( AES(self.key), Crypto_modes.ECB() ).encryptor()
            crypted_text = encryptor.update(raw) + encryptor.finalize()

        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc, use_base64=True, decode_text=True, verify_padding=False, iv=False, header=None, tag=None):
        if not iv:
            if use_base64:
                enc = base64.b64decode(enc)
            if len(enc) % 16 != 0:
                raise ValueError("invalid length")
        if iv:
            iv, enc = self.get_decryption_iv( iv, enc )
            if tag is None:
                decryptor = Crypto( AES(self.key), Crypto_modes.CTR(iv + b'\x00\x00\x00\x02') ).decryptor()
            else:
                decryptor = Crypto( AES(self.key), Crypto_modes.GCM(iv, tag) ).decryptor()
            if header and (tag is not None):
                decryptor.authenticate_additional_data( header )
            raw = decryptor.update( enc ) + decryptor.finalize()
        else:
            decryptor = Crypto( AES(self.key), Crypto_modes.ECB() ).decryptor()
            raw = decryptor.update( enc ) + decryptor.finalize()
            raw = self._unpad(raw, verify_padding)
        return raw.decode("utf-8") if decode_text else raw

class _AESCipher_PyCrypto(_AESCipher_Base):
    def encrypt(self, raw, use_base64=True, pad=True, iv=False, header=None): # pylint: disable=W0621
        if iv: # initialization vector or nonce (number used once)
            iv = self.get_encryption_iv( iv )
            cipher = AES.new(self.key, mode=AES.MODE_GCM, nonce=iv)
            if header:
                cipher.update(header)
            crypted_text, tag = cipher.encrypt_and_digest(raw)
            crypted_text = cipher.nonce + crypted_text + tag
        else:
            if pad: raw = self._pad(raw, 16)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)

        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc, use_base64=True, decode_text=True, verify_padding=False, iv=False, header=None, tag=None):
        if not iv:
            if use_base64:
                enc = base64.b64decode(enc)
            if len(enc) % 16 != 0:
                raise ValueError("invalid length")
        if iv:
            iv, enc = self.get_decryption_iv( iv, enc )
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            if header:
                cipher.update(header)
            if tag:
                raw = cipher.decrypt_and_verify(enc, tag)
            else:
                raw = cipher.decrypt(enc)
        else:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            raw = self._unpad(raw, verify_padding)
        return raw.decode("utf-8") if decode_text else raw

class _AESCipher_pyaes(_AESCipher_Base):
    def encrypt(self, raw, use_base64=True, pad=True, iv=False, header=None): # pylint: disable=W0621
        if iv:
            # GCM required for 3.5 devices
            raise NotImplementedError( 'pyaes does not support GCM, please install PyCryptodome' )

        # pylint: disable-next=used-before-assignment
        cipher = pyaes.blockfeeder.Encrypter(
            pyaes.AESModeOfOperationECB(self.key),
            pyaes.PADDING_DEFAULT if pad else pyaes.PADDING_NONE
        )  # no IV, auto pads to 16
        crypted_text = cipher.feed(raw)
        crypted_text += cipher.feed()  # flush final block
        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc, use_base64=True, decode_text=True, verify_padding=False, iv=False, header=None, tag=None):
        if iv:
            # GCM required for 3.5 devices
            raise NotImplementedError( 'pyaes does not support GCM, please install PyCryptodome' )

        if use_base64:
            enc = base64.b64decode(enc)

        if len(enc) % 16 != 0:
            raise ValueError("invalid length")

        cipher = pyaes.blockfeeder.Decrypter(
            pyaes.AESModeOfOperationECB(self.key),
            pyaes.PADDING_NONE if verify_padding else pyaes.PADDING_DEFAULT
        )  # no IV, auto pads to 16

        raw = cipher.feed(enc)
        raw += cipher.feed()  # flush final block

        if verify_padding: raw = self._unpad(raw, verify_padding)
        return raw.decode("utf-8") if decode_text else raw

if CRYPTOLIB[:8] == 'PyCrypto': # PyCrypto, PyCryptodome, and PyCryptodomex
    class AESCipher(_AESCipher_PyCrypto):
        CRYPTOLIB = CRYPTOLIB
        CRYPTOLIB_VER = '.'.join( [str(x) for x in Crypto.version_info] )
        CRYPTOLIB_HAS_GCM = getattr( AES, 'MODE_GCM', False ) # only PyCryptodome supports GCM, PyCrypto does not
elif CRYPTOLIB == 'pyaes':
    class AESCipher(_AESCipher_pyaes):
        CRYPTOLIB = CRYPTOLIB
        CRYPTOLIB_VER = '.'.join( [str(x) for x in pyaes.VERSION] )
        CRYPTOLIB_HAS_GCM = False
elif CRYPTOLIB == 'pyca/cryptography':
    class AESCipher(_AESCipher_pyca):
        CRYPTOLIB = CRYPTOLIB
        CRYPTOLIB_VER = Crypto_version
        CRYPTOLIB_HAS_GCM = getattr( Crypto_modes, 'GCM', False )

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
        log.debug("Python %s on %s", sys.version, sys.platform)
        if AESCipher.CRYPTOLIB_HAS_GCM == False:
            log.debug("Using %s %s for crypto", AESCipher.CRYPTOLIB, AESCipher.CRYPTOLIB_VER)
            log.debug("Warning: Crypto library does not support AES-GCM, v3.5 devices will not work!")
        else:
            log.debug("Using %s %s for crypto, GCM is supported", AESCipher.CRYPTOLIB, AESCipher.CRYPTOLIB_VER)
    else:
        log.setLevel(logging.NOTSET)

def pack_message(msg, hmac_key=None):
    """Pack a TuyaMessage into bytes."""
    if msg.prefix == PREFIX_55AA_VALUE:
        header_fmt = MESSAGE_HEADER_FMT_55AA
        end_fmt = MESSAGE_END_FMT_HMAC if hmac_key else MESSAGE_END_FMT_55AA
        msg_len = len(msg.payload) + struct.calcsize(end_fmt)
        header_data = ( msg.prefix, msg.seqno, msg.cmd, msg_len )
    elif msg.prefix == PREFIX_6699_VALUE:
        if not hmac_key:
            raise TypeError( 'key must be provided to pack 6699-format messages' )
        header_fmt = MESSAGE_HEADER_FMT_6699
        end_fmt = MESSAGE_END_FMT_6699
        msg_len = len(msg.payload) + (struct.calcsize(end_fmt) - 4) + 12
        if type(msg.retcode) == int:
            msg_len += struct.calcsize(MESSAGE_RETCODE_FMT)
        header_data = ( msg.prefix, 0, msg.seqno, msg.cmd, msg_len )
    else:
        raise ValueError( 'pack_message() cannot handle message format %08X' % msg.prefix )

    # Create full message excluding CRC and suffix
    data = struct.pack( header_fmt, *header_data )

    if msg.prefix == PREFIX_6699_VALUE:
        cipher = AESCipher( hmac_key )
        if type(msg.retcode) == int:
            raw = struct.pack( MESSAGE_RETCODE_FMT, msg.retcode ) + msg.payload
        else:
            raw = msg.payload
        data2 = cipher.encrypt( raw, use_base64=False, pad=False, iv=True if not msg.iv else msg.iv, header=data[4:])
        data += data2 + SUFFIX_6699_BIN
    else:
        data += msg.payload
        if hmac_key:
            crc = hmac.new(hmac_key, data, sha256).digest()
        else:
            crc = binascii.crc32(data) & 0xFFFFFFFF
        # Calculate CRC, add it together with suffix
        data += struct.pack( end_fmt, crc, SUFFIX_VALUE )

    return data

def unpack_message(data, hmac_key=None, header=None, no_retcode=False):
    """Unpack bytes into a TuyaMessage."""
    if header is None:
        header = parse_header(data)

    if header.prefix == PREFIX_55AA_VALUE:
        # 4-word header plus return code
        header_len = struct.calcsize(MESSAGE_HEADER_FMT_55AA)
        end_fmt = MESSAGE_END_FMT_HMAC if hmac_key else MESSAGE_END_FMT_55AA
        retcode_len = 0 if no_retcode else struct.calcsize(MESSAGE_RETCODE_FMT)
        msg_len = header_len + header.length
    elif header.prefix == PREFIX_6699_VALUE:
        if not hmac_key:
            raise TypeError( 'key must be provided to unpack 6699-format messages' )
        header_len = struct.calcsize(MESSAGE_HEADER_FMT_6699)
        end_fmt = MESSAGE_END_FMT_6699
        retcode_len = 0
        msg_len = header_len + header.length + 4
    else:
        raise ValueError( 'unpack_message() cannot handle message format %08X' % header.prefix )

    if len(data) < msg_len:
        log.debug('unpack_message(): not enough data to unpack payload! need %d but only have %d', header_len+header.length, len(data))
        raise DecodeError('Not enough data to unpack payload')

    end_len = struct.calcsize(end_fmt)
    # the retcode is technically part of the payload, but strip it as we do not want it here
    retcode = 0 if not retcode_len else struct.unpack(MESSAGE_RETCODE_FMT, data[header_len:header_len+retcode_len])[0]
    payload = data[header_len+retcode_len:msg_len]
    crc, suffix = struct.unpack(end_fmt, payload[-end_len:])
    crc_good = False
    payload = payload[:-end_len]

    if header.prefix == PREFIX_55AA_VALUE:
        if hmac_key:
            have_crc = hmac.new(hmac_key, data[:(header_len+header.length)-end_len], sha256).digest()
        else:
            have_crc = binascii.crc32(data[:(header_len+header.length)-end_len]) & 0xFFFFFFFF

        if suffix != SUFFIX_VALUE:
            log.debug('Suffix prefix wrong! %08X != %08X', suffix, SUFFIX_VALUE)

        if crc != have_crc:
            if hmac_key:
                log.debug('HMAC checksum wrong! %r != %r', binascii.hexlify(have_crc), binascii.hexlify(crc))
            else:
                log.debug('CRC wrong! %08X != %08X', have_crc, crc)
        crc_good = crc == have_crc
        iv = None
    elif header.prefix == PREFIX_6699_VALUE:
        iv = payload[:12]
        payload = payload[12:]
        try:
            cipher = AESCipher( hmac_key )
            payload = cipher.decrypt( payload, use_base64=False, decode_text=False, verify_padding=False, iv=iv, header=data[4:header_len], tag=crc)
            crc_good = True
        except:
            crc_good = False

        retcode_len = struct.calcsize(MESSAGE_RETCODE_FMT)
        if no_retcode is False:
            pass
        elif no_retcode is None and payload[0:1] != b'{' and payload[retcode_len:retcode_len+1] == b'{':
            retcode_len = struct.calcsize(MESSAGE_RETCODE_FMT)
        else:
            retcode_len = 0
        if retcode_len:
            retcode = struct.unpack(MESSAGE_RETCODE_FMT, payload[:retcode_len])[0]
            payload = payload[retcode_len:]

    return TuyaMessage(header.seqno, header.cmd, retcode, payload, crc, crc_good, header.prefix, iv)

def parse_header(data):
    if( data[:4] == PREFIX_6699_BIN ):
        fmt = MESSAGE_HEADER_FMT_6699
    else:
        fmt = MESSAGE_HEADER_FMT_55AA

    header_len = struct.calcsize(fmt)

    if len(data) < header_len:
        raise DecodeError('Not enough data to unpack header')

    unpacked = struct.unpack( fmt, data[:header_len] )
    prefix = unpacked[0]

    if prefix == PREFIX_55AA_VALUE:
        prefix, seqno, cmd, payload_len = unpacked
        total_length = payload_len + header_len
    elif prefix == PREFIX_6699_VALUE:
        prefix, unknown, seqno, cmd, payload_len = unpacked
        #seqno |= unknown << 32
        total_length = payload_len + header_len + len(SUFFIX_6699_BIN)
    else:
        #log.debug('Header prefix wrong! %08X != %08X', prefix, PREFIX_VALUE)
        raise DecodeError('Header prefix wrong! %08X is not %08X or %08X' % (prefix, PREFIX_55AA_VALUE, PREFIX_6699_VALUE))

    # sanity check. currently the max payload length is somewhere around 300 bytes
    if payload_len > 1000:
        raise DecodeError('Header claims the packet size is over 1000 bytes!  It is most likely corrupt.  Claimed size: %d bytes. fmt:%s unpacked:%r' % (payload_len,fmt,unpacked))

    return TuyaHeader(prefix, seqno, cmd, payload_len, total_length)

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

def find_device(dev_id=None, address=None):
    """Scans network for Tuya devices with either ID = dev_id or IP = address

    Parameters:
        dev_id = The specific Device ID you are looking for
        address = The IP address you are tring to find the Device ID for

    Response:
        {'ip':<ip>, 'version':<version>, 'id':<id>, 'product_id':<product_id>, 'data':<broadcast data>}
    """
    if dev_id is None and address is None:
        return {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}

    from . import scanner

    want_ids = (dev_id,) if dev_id else None
    want_ips = (address,) if address else None
    all_results = scanner.devices(verbose=False, poll=False, forcescan=False, byID=True, wantids=want_ids, wantips=want_ips)
    ret = None

    for gwId in all_results:
        # Check to see if we are only looking for one device
        if dev_id and gwId != dev_id:
            continue
        if address and address != all_results[gwId]['ip']:
            continue

        # We found it!
        result = all_results[gwId]
        product_id = '' if 'productKey' not in result else result['productKey']
        ret = {'ip':result['ip'], 'version':result['version'], 'id':gwId, 'product_id':product_id, 'data':result}
        break

    if ret is None:
        ret = {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}
    log.debug( 'find() is returning: %r', ret )
    return ret

def device_info( dev_id ):
    """Searches the devices.json file for devices with ID = dev_id

    Parameters:
        dev_id = The specific Device ID you are looking for

    Response:
        {dict} containing the the device info, or None if not found
    """
    devinfo = None
    try:
        # Load defaults
        with open(DEVICEFILE, 'r') as f:
            tuyadevices = json.load(f)
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
            for dev in tuyadevices:
                if 'id' in dev and dev['id'] == dev_id:
                    log.debug("Device %r found in %s", dev_id, DEVICEFILE)
                    devinfo = dev
                    break
    except:
        # No DEVICEFILE
        pass

    return devinfo

def assign_dp_mappings( tuyadevices, mappings ):
    """ Adds mappings to all the devices in the tuyadevices list

    Parameters:
        tuyadevices = list of devices
        mappings = dict containing the mappings

    Response:
        Nothing, modifies tuyadevices in place
    """
    if type(mappings) != dict:
        raise ValueError( '\'mappings\' must be a dict' )

    if (not mappings) or (not tuyadevices):
        return None

    for dev in tuyadevices:
        try:
            devid = dev['id']
            productid = dev['product_id']
        except:
            # we need both the device id and the product id to download mappings!
            log.debug( 'Cannot add DP mapping, no device id and/or product id: %r', dev )
            continue

        if productid in mappings:
            dev['mapping'] = mappings[productid]
        else:
            log.debug( 'Device %s has no mapping!', devid )
            dev['mapping'] = None

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
        LAN_EXT_STREAM: { "command": { "reqType": "", "data": {} }},
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
    # v3.3+ devices do not need devId/gwId/uid
    "v3.4": {
        CONTROL: {
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
            },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        DP_QUERY: {
            "command_override": DP_QUERY_NEW,
            "command": {} #"protocol":4, "t": "int", "data": {}}
        },
        DP_QUERY_NEW: {
            "command": {}
        },
    },
    # v3.5 is just a copy of v3.4
    "v3.5": {
        CONTROL: {
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        DP_QUERY: {
            "command_override": DP_QUERY_NEW,
            "command": {}
        },
        DP_QUERY_NEW: {
            "command": {}
        },
    },
    # placeholders, not yet needed
    "gateway": { },
    "gateway_v3.4": { },
    "gateway_v3.5": { },
    "zigbee": {
        CONTROL: { "command": {"t": "int", "cid": ""} },
        DP_QUERY: { "command": {"t": "int", "cid": ""} },
    },
    "zigbee_v3.4": {
        CONTROL: {
            "command_override": CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
    "zigbee_v3.5": {
        CONTROL: {
            "command_override": CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
}

########################################################
#             Core Classes and Functions
########################################################

class XenonDevice(object):
    def __init__(
            self, dev_id, address=None, local_key="", dev_type="default", connection_timeout=5, version=3.1, persist=False, cid=None, node_id=None, parent=None, connection_retry_limit=5, connection_retry_delay=5, port=TCPPORT # pylint: disable=W0621
    ):
        """
        Represents a Tuya device.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            cid (str: Optional sub device id. Default to None.
            node_id (str: alias for cid)
            parent (object: gateway device this device is a child of)

        Attributes:
            port (int): The port to connect to.
        """

        self.id = dev_id
        self.cid = cid if cid else node_id
        self.address = address
        self.auto_ip = False
        self.dev_type = dev_type
        self.dev_type_auto = self.dev_type == 'default'
        self.last_dev_type = ''
        self.connection_timeout = connection_timeout
        self.retry = True
        self.disabledetect = False  # if True do not detect device22
        self.port = port  # default - do not expect caller to pass in
        self.socket = None
        self.socketPersistent = False if not persist else True # pylint: disable=R1719
        self.socketNODELAY = True
        self.socketRetryLimit = connection_retry_limit
        self.socketRetryDelay = connection_retry_delay
        self.version = 0
        self.dps_to_request = {}
        self.seqno = 1
        self.sendWait = 0.01
        self.dps_cache = {}
        self.parent = parent
        self.children = {}
        self.received_wrong_cid_queue = []
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''
        self.payload_dict = None

        if not local_key:
            local_key = ""
            # sub-devices do not need a local key, so only look it up if we are not a sub-device
            if not parent:
                devinfo = device_info( dev_id )
                if devinfo and 'key' in devinfo and devinfo['key']:
                    local_key = devinfo['key']
        self.local_key = local_key.encode("latin1")
        self.real_local_key = self.local_key
        self.cipher = None

        if self.parent:
            # if we are a child then we should have a cid/node_id but none were given - try and find it the same way we look up local keys
            if not self.cid:
                devinfo = device_info( dev_id )
                if devinfo and 'node_id' in devinfo and devinfo['node_id']:
                    self.cid = devinfo['node_id']
            if not self.cid:
                # not fatal as the user could have set the device_id to the cid
                # in that case dev_type should be 'zigbee' to set the proper fields in requests
                log.debug( 'Child device but no cid/node_id given!' )
            XenonDevice.set_version(self, self.parent.version)
            self.parent._register_child(self)
        elif (not address) or address == "Auto" or address == "0.0.0.0":
            # try to determine IP address automatically
            self.auto_ip = True
            bcast_data = find_device(dev_id)
            if bcast_data['ip'] is None:
                log.debug("Unable to find device on network (specify IP address)")
                raise Exception("Unable to find device on network (specify IP address)")
            self.address = bcast_data['ip']
            self.set_version(float(bcast_data['version']))
            time.sleep(0.1)
        elif version:
            self.set_version(float(version))
        else:
            # make sure we call our set_version() and not a subclass since some of
            # them (such as BulbDevice) make connections when called
            XenonDevice.set_version(self, 3.1)

    def __del__(self):
        # In case we have a lingering socket connection, close it
        try:
            if self.socket:
                # self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                self.socket = None
        except:
            pass

    def __repr__(self):
        # FIXME can do better than this
        if self.parent:
            parent = self.parent.id
        else:
            parent = None
        return ("%s( %r, address=%r, local_key=%r, dev_type=%r, connection_timeout=%r, version=%r, persist=%r, cid=%r, parent=%r, children=%r )" %
                (self.__class__.__name__, self.id, self.address, self.real_local_key.decode(), self.dev_type, self.connection_timeout, self.version, self.socketPersistent, self.cid, parent, self.children))

    def _get_socket(self, renew):
        if renew and self.socket is not None:
            # self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.socket = None
        if self.socket is None:
            # Set up Socket
            retries = 0
            err = ERR_OFFLINE
            while retries < self.socketRetryLimit:
                if self.auto_ip and not self.address:
                    bcast_data = find_device(self.id)
                    if bcast_data['ip'] is None:
                        log.debug("Unable to find device on network (specify IP address)")
                        return ERR_OFFLINE
                    self.address = bcast_data['ip']
                    new_version = float(bcast_data['version'])
                    if new_version != self.version:
                        # this may trigger a network call which will call _get_socket() again
                        #self.set_version(new_version)
                        self.version = new_version
                        self.version_str = "v" + str(version)
                        self.version_bytes = str(version).encode('latin1')
                        self.version_header = self.version_bytes + PROTOCOL_3x_HEADER
                        self.payload_dict = None

                if not self.address:
                    log.debug("No address for device!")
                    return ERR_OFFLINE

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.socketNODELAY:
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.settimeout(self.connection_timeout)
                try:
                    retries = retries + 1
                    self.socket.connect((self.address, self.port))
                    if self.version >= 3.4:
                        # restart session key negotiation
                        if self._negotiate_session_key():
                            return True
                        else:
                            if self.socket:
                                self.socket.close()
                                self.socket = None
                            return ERR_KEY_OR_VER
                    else:
                        return True
                except socket.timeout as e:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect (timeout) - retry %d/%d",
                        retries, self.socketRetryLimit
                    )
                    err = ERR_OFFLINE
                except Exception as e:
                    # unable to open socket
                    log.debug(
                        "socket unable to connect (exception) - retry %d/%d",
                        retries, self.socketRetryLimit, exc_info=True
                    )
                    err = ERR_CONNECT
                if self.socket:
                    self.socket.close()
                    self.socket = None
                if retries < self.socketRetryLimit:
                    time.sleep(self.socketRetryDelay)
                if self.auto_ip:
                    self.address = None
            # unable to get connection
            return err
        # existing socket active
        return True

    def _check_socket_close(self, force=False):
        if (force or not self.socketPersistent) and self.socket:
            self.socket.close()
            self.socket = None

    def _recv_all(self, length):
        tries = 2
        data = b''

        while length > 0:
            newdata = self.socket.recv(length)
            if not newdata or len(newdata) == 0:
                log.debug("_recv_all(): no data? %r", newdata)
                # connection closed?
                tries -= 1
                if tries == 0:
                    raise DecodeError('No data received - connection closed?')
                if self.sendWait is not None:
                    time.sleep(self.sendWait)
                continue
            data += newdata
            length -= len(newdata)
            tries = 2
        return data

    def _receive(self):
        # make sure to use the parent's self.seqno and session key
        if self.parent:
            return self.parent._receive()
        # message consists of header + retcode + [data] + crc (4 or 32) + footer
        min_len_55AA = struct.calcsize(MESSAGE_HEADER_FMT_55AA) + 4 + 4 + len(SUFFIX_BIN)
        # message consists of header + iv + retcode + [data] + crc (16) + footer
        min_len_6699 = struct.calcsize(MESSAGE_HEADER_FMT_6699) + 12 + 4 + 16 + len(SUFFIX_BIN)
        min_len = min_len_55AA if min_len_55AA < min_len_6699 else min_len_6699
        prefix_len = len( PREFIX_55AA_BIN )

        data = self._recv_all( min_len )

        # search for the prefix.  if not found, delete everything except
        # the last (prefix_len - 1) bytes and recv more to replace it
        prefix_offset_55AA = data.find( PREFIX_55AA_BIN )
        prefix_offset_6699 = data.find( PREFIX_6699_BIN )

        while prefix_offset_55AA != 0 and prefix_offset_6699 != 0:
            log.debug('Message prefix not at the beginning of the received data!')
            log.debug('Offset 55AA: %d, 6699: %d, Received data: %r', prefix_offset_55AA, prefix_offset_6699, data)
            if prefix_offset_55AA < 0 and prefix_offset_6699 < 0:
                data = data[1-prefix_len:]
            else:
                prefix_offset = prefix_offset_6699 if prefix_offset_55AA < 0 else prefix_offset_55AA
                data = data[prefix_offset:]

            data += self._recv_all( min_len - len(data) )
            prefix_offset_55AA = data.find( PREFIX_55AA_BIN )
            prefix_offset_6699 = data.find( PREFIX_6699_BIN )

        header = parse_header(data)
        remaining = header.total_length - len(data)
        if remaining > 0:
            data += self._recv_all( remaining )

        log.debug("received data=%r", binascii.hexlify(data))
        hmac_key = self.local_key if self.version >= 3.4 else None
        no_retcode = False #None if self.version >= 3.5 else False
        return unpack_message(data, header=header, hmac_key=hmac_key, no_retcode=no_retcode)

    # similar to _send_receive() but never retries sending and does not decode the response
    def _send_receive_quick(self, payload, recv_retries, from_child=None): # pylint: disable=W0613
        if self.parent:
            return self.parent._send_receive_quick(payload, recv_retries, from_child=self)

        log.debug("sending payload quick")
        if self._get_socket(False) is not True:
            return None
        enc_payload = self._encode_message(payload) if type(payload) == MessagePayload else payload
        try:
            self.socket.sendall(enc_payload)
        except:
            self._check_socket_close(True)
            return None
        if not recv_retries:
            return True
        while recv_retries:
            try:
                msg = self._receive()
            except:
                msg = None
            if msg and len(msg.payload) != 0:
                return msg
            recv_retries -= 1
            if recv_retries == 0:
                log.debug("received null payload (%r) but out of recv retries, giving up", msg)
            else:
                log.debug("received null payload (%r), fetch new one - %s retries remaining", msg, recv_retries)
        return False

    def _send_receive(self, payload, minresponse=28, getresponse=True, decode_response=True, from_child=None):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send. Set to 'None' to receive only.
            minresponse(int): Minimum response size expected (default=28 bytes)
            getresponse(bool): If True, wait for and return response.
        """
        if self.parent:
            return self.parent._send_receive(payload, minresponse, getresponse, decode_response, from_child=self)

        if (not payload) and getresponse and self.received_wrong_cid_queue:
            if (not self.children) or (not from_child):
                r = self.received_wrong_cid_queue[0]
                self.received_wrong_cid_queue = self.received_wrong_cid_queue[1:]
                return r
            found_rq = False
            for rq in self.received_wrong_cid_queue:
                if rq[0] == from_child:
                    found_rq = rq
                    break
            if found_rq:
                self.received_wrong_cid_queue.remove(found_rq)
                return found_rq[1]

        success = False
        partial_success = False
        retries = 0
        recv_retries = 0
        #max_recv_retries = 0 if not self.retry else 2 if self.socketRetryLimit > 2 else self.socketRetryLimit
        max_recv_retries = 0 if not self.retry else self.socketRetryLimit
        dev_type = self.dev_type
        do_send = True
        msg = None
        while not success:
            # open up socket if device is available
            sock_result = self._get_socket(False)
            if sock_result is not True:
                # unable to get a socket - device likely offline
                self._check_socket_close(True)
                return error_json( sock_result if sock_result else ERR_OFFLINE )
            # send request to device
            try:
                if payload is not None and do_send:
                    log.debug("sending payload")
                    enc_payload = self._encode_message(payload) if type(payload) == MessagePayload else payload
                    self.socket.sendall(enc_payload)
                    if self.sendWait is not None:
                        time.sleep(self.sendWait)  # give device time to respond
                if getresponse:
                    do_send = False
                    rmsg = self._receive()
                    # device may send null ack (28 byte) response before a full response
                    # consider it an ACK and do not retry the send even if we do not get a full response
                    if rmsg:
                        payload = None
                        partial_success = True
                        msg = rmsg
                    if (not msg or len(msg.payload) == 0) and recv_retries <= max_recv_retries:
                        log.debug("received null payload (%r), fetch new one - retry %s / %s", msg, recv_retries, max_recv_retries)
                        recv_retries += 1
                        if recv_retries > max_recv_retries:
                            success = True
                    else:
                        success = True
                        log.debug("received message=%r", msg)
                else:
                    # legacy/default mode avoids persisting socket across commands
                    self._check_socket_close()
                    return None
            except (KeyboardInterrupt, SystemExit) as err:
                log.debug("Keyboard Interrupt - Exiting")
                raise
            except socket.timeout as err:
                # a socket timeout occurred
                if payload is None:
                    # Receive only mode - return None
                    self._check_socket_close()
                    return None
                do_send = True
                retries += 1
                # toss old socket and get new one
                self._check_socket_close(True)
                log.debug(
                    "Timeout in _send_receive() - retry %s / %s",
                    retries, self.socketRetryLimit
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    # timeout reached - return error
                    return error_json(ERR_KEY_OR_VER)
                # wait a bit before retrying
                time.sleep(0.1)
            except DecodeError as err:
                log.debug("Error decoding received data - read retry %s/%s", recv_retries, max_recv_retries, exc_info=True)
                recv_retries += 1
                if recv_retries > max_recv_retries:
                    # we recieved at least 1 valid message with a null payload, so the send was successful
                    if partial_success:
                        self._check_socket_close()
                        return None
                    # no valid messages received
                    self._check_socket_close(True)
                    return error_json(ERR_PAYLOAD)
            except Exception as err:
                # likely network or connection error
                do_send = True
                retries += 1
                # toss old socket and get new one
                self._check_socket_close(True)
                log.debug(
                    "Network connection error in _send_receive() - retry %s/%s",
                    retries, self.socketRetryLimit, exc_info=True
                )
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    log.debug(
                        "Exceeded tinytuya retry limit (%s)",
                        self.socketRetryLimit
                    )
                    log.debug("Unable to connect to device ")
                    # timeout reached - return error
                    return error_json(ERR_CONNECT)
                # wait a bit before retrying
                time.sleep(0.1)
            # except
        # while

        # could be None or have a null payload
        if not decode_response:
            # legacy/default mode avoids persisting socket across commands
            self._check_socket_close()
            return msg

        return self._process_message( msg, dev_type, from_child, minresponse, decode_response )

    def _process_message( self, msg, dev_type=None, from_child=None, minresponse=28, decode_response=True ):
        # null packet, nothing to decode
        if not msg or len(msg.payload) == 0:
            log.debug("raw unpacked message = %r", msg)
            # legacy/default mode avoids persisting socket across commands
            self._check_socket_close()
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
            log.debug("error unpacking or decoding tuya JSON payload", exc_info=True)
            result = error_json(ERR_PAYLOAD)

        # Did we detect a device22 device? Return ERR_DEVTYPE error.
        if dev_type and dev_type != self.dev_type:
            log.debug(
                "Device22 detected and updated (%s -> %s) - Update payload and try again",
                dev_type,
                self.dev_type,
            )
            result = error_json(ERR_DEVTYPE)

        found_child = False
        if self.children:
            found_cid = None
            if result and 'cid' in result:
                found_cid = result['cid']
            elif result and 'data' in result and type(result['data']) == dict and 'cid' in result['data']:
                found_cid = result['data']['cid']

            if found_cid:
                for c in self.children:
                    if self.children[c].cid == found_cid:
                        result['device'] = found_child = self.children[c]
                        break

            if from_child and from_child is not True and from_child != found_child:
                # async update from different CID, try again
                log.debug( 'Recieved async update for wrong CID %s while looking for CID %s, trying again', found_cid, from_child.cid )
                if self.socketPersistent:
                    # if persistent, save response until the next receive() call
                    # otherwise, trash it
                    if found_child:
                        result = found_child._process_response(result)
                    else:
                        result = self._process_response(result)
                    self.received_wrong_cid_queue.append( (found_child, result) )
                # events should not be coming in so fast that we will never timeout a read, so don't worry about loops
                return self._send_receive( None, minresponse, True, decode_response, from_child=from_child)

        # legacy/default mode avoids persisting socket across commands
        self._check_socket_close()

        if found_child:
            return found_child._process_response(result)

        return self._process_response(result)

    def _decode_payload(self, payload):
        log.debug("decode payload=%r", payload)
        cipher = AESCipher(self.local_key)

        if self.version == 3.4:
            # 3.4 devices encrypt the version header in addition to the payload
            try:
                log.debug("decrypting=%r", payload)
                payload = cipher.decrypt(payload, False, decode_text=False)
            except:
                log.debug("incomplete payload=%r (len:%d)", payload, len(payload), exc_info=True)
                return error_json(ERR_PAYLOAD)

            log.debug("decrypted 3.x payload=%r", payload)
            log.debug("payload type = %s", type(payload))

        if payload.startswith(PROTOCOL_VERSION_BYTES_31):
            # Received an encrypted payload
            # Remove version header
            payload = payload[len(PROTOCOL_VERSION_BYTES_31) :]
            # Decrypt payload
            # Remove 16-bytes of MD5 hexdigest of payload
            payload = cipher.decrypt(payload[16:])
        elif self.version >= 3.2: # 3.2 or 3.3 or 3.4 or 3.5
            # Trim header for non-default device type
            if payload.startswith( self.version_bytes ):
                payload = payload[len(self.version_header) :]
                log.debug("removing 3.x=%r", payload)
            elif self.dev_type == "device22" and (len(payload) & 0x0F) != 0:
                payload = payload[len(self.version_header) :]
                log.debug("removing device22 3.x header=%r", payload)

            if self.version < 3.4:
                try:
                    log.debug("decrypting=%r", payload)
                    payload = cipher.decrypt(payload, False)
                except:
                    log.debug("incomplete payload=%r (len:%d)", payload, len(payload), exc_info=True)
                    return error_json(ERR_PAYLOAD)

                log.debug("decrypted 3.x payload=%r", payload)
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

        # v3.4 stuffs it into {"data":{"dps":{"1":true}}, ...}
        if "dps" not in json_payload and "data" in json_payload and "dps" in json_payload['data']:
            json_payload['dps'] = json_payload['data']['dps']

        return json_payload

    def _process_response(self, response): # pylint: disable=R0201
        """
        Override this function in a sub-class if you want to do some processing on the received data
        """
        return response

    def _negotiate_session_key(self):
        rkey = self._send_receive_quick( self._negotiate_session_key_generate_step_1(), 2 )
        step3 = self._negotiate_session_key_generate_step_3( rkey )
        if not step3:
            return False
        self._send_receive_quick( step3, None )
        self._negotiate_session_key_generate_finalize()
        return True

    def _negotiate_session_key_generate_step_1( self ):
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''
        self.local_key = self.real_local_key

        return MessagePayload(SESS_KEY_NEG_START, self.local_nonce)

    def _negotiate_session_key_generate_step_3( self, rkey ):
        if not rkey or type(rkey) != TuyaMessage or len(rkey.payload) < 48:
            # error
            log.debug("session key negotiation failed on step 1")
            return False

        if rkey.cmd != SESS_KEY_NEG_RESP:
            log.debug("session key negotiation step 2 returned wrong command: %d", rkey.cmd)
            return False

        payload = rkey.payload
        if self.version == 3.4:
            try:
                log.debug("decrypting=%r", payload)
                cipher = AESCipher(self.real_local_key)
                payload = cipher.decrypt(payload, False, decode_text=False)
            except:
                log.debug("session key step 2 decrypt failed, payload=%r (len:%d)", payload, len(payload), exc_info=True)
                return False

        log.debug("decrypted session key negotiation step 2 payload=%r", payload)
        log.debug("payload type = %s len = %d", type(payload), len(payload))

        if len(payload) < 48:
            log.debug("session key negotiation step 2 failed, too short response")
            return False

        self.remote_nonce = payload[:16]
        hmac_check = hmac.new(self.local_key, self.local_nonce, sha256).digest()

        if hmac_check != payload[16:48]:
            log.debug("session key negotiation step 2 failed HMAC check! wanted=%r but got=%r", binascii.hexlify(hmac_check), binascii.hexlify(payload[16:48]))
            return False

        log.debug("session local nonce: %r remote nonce: %r", self.local_nonce, self.remote_nonce)

        rkey_hmac = hmac.new(self.local_key, self.remote_nonce, sha256).digest()
        return MessagePayload(SESS_KEY_NEG_FINISH, rkey_hmac)

    def _negotiate_session_key_generate_finalize( self ):
        if IS_PY2:
            k = [ chr(ord(a)^ord(b)) for (a,b) in zip(self.local_nonce,self.remote_nonce) ]
            self.local_key = ''.join(k)
        else:
            self.local_key = bytes( [ a^b for (a,b) in zip(self.local_nonce,self.remote_nonce) ] )
        log.debug("Session nonce XOR'd: %r", self.local_key)

        cipher = AESCipher(self.real_local_key)
        if self.version == 3.4:
            self.local_key = cipher.encrypt( self.local_key, False, pad=False )
        else:
            iv = self.local_nonce[:12]
            log.debug("Session IV: %r", iv)
            self.local_key = cipher.encrypt( self.local_key, use_base64=False, pad=False, iv=iv )[12:28]

        log.debug("Session key negotiate success! session key: %r", self.local_key)
        return True

    # adds protocol header (if needed) and encrypts
    def _encode_message( self, msg ):
        # make sure to use the parent's self.seqno and session key
        if self.parent:
            return self.parent._encode_message( msg )
        hmac_key = None
        iv = None
        payload = msg.payload
        self.cipher = AESCipher(self.local_key)

        if self.version >= 3.4:
            hmac_key = self.local_key
            if msg.cmd not in NO_PROTOCOL_HEADER_CMDS:
                # add the 3.x header
                payload = self.version_header + payload
            log.debug('final payload: %r', payload)

            if self.version >= 3.5:
                iv = True
                # seqno cmd retcode payload crc crc_good, prefix, iv
                msg = TuyaMessage(self.seqno, msg.cmd, None, payload, 0, True, PREFIX_6699_VALUE, True)
                self.seqno += 1  # increase message sequence number
                data = pack_message(msg,hmac_key=self.local_key)
                log.debug("payload encrypted=%r",binascii.hexlify(data))
                return data

            payload = self.cipher.encrypt(payload, False)
        elif self.version >= 3.2:
            # expect to connect and then disconnect to set new
            payload = self.cipher.encrypt(payload, False)
            if msg.cmd not in NO_PROTOCOL_HEADER_CMDS:
                # add the 3.x header
                payload = self.version_header + payload
        elif msg.cmd == CONTROL:
            # need to encrypt
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
        msg = TuyaMessage(self.seqno, msg.cmd, 0, payload, 0, True, PREFIX_55AA_VALUE, False)
        self.seqno += 1  # increase message sequence number
        buffer = pack_message(msg,hmac_key=hmac_key)
        log.debug("payload encrypted=%r",binascii.hexlify(buffer))
        return buffer

    def _register_child(self, child):
        if child.id in self.children and child != self.children[child.id]:
            log.debug('Replacing existing child %r!', child.id)
        self.children[child.id] = child
        # disable device22 detection as some gateways return "json obj data unvalid" when the gateway is polled without a cid
        self.disabledetect = True
        self.payload_dict = None

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

    def status(self, nowait=False):
        """Return device status."""
        query_type = DP_QUERY
        log.debug("status() entry (dev_type is %s)", self.dev_type)
        payload = self.generate_payload(query_type)

        data = self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("status() received data=%r", data)
        # Error handling
        if (not nowait) and data and "Err" in data:
            if data["Err"] == str(ERR_DEVTYPE):
                # Device22 detected and change - resend with new payload
                log.debug("status() rebuilding payload for device22")
                payload = self.generate_payload(query_type)
                data = self._send_receive(payload)
            elif data["Err"] == str(ERR_PAYLOAD):
                log.debug("Status request returned an error, is version %r and local key %r correct?", self.version, self.local_key)

        return data

    def subdev_query( self, nowait=False ):
        """Query for a list of sub-devices and their status"""
        # final payload should look like: {"data":{"cids":[]},"reqType":"subdev_online_stat_query"}
        payload = self.generate_payload(LAN_EXT_STREAM, rawData={"cids":[]}, reqType='subdev_online_stat_query')
        return self._send_receive(payload, 0, getresponse=(not nowait))

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
            if data is not None and "dps" in data:
                for k in data["dps"]:
                    self.dps_cache[k] = None

            if self.dev_type == "default":
                self.dps_to_request = self.dps_cache
                return self.dps_cache
        log.debug("Detected dps: %s", self.dps_cache)
        self.dps_to_request = self.dps_cache
        return self.dps_cache

    def add_dps_to_request(self, dp_indicies):
        """Add a datapoint (DP) to be included in requests."""
        if isinstance(dp_indicies, int):
            self.dps_to_request[str(dp_indicies)] = None
        else:
            self.dps_to_request.update({str(index): None for index in dp_indicies})

    def set_version(self, version): # pylint: disable=W0621
        version = float(version)
        self.version = version
        self.version_str = "v" + str(version)
        self.version_bytes = str(version).encode('latin1')
        self.version_header = self.version_bytes + PROTOCOL_3x_HEADER
        self.payload_dict = None
        if version == 3.2: # 3.2 behaves like 3.3 with device22
            self.dev_type="device22"
            if self.dps_to_request == {}:
                self.detect_available_dps()

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

    def set_socketRetryDelay(self, delay):
        self.socketRetryDelay = delay

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

    @staticmethod
    def find(did):
        """
        Mainly here for backwards compatibility.
        Calling tinytuya.find_device() directly is recommended.

        Parameters:
            did = The specific Device ID you are looking for (returns only IP and Version)

        Response:
            (ip, version)
        """
        bcast_data = find_device(dev_id=did)
        return (bcast_data['ip'], bcast_data['version'])

    def generate_payload(self, command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None):
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
        # dicts will get referenced instead of copied if we don't do this
        def _deepcopy(dict1):
            result = {}
            for k in dict1:
                if isinstance( dict1[k], dict ):
                    result[k] = _deepcopy( dict1[k] )
                else:
                    result[k] = dict1[k]
            return result

        # dict2 will be merged into dict1
        # as dict2 is payload_dict['...'] we only need to worry about copying 2 levels deep,
        #  the command id and "command"/"command_override" keys: i.e. dict2[CMD_ID]["command"]
        def _merge_payload_dicts(dict1, dict2):
            for cmd in dict2:
                if cmd not in dict1:
                    # make a deep copy so we don't get a reference
                    dict1[cmd] = _deepcopy( dict2[cmd] )
                else:
                    for var in dict2[cmd]:
                        if not isinstance( dict2[cmd][var], dict ):
                            # not a dict, safe to copy
                            dict1[cmd][var] = dict2[cmd][var]
                        else:
                            # make a deep copy so we don't get a reference
                            dict1[cmd][var] = _deepcopy( dict2[cmd][var] )

        # start merging down to the final payload dict
        # later merges overwrite earlier merges
        # "default" - ("gateway" if gateway) - ("zigbee" if sub-device) - [version string] - ('gateway_'+[version string] if gateway) -
        #   'zigbee_'+[version string] if sub-device - [dev_type if not "default"]
        if not self.payload_dict or self.last_dev_type != self.dev_type:
            self.payload_dict = {}
            _merge_payload_dicts( self.payload_dict, payload_dict['default'] )
            if self.children:
                _merge_payload_dicts( self.payload_dict, payload_dict['gateway'] )
            if self.cid:
                _merge_payload_dicts( self.payload_dict, payload_dict['zigbee'] )
            if self.version_str in payload_dict:
                _merge_payload_dicts( self.payload_dict, payload_dict[self.version_str] )
            if self.children and ('gateway_'+self.version_str) in payload_dict:
                _merge_payload_dicts( self.payload_dict, payload_dict['gateway_'+self.version_str] )
            if self.cid and ('zigbee_'+self.version_str) in payload_dict:
                _merge_payload_dicts( self.payload_dict, payload_dict['zigbee_'+self.version_str] )
            if self.dev_type != 'default':
                _merge_payload_dicts( self.payload_dict, payload_dict[self.dev_type] )
            log.debug( 'final payload_dict for %r (%r/%r): %r', self.id, self.version_str, self.dev_type, self.payload_dict )
            # save it so we don't have to calculate this again unless something changes
            self.last_dev_type = self.dev_type

        json_data = command_override = None

        if command in self.payload_dict:
            if 'command' in self.payload_dict[command]:
                json_data = self.payload_dict[command]['command']
            if 'command_override' in self.payload_dict[command]:
                command_override = self.payload_dict[command]['command_override']

        if command_override is None:
            command_override = command
        if json_data is None:
            # I have yet to see a device complain about included but unneeded attribs, but they *will*
            # complain about missing attribs, so just include them all unless otherwise specified
            json_data = {"gwId": "", "devId": "", "uid": "", "t": ""}

        # make sure we don't modify payload_dict
        json_data = json_data.copy()

        if "gwId" in json_data:
            if gwId is not None:
                json_data["gwId"] = gwId
            elif self.parent:
                json_data["gwId"] = self.parent.id
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
        if self.cid:
            json_data["cid"] = self.cid
            if "data" in json_data:
                json_data["data"]["cid"] = self.cid
                json_data["data"]["ctype"] = 0
        #elif "cid" in json_data:
        #    del json_data['cid']
        if "t" in json_data:
            if json_data['t'] == "int":
                json_data["t"] = int(time.time())
            else:
                json_data["t"] = str(int(time.time()))
        if rawData is not None and "data" in json_data:
            json_data["data"] = rawData
        elif data is not None:
            if "dpId" in json_data:
                json_data["dpId"] = data
            elif "data" in json_data:
                json_data["data"]["dps"] = data
            else:
                json_data["dps"] = data
        elif self.dev_type == "device22" and command == DP_QUERY:
            json_data["dps"] = self.dps_to_request
        if reqType and "reqType" in json_data:
            json_data["reqType"] = reqType

        # Create byte buffer from hex data
        if json_data == "":
            payload = ""
        else:
            payload = json.dumps(json_data)
        # if spaces are not removed device does not respond!
        payload = payload.replace(" ", "")
        payload = payload.encode("utf-8")
        log.debug("building command %s payload=%r", command, payload)

        # create Tuya message packet
        return MessagePayload(command_override, payload)


class Device(XenonDevice):
    #def __init__(self, *args, **kwargs):
    #    super(Device, self).__init__(*args, **kwargs)

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

    def heartbeat(self, nowait=True):
        """
        Send a keep-alive HEART_BEAT command to keep the TCP connection open.

        Devices only send an empty-payload response, so no need to wait for it.

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

    def set_multiple_values(self, data, nowait=False):
        """
        Set multiple indexes at the same time

        Args:
            data(dict): array of index/value pairs to set
            nowait(bool): True to send without waiting for response.
        """
        out = {}
        for i in data:
            out[str(i)] = data[i]
        payload = self.generate_payload(CONTROL, out)
        return self._send_receive(payload, getresponse=(not nowait))

    def turn_on(self, switch=1, nowait=False):
        """Turn the device on"""
        return self.set_status(True, switch, nowait)

    def turn_off(self, switch=1, nowait=False):
        """Turn the device off"""
        return self.set_status(False, switch, nowait)

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
    return AESCipher( key ).encrypt( msg, use_base64=False, pad=True )

def decrypt(msg, key):
    return AESCipher( key ).decrypt( msg, use_base64=False, decode_text=True )

#def decrypt_gcm(msg, key):
#    nonce = msg[:12]
#    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt(msg[12:]).decode()

# UDP packet payload decryption - credit to tuya-convert
udpkey = md5(b"yGAdlopoPVldABfn").digest()

def decrypt_udp(msg):
    try:
        header = parse_header(msg)
    except:
        header = None
    if not header:
        return decrypt(msg, udpkey)
    if header.prefix == PREFIX_55AA_VALUE:
        payload = unpack_message(msg).payload
        try:
            if payload[:1] == b'{' and payload[-1:] == b'}':
                return payload.decode()
        except:
            pass
        return decrypt(payload, udpkey)
    if header.prefix == PREFIX_6699_VALUE:
        unpacked = unpack_message(msg, hmac_key=udpkey, no_retcode=None)
        payload = unpacked.payload.decode()
        # app sometimes has extra bytes at the end
        while payload[-1] == chr(0):
            payload = payload[:-1]
        return payload
    return decrypt(msg, udpkey)


def appenddevice(newdevice, devices):
    if newdevice["ip"] in devices:
        return True
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
    scanner.scan(scantime=maxretry, color=color, forcescan=forcescan)


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
    return scanner.devices(verbose=verbose, scantime=maxretry, color=color, poll=poll, forcescan=forcescan, byID=byID)
