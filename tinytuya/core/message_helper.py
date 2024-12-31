# TinyTuya Module
# -*- coding: utf-8 -*-

import binascii
from collections import namedtuple
import hmac
import logging
import struct
from hashlib import sha256

from .crypto_helper import AESCipher
from .exceptions import DecodeError

log = logging.getLogger(__name__)

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


# Tuya Packet Format
TuyaHeader = namedtuple('TuyaHeader', 'prefix seqno cmd length total_length')
MessagePayload = namedtuple("MessagePayload", "cmd payload")
try:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv", defaults=(True,0x55AA,None))
except:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv")


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


def has_suffix(payload):
    """Check to see if payload has valid Tuya suffix"""
    if len(payload) < 4:
        return False
    log.debug("buffer %r = %r", payload[-4:], SUFFIX_BIN)
    return payload[-4:] == SUFFIX_BIN


