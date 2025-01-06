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
from . import header as H

log = logging.getLogger(__name__)


# Tuya Packet Format
TuyaHeader = namedtuple('TuyaHeader', 'prefix seqno cmd length total_length')
MessagePayload = namedtuple("MessagePayload", "cmd payload")
try:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv", defaults=(True,0x55AA,None))
except:
    TuyaMessage = namedtuple("TuyaMessage", "seqno cmd retcode payload crc crc_good prefix iv")


def pack_message(msg, hmac_key=None):
    """Pack a TuyaMessage into bytes."""
    if msg.prefix == H.PREFIX_55AA_VALUE:
        header_fmt = H.MESSAGE_HEADER_FMT_55AA
        end_fmt = H.MESSAGE_END_FMT_HMAC if hmac_key else H.MESSAGE_END_FMT_55AA
        msg_len = len(msg.payload) + struct.calcsize(end_fmt)
        header_data = ( msg.prefix, msg.seqno, msg.cmd, msg_len )
    elif msg.prefix == H.PREFIX_6699_VALUE:
        if not hmac_key:
            raise TypeError( 'key must be provided to pack 6699-format messages' )
        header_fmt = H.MESSAGE_HEADER_FMT_6699
        end_fmt = H.MESSAGE_END_FMT_6699
        msg_len = len(msg.payload) + (struct.calcsize(end_fmt) - 4) + 12
        if type(msg.retcode) == int:
            msg_len += struct.calcsize(H.MESSAGE_RETCODE_FMT)
        header_data = ( msg.prefix, 0, msg.seqno, msg.cmd, msg_len )
    else:
        raise ValueError( 'pack_message() cannot handle message format %08X' % msg.prefix )

    # Create full message excluding CRC and suffix
    data = struct.pack( header_fmt, *header_data )

    if msg.prefix == H.PREFIX_6699_VALUE:
        cipher = AESCipher( hmac_key )
        if type(msg.retcode) == int:
            raw = struct.pack( H.MESSAGE_RETCODE_FMT, msg.retcode ) + msg.payload
        else:
            raw = msg.payload
        data2 = cipher.encrypt( raw, use_base64=False, pad=False, iv=True if not msg.iv else msg.iv, header=data[4:])
        data += data2 + H.SUFFIX_6699_BIN
    else:
        data += msg.payload
        if hmac_key:
            crc = hmac.new(hmac_key, data, sha256).digest()
        else:
            crc = binascii.crc32(data) & 0xFFFFFFFF
        # Calculate CRC, add it together with suffix
        data += struct.pack( end_fmt, crc, H.SUFFIX_VALUE )

    return data


def parse_header(data):
    if( data[:4] == H.PREFIX_6699_BIN ):
        fmt = H.MESSAGE_HEADER_FMT_6699
    else:
        fmt = H.MESSAGE_HEADER_FMT_55AA

    header_len = struct.calcsize(fmt)

    if len(data) < header_len:
        raise DecodeError('Not enough data to unpack header')

    unpacked = struct.unpack( fmt, data[:header_len] )
    prefix = unpacked[0]

    if prefix == H.PREFIX_55AA_VALUE:
        prefix, seqno, cmd, payload_len = unpacked
        total_length = payload_len + header_len
    elif prefix == H.PREFIX_6699_VALUE:
        prefix, unknown, seqno, cmd, payload_len = unpacked
        #seqno |= unknown << 32
        total_length = payload_len + header_len + len(H.SUFFIX_6699_BIN)
    else:
        #log.debug('Header prefix wrong! %08X != %08X', prefix, PREFIX_VALUE)
        raise DecodeError('Header prefix wrong! %08X is not %08X or %08X' % (prefix, H.PREFIX_55AA_VALUE, H.PREFIX_6699_VALUE))

    # sanity check. currently the max payload length is somewhere around 300 bytes
    if payload_len > 1000:
        raise DecodeError('Header claims the packet size is over 1000 bytes!  It is most likely corrupt.  Claimed size: %d bytes. fmt:%s unpacked:%r' % (payload_len,fmt,unpacked))

    return TuyaHeader(prefix, seqno, cmd, payload_len, total_length)


def unpack_message(data, hmac_key=None, header=None, no_retcode=False):
    """Unpack bytes into a TuyaMessage."""
    if header is None:
        header = parse_header(data)

    if header.prefix == H.PREFIX_55AA_VALUE:
        # 4-word header plus return code
        header_len = struct.calcsize(H.MESSAGE_HEADER_FMT_55AA)
        end_fmt = H.MESSAGE_END_FMT_HMAC if hmac_key else H.MESSAGE_END_FMT_55AA
        retcode_len = 0 if no_retcode else struct.calcsize(H.MESSAGE_RETCODE_FMT)
        msg_len = header_len + header.length
    elif header.prefix == H.PREFIX_6699_VALUE:
        if not hmac_key:
            raise TypeError( 'key must be provided to unpack 6699-format messages' )
        header_len = struct.calcsize(H.MESSAGE_HEADER_FMT_6699)
        end_fmt = H.MESSAGE_END_FMT_6699
        retcode_len = 0
        msg_len = header_len + header.length + 4
    else:
        raise ValueError( 'unpack_message() cannot handle message format %08X' % header.prefix )

    if len(data) < msg_len:
        log.debug('unpack_message(): not enough data to unpack payload! need %d but only have %d', header_len+header.length, len(data))
        raise DecodeError('Not enough data to unpack payload')

    end_len = struct.calcsize(end_fmt)
    # the retcode is technically part of the payload, but strip it as we do not want it here
    retcode = 0 if not retcode_len else struct.unpack(H.MESSAGE_RETCODE_FMT, data[header_len:header_len+retcode_len])[0]
    payload = data[header_len+retcode_len:msg_len]
    crc, suffix = struct.unpack(end_fmt, payload[-end_len:])
    crc_good = False
    payload = payload[:-end_len]

    if header.prefix == H.PREFIX_55AA_VALUE:
        if hmac_key:
            have_crc = hmac.new(hmac_key, data[:(header_len+header.length)-end_len], sha256).digest()
        else:
            have_crc = binascii.crc32(data[:(header_len+header.length)-end_len]) & 0xFFFFFFFF

        if suffix != H.SUFFIX_VALUE:
            log.debug('Suffix prefix wrong! %08X != %08X', suffix, H.SUFFIX_VALUE)

        if crc != have_crc:
            if hmac_key:
                log.debug('HMAC checksum wrong! %r != %r', binascii.hexlify(have_crc), binascii.hexlify(crc))
            else:
                log.debug('CRC wrong! %08X != %08X', have_crc, crc)
        crc_good = crc == have_crc
        iv = None
    elif header.prefix == H.PREFIX_6699_VALUE:
        iv = payload[:12]
        payload = payload[12:]
        try:
            cipher = AESCipher( hmac_key )
            payload = cipher.decrypt( payload, use_base64=False, decode_text=False, verify_padding=False, iv=iv, header=data[4:header_len], tag=crc)
            crc_good = True
        except:
            crc_good = False

        retcode_len = struct.calcsize(H.MESSAGE_RETCODE_FMT)
        if no_retcode is False:
            pass
        elif no_retcode is None and payload[0:1] != b'{' and payload[retcode_len:retcode_len+1] == b'{':
            retcode_len = struct.calcsize(H.MESSAGE_RETCODE_FMT)
        else:
            retcode_len = 0
        if retcode_len:
            retcode = struct.unpack(H.MESSAGE_RETCODE_FMT, payload[:retcode_len])[0]
            payload = payload[retcode_len:]

    return TuyaMessage(header.seqno, header.cmd, retcode, payload, crc, crc_good, header.prefix, iv)


def has_suffix(payload):
    """Check to see if payload has valid Tuya suffix"""
    if len(payload) < 4:
        return False
    log.debug("buffer %r = %r", payload[-4:], H.SUFFIX_BIN)
    return payload[-4:] == H.SUFFIX_BIN


