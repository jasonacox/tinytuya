# TinyTuya Module
# -*- coding: utf-8 -*-
from hashlib import md5

from .crypto_helper import AESCipher
from . import header as H
from .message_helper import parse_header, unpack_message


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
    if header.prefix == H.PREFIX_55AA_VALUE:
        payload = unpack_message(msg).payload
        try:
            if payload[:1] == b'{' and payload[-1:] == b'}':
                return payload.decode()
        except:
            pass
        return decrypt(payload, udpkey)
    if header.prefix == H.PREFIX_6699_VALUE:
        unpacked = unpack_message(msg, hmac_key=udpkey, no_retcode=None)
        payload = unpacked.payload.decode()
        # app sometimes has extra bytes at the end
        while payload[-1] == chr(0):
            payload = payload[:-1]
        return payload
    return decrypt(msg, udpkey)