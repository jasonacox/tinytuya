# TinyTuya Module
# -*- coding: utf-8 -*-

from __future__ import print_function  # python 2.7 support
import base64
import logging
import time

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

log = logging.getLogger(__name__)


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
