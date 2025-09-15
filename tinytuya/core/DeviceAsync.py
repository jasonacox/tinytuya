# TinyTuya Module
# -*- coding: utf-8 -*-

import asyncio
import binascii
import hmac
import json
from hashlib import md5, sha256
import logging
import socket
import struct
import time

from .const import DEVICEFILE, TCPPORT
from .crypto_helper import AESCipher
from .error_helper import ERR_CONNECT, ERR_DEVTYPE, ERR_JSON, ERR_KEY_OR_VER, ERR_OFFLINE, ERR_PAYLOAD, error_json
from .exceptions import DecodeError
from .message_helper import MessagePayload, TuyaMessage, pack_message, unpack_message, parse_header
from . import command_types as CT, header as H
from .core import merge_dps_results
from .XenonDevice import find_device, device_info

log = logging.getLogger(__name__)

# Async helper functions
async def find_device_async(dev_id=None, address=None, scantime=None):
    # Use asyncio.to_thread if available (Python 3.9+), otherwise use executor
    # Call the actual sync implementation defined above, not the wrapper
    if hasattr(asyncio, 'to_thread'):
        return await asyncio.to_thread(find_device, dev_id, address, scantime)
    else:
        # Python 3.8 compatibility
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, find_device, dev_id, address, scantime)

async def device_info_async(dev_id):
    # Use asyncio.to_thread if available (Python 3.9+), otherwise use executor
    # Call the actual sync implementation defined above, not the wrapper
    if hasattr(asyncio, 'to_thread'):
        return await asyncio.to_thread(device_info, dev_id)
    else:
        # Python 3.8 compatibility
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, device_info, dev_id)

class DeviceAsync(object):
    def __init__(
            self, dev_id, address=None, local_key="", dev_type="default", connection_timeout=5,
            version=3.1, persist=False, cid=None, node_id=None, parent=None,
            connection_retry_limit=5, connection_retry_delay=5, port=TCPPORT,
            max_simultaneous_dps=0
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
        self.auto_ip = (not address) or address == "Auto" or address == "0.0.0.0"
        self.dev_type = dev_type
        self.dev_type_auto = self.dev_type == 'default'
        self.last_dev_type = ''
        self.connection_timeout = connection_timeout
        self.retry = True
        self.disabledetect = False # if True do not detect device22
        self.port = port
        self.socketPersistent = persist
        self.socketNODELAY = True
        self.socketRetryLimit = connection_retry_limit
        self.socketRetryDelay = connection_retry_delay
        self.seqno = 1
        self.sendWait = 0.01
        self.dps_cache = {}
        self.parent = parent
        self.children = {}
        self.received_wrong_cid_queue = []
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''
        self.payload_dict = None
        self._historic_status = {}
        self._last_status = {}
        self._have_status = False
        self.max_simultaneous_dps = max_simultaneous_dps if max_simultaneous_dps else 0
        self.raw_sent = None
        self.raw_recv = []
        self.cmd_retcode = None
        self.reader = None
        self.writer = None
        self.cipher = None
        self.local_key = local_key.encode("latin1")
        self.real_local_key = self.local_key
        self._initialized = False
        self.version = version
        #self._callback_queue = asyncio.Queue()
        self._callbacks_connect = []
        self._callbacks_response = []
        self._callbacks_data = []
        self._scanner = None

    @classmethod
    async def create(cls, *args, **kwargs):
        device = cls(*args, **kwargs)
        await device.initialize()
        return device

    async def initialize(self):
        if self._initialized:
            return
        self._initialized = True

        if self.parent:
            # if we are a child then we should have a cid/node_id but none were given - try and find it the same way we look up local keys
            if not self.cid:
                devinfo = await device_info_async( self.id )
                if devinfo and 'node_id' in devinfo and devinfo['node_id']:
                    self.cid = devinfo['node_id']
            if not self.cid:
                # not fatal as the user could have set the device_id to the cid
                # in that case dev_type should be 'zigbee' to set the proper fields in requests
                log.debug( 'Child device but no cid/node_id given!' )
            self._set_version(self.parent.version)
            self.parent._register_child(self)
        else:
            if self.auto_ip:
                bcast_data = await find_device_async(self.id)
                if bcast_data['ip'] is None:
                    log.debug("Unable to find device on network (specify IP address)")
                    raise RuntimeError("Unable to find device on network (specify IP address)")
                self.address = bcast_data['ip']
                self.version = float(bcast_data['version'])
            if self.local_key == "":
                devinfo = await device_info_async( self.id )
                if devinfo and 'key' in devinfo and devinfo['key']:
                    local_key = devinfo['key']
                    self.local_key = local_key.encode("latin1")
                    self.real_local_key = self.local_key
            if self.version:
                self._set_version(float(self.version))
            else:
                self._set_version(3.1)

    def __repr__(self):
        # FIXME can do better than this
        if self.parent:
            parent = self.parent.id
        else:
            parent = None
        return ("%s( %r, address=%r, local_key=%r, dev_type=%r, connection_timeout=%r, version=%r, persist=%r, cid=%r, parent=%r, children=%r )" %
                (self.__class__.__name__, self.id, self.address, self.real_local_key.decode(), self.dev_type, self.connection_timeout, self.version, self.socketPersistent, self.cid, parent, self.children))

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _ensure_connection(self, renew=False):
        """
        error = self._ensure_socket_connection(renew=False)

        Returns 0 on success, or an ERR_* constant on error
        """
        # Replaces _get_socket method
        if renew and self.writer:
            await self.close()

        if self.writer:
            return 0

        retries = 0
        err = ERR_OFFLINE
        while retries < self.socketRetryLimit:
            if self.auto_ip and not self.address:
                if self._scanner:
                    bcast_data = await self._scanner.scanfor( self.id, timeout=None )
                else:
                    bcast_data = await find_device_async(self.id)
                if bcast_data['ip'] is None:
                    log.debug("Unable to find device on network (specify IP address)")
                    err = ERR_OFFLINE
                    break
                self.address = bcast_data['ip']
                self._set_version(float(bcast_data['version']))

            if not self.address:
                log.debug("No address for device!")
                err = ERR_OFFLINE
                break

            if self.version > 3.1:
                if not self.local_key:
                    log.debug("No local key for device!")
                    err = ERR_KEY_OR_VER
                    break
                elif len(self.local_key) != 16:
                    log.debug("Bad local key length for device!")
                    err = ERR_KEY_OR_VER
                    break
            try:
                retries += 1
                fut = asyncio.open_connection(self.address, self.port)
                self.reader, self.writer = await asyncio.wait_for(fut, timeout=self.connection_timeout)

                # TCP_NODELAY
                sock = self.writer.get_extra_info('socket')
                if sock and self.socketNODELAY:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                if self.version >= 3.4:
                    # restart session key negotiation
                    if await self._negotiate_session_key():
                        err = 0
                    else:
                        await self.close()
                        err = ERR_KEY_OR_VER
                else:
                    err = 0
                break
            except (asyncio.TimeoutError, socket.timeout):
                log.debug(f"Connection timeout - retry {retries}/{self.socketRetryLimit}")
                err = ERR_OFFLINE
            except Exception as e:
                log.debug(f"Connection failed (exception) - retry {retries}/{self.socketRetryLimit}", exc_info=True)
                err = ERR_CONNECT

            await self.close()
            if retries < self.socketRetryLimit:
                await asyncio.sleep(self.socketRetryDelay)
            if self.auto_ip:
                self.address = None

        for cb in self._callbacks_connect:
            await cb( self, err )

        return err

    async def _check_socket_close(self, force=False):
        if force or not self.socketPersistent:
            await self.close()

    async def _recv_all(self, length):
        try:
            return await asyncio.wait_for(self.reader.readexactly(length), timeout=self.connection_timeout)
        except asyncio.IncompleteReadError as e:
            log.debug(f"_recv_all(): no data?: {e}")
            raise DecodeError('No data received - connection closed?')

    async def _receive(self):
        # make sure to use the parent's self.seqno and session key
        if self.parent:
            return await self.parent._receive()
        # message consists of header + retcode + [data] + crc (4 or 32) + footer
        min_len_55AA = struct.calcsize(H.MESSAGE_HEADER_FMT_55AA) + 4 + 4 + len(H.SUFFIX_BIN)
        # message consists of header + iv + retcode + [data] + crc (16) + footer
        min_len_6699 = struct.calcsize(H.MESSAGE_HEADER_FMT_6699) + 12 + 4 + 16 + len(H.SUFFIX_BIN)
        min_len = min(min_len_55AA, min_len_6699)

        data = await self._recv_all(min_len)

        # search for the prefix.  if not found, delete everything except
        # the last (prefix_len - 1) bytes and recv more to replace it
        prefix_offset_55AA = data.find(H.PREFIX_55AA_BIN)
        prefix_offset_6699 = data.find(H.PREFIX_6699_BIN)

        while prefix_offset_55AA != 0 and prefix_offset_6699 != 0:
            log.debug('Message prefix not at the beginning of the received data!')
            log.debug('Offset 55AA: %d, 6699: %d, Received data: %r', prefix_offset_55AA, prefix_offset_6699, data)
            if prefix_offset_55AA < 0 and prefix_offset_6699 < 0:
                data = data[1 - len(H.PREFIX_55AA_BIN):]
            else:
                prefix_offset = prefix_offset_6699 if prefix_offset_55AA < 0 else prefix_offset_55AA
                data = data[prefix_offset:]

            data += await self._recv_all(min_len - len(data))
            prefix_offset_55AA = data.find(H.PREFIX_55AA_BIN)
            prefix_offset_6699 = data.find(H.PREFIX_6699_BIN)

        header = parse_header(data)
        remaining = header.total_length - len(data)
        if remaining > 0:
            data += await self._recv_all(remaining)

        log.debug("received data=%r", binascii.hexlify(data))
        hmac_key = self.local_key if self.version >= 3.4 else None
        no_retcode = False #None if self.version >= 3.5 else False
        return unpack_message(data, header=header, hmac_key=hmac_key, no_retcode=no_retcode)

    # similar to _send_receive() but never retries sending and does not decode the response
    async def _send_receive_quick(self, payload, recv_retries, from_child=None):
        if self.parent:
            return await self.parent._send_receive_quick(payload, recv_retries, from_child=self)

        log.debug("sending payload quick")
        self.raw_sent = None
        self.raw_recv = []
        self.cmd_retcode = None
        if await self._ensure_connection():
            return None
        enc_payload = self._encode_message(payload) if isinstance(payload, MessagePayload) else payload
        try:
            self.writer.write(enc_payload)
            await self.writer.drain()
        except Exception:
            await self._check_socket_close(True)
            return None
        try:
            self.raw_sent = parse_header(enc_payload)
        except:
            self.raw_sent = None
        if not recv_retries:
            return True
        while recv_retries:
            try:
                msg = await self._receive()
                self.raw_recv.append(msg)
            except Exception:
                msg = None
            if msg:
                self._get_retcode(self.raw_sent, msg) # set self.cmd_retcode
                if len(msg.payload) != 0:
                    return msg
            recv_retries -= 1
            if recv_retries == 0:
                log.debug("received null payload (%r) but out of recv retries, giving up", msg)
            else:
                log.debug("received null payload (%r), fetch new one - %s retries remaining", msg, recv_retries)
        return False

    async def _send_receive(self, payload, minresponse=28, getresponse=True, decode_response=True, from_child=None):
        """
        Send single buffer `payload` and receive a single buffer.

        Args:
            payload(bytes): Data to send. Set to 'None' to receive only.
            minresponse(int): Minimum response size expected (default=28 bytes)
            getresponse(bool): If True, wait for and return response.
        """
        if self.parent:
            return await self.parent._send_receive(payload, minresponse, getresponse, decode_response, from_child=self)

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
        max_recv_retries = 0 if not self.retry else self.socketRetryLimit
        dev_type = self.dev_type
        do_send = True
        msg = None
        self.raw_recv = []
        self.cmd_retcode = None
        while not success:
            # open up socket if device is available
            sock_error = await self._ensure_connection()
            if sock_error:
                await self._check_socket_close(True)
                return error_json(sock_error)
            # send request to device
            try:
                if payload is not None and do_send:
                    log.debug("sending payload")
                    enc_payload = self._encode_message(payload) if isinstance(payload, MessagePayload) else payload
                    self.writer.write(enc_payload)
                    await self.writer.drain()
                    try:
                        self.raw_sent = parse_header(enc_payload)
                    except:
                        self.raw_sent = None
                    if self.sendWait is not None:
                        await asyncio.sleep(self.sendWait)
                if getresponse:
                    do_send = False
                    rmsg = await self._receive()
                    # device may send null ack (28 byte) response before a full response
                    # consider it an ACK and do not retry the send even if we do not get a full response
                    if rmsg:
                        payload = None
                        partial_success = True
                        msg = rmsg
                        self.raw_recv.append(rmsg)
                        self._get_retcode(self.raw_sent, rmsg) # set self.cmd_retcode
                        if len(msg.payload) == 0:
                            for cb in self._callbacks_response:
                                await cb( self, msg )
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
                    await self._check_socket_close()
                    return None
            except (KeyboardInterrupt, SystemExit) as err:
                log.debug("Keyboard Interrupt - Exiting")
                raise
            except (asyncio.TimeoutError, socket.timeout):
                # a socket timeout occurred
                if payload is None:
                    # Receive only mode - return None
                    await self._check_socket_close()
                    return None
                do_send = True
                retries += 1
                # toss old socket and get new one
                await self._check_socket_close(True)
                log.debug(f"Timeout in _send_receive() - retry {retries}/{self.socketRetryLimit}")
                # if we exceed the limit of retries then lets get out of here
                if retries > self.socketRetryLimit:
                    return error_json(ERR_KEY_OR_VER)
                # wait a bit before retrying
                await asyncio.sleep(0.1)
            except DecodeError:
                log.debug("Error decoding received data - retry", exc_info=True)
                recv_retries += 1
                if recv_retries > max_recv_retries:
                    # we recieved at least 1 valid message with a null payload, so the send was successful
                    if partial_success:
                        await self._check_socket_close()
                        return None
                    # no valid messages received
                    await self._check_socket_close(True)
                    return error_json(ERR_PAYLOAD)
            except Exception as err:
                # likely network or connection error
                do_send = True
                retries += 1
                # toss old socket and get new one
                await self._check_socket_close(True)
                log.debug(f"Network connection error - retry {retries}/{self.socketRetryLimit}", exc_info=True)
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
                await asyncio.sleep(0.1)
            # except
        # while

        # could be None or have a null payload
        if not decode_response:
            await self._check_socket_close()
            return msg

        return await self._process_message(msg, dev_type, from_child, minresponse, decode_response)

    async def _process_message( self, msg, dev_type=None, from_child=None, minresponse=28, decode_response=True ):
        # null packet, nothing to decode
        if not msg or len(msg.payload) == 0:
            log.debug("raw unpacked message = %r", msg)
            # legacy/default mode avoids persisting socket across commands
            await self._check_socket_close()
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
                        await found_child._handle_response(result, msg)
                        result = found_child._process_response(result)
                    else:
                        await self._handle_response(result, msg)
                        result = self._process_response(result)
                    self.received_wrong_cid_queue.append( (found_child, result) )
                # events should not be coming in so fast that we will never timeout a read, so don't worry about loops
                return await self._send_receive( None, minresponse, True, decode_response, from_child=from_child)

        # legacy/default mode avoids persisting socket across commands
        await self._check_socket_close()

        if found_child:
            await found_child._handle_response(result, msg)
            return found_child._process_response(result)

        await self._handle_response(result, msg)
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

        if payload.startswith(H.PROTOCOL_VERSION_BYTES_31):
            # Received an encrypted payload
            # Remove version header
            payload = payload[len(H.PROTOCOL_VERSION_BYTES_31) :]
            # Decrypt payload
            # Remove 16-bytes of MD5 hexdigest of payload
            payload = cipher.decrypt(payload[16:], decode_text=False)
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
                    payload = cipher.decrypt(payload, False, decode_text=False)
                except:
                    log.debug("incomplete payload=%r (len:%d)", payload, len(payload), exc_info=True)
                    return error_json(ERR_PAYLOAD)

                log.debug("decrypted 3.x payload=%r", payload)
                # Try to detect if device22 found
                log.debug("payload type = %s", type(payload))

            if isinstance(payload, str):
                payload = payload.encode('utf-8')

            if not self.disabledetect and b"data unvalid" in payload and self.version in (3.3, 3.4):
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

        invalid_json = None
        if not isinstance(payload, str):
            try:
                payload = payload.decode()
            except UnicodeDecodeError:
                if (payload[:1] == b'{') and (payload[-1:] == b'}'):
                    try:
                        invalid_json = payload
                        payload = payload.decode( errors='replace' )
                    except:
                        pass
            except:
                pass

            # if .decode() threw an exception, `payload` will still be bytes
            if not isinstance(payload, str):
                log.debug("payload was not string type and decoding failed")
                return error_json(ERR_JSON, payload)

        log.debug("decoded results=%r", payload)
        try:
            json_payload = json.loads(payload)
        except:
            json_payload = error_json(ERR_JSON, payload)
            json_payload['invalid_json'] = payload

        if invalid_json and isinstance(json_payload, dict):
            # give it to the user so they can try to decode it if they want
            json_payload['invalid_json'] = invalid_json

        # v3.4 stuffs it into {"data":{"dps":{"1":true}}, ...}
        if "dps" not in json_payload and "data" in json_payload and "dps" in json_payload['data']:
            json_payload['dps'] = json_payload['data']['dps']

        return json_payload

    async def _handle_response(self, response, raw_msg ):
        """
        Cache the last DP values and kick off the data callbacks
        """

        # Save (cache) the last value of every DP
        merge_dps_results(self._historic_status, response)

        for cb in self._callbacks_data:
            await cb( self, response, raw_msg )

        if (not self.socketPersistent) or (not self.writer):
            return

        log.debug('caching: %s', response)
        merge_dps_results(self._last_status, response)
        log.debug('merged: %s', self._last_status)

    def _process_response(self, response): # pylint: disable=R0201
        """
        Override this function in a sub-class if you want to do some processing on the received data
        """
        return response

    async def _negotiate_session_key(self):
        rkey = await self._send_receive_quick( self._negotiate_session_key_generate_step_1(), 2 )
        step3 = self._negotiate_session_key_generate_step_3( rkey )
        if not step3:
            return False
        await self._send_receive_quick( step3, None )
        self._negotiate_session_key_generate_finalize()
        return True

    def _negotiate_session_key_generate_step_1( self ):
        self.local_nonce = b'0123456789abcdef' # not-so-random random key
        self.remote_nonce = b''
        self.local_key = self.real_local_key

        return MessagePayload(CT.SESS_KEY_NEG_START, self.local_nonce)

    def _negotiate_session_key_generate_step_3( self, rkey ):
        if not rkey or type(rkey) != TuyaMessage or len(rkey.payload) < 48:
            # error
            log.debug("session key negotiation failed on step 1")
            return False

        if rkey.cmd != CT.SESS_KEY_NEG_RESP:
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
        return MessagePayload(CT.SESS_KEY_NEG_FINISH, rkey_hmac)

    def _negotiate_session_key_generate_finalize( self ):
        # Python 3: nonce XOR produces bytes object directly
        self.local_key = bytes(a ^ b for (a, b) in zip(self.local_nonce, self.remote_nonce))
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
            if msg.cmd not in H.NO_PROTOCOL_HEADER_CMDS:
                # add the 3.x header
                payload = self.version_header + payload
            log.debug('final payload: %r', payload)

            if self.version >= 3.5:
                iv = True
                # seqno cmd retcode payload crc crc_good, prefix, iv
                msg = TuyaMessage(self.seqno, msg.cmd, None, payload, 0, True, H.PREFIX_6699_VALUE, True)
                self.seqno += 1  # increase message sequence number
                data = pack_message(msg,hmac_key=self.local_key)
                log.debug("payload [%d] encrypted=%r",self.seqno, binascii.hexlify(data) )
                return data

            payload = self.cipher.encrypt(payload, False)
        elif self.version >= 3.2:
            # expect to connect and then disconnect to set new
            payload = self.cipher.encrypt(payload, False)
            if msg.cmd not in H.NO_PROTOCOL_HEADER_CMDS:
                # add the 3.x header
                payload = self.version_header + payload
        elif msg.cmd == CT.CONTROL:
            # need to encrypt
            payload = self.cipher.encrypt(payload)
            preMd5String = (
                b"data="
                + payload
                + b"||lpv="
                + H.PROTOCOL_VERSION_BYTES_31
                + b"||"
                + self.local_key
            )
            m = md5()
            m.update(preMd5String)
            hexdigest = m.hexdigest()
            # some tuya libraries strip 8: to :24
            payload = (
                H.PROTOCOL_VERSION_BYTES_31
                + hexdigest[8:][:16].encode("latin1")
                + payload
            )

        self.cipher = None
        msg = TuyaMessage(self.seqno, msg.cmd, 0, payload, 0, True, H.PREFIX_55AA_VALUE, False)
        self.seqno += 1  # increase message sequence number
        buffer = pack_message(msg,hmac_key=hmac_key)
        log.debug("payload encrypted=%r",binascii.hexlify(buffer))
        return buffer

    def _get_retcode(self, sent, msg):
        """Try to get the retcode for the last sent message"""
        if (not sent) or (not msg):
            return
        if sent.cmd != msg.cmd:
            return
        if self.version < 3.5:
            # v3.5 devices respond with a global incrementing seqno, not the sent seqno
            if sent.seqno != msg.seqno:
                return
        self.cmd_retcode = msg.retcode

    def _register_child(self, child):
        if child.id in self.children and child != self.children[child.id]:
            log.debug('Replacing existing child %r!', child.id)
        self.children[child.id] = child
        # disable device22 detection as some gateways return "json obj data unvalid" when the gateway is polled without a cid
        self.disabledetect = True
        self.payload_dict = None

    async def receive(self):
        """
        Poll device to read any payload in the buffer.  Timeout results in None returned.
        """
        return await self._send_receive(None)

    async def send(self, payload):
        """
        Send single buffer `payload`.

        Args:
            payload(bytes): Data to send.
        """
        return await self._send_receive(payload, 0, getresponse=False)

    async def status(self, nowait=False):
        """Return device status."""
        query_type = CT.DP_QUERY
        log.debug("status() entry (dev_type is %s)", self.dev_type)
        payload = self.generate_payload(query_type)

        data = await self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("status() received data=%r", data)
        if (not nowait) and data and "Err" in data:
            if data["Err"] == str(ERR_DEVTYPE):
                log.debug("status() rebuilding payload for device22")
                payload = self.generate_payload(query_type)
                data = await self._send_receive(payload)
            elif data["Err"] == str(ERR_PAYLOAD):
                log.debug("Status request error, check version %r and key %r", self.version, self.local_key)
        return data

    async def cached_status(self, historic=False, nowait=False):
        """
        Return device last status if a persistent connection is open.

        Args:
            nowait(bool): If cached status is is not available, either call status() (when nowait=False) or immediately return None (when nowait=True)

        Response:
            json if cache is available, else
                json from status() if nowait=False, or
                None if nowait=True
        """
        if historic:
            return self._historic_status
        if (not self._have_status) or (not self.socketPersistent) or (not self.writer) or (not self._last_status):
            if not nowait:
                log.debug("Cache not available, requesting status from device")
                return await self.status()
            log.debug("Cache not available, returning None")
            return None
        return self._last_status

    def cache_clear(self):
        self._last_status = {}
        self._have_status = False

    async def subdev_query(self, nowait=False):
        """Query for a list of sub-devices and their status"""
        # final payload should look like: {"data":{"cids":[]},"reqType":"subdev_online_stat_query"}
        payload = self.generate_payload(CT.LAN_EXT_STREAM, rawData={"cids":[]}, reqType='subdev_online_stat_query')
        return await self._send_receive(payload, 0, getresponse=(not nowait))

    async def detect_available_dps(self):
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
                data = await self.status()
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

    def set_version(self, version):
        return self._set_version(version)

    def _set_version(self, version):
        # FIXME rework the await self.detect_available_dps() below
        version = float(version)
        self.version = version
        self.version_str = "v" + str(version)
        self.version_bytes = str(version).encode('latin1')
        self.version_header = self.version_bytes + H.PROTOCOL_3x_HEADER
        self.payload_dict = None
        if version == 3.2: # 3.2 behaves like 3.3 with device22
            self.dev_type="device22"
            if self.dps_to_request == {}:
                self.detect_available_dps()

    def set_socketPersistent(self, persist):
        self.socketPersistent = persist
        if not persist:
            self.close()
            self.cache_clear()

    def set_socketNODELAY(self, nodelay):
        self.socketNODELAY = nodelay
        sock = self.writer.get_extra_info('socket')
        if sock:
            if nodelay:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            else:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

    def set_socketRetryLimit(self, limit):
        self.socketRetryLimit = limit

    def set_socketRetryDelay(self, delay):
        self.socketRetryDelay = delay

    def set_socketTimeout(self, s):
        self.connection_timeout = s

    def set_dpsUsed(self, dps_to_request):
        self.dps_to_request = dps_to_request

    def set_retry(self, retry):
        self.retry = retry

    def set_sendWait(self, s):
        self.sendWait = s

    async def close(self):
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                log.debug(f"Error closing writer: {e}")
        self.writer = None
        self.reader = None
        self.cache_clear()

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
        # as dict2 is CT.payload_dict['...'] we only need to worry about copying 2 levels deep,
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
            _merge_payload_dicts( self.payload_dict, CT.payload_dict['default'] )
            if self.children:
                _merge_payload_dicts( self.payload_dict, CT.payload_dict['gateway'] )
            if self.cid:
                _merge_payload_dicts( self.payload_dict, CT.payload_dict['zigbee'] )
            if self.version_str in CT.payload_dict:
                _merge_payload_dicts( self.payload_dict, CT.payload_dict[self.version_str] )
            if self.children and ('gateway_'+self.version_str) in CT.payload_dict:
                _merge_payload_dicts( self.payload_dict, CT.payload_dict['gateway_'+self.version_str] )
            if self.cid and ('zigbee_'+self.version_str) in CT.payload_dict:
                _merge_payload_dicts( self.payload_dict, CT.payload_dict['zigbee_'+self.version_str] )
            if self.dev_type != 'default':
                _merge_payload_dicts( self.payload_dict, CT.payload_dict[self.dev_type] )
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

        if command == CT.DP_QUERY or command == CT.DP_QUERY_NEW:
            self._have_status = True

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
        elif self.dev_type == "device22" and command == CT.DP_QUERY:
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


    def register_connect_handler( self, cb ):
        if cb not in self._callbacks_connect:
            self._callbacks_connect.append( cb )

    def register_response_handler( self, cb ):
        if cb not in self._callbacks_response:
            self._callbacks_response.append( cb )

    def register_data_handler( self, cb ):
        if cb not in self._callbacks_data:
            self._callbacks_data.append( cb )

    def register_scanner( self, scanner ):
        self._scanner = scanner

    #
    # The following methods are taken from the v1 Device class and modified to be async-compatible.
    #
    async def set_status(self, on, switch=1, nowait=False):
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
        payload = self.generate_payload(CT.CONTROL, {switch: on})

        data = await self._send_receive(payload, getresponse=(not nowait))
        log.debug("set_status received data=%r", data)

        return data

    async def product(self):
        """
        Request AP_CONFIG Product Info from device. [BETA]

        """
        # open device, send request, then close connection
        payload = self.generate_payload(CT.AP_CONFIG)
        data = await self._send_receive(payload, 0)
        log.debug("product received data=%r", data)
        return data

    async def heartbeat(self, nowait=True):
        """
        Send a keep-alive HEART_BEAT command to keep the TCP connection open.

        Devices only send an empty-payload response, so no need to wait for it.

        Args:
            nowait(bool): True to send without waiting for response.
        """
        # open device, send request, then close connection
        payload = self.generate_payload(CT.HEART_BEAT)
        data = await self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("heartbeat received data=%r", data)
        return data

    async def updatedps(self, index=None, nowait=False):
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
        payload = self.generate_payload(CT.UPDATEDPS, index)
        data = await self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("updatedps received data=%r", data)
        return data

    async def set_value(self, index, value, nowait=False):
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

        payload = self.generate_payload(CT.CONTROL, {index: value})

        data = await self._send_receive(payload, getresponse=(not nowait))

        return data

    async def set_multiple_values(self, data, nowait=False):
        """
        Set multiple indexes at the same time

        Args:
            data(dict): array of index/value pairs to set
            nowait(bool): True to send without waiting for response.
        """
        # if nowait is set we can't detect failure
        if nowait:
            if self.max_simultaneous_dps > 0 and len(data) > self.max_simultaneous_dps:
                # too many DPs, break it up into smaller chunks
                ret = None
                for k in data:
                    ret = await self.set_value(k, data[k], nowait=nowait)
                return ret
            else:
                # send them all. since nowait is set we can't detect failure
                out = {}
                for k in data:
                    out[str(k)] = data[k]
                payload = self.generate_payload(CT.CONTROL, out)
                return await self._send_receive(payload, getresponse=(not nowait))

        if self.max_simultaneous_dps > 0 and len(data) > self.max_simultaneous_dps:
            # too many DPs, break it up into smaller chunks
            ret = {}
            for k in data:
                if (not nowait) and bool(ret):
                    await asyncio.sleep(1)
                result = await self.set_value(k, data[k], nowait=nowait)
                merge_dps_results(ret, result)
            return ret

        # send them all, but try to detect devices which cannot handle multiple
        out = {}
        for k in data:
            out[str(k)] = data[k]

        payload = self.generate_payload(CT.CONTROL, out)
        result = await self._send_receive(payload, getresponse=(not nowait))

        if result and 'Err' in result and len(out) > 1:
            # sending failed! device might only be able to handle 1 DP at a time
            first_dp = next(iter( out ))
            res = await self.set_value(first_dp, out[first_dp], nowait=nowait)
            del out[first_dp]
            if res and 'Err' not in res:
                # single DP succeeded! set limit to 1
                self.max_simultaneous_dps = 1
                result = res
                for k in out:
                    res = await self.set_value(k, out[k], nowait=nowait)
                    merge_dps_results(result, res)
        return result

    async def turn_on(self, switch=1, nowait=False):
        """Turn the device on"""
        return await self.set_status(True, switch, nowait)

    async def turn_off(self, switch=1, nowait=False):
        """Turn the device off"""
        return await self.set_status(False, switch, nowait)

    async def set_timer(self, num_secs, dps_id=0, nowait=False):
        """
        Set a timer.

        Args:
            num_secs(int): Number of seconds
            dps_id(int): DPS Index for Timer
            nowait(bool): True to send without waiting for response.
        """

        # Query status, pick last device id as that is probably the timer
        if dps_id == 0:
            status = await self.status()
            if "dps" in status:
                devices = status["dps"]
                devices_numbers = list(devices.keys())
                devices_numbers.sort()
                dps_id = devices_numbers[-1]
            else:
                log.debug("set_timer received error=%r", status)
                return status

        payload = self.generate_payload(CT.CONTROL, {dps_id: num_secs})

        data = await self._send_receive(payload, getresponse=(not nowait))
        log.debug("set_timer received data=%r", data)
        return data
