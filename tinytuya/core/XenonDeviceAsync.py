# TinyTuya Module
# -*- coding: utf-8 -*-

import asyncio
from .XenonDevice import *

async def find_device_async(dev_id=None, address=None):
    return await asyncio.to_thread(find_device, dev_id, address)

async def device_info_async(dev_id):
    return await asyncio.to_thread(device_info, dev_id)

class XenonDeviceAsync(XenonDevice):
    def __init__(
            self, dev_id, address=None, local_key="", dev_type="default", connection_timeout=5,
            version=3.1, persist=False, cid=None, node_id=None, parent=None,
            connection_retry_limit=5, connection_retry_delay=5, port=TCPPORT,
            max_simultaneous_dps=0
    ):
        self.id = dev_id
        self.cid = cid if cid else node_id
        self.address = address
        self.auto_ip = (not address) or address == "Auto" or address == "0.0.0.0"
        self.dev_type = dev_type
        self.dev_type_auto = self.dev_type == 'default'
        self.last_dev_type = ''
        self.connection_timeout = connection_timeout
        self.retry = True
        self.disabledetect = False
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
        self.local_nonce = b'0123456789abcdef'
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
        self.queue_lock = asyncio.Lock()
        self._initialized = False
        self.version = version

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
            self.set_version(self.parent.version)
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
                self.set_version(float(self.version))
            else:
                self.set_version(3.1)

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

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

    def __del__(self):
        pass

    async def _ensure_connection(self, renew=False):
        if renew and self.writer:
            await self.close()

        if not self.writer:
            retries = 0
            err = ERR_OFFLINE
            while retries < self.socketRetryLimit:
                if self.auto_ip and not self.address:
                    bcast_data = await find_device_async(self.id)
                    if bcast_data['ip'] is None:
                        log.debug("Unable to find device on network (specify IP address)")
                        return ERR_OFFLINE
                    self.address = bcast_data['ip']
                    self.set_version(float(bcast_data['version']))

                if not self.address:
                    log.debug("No address for device!")
                    return ERR_OFFLINE

                if (self.version > 3.1) and ((not self.local_key) or (len(self.local_key) != 16)):
                    log.debug("No/bad local key for device!")
                    return ERR_KEY_OR_VER

                try:
                    retries += 1
                    fut = asyncio.open_connection(self.address, self.port)
                    self.reader, self.writer = await asyncio.wait_for(fut, timeout=self.connection_timeout)

                    # TCP_NODELAY
                    sock = self.writer.get_extra_info('socket')
                    if sock and self.socketNODELAY:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                    if self.version >= 3.4:
                        if await self._negotiate_session_key():
                            return True
                        else:
                            await self.close()
                            return ERR_KEY_OR_VER
                    else:
                        return True
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
            return err
        return True

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
        if await self._ensure_connection() is not True:
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

        async with self.queue_lock:
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
            sock_result = await self._ensure_connection()
            if sock_result is not True:
                await self._check_socket_close(True)
                return error_json(sock_result if sock_result else ERR_OFFLINE)
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
                        found_child._cache_response(result)
                        result = found_child._process_response(result)
                    else:
                        self._cache_response(result)
                        result = self._process_response(result)
                    async with self.queue_lock:
                        self.received_wrong_cid_queue.append( (found_child, result) )
                # events should not be coming in so fast that we will never timeout a read, so don't worry about loops
                return await self._send_receive( None, minresponse, True, decode_response, from_child=from_child)

        # legacy/default mode avoids persisting socket across commands
        await self._check_socket_close()

        if found_child:
            found_child._cache_response(result)
            return found_child._process_response(result)

        self._cache_response(result)
        return self._process_response(result)

    async def receive(self):
        return await self._send_receive(None)

    async def send(self, payload):
        return await self._send_receive(payload, 0, getresponse=False)

    async def status(self, nowait=False):
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
        if historic:
            return self._historic_status
        if (not self._have_status) or (not self.socketPersistent) or (not self.writer) or (not self._last_status):
            if not nowait:
                log.debug("Cache not available, requesting status from device")
                return await self.status()
            log.debug("Cache not available, returning None")
            return None
        return self._last_status

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

    async def _negotiate_session_key(self):
        rkey = await self._send_receive_quick( self._negotiate_session_key_generate_step_1(), 2 )
        step3 = self._negotiate_session_key_generate_step_3( rkey )
        if not step3:
            return False
        await self._send_receive_quick( step3, None )
        self._negotiate_session_key_generate_finalize()
        return True

    def _cache_response(self, response):
        """
        Save (cache) the last value of every DP
        """
        merge_dps_results(self._historic_status, response)

        if (not self.socketPersistent) or (not self.writer):
            return

        log.debug('caching: %s', response)
        merge_dps_results(self._last_status, response)
        log.debug('merged: %s', self._last_status)
