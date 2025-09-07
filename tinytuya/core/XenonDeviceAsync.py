# TinyTuya Module - XenonDeviceAsync (Async-First Implementation)
# -*- coding: utf-8 -*-

import asyncio
import binascii
import hmac
import json
import logging
import socket
import struct
import time
import sys
from hashlib import md5, sha256

from .const import DEVICEFILE, TCPPORT
from .crypto_helper import AESCipher
from .error_helper import ERR_CONNECT, ERR_DEVTYPE, ERR_JSON, ERR_KEY_OR_VER, ERR_OFFLINE, ERR_PAYLOAD, error_json
from .exceptions import DecodeError
from .message_helper import MessagePayload, TuyaMessage, pack_message, parse_header, unpack_message
from . import command_types as CT, header as H

# Utility functions
def merge_dps_results(dest, src):
    """Merge multiple receive() responses into a single dict

    `src` will be combined with and merged into `dest`
    """
    if src and isinstance(src, dict) and 'Error' not in src and 'Err' not in src:
        for k in src:
            if k == 'dps' and src[k] and isinstance(src[k], dict):
                if 'dps' not in dest or not isinstance(dest['dps'], dict):
                    dest['dps'] = {}
                for dkey in src[k]:
                    dest['dps'][dkey] = src[k][dkey]
            elif k == 'data' and src[k] and isinstance(src[k], dict) and 'dps' in src[k] and isinstance(src[k]['dps'], dict):
                if k not in dest or not isinstance(dest[k], dict):
                    dest[k] = {'dps': {}}
                if 'dps' not in dest[k] or not isinstance(dest[k]['dps'], dict):
                    dest[k]['dps'] = {}
                for dkey in src[k]['dps']:
                    dest[k]['dps'][dkey] = src[k]['dps'][dkey]
            else:
                dest[k] = src[k]

# Tuya Device Dictionary - Command and Payload Overrides
payload_dict = {
    # Default Device
    "default": {
        CT.AP_CONFIG: {  # [BETA] Set Control Values on Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CT.CONTROL: {  # Set Control Values on Device
            "command": {"devId": "", "uid": "", "t": ""},
        },
        CT.STATUS: {  # Get Status from Device
            "command": {"gwId": "", "devId": ""},
        },
        CT.HEART_BEAT: {"command": {"gwId": "", "devId": ""}},
        CT.DP_QUERY: {  # Get Data Points from Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CT.CONTROL_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        CT.DP_QUERY_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        CT.UPDATEDPS: {"command": {"dpId": [18, 19, 20]}},
        CT.LAN_EXT_STREAM: { "command": { "reqType": "", "data": {} }},
    },
    # Special Case Device with 22 character ID
    "device22": {
        CT.DP_QUERY: {  # Get Data Points from Device
            "command_override": CT.CONTROL_NEW,  # Uses CONTROL_NEW command for some reason
            "command": {"devId": "", "uid": "", "t": ""},
        },
    },
    # Gateway device commands (placeholder)
    "gateway": { },
    "gateway_v3.4": { },
    "gateway_v3.5": { },
    # Zigbee sub-device commands
    "zigbee": {
        CT.CONTROL: {"command": {"t": "int", "cid": ""}},
        CT.DP_QUERY: {"command": {"t": "int", "cid": ""}},
    },
    "zigbee_v3.4": {
        CT.CONTROL: {
            "command_override": CT.CONTROL_NEW,
            "command": {"t": "int", "cid": ""}
        },
    },
}

log = logging.getLogger(__name__)

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

# Helper functions - these can remain sync since they don't do I/O
def find_device(dev_id=None, address=None):
    """Scans network for Tuya devices with either ID = dev_id or IP = address"""
    if dev_id is None and address is None:
        return {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}

    from .. import scanner

    want_ids = (dev_id,) if dev_id else None
    want_ips = (address,) if address else None
    all_results = scanner.devices(verbose=False, poll=False, forcescan=False, byID=True, wantids=want_ids, wantips=want_ips)
    ret = None

    for gwId in all_results:
        if dev_id and gwId != dev_id:
            continue
        if address and address != all_results[gwId]['ip']:
            continue

        result = all_results[gwId]
        product_id = '' if 'productKey' not in result else result['productKey']
        ret = {'ip':result['ip'], 'version':result['version'], 'id':gwId, 'product_id':product_id, 'data':result}
        break

    if ret is None:
        ret = {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}
    log.debug( 'find() is returning: %r', ret )
    return ret

def device_info(dev_id):
    """Searches the devices.json file for devices with ID = dev_id"""
    devinfo = None
    try:
        with open(DEVICEFILE, 'r') as f:
            tuyadevices = json.load(f)
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
            for dev in tuyadevices:
                if 'id' in dev and dev['id'] == dev_id:
                    log.debug("Device %r found in %s", dev_id, DEVICEFILE)
                    devinfo = dev
                    break
    except:
        pass
    return devinfo

# Async helper functions
async def find_device_async(dev_id=None, address=None):
    return await asyncio.to_thread(find_device, dev_id, address)

async def device_info_async(dev_id):
    return await asyncio.to_thread(device_info, dev_id)


class XenonDeviceAsync(object):
    """
    Async-first implementation containing ALL device communication logic.
    
    This class contains the complete implementation that was previously
    split between XenonDevice (sync) and XenonDeviceAsync (async wrapper).
    
    All device communication, protocol handling, and state management
    happens here using async/await patterns.
    """
    
    def __init__(
        self, dev_id, address=None, local_key="", dev_type="default", 
        connection_timeout=5, version=3.1, persist=False, cid=None, 
        node_id=None, parent=None, connection_retry_limit=5, 
        connection_retry_delay=5, port=TCPPORT, max_simultaneous_dps=0
    ):
        # Device identification
        self.id = dev_id
        self.cid = cid if cid else node_id
        self.address = address
        self.auto_ip = (not address) or address == "Auto" or address == "0.0.0.0"
        
        # Device configuration
        self.dev_type = dev_type
        self.dev_type_auto = self.dev_type == 'default'
        self.last_dev_type = ''
        self.connection_timeout = connection_timeout
        self.retry = True
        self.disabledetect = False
        self.port = port
        
        # Socket configuration
        self.socketPersistent = persist
        self.socketNODELAY = True
        self.socketRetryLimit = connection_retry_limit
        self.socketRetryDelay = connection_retry_delay
        
        # Protocol state
        self.seqno = 1
        self.sendWait = 0.01
        self.version = float(version or 3.1)
        self.version_str = "v" + str(self.version)
        self.version_bytes = str(self.version).encode('latin1')
        self.version_header = self.version_bytes + H.PROTOCOL_3x_HEADER
        self.dps_cache = {}
        self.max_simultaneous_dps = max_simultaneous_dps if max_simultaneous_dps else 0
        
        # Device relationships
        self.parent = parent
        self.children = {}
        self.received_wrong_cid_queue = []
        
        # Cryptographic state
        self.local_nonce = b'0123456789abcdef'
        self.remote_nonce = b''
        self.cipher = None
        self.local_key = local_key.encode("latin1") if isinstance(local_key, str) else local_key
        self.real_local_key = self.local_key
        
        # Device state caching
        self._historic_status = {}
        self._last_status = {}
        self._have_status = False
        self.payload_dict = None
        
        # Communication state
        self.raw_sent = None
        self.raw_recv = []
        self.cmd_retcode = None
        self.dps_to_request = {"1": None}  # Default DPS to request
        
        # Async-specific attributes
        self.reader = None
        self.writer = None
        self._initialized = False
        
        # Initialize payload dictionary based on device type
        self._initialize_payload_dict()

    def _initialize_payload_dict(self):
        """Initialize the payload dictionary based on device type"""
        payload_dict_by_type = {
            "device22": {
                CT.DP_QUERY: {'gwId': '', 'devId': '', 'uid': '', 't': ''},
                CT.CONTROL: {'devId': '', 'uid': '', 't': ''},
                CT.STATUS: {'gwId': '', 'devId': ''},
                CT.HEART_BEAT: {'gwId': '', 'devId': ''},
                CT.UPDATEDPS: {"dpId": [18, 19, 20]},
                CT.AP_CONFIG: {'gwId': '', 'devId': '', 'uid': '', 't': ''},
            },
            "zigbee": {
                CT.CONTROL: {'cid': '', 't': ''},
                CT.STATUS: {'cid': ''},
            }
        }

        if self.dev_type in payload_dict_by_type:
            self.payload_dict = payload_dict_by_type[self.dev_type].copy()
        else:
            self.payload_dict = {}

    def __del__(self):
        """Cleanup when object is destroyed"""
        # Python handles most cleanup automatically for async objects
        # More complex cleanup would be handled in close() methods

    def __repr__(self):
        """String representation of the device"""
        items = []
        items.append('id=' + repr(self.id))
        if hasattr(self, 'address'):
            items.append('address=' + repr(self.address))
        if hasattr(self, 'local_key'):
            items.append('local_key=' + repr(self.local_key))
        if hasattr(self, 'version'):
            items.append('version=' + repr(self.version))
        return '%s(%s)' % (self.__class__.__name__, ', '.join(items))

    @classmethod
    async def create(cls, *args, **kwargs):
        """Async factory method to create and initialize a device"""
        device = cls(*args, **kwargs)
        await device.initialize()
        return device

    async def initialize(self):
        """Initialize the device asynchronously"""
        if self._initialized:
            return
        self._initialized = True
        
        if self.parent:
            # Child device initialization
            if not self.cid:
                devinfo = await device_info_async(self.id)
                if devinfo and 'node_id' in devinfo and devinfo['node_id']:
                    self.cid = devinfo['node_id']
            if not self.cid:
                log.debug('Child device but no cid/node_id given!')
            self.set_version(self.parent.version)
            self.parent._register_child(self)
        else:
            # Parent device initialization
            if self.auto_ip:
                bcast_data = await find_device_async(self.id)
                if bcast_data['ip'] is None:
                    log.debug("Unable to find device on network (specify IP address)")
                    raise RuntimeError("Unable to find device on network (specify IP address)")
                self.address = bcast_data['ip']
                self.version = float(bcast_data['version'])
            
            if self.local_key == b"":
                devinfo = await device_info_async(self.id)
                if devinfo and 'key' in devinfo and devinfo['key']:
                    local_key = devinfo['key']
                    self.local_key = local_key.encode("latin1")
                    self.real_local_key = self.local_key
            
            if self.version:
                self.set_version(float(self.version))
            else:
                self.set_version(3.1)

    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def close(self):
        """Close the device connection and cleanup resources"""
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                log.debug("Error closing writer: %s", e)
        self.writer = None
        self.reader = None
        self.cache_clear()

    # ---- Connection Management ----
    
    async def _ensure_connection(self, renew=False):
        """Ensure device connection is established"""
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
                    log.debug("Connection timeout - retry %s/%s", retries, self.socketRetryLimit)
                    err = ERR_OFFLINE
                except Exception as e:
                    log.debug("Connection failed (exception) - retry %s/%s", retries, self.socketRetryLimit, exc_info=True)
                    err = ERR_CONNECT

                await self.close()
                if retries < self.socketRetryLimit:
                    await asyncio.sleep(self.socketRetryDelay)
                if self.auto_ip:
                    self.address = None
            return err
        return True

    async def _check_socket_close(self, force=False):
        """Check if socket should be closed"""
        if force or not self.socketPersistent:
            await self.close()

    # ---- Configuration Methods ----

    def set_version(self, version):
        """Set protocol version and update configuration"""
        self.version = version
        self.version_str = "v" + str(version)
        self.version_bytes = str(self.version).encode('latin1')
        self.version_header = self.version_bytes + H.PROTOCOL_3x_HEADER
        log.debug("set_version: %s", version)

        # Clear payload_dict and rebuild based on device type and version
        self.payload_dict = {}
        
        if self.dev_type_auto:
            if version == 3.2:
                self.dev_type = 'device22'
            else:
                self.dev_type = 'default'
        
        # Rebuild payload dict
        self._initialize_payload_dict()

        if version >= 3.2:
            self.cipher = AESCipher(self.local_key)

    def set_socketPersistent(self, persist):
        """Set socket persistence"""
        self.socketPersistent = persist
        if not persist:
            # Close connection if not persistent
            if hasattr(self, 'writer') and self.writer:
                asyncio.create_task(self.close())

    def set_socketNODELAY(self, nodelay):
        """Set TCP_NODELAY option"""
        self.socketNODELAY = nodelay
        if hasattr(self, 'writer') and self.writer:
            try:
                sock = self.writer.get_extra_info('socket')
                if sock:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if nodelay else 0)
            except Exception as e:
                log.debug("Error setting TCP_NODELAY: %s", e)

    def set_socketRetryLimit(self, limit):
        """Set socket retry limit"""
        self.socketRetryLimit = limit

    def set_socketRetryDelay(self, delay):
        """Set socket retry delay"""
        self.socketRetryDelay = delay

    def set_socketTimeout(self, timeout):
        """Set connection timeout"""
        self.connection_timeout = timeout

    def set_dpsUsed(self, dps_to_request):
        """Set DPS values to request"""
        self.dps_cache = dps_to_request

    def set_retry(self, retry):
        """Set retry flag"""
        self.retry = retry

    def set_sendWait(self, wait_time):
        """Set send wait time"""
        self.sendWait = wait_time

    def cache_clear(self):
        """Clear device status cache"""
        self._historic_status = {}
        self._last_status = {}
        self._have_status = False

    def add_dps_to_request(self, dp_indices):
        """Add DPS indices to request cache"""
        if dp_indices is None:
            return
        if not isinstance(dp_indices, list):
            dp_indices = [dp_indices]
        for dp in dp_indices:
            self.dps_cache[str(dp)] = None

    def _register_child(self, child):
        """Register a child device (for gateway devices)"""
        if child.cid:
            self.children[child.cid] = child
        if child.id:
            self.children[child.id] = child

    # ---- Status and Communication ----

    async def status(self, nowait=False):
        """Get device status"""
        query_type = CT.DP_QUERY
        log.debug("status() entry (dev_type is %s)", self.dev_type)
        payload = self.generate_payload(query_type)

        data = await self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("status() received data=%r", data)
        
        # Error handling
        if (not nowait) and data and "Err" in data:
            if data["Err"] == str(ERR_DEVTYPE):
                # Device22 detected and change - resend with new payload
                log.debug("status() rebuilding payload for device22")
                payload = self.generate_payload(query_type)
                data = await self._send_receive(payload)
            elif data["Err"] == str(ERR_PAYLOAD):
                log.debug("Status request returned an error, is version %r and local key %r correct?", self.version, self.local_key)

        return data

    async def cached_status(self, historic=False, nowait=False):
        """Get cached device status"""
        if historic:
            return self._historic_status
        if (not self._have_status) or (not self.socketPersistent) or (not self.writer) or (not self._last_status):
            if not nowait:
                log.debug("Cache not available, requesting status from device")
                return await self.status()
            log.debug("Cache not available, returning None")
            return None
        return self._last_status.copy()

    async def subdev_query(self, nowait=False):
        """Query sub-device status (for gateway devices)"""
        log.debug("subdev_query() entry (dev_type is %s)", self.dev_type)
        payload = self.generate_payload(CT.LAN_GW_ACTIVE)
        data = await self._send_receive(payload, 0, getresponse=(not nowait))
        log.debug("subdev_query received data=%r", data)
        return data

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
            sock_result = await self._get_socket_async(False)
            if sock_result is not True:
                # unable to get a socket - device likely offline
                await self._check_socket_close_async(True)
                return error_json(sock_result if sock_result else ERR_OFFLINE)
                
            # send request to device
            try:
                if payload is not None and do_send:
                    log.debug("sending payload")
                    enc_payload = self._encode_message(payload) if type(payload) == MessagePayload else payload
                    self.writer.write(enc_payload)
                    await self.writer.drain()
                    try:
                        self.raw_sent = parse_header(enc_payload)
                    except:
                        self.raw_sent = None
                    if self.sendWait is not None:
                        await asyncio.sleep(self.sendWait)  # give device time to respond
                        
                if getresponse:
                    do_send = False
                    rmsg = await self._receive_async()
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
                    await self._check_socket_close_async()
                    return None
                    
            except (KeyboardInterrupt, SystemExit) as err:
                log.debug("Keyboard Interrupt - Exiting")
                raise
            except asyncio.TimeoutError as err:
                # a socket timeout occurred
                if payload is None:
                    # Receive only mode - return None
                    await self._check_socket_close_async()
                    return None
                do_send = True
                retries += 1
                # toss old socket and get new one
                await self._check_socket_close_async(True)
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
                await asyncio.sleep(0.1)
            except DecodeError as err:
                log.debug("Error decoding received data - read retry %s/%s", recv_retries, max_recv_retries, exc_info=True)
                recv_retries += 1
                if recv_retries > max_recv_retries:
                    # we recieved at least 1 valid message with a null payload, so the send was successful
                    if partial_success:
                        await self._check_socket_close_async()
                        return None
                    # no valid messages received
                    await self._check_socket_close_async(True)
                    return error_json(ERR_PAYLOAD)
            except Exception as err:
                # likely network or connection error
                do_send = True
                retries += 1
                # toss old socket and get new one
                await self._check_socket_close_async(True)
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
                await asyncio.sleep(0.1)
            # except
        # while

        # could be None or have a null payload
        if not decode_response:
            # legacy/default mode avoids persisting socket across commands
            await self._check_socket_close_async()
            return msg

        return await self._process_message_async(msg, dev_type, from_child, minresponse, decode_response)

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
                if isinstance(dict1[k], dict):
                    result[k] = _deepcopy(dict1[k])
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
                    dict1[cmd] = _deepcopy(dict2[cmd])
                else:
                    for var in dict2[cmd]:
                        if not isinstance(dict2[cmd][var], dict):
                            # not a dict, safe to copy
                            dict1[cmd][var] = dict2[cmd][var]
                        else:
                            # make a deep copy so we don't get a reference
                            dict1[cmd][var] = _deepcopy(dict2[cmd][var])

        # start merging down to the final payload dict
        # later merges overwrite earlier merges
        # "default" - ("gateway" if gateway) - ("zigbee" if sub-device) - [version string] - ('gateway_'+[version string] if gateway) -
        #   'zigbee_'+[version string] if sub-device - [dev_type if not "default"]
        if not self.payload_dict or self.last_dev_type != self.dev_type:
            self.payload_dict = {}
            _merge_payload_dicts(self.payload_dict, payload_dict['default'])
            if self.children:
                _merge_payload_dicts(self.payload_dict, payload_dict['gateway'])
            if self.cid:
                _merge_payload_dicts(self.payload_dict, payload_dict['zigbee'])
            if self.version_str in payload_dict:
                _merge_payload_dicts(self.payload_dict, payload_dict[self.version_str])
            if self.children and ('gateway_'+self.version_str) in payload_dict:
                _merge_payload_dicts(self.payload_dict, payload_dict['gateway_'+self.version_str])
            if self.cid and ('zigbee_'+self.version_str) in payload_dict:
                _merge_payload_dicts(self.payload_dict, payload_dict['zigbee_'+self.version_str])
            if self.dev_type != 'default':
                _merge_payload_dicts(self.payload_dict, payload_dict[self.dev_type])
            log.debug('final payload_dict for %r (%r/%r): %r', self.id, self.version_str, self.dev_type, self.payload_dict)
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

    async def receive(self):
        """
        Poll device to read any payload in the buffer. Timeout results in None returned.
        
        Returns:
            dict: Decoded response data or None if timeout
        """
        return await self._send_receive(None)

    async def send(self, payload):
        """
        Send single buffer `payload`.

        Args:
            payload(bytes): Data to send.
            
        Returns:
            bool: True if send successful
        """
        result = await self._send_receive(payload, 0, getresponse=False)
        return result is not None

    # ---- Async Helper Methods ----
    
    async def _get_socket_async(self, renew):
        """Async version of _get_socket"""
        return await self._ensure_connection(renew)
    
    async def _check_socket_close_async(self, force=False):  # pylint: disable=W0613
        """Async version of _check_socket_close"""
        # Close connection cleanup
        if self.writer and not self.writer.is_closing():
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        self.writer = None
        self.reader = None
    
    async def _recv_all_async(self, length):
        """Async version of _recv_all"""
        tries = 2
        data = b''

        while length > 0:
            try:
                newdata = await self.reader.read(length)
            except Exception as e:
                log.debug("_recv_all_async(): exception %r", e)
                newdata = b''
                
            if not newdata or len(newdata) == 0:
                log.debug("_recv_all_async(): no data? %r", newdata)
                # connection closed?
                tries -= 1
                if tries == 0:
                    raise DecodeError('No data received - connection closed?')
                if self.sendWait is not None:
                    await asyncio.sleep(self.sendWait)
                continue
            data += newdata
            length -= len(newdata)
            tries = 2
        return data

    async def _receive_async(self):
        """Async version of _receive"""
        # make sure to use the parent's self.seqno and session key
        if self.parent:
            return await self.parent._receive_async()
            
        # message consists of header + retcode + [data] + crc (4 or 32) + footer
        min_len_55AA = struct.calcsize(H.MESSAGE_HEADER_FMT_55AA) + 4 + 4 + len(H.SUFFIX_BIN)
        # message consists of header + iv + retcode + [data] + crc (16) + footer
        min_len_6699 = struct.calcsize(H.MESSAGE_HEADER_FMT_6699) + 12 + 4 + 16 + len(H.SUFFIX_BIN)
        min_len = min_len_55AA if min_len_55AA < min_len_6699 else min_len_6699
        prefix_len = len( H.PREFIX_55AA_BIN )

        data = await self._recv_all_async( min_len )

        # search for the prefix.  if not found, delete everything except
        # the last (prefix_len - 1) bytes and recv more to replace it
        prefix_offset_55AA = data.find( H.PREFIX_55AA_BIN )
        prefix_offset_6699 = data.find( H.PREFIX_6699_BIN )

        while prefix_offset_55AA != 0 and prefix_offset_6699 != 0:
            log.debug('Message prefix not at the beginning of the received data!')
            log.debug('Offset 55AA: %d, 6699: %d, Received data: %r', prefix_offset_55AA, prefix_offset_6699, data)
            if prefix_offset_55AA < 0 and prefix_offset_6699 < 0:
                data = data[1-prefix_len:]
            else:
                prefix_offset = prefix_offset_6699 if prefix_offset_55AA < 0 else prefix_offset_55AA
                data = data[prefix_offset:]

            data += await self._recv_all_async( min_len - len(data) )
            prefix_offset_55AA = data.find( H.PREFIX_55AA_BIN )
            prefix_offset_6699 = data.find( H.PREFIX_6699_BIN )

        header = parse_header(data)
        remaining = header.total_length - len(data)
        if remaining > 0:
            data += await self._recv_all_async( remaining )

        log.debug("received data=%r", binascii.hexlify(data))
        hmac_key = self.local_key if self.version >= 3.4 else None
        no_retcode = False #None if self.version >= 3.5 else False
        return unpack_message(data, header=header, hmac_key=hmac_key, no_retcode=no_retcode)
    
    def _get_retcode(self, sent_msg, recv_msg):
        """Extract return code from messages (sync method)"""
        # This method doesn't need to be async as it's just data processing
        try:
            if sent_msg and recv_msg:
                self.cmd_retcode = recv_msg.retcode
        except:
            self.cmd_retcode = None
    
    def _encode_message(self, msg):
        """Encode message for transmission (sync method)"""
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
        buffer = pack_message(msg, hmac_key)
        log.debug("payload encrypted=%r", binascii.hexlify(buffer))

        return buffer
    
    async def _negotiate_session_key(self):
        """
        Negotiate session key for v3.4+ devices
        
        Returns:
            bool: True if negotiation successful, False otherwise
        """
        try:
            # Step 1: Send initial session key request
            step1 = self._negotiate_session_key_generate_step_1()
            enc_step1 = self._encode_message(step1)
            self.writer.write(enc_step1)
            await self.writer.drain()
            
            log.debug("Sent session key step 1")
            
            # Wait for response with timeout
            try:
                msg = await asyncio.wait_for(self._receive_async(), timeout=5.0)
            except asyncio.TimeoutError:
                log.debug("Session key step 1 response timeout")
                return False
                
            if not msg:
                log.debug("Empty session key response")
                return False
                
            log.debug("Received session key response: cmd=%s", msg.cmd)
            
            if msg.cmd == CT.SESS_KEY_NEG_RESP:
                log.debug("Processing session key step 2...")
                step3 = self._negotiate_session_key_generate_step_3(msg)
                if step3:
                    enc_step3 = self._encode_message(step3)
                    self.writer.write(enc_step3)
                    await self.writer.drain()
                    self._negotiate_session_key_generate_finalize()
                    log.debug("Session key negotiation complete!")
                    return True
                else:
                    log.debug("Session key step 3 generation failed")
                    return False
            else:
                log.debug("Unexpected response cmd: %s", msg.cmd)
                return False
                
        except Exception as e:
            log.debug("Session key negotiation failed: %s", e, exc_info=True)
            return False
    
    def _negotiate_session_key_generate_step_1(self):
        """Generate step 1 of session key negotiation"""
        self.local_nonce = b'0123456789abcdef'  # not-so-random random key
        self.remote_nonce = b''
        self.local_key = self.real_local_key

        return MessagePayload(CT.SESS_KEY_NEG_START, self.local_nonce)

    def _negotiate_session_key_generate_step_3(self, rkey):
        """Generate step 3 of session key negotiation"""
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

    def _negotiate_session_key_generate_finalize(self):
        """Finalize session key negotiation"""
        try:
            # Python 3 version
            self.local_key = bytes([a ^ b for (a, b) in zip(self.local_nonce, self.remote_nonce)])
        except:
            # Fallback for older Python versions
            k = [chr(ord(a) ^ ord(b)) for (a, b) in zip(self.local_nonce, self.remote_nonce)]
            self.local_key = ''.join(k)
            
        log.debug("Session nonce XOR'd: %r", self.local_key)

        cipher = AESCipher(self.real_local_key)
        if self.version == 3.4:
            self.local_key = cipher.encrypt(self.local_key, False, pad=False)
        else:
            iv = self.local_nonce[:12]
            log.debug("Session IV: %r", iv)
            self.local_key = cipher.encrypt(self.local_key, use_base64=False, pad=False, iv=iv)[12:28]

        log.debug("Session key negotiate success! session key: %r", self.local_key)
        return True
    
    async def _process_message_async(self, msg, dev_type=None, from_child=None, minresponse=28, decode_response=True):
        """Async version of _process_message"""
        # null packet, nothing to decode
        if not msg or len(msg.payload) == 0:
            log.debug("raw unpacked message = %r", msg)
            # legacy/default mode avoids persisting socket across commands
            await self._check_socket_close_async()
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
                log.debug('Recieved async update for wrong CID %s while looking for CID %s, trying again', found_cid, from_child.cid)
                if self.socketPersistent:
                    # if persistent, save response until the next receive() call
                    # otherwise, trash it
                    if found_child:
                        found_child._cache_response(result)
                        result = found_child._process_response(result)
                    else:
                        self._cache_response(result)
                        result = self._process_response(result)
                    self.received_wrong_cid_queue.append((found_child, result))
                # events should not be coming in so fast that we will never timeout a read, so don't worry about loops
                return await self._send_receive(None, minresponse, True, decode_response, from_child=from_child)

        # legacy/default mode avoids persisting socket across commands
        await self._check_socket_close_async()

        if found_child:
            found_child._cache_response(result)
            return found_child._process_response(result)

        self._cache_response(result)
        return self._process_response(result)

    def _decode_payload(self, payload):
        """Decode payload (sync method since it's just data processing)"""
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
            payload = payload[len(H.PROTOCOL_VERSION_BYTES_31):]
            # Decrypt payload
            # Remove 16-bytes of MD5 hexdigest of payload
            payload = cipher.decrypt(payload[16:], decode_text=False)
        elif self.version >= 3.2:  # 3.2 or 3.3 or 3.4 or 3.5
            # Trim header for non-default device type
            if payload.startswith(self.version_bytes):
                payload = payload[len(self.version_header):]
                log.debug("removing 3.x=%r", payload)
            elif self.dev_type == "device22" and (len(payload) & 0x0F) != 0:
                payload = payload[len(self.version_header):]
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
                        payload = payload.decode(errors='replace')
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

    def _cache_response(self, response):
        """Save (cache) the last value of every DP"""
        merge_dps_results(self._historic_status, response)

        if (not self.socketPersistent) or (not self.writer):
            return

        log.debug('caching: %s', response)
        merge_dps_results(self._last_status, response)
        log.debug('merged: %s', self._last_status)

    def _process_response(self, response):  # pylint: disable=R0201
        """Override this function in a sub-class if you want to do some processing on the received data"""
        return response
