# TinyTuya Setup Wizard
# -*- coding: utf-8 -*-
"""
TinyTuya Network Scanner for Tuya based WiFi smart devices

Author: Jason A. Cox
For more information see https://github.com/jasonacox/tinytuya

Description
    Scan will scan the local network for Tuya devices and if a local devices.json is
    present in the local directory, will use the Local KEYs to poll the devices for
    status.

"""
# Modules
from __future__ import print_function
from collections import namedtuple
import ipaddress
import json
import logging
import socket
import select
import sys
import time
import errno
import base64
import traceback
from colorama import init
import tinytuya

# Optional libraries required for forced scanning
#try:
#    from getmac import get_mac_address
#    SCANLIBS = True
#except:
#    SCANLIBS = False

# Backward compatibility for python2
try:
    input = raw_input
except NameError:
    pass

try:
    import netifaces # pylint: disable=E0401
    NETIFLIBS = True
except ImportError:
    NETIFLIBS = False

try:
    import psutil # pylint: disable=E0401
    PSULIBS = True
except ImportError:
    PSULIBS = False

# Colorama terminal color capability for all platforms
init()

# Configuration Files
DEVICEFILE = tinytuya.DEVICEFILE
SNAPSHOTFILE = tinytuya.SNAPSHOTFILE

# Global Network Configs
DEFAULT_NETWORK = tinytuya.DEFAULT_NETWORK
TCPTIMEOUT = tinytuya.TCPTIMEOUT    # Seconds to wait for socket open for scanning
TCPPORT = tinytuya.TCPPORT          # Tuya TCP Local Port
MAXCOUNT = tinytuya.MAXCOUNT        # How many tries before stopping
UDPPORT = tinytuya.UDPPORT          # Tuya 3.1 UDP Port
UDPPORTS = tinytuya.UDPPORTS        # Tuya 3.3 encrypted UDP Port
UDPPORTAPP = tinytuya.UDPPORTAPP    # Tuya app encrypted UDP Port
TIMEOUT = tinytuya.TIMEOUT          # Socket Timeout
SCANTIME = tinytuya.SCANTIME        # How many seconds to wait before stopping
BROADCASTTIME = 6                   # How often to broadcast to port 7000 to get v3.5 devices to send us their info

max_parallel = 300
connect_timeout = 3

devinfo_keys = ('ip', 'mac', 'name', 'key', 'gwId', 'active', 'ability', 'encrypt', 'productKey', 'version', 'token', 'wf_cfg' )
# id ver

TermColors = namedtuple("TermColors", "bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow")

FSCAN_NOT_STARTED = 0
FSCAN_INITIAL_CONNECT = 1
FSCAN_v3x_PROVOKE_RESPONSE = 2
FSCAN_v31_BRUTE_FORCE_ACTIVE = 3
FSCAN_v33_BRUTE_FORCE_ACTIVE = 4
FSCAN_v34_BRUTE_FORCE_ACTIVE = 5
FSCAN_v33_BRUTE_FORCE_ACQUIRE = 6
FSCAN_v31_PASSIVE_LISTEN = 7
#FSCAN_ = 8
FSCAN_FINAL_POLL = 100


# Logging
log = logging.getLogger(__name__)

# Helper Functions
def getmyIP():
    # Fetch my IP address and assume /24 network
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    r = str(r).split('.')
    # assume a /24 network
    return '%s.%s.%s.0/24' % tuple(r[:3])

def getmyIPs( term, verbose, ask ):
    if NETIFLIBS:
        return getmyIPs_via_netifaces( term, verbose, ask )
    if PSULIBS:
        return getmyIPs_via_psutil( term, verbose, ask )
    return None

def getmyIPs_via_netifaces( term, verbose, ask ):
    ips = {}
    interfaces = netifaces.interfaces()
    try:
        # skip the loopback interface
        interfaces.remove('lo')
    except:
        pass
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        #for address_family in (netifaces.AF_INET, netifaces.AF_INET6):
        family_addresses = addresses.get(netifaces.AF_INET)
        if not family_addresses:
            continue

        for address in family_addresses:
            k = str(ipaddress.IPv4Interface(address['addr']+'/'+address['netmask']).network)
            if k[:4] == '127.':
                # skip the loopback interface
                continue
            if ask:
                if ask != 2:
                    answer = input( '%sScan network %s from interface %s?%s ([Y]es/[n]o/[a]ll yes): ' % (term.bold, k, str(interface), term.normal) )
                    if answer[0:1].lower() == 'a':
                        ask = 2
                    elif answer.lower().find('n') >= 0:
                        continue
            if verbose:
                print(term.dim + 'Adding Network', k, 'to the force-scan list')
            ips[k] = True
    return ips.keys()

def getmyIPs_via_psutil( term, verbose, ask ):
    ips = {}
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        addresses = interfaces[interface]
        for addr in addresses:
            if addr.family != socket.AF_INET:
                continue
            k = str(ipaddress.IPv4Interface(addr.address+'/'+addr.netmask).network)
            if k[:4] == '127.':
                # skip the loopback interface
                continue
            if ask:
                if ask != 2:
                    answer = input( '%sScan network %s from interface %s?%s ([Y]es/[n]o/[a]ll yes): ' % (term.bold, k, str(interface), term.normal) )
                    if answer[0:1].lower() == 'a':
                        ask = 2
                    elif answer.lower().find('n') >= 0:
                        continue
            if verbose:
                print(term.dim + 'Adding Network', k, 'to the force-scan list')
            ips[k] = True
    return ips.keys()

def get_ip_to_broadcast():
    ip_to_broadcast = {}

    if NETIFLIBS:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addresses = netifaces.ifaddresses(interface)
            ipv4 = addresses.get(netifaces.AF_INET)

            if ipv4:
                for addr in ipv4:
                    if 'broadcast' in addr and 'addr' in addr and addr['broadcast'] != addr['addr']:
                        ip_to_broadcast[addr['broadcast']] = addr['addr']

        if ip_to_broadcast:
            return ip_to_broadcast

    if PSULIBS:
        interfaces = psutil.net_if_addrs()
        for addresses in interfaces.values():
            for addr in addresses:
                if addr.family == socket.AF_INET and addr.broadcast and addr.address and addr.address != addr.broadcast:  # AF_INET is for IPv4
                    ip_to_broadcast[addr.broadcast] = addr.address

        if ip_to_broadcast:
            return ip_to_broadcast

    ip_to_broadcast['255.255.255.255'] = getmyIP()
    return ip_to_broadcast

def send_discovery_request( iface_list=None ):
    close_sockets = False

    if not iface_list:
        close_sockets = True
        iface_list = {}
        client_bcast_addrs = get_ip_to_broadcast()
        for bcast in client_bcast_addrs:
            addr = client_bcast_addrs[bcast]
            iface_list[addr] = { 'broadcast': bcast }

    for address in iface_list:
        iface = iface_list[address]
        if 'socket' not in iface:
            iface['socket'] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            iface['socket'].setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            iface['socket'].bind( (address,0) )

        if 'payload' not in iface:
            bcast = json.dumps( {"from":"app","ip":address} ).encode()
            bcast_msg = tinytuya.TuyaMessage( 0, tinytuya.REQ_DEVINFO, None, bcast, 0, True, tinytuya.PREFIX_6699_VALUE, True )
            iface['payload'] = tinytuya.pack_message( bcast_msg, hmac_key=tinytuya.udpkey )

        if 'port' not in iface:
            iface['port'] = 7000

        log.debug( 'Sending discovery broadcast from %r to %r on port %r', address, iface['broadcast'], iface['port'] )
        # the official app always sends it twice, so do the same
        iface['socket'].sendto( iface['payload'], (iface['broadcast'], iface['port']) )
        iface['socket'].sendto( iface['payload'], (iface['broadcast'], iface['port']) )

        if close_sockets:
            iface['socket'].close()
            del iface['socket']

class KeyObj(object):
    def __init__( self, gwId, key ):
        self.gwId = gwId
        self.key = key
        self.key_encoded = key.encode('utf8')
        self.used = False

class DeviceDetect(object):
    def __init__( self, ip, deviceinfo, options, debug ):
        self.ip = ip
        self.deviceinfo = None
        self.options = options
        self.debug = debug
        self.device = None
        self.scanned = False
        self.broadcasted = False
        self.found = False
        self.key_found = False
        self.gwid_found = False
        self.err_found = False
        self.ver_found = False
        self.displayed = False
        self.message = None
        self.passive = False
        self.msgs = []
        self.send_queue = []
        self.sock = None
        self.read = False
        self.write = False
        self.remove = False
        self.timeo = 0
        self.resets = 0
        self.step = FSCAN_NOT_STARTED
        self.try_v35_with_v34 = False
        self.cur_key = None
        self.hard_time_limit = time.time() + 30
        self.initial_connect_retries = options['retries']

        if not deviceinfo:
            deviceinfo = {}
        # some devices report "ability" but most have this as the typo "ablilty"
        if 'ablilty' in deviceinfo and 'ability' not in deviceinfo:
            deviceinfo['ability'] = deviceinfo['ablilty']
            del deviceinfo['ablilty']
        self.deviceinfo = deviceinfo
        for k in devinfo_keys:
            if k not in deviceinfo:
                self.deviceinfo[k] = ''

        if not self.deviceinfo['version']:
            self.deviceinfo['version']  = 3.1
        if ('dev_type' not in self.deviceinfo) or (not self.deviceinfo['dev_type']):
            self.deviceinfo['dev_type'] = 'default'
        #if not self.deviceinfo['gwId']:
        #    self.deviceinfo['gwId'] = ''
        #if not self.deviceinfo['key']:
        #    self.deviceinfo['key'] = ''
        self.deviceinfo['ip'] = ip

    def connect( self ):
        if self.debug:
            print('Connecting to debug ip', self.ip)
        if self.sock: self.sock.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.settimeout(TCPTIMEOUT)
        self.sock.setblocking(False)
        self.sock.connect_ex( (str(self.ip), TCPPORT) )
        self.read = False
        self.write = True
        self.send_queue = []
        self.timeo = time.time() + self.options['connect_timeout']
        #print( 'key', self.ip, self.deviceinfo['key'])
        key = self.cur_key.key if self.cur_key else self.deviceinfo['key']
        if key == "":
            key = 'f'*16 # use bogus key if missing
        self.device = tinytuya.OutletDevice( self.deviceinfo['gwId'], self.ip, key, dev_type=self.deviceinfo['dev_type'], version=float(self.deviceinfo['version']))
        self.device.set_socketPersistent(True)
        self.device.socket = self.sock

    def close( self ):
        if self.debug:
            print('in close 0', self.ip)
        if self.sock: self.sock.close()
        self.sock = None
        self.read = self.write = False
        self.remove = True

    def stop(self):
        if self.debug:
            print('in stop 0', self.ip)
        if self.sock:
            self.close()

    def get_peer(self):
        try:
            # getpeername() blows up with "OSError: [Errno 107] Transport endpoint is
            # not connected" if the connection was refused
            addr = self.sock.getpeername()[0]
        except Exception as e:
            addr = None
            if self.debug:
                traceback.print_exception(e,e,None)
                print('Debug sock', self.ip, 'connection failed!')
                print(self.sock)
        # connection failed
        if not addr:
            # sometimes the devices accept the connection, but then immediately close it
            # so, retry if that happens
            try:
                # this should throw either ConnectionResetError or ConnectionRefusedError
                r = self.sock.recv( 5000 )
                if self.debug:
                    print('Debug sock', self.ip, 'closed but received data?? Received:', r)
            # ugh, ConnectionResetError and ConnectionRefusedError are not available on python 2.7
            #except ConnectionResetError:
            except OSError as e:
                if self.initial_connect_retries and e.errno == errno.ECONNRESET:
                    # connected, but then closed
                    self.initial_connect_retries -= 1
                    if self.debug:
                        print('Debug sock', self.ip, 'connection made but then closed, retrying')
                    return False
                elif e.errno == errno.ECONNRESET:
                    if self.debug:
                        print('Debug sock', self.ip, 'connection made but then closed and retry limit exceeded, giving up')
                else:
                    if self.debug:
                        traceback.print_exception(e,e,None)
                        print('Debug sock', self.ip, 'connection refused, not retrying')
                    return None
            except:
                if self.debug:
                    print('Debug sock', self.ip, 'unhandled connection exception!')
                    traceback.print_exc()
                self.close()
                return None
            # we should never get here
            return False
        return addr

    def v34_negotiate_sess_key_start( self ):
        if self.debug:
            print('v3.4/5 trying key', self.ip, self.device.real_local_key)
        step1 = self.device._negotiate_session_key_generate_step_1()
        self.sock.sendall( self.device._encode_message( step1 ) )
        if self.try_v35_with_v34 and self.device.version == 3.4:
            self.device.version = 3.5
            step1 = self.device._negotiate_session_key_generate_step_1()
            self.sock.sendall( self.device._encode_message( step1 ) )
            self.device.version = 3.4
        if self.debug:
            print('v3.4/5 session key neg start, debug ip', self.ip)

    def v34_negotiate_sess_key_step_2( self, rkey ):
        lastloglevel = log.level
        if self.debug:
            log.setLevel(logging.DEBUG)
        step3 = self.device._negotiate_session_key_generate_step_3( rkey )
        if not step3:
            log.setLevel(lastloglevel)
            return False
        self.sock.sendall( self.device._encode_message( step3 ) )
        self.device._negotiate_session_key_generate_finalize()
        log.setLevel(lastloglevel)
        return True

class ForceScannedDevice(DeviceDetect):
    def __init__( self, ip, deviceinfo, options, debug ):
        super(ForceScannedDevice, self).__init__( ip, deviceinfo, options, debug )
        self.retries = 0
        self.keygen = None
        self.brute_force_data = []
        self.try_v35_with_v34 = True
        self.v34_connect_ok = False

        self.connect()

    def abort( self ):
        if self.debug:
            print('in abort', self.ip)
        self.found = False
        self.close()

    def stop( self ):
        if self.debug:
            print('in stop', self.ip)
        super(ForceScannedDevice, self).stop()

        if self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
            self.brute_force_v3x_data()

        if not self.ver_found:
            self.deviceinfo['version'] = 0.0

        if self.options['verbose'] and self.found and not self.displayed:
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan, FORCED STOP', self.options['termcolors'], self.message, self.options['verbose'] )
            self.displayed = True

    def timeout( self, forced=False ):
        if self.debug:
            print( 'in timeout', self.ip, self.step ) #self.__dict__ )
        if self.remove:
            return

        if self.step == FSCAN_NOT_STARTED:
            self.remove = True
            self.err_found = True
            if self.debug:
                print('ForceScannedDevice: Debug sock', self.ip, 'connect timed out!')
        elif self.step == FSCAN_INITIAL_CONNECT:
            if self.debug:
                print('ForceScannedDevice: Debug sock', self.ip, 'socket send failed,', 'no data received,' if forced else 'receive timed out,', 'current retry:', self.retries)
            if self.retries < 2:
                self.retries += 1
                self.connect()
            else:
                if self.debug:
                    print('ForceScannedDevice: Debug sock closed thrice:', self.ip)
                if self.deviceinfo['dev_type'] == 'default':
                    # could be a device22, try 2 more times
                    if self.debug:
                        print('ForceScannedDevice: Retrying as v3.3 Device22')
                    self.retries = 1
                    self.deviceinfo['dev_type'] = 'device22'
                    self.step = FSCAN_NOT_STARTED
                    self.connect()
                    return
                # closed thrice, probably a v3.4 device
                if self.debug:
                    print('ForceScannedDevice: Retrying as v3.4')
                self.retries = 0
                self.deviceinfo['dev_type'] = 'default'
                self.step = FSCAN_v34_BRUTE_FORCE_ACTIVE
                self.deviceinfo['version'] = 3.4
                self.ver_found = True
                self.keygen = (i for i in self.options['keylist'] if not i.used)
                self.cur_key = next( self.keygen, None )
                if self.debug:
                    print('ForceScannedDevice: Keygen gave:', self.cur_key, self.ip)
                if self.cur_key is None:
                    self.remove = True
                else:
                    self.connect()
                    self.v34_connect_ok = False
        elif self.step == FSCAN_v34_BRUTE_FORCE_ACTIVE:
            if( (not forced) and (not self.v34_connect_ok) ):
                # actual timeout, connect failed
                if self.retries < 2:
                    self.retries += 1
                    self.connect()
                else:
                    self.err_found = True
                    self.deviceinfo['version'] = 0.0
                    self.message = "%s    Polling %s Failed: Device stopped responding before key was found" % (self.options['termcolors'].alertdim, self.ip)
                    _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message, self.options['verbose'])
                    self.displayed = True
                    self.close()
                return
            # brute-forcing the key
            self.v3x_brute_force_try_next_key()
            self.v34_connect_ok = False
        elif self.step == FSCAN_v31_BRUTE_FORCE_ACTIVE:
            # brute-forcing the key
            self.v3x_brute_force_try_next_key()
        elif forced:
            self.err_found = True
            self.message = "%s    Polling %s Failed: Unexpected close during read/write operation" % (self.options['termcolors'].alertdim, self.ip)
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message, self.options['verbose']) 
            self.displayed = True
            self.remove = True
        elif self.step == FSCAN_v31_PASSIVE_LISTEN or self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
            if not self.brute_force_v3x_data():
                # passively wait for async status updates
                self.timeo = time.time() + 5.0
                self.passive = True
        elif self.step == FSCAN_FINAL_POLL:
            if not self.message:
                self.message = "%s    Polling %s Failed: No response to poll request" % (self.options['termcolors'].alertdim, self.ip)
            _print_device_info( self.deviceinfo, 'Force-Scanned', self.options['termcolors'], self.message, self.options['verbose'])
            self.displayed = True
            self.remove = True
        else:
            if self.debug:
                print('ForceScannedDevice: Debug sock', self.ip, 'timeout on unhandled step', self.step)
            self.remove = True
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message, self.options['verbose'])
            self.displayed = True

        if self.remove:
            self.close()

    def write_data( self ):
        # get_peer() returns:
        #  'None' on connection refused
        #  'False' when connection was made but then closed
        #  The IP address when the connection is still open
        addr = self.get_peer()
        if self.debug:
            print('ForceScannedDevice: device', self.ip, 'addr is:', addr)
        if addr is None:
            # refused
            self.close()
            return
        elif addr is False:
            # sometimes the devices immediately close the connection, so retry
            if self.debug:
                print('ForceScannedDevice: Retrying connect', self.ip)
            if self.sock:
                self.sock.close()
            self.connect()
            return

        # connection succeeded!
        #self.timeo = time.time() + self.options['data_timeout']
        self.timeo = time.time() + 1.5
        self.found = True
        self.v34_connect_ok = True

        if len(self.send_queue) > 0:
            self.sock.sendall( self.device._encode_message( self.send_queue[0] ) )
            self.send_queue = self.send_queue[1:]
            if len(self.send_queue) == 0:
                self.write = False
                self.read = True
            return

        self.write = False
        self.read = True
        log.debug("Force-Scan Found Device %s", self.ip)
        #if self.options['verbose'] and self.step == 0:
        if self.debug and self.step == 0:
            print(" ForceScannedDevice: Force-Scan Found Device %s" % (self.ip,))

        msg = None
        if self.step == FSCAN_NOT_STARTED:
            self.scanned = True
            self.step = FSCAN_INITIAL_CONNECT
            # try to figure out what version device it is by sending an unencrypted status request
            # v3.1 devices will return the status
            # v3.2 devices will ???
            # v3.3 devices will return an encrypted rejection message
            # v3.4/3.5 devices will slam the door in our face by dropping the connection
            if self.deviceinfo['dev_type'] == 'device22':
                msg = tinytuya.MessagePayload(tinytuya.CONTROL_NEW, b'')
            else:
                msg = tinytuya.MessagePayload(tinytuya.DP_QUERY, b'')
        elif self.step == FSCAN_INITIAL_CONNECT:
            # this is a connect retry
            dummy_payload = bytes(bytearray.fromhex('deadbeef112233445566778899aabbccddeeffb00bface112233feedbabe74f0'))
            if self.deviceinfo['dev_type'] == 'device22':
                msg = tinytuya.MessagePayload(tinytuya.CONTROL_NEW, dummy_payload)
            else:
                msg = tinytuya.MessagePayload(tinytuya.DP_QUERY, dummy_payload)
        elif self.step == FSCAN_v31_BRUTE_FORCE_ACTIVE:
            dummy_payload = bytes(bytearray.fromhex('deadbeef112233445566778899aabbccddeeffb00bface112233feedbabe74f0'))
            msg = tinytuya.MessagePayload(tinytuya.CONTROL, dummy_payload)
        #elif self.step == FSCAN_v33_BRUTE_FORCE_ACTIVE:
        #    pass
        elif self.step == FSCAN_v34_BRUTE_FORCE_ACTIVE:
            # try to brute-force the key
            self.v34_negotiate_sess_key_start()
        else:
            print('ForceScannedDevice: Unhandled step in write()?!?!', self.ip, 'step', self.step)

        if msg:
            if self.debug:
                print(" ForceScannedDevice: Sending Device %s Message %r" % (self.ip,msg))
            msg = self.device._encode_message( msg )
            try:
                self.sock.sendall( msg )
            except:
                self.send_queue.append( msg )
                self.write = True
                self.read = False

    def read_data( self ):
        try:
            data = self.sock.recv( 5000 )
        except:
            data = b''

        if self.debug:
            print('ForceScannedDevice:', self.ip, 'got step', self.step, 'data:', data )

        if len(data) == 0:
            self.timeout( True )
            return

        while len(data):
            try:
                if self.deviceinfo['version'] == 3.5:
                    prefix_offset = data.find(tinytuya.PREFIX_6699_BIN)
                    if prefix_offset > 0:
                        data = data[prefix_offset:]
                else:
                    prefix_offset = data.find(tinytuya.PREFIX_BIN)
                    if prefix_offset >= 0:
                        data = data[prefix_offset:]
                        self.try_v35_with_v34 = False
                    elif self.try_v35_with_v34 and self.deviceinfo['version'] == 3.4:
                        prefix_offset = data.find(tinytuya.PREFIX_6699_BIN)
                        if prefix_offset >= 0:
                            if self.debug:
                                print('ForceScannedDevice: device is v3.5!')
                            data = data[prefix_offset:]
                            self.try_v35_with_v34 = False
                            self.deviceinfo['version'] = 3.5
                            self.device.set_version(3.5)
                            self.ver_found = True
                hmac_key = self.device.local_key if self.deviceinfo['version'] >= 3.4 else None
                msg = tinytuya.unpack_message(data, hmac_key=hmac_key)
            except:
                break

            odata = data
            #data = data[tinytuya.message_length(msg.payload):]
            # this will not strip everything, but it will be enough for data.find() to find it
            data = data[len(msg.payload)+8:]

            # ignore NULL packets
            if not msg or len(msg.payload) == 0:
                continue

            if msg.cmd == tinytuya.SESS_KEY_NEG_RESP:
                if not self.v34_negotiate_sess_key_step_2( msg ):
                    #if self.debug:
                    print('odata:', odata)
                    self.timeout()
                    return
                self.read = False
                self.write = True
                self.step = FSCAN_FINAL_POLL
                self.message = "%s    Polling %s Failed: No response to poll request" % (self.options['termcolors'].alertdim, self.ip)
                self.ver_found = True
                self.deviceinfo['key'] = self.cur_key.key
                self.found_key()
                self.cur_key.used = True
                self.send_queue.append(self.device.generate_payload(tinytuya.DP_QUERY))
                return

            if msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
                self.deviceinfo['version'] = 3.1
                payload = msg.payload[len(tinytuya.PROTOCOL_VERSION_BYTES_31)+16 :]
                self.ver_found = True
            elif msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                self.deviceinfo['version'] = 3.3
                payload = msg.payload[len(tinytuya.PROTOCOL_33_HEADER) :]
                self.ver_found = True
            else:
                payload = msg.payload

            if self.debug:
                print( 'Got message from %s for step %s: %r' % (self.ip, self.step, msg) )

            if self.step == FSCAN_INITIAL_CONNECT:
                # FIXME try and use the response?
            #    self.step = FSCAN_v3x_PROVOKE_RESPONSE
            #    self.timeo = time.time() + 1.0
            #    self.sock.sendall( self.device._encode_message( tinytuya.MessagePayload(tinytuya.DP_QUERY, b'') ) )
            #elif self.step == FSCAN_v3x_PROVOKE_RESPONSE:
                self.timeo = time.time() + 5.0
                have_err_string = False
                try:
                    if 'error' in payload.decode('utf8'):
                        # clear-text response, device is v3.1
                        self.ver_found = True
                        self.device.set_version(3.1)
                        self.deviceinfo['version'] = 3.1
                        # there is no good way of brute-forcing this one, so listen passively in hopes of receiving a message containing the gwId
                        self.step = FSCAN_v31_BRUTE_FORCE_ACTIVE #FSCAN_v31_PASSIVE_LISTEN
                        #self.passive = True
                        have_err_string = True
                        if self.debug:
                            print( 'Trying brute force!' )

                        self.keygen = (i for i in self.options['keylist'] if not i.used)
                        self.v3x_brute_force_try_next_key()
                        #self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )
                        #self.step = FSCAN_FINAL_POLL
                except:
                    pass

                if not have_err_string:
                    # encrypted response, probably v3.3
                    if self.debug:
                        print( 'Device %s is probably v3.3' % self.ip )
                    self.device.set_version(3.3)
                    self.deviceinfo['version'] = 3.3
                    self.ver_found = True
                    self.step = FSCAN_v33_BRUTE_FORCE_ACQUIRE
                    self.brute_force_data.append( payload )
            elif self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
                # no timout resetting for this one, let self.timeout() process the data
                self.brute_force_data.append( payload )
            elif self.step ==  FSCAN_v31_BRUTE_FORCE_ACTIVE:
                if 'error' in payload.decode('utf8'):
                    self.brute_force_found_key()
            elif self.step == FSCAN_v31_PASSIVE_LISTEN:
                if msg.cmd == tinytuya.STATUS and msg.retcode == 0:
                    try:
                        self.brute_force_data.append( base64.b64decode( payload ) )
                        self.brute_force_v3x_data()
                    except:
                        pass

            elif self.step == FSCAN_FINAL_POLL:
                result = self.device._decode_payload( msg.payload )
                if self.debug:
                    print('ForceScannedDevice: Final Poll', self.ip, self.step, payload)
                    print(result)

                finished = False
                if not result:
                    #self.message = "%s    Error: %s" % (self.options['termcolors'].alertdim, result)
                    pass
                elif 'dps' in result:
                    if len(result['dps']) > 2:
                        finished = True
                    self.message = "%s    Status: %s" % (self.options['termcolors'].dim, result["dps"])
                    #self.last_result = result
                elif 'Error' in result:
                    self.message = "%s    Error: %s" % (self.options['termcolors'].alertdim, result)
                else:
                    self.message = "%s    Unknown: %s" % (self.options['termcolors'].dim, result)

                if self.options['verbose'] and finished:
                    _print_device_info( self.deviceinfo, 'Force-Scanned', self.options['termcolors'], self.message )
                    self.displayed = True

                if finished:
                    self.close()
                else:
                    self.timeo = time.time() + 2.0
                return

    def brute_force_v3x_data( self ):
        if len( self.brute_force_data ) == 0:
            return False

        for key in (i for i in self.options['keylist'] if not i.used):
            self.cur_key = key
            bad = False
            cipher = tinytuya.AESCipher( key.key_encoded )
            matched = None
            for msg in self.brute_force_data:
                matched = None
                try:
                    text = cipher.decrypt( msg, False, True )

                    if len(text) == 0:
                        continue

                    if self.debug: #self.options['verbose']:
                        print('ForceScannedDevice: Brute force', self.ip, 'decrypted:', text)
                    matched = cipher.key
                except:
                    pass

                if not matched:
                    bad = True
                    break

            if matched and not bad:
                self.brute_force_found_key()
                return True

        self.brute_force_data = []
        return False

    def v3x_brute_force_try_next_key( self ):
        self.cur_key = next( self.keygen, None )

        if not self.passive:
            while self.cur_key and self.cur_key.used:
                self.cur_key = next( self.keygen, None )
        #if self.debug and self.cur_key:
        #    print( 'ForceScannedDevice: v3.x', self.step, 'brute force got key', self.cur_key.key )
        if self.cur_key is None:
            # Keep trying.  Go through the list again but include "already-used" keys as well
            if not self.passive:
                self.keygen = (i for i in self.options['keylist'])
                try:
                    self.cur_key = next( self.keygen, None )
                except:
                    self.cur_key = None
            self.passive = True
            if self.cur_key is None:
                if self.debug:
                    print('ForceScannedDevice: v3.x brute force ran out of keys without finding a match!', self.ip)
                self.remove = True
                self.deviceinfo['version'] = 0.0
                self.message = "%s    Polling %s Failed: No matching key found" % (self.options['termcolors'].alertdim, self.ip)
                _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message, self.options['verbose'] )
                self.displayed = True
            else:
                if self.debug:
                    print('ForceScannedDevice: v3.x brute force ran out of keys, restarting without skipping any', self.ip, self.cur_key.key)
                self.connect()
        else:
            if self.debug:
                print('ForceScannedDevice: v3.x brute force trying next key', self.ip, self.cur_key.key)
            self.connect()

    def brute_force_found_key( self ):
        if self.debug:
            print('ForceScannedDevice: v3.x brute forced key', self.cur_key.key, 'for', self.ip)
        self.brute_force_data = []
        self.read = True
        self.write = False
        self.ver_found = True
        self.deviceinfo['key'] = self.cur_key.key
        self.found_key()
        self.device.local_key = self.device.real_local_key = self.cur_key.key_encoded
        self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )
        self.step = FSCAN_FINAL_POLL
        self.message = "%s    Polling %s Failed: No response to poll request" % (self.options['termcolors'].alertdim, self.ip)
        self.timeo = time.time() + 2.0
        self.cur_key.used = True

    def found_key( self ):
        for dev in self.options['tuyadevices']:
            if dev['key'] == self.deviceinfo['key']:
                self.deviceinfo['name'] = dev['name']
                self.deviceinfo['id'] = self.deviceinfo['gwId'] = dev['id']
                if 'mac' in dev and dev['mac'] and ('mac' not in self.deviceinfo or not self.deviceinfo['mac']):
                    self.deviceinfo['mac'] = dev['mac']
                self.device.id = dev['id']
                self.key_found = True
                return


class PollDevice(DeviceDetect):
    def __init__( self, ip, deviceinfo, options, debug ):
        super(PollDevice, self).__init__( ip, deviceinfo, options, debug )
        self.broadcasted = True
        self.retries = options['retries']
        self.finished = False

    def close(self):
        super(PollDevice, self).close()
        if self.options['verbose']:
            _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'], self.message )
            self.displayed = True

    def	timeout( self ):
        if self.retries > 0:
            if self.debug:
                print('PollDevice: Timeout for debug ip', self.ip, '- reconnecting, retries', self.retries)
            self.retries -= 1
            # get_peer() may have closed it already
            if self.sock:
                self.sock.close()
            self.connect()
            self.timeo = time.time() + tinytuya.TIMEOUT
            if self.debug:
                print('PollDevice: New timeo:', self.timeo)
        else:
            if self.debug:
                print('PollDevice: Final timeout for debug ip', self.ip, '- aborting')
            err = ""
            if "err" in self.deviceinfo:
                err = self.deviceinfo["err"]
            self.message = "%s    Polling %s Failed: %s" % (self.options['termcolors'].alertdim, self.ip, err)
            self.close()

    def write_data( self ):
        addr = self.get_peer()
        if not addr:
            if ("err" not in self.deviceinfo) or (not self.deviceinfo["err"]):
                self.deviceinfo["err"] = "Connect Failed"
            if self.debug:
                print('PollDevice: Debug sock', self.ip, 'failed!', addr, self.sock)
                print(traceback.format_exc())
            self.timeout()
            return

        # connection succeeded!
        self.timeo = time.time() + self.options['data_timeout']
        if self.debug:
            print('PollDevice: WD New timeo:', self.timeo)

        if len(self.send_queue) > 0:
            self.sock.sendall( self.device._encode_message( self.send_queue[0] ) )
            self.send_queue = self.send_queue[1:]
            if len(self.send_queue) == 0:
                self.write = False
                self.read = True
            return

        self.write = False

        try:
            # connected, send the query
            if self.device.version >= 3.4 :
                # self.device.real_local_key, self.device.local_key
                self.v34_negotiate_sess_key_start()
            else:
                self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )

            self.read = True
            #deviceslist[ip]["err"] = "Check DEVICE KEY - Invalid response"
            self.deviceinfo["err"] = "No response"
        except:
            self.deviceinfo["err"] = "Send Poll failed"
            print(traceback.format_exc())
            self.timeout()


    def read_data( self ):
        try:
            data = self.sock.recv( 5000 )
        except:
            if self.retries > 0:
                if self.options['verbose']:
                    print('read_data() failed, retrying', self.ip)
                self.timeout()
                return

            self.message = "%s    Polling %s Failed: Read error" % (self.options['termcolors'].alertdim, self.ip)
            self.close()
            return

        while len(data):
            try:
                prefix_offset = data.find(tinytuya.PREFIX_BIN)
                if prefix_offset > 0:
                    data = data[prefix_offset:]
                hmac_key = self.device.local_key if self.device.version >= 3.4 else None
                msg = tinytuya.unpack_message(data, hmac_key=hmac_key)
            except:
                break

            # this will not strip everything, but it will be enough for data.find() to find it
            odata = data
            data = data[len(msg.payload)+8:]

            # ignore NULL packets
            if not msg or len(msg.payload) == 0:
                continue

            if msg.cmd == tinytuya.SESS_KEY_NEG_RESP:
                if not self.v34_negotiate_sess_key_step_2( msg ):
                    print('odata:', odata)
                    self.timeout()
                    return
                self.read = False
                self.write = True
                self.send_queue.append(self.device.generate_payload(tinytuya.DP_QUERY))
                return

            dev_type = self.device.dev_type
            try:
                # Data available: seqno cmd retcode payload crc
                log.debug("PollDevice: raw unpacked message = %r", msg)
                result = self.device._decode_payload(msg.payload)
            except:
                log.debug("PollDevice: error unpacking or decoding tuya JSON payload")
                result = tinytuya.error_json(tinytuya.ERR_PAYLOAD)

            # Did we detect a device22 device? Return ERR_DEVTYPE error.
            if dev_type != self.device.dev_type:
                log.debug(
                    "PollDevice: Device22 detected and updated (%s -> %s) - Update payload and try again",
                    dev_type,
                    self.device.dev_type,
                )
                self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )
                break

            self.finished = True
            self.deviceinfo['type'] = self.device.dev_type

            if not result or "dps" not in result:
                if result and "Error" in result:
                    self.message = "%s    Access rejected by %s (check key): %s: %s" % (self.options['termcolors'].alertdim, self.ip, result["Error"], result["Payload"])
                else:
                    self.message = "%s    Check DEVICE KEY - Invalid response from %s: %r" % (self.options['termcolors'].alertdim, self.ip, result)
                self.deviceinfo["err"] = "Unable to poll"
                self.close()
            else:
                self.deviceinfo["dps"] = result
                self.deviceinfo["err"] = ""
                self.message = self.options['termcolors'].dim + "    Status: %s" % result["dps"]
                self.close()



# Scan function shortcut
def scan(scantime=None, color=True, forcescan=False, discover=True, assume_yes=False):
    """Scans your network for Tuya devices with output to stdout"""
    devices(verbose=True, scantime=scantime, color=color, poll=True, forcescan=forcescan, discover=discover, assume_yes=assume_yes)

def _generate_ip(networks, verbose, term):
    for netblock in networks:
        if tinytuya.IS_PY2 and type(netblock) == str:
            netblock = netblock.decode('latin1')
        try:
            network = ipaddress.ip_network(netblock, strict=False)
            log.debug("Starting brute force network scan %s", network)
        except:
            log.debug("Unable to get network for %r, ignoring", netblock)
            if verbose:
                print(term.alert +
                    'ERROR: Unable to get network for %r, ignoring.' % netblock + term.normal)
                print(traceback.format_exc())
            continue

        if verbose:
            print(term.bold + '  Starting Scan for network %s%s' % (network, term.dim))
        # Loop through each host
        for addr in ipaddress.IPv4Network(network):
            yield str(addr)

def _print_device_info( result, note, term, extra_message=None, verbose=True ):
    if not verbose:
        return
    ip = result["ip"]
    gwId = result["gwId"]
    productKey = result["productKey"] if result["productKey"] else '?'
    version = result["version"] if result["version"] and result["version"] != '0.0' else '??'
    devicename = result["name"]
    dkey = result["key"]
    mac = result["mac"]
    devicetype = result['dev_type'] if 'dev_type' in result else '??'

    suffix = term.dim + ", MAC = " + mac + ""
    if not result['name']:
        devicename = "%sUnknown v%s Device%s" % (term.alert, version, term.normal+term.dim) # (term.normal+term.dim, term.normal, version, term.dim)
    else:
        devicename = term.normal + result['name'] + term.dim
    print(
        "%s   Product ID = %s  [%s]:\n    %sAddress = %s   %sDevice ID = %s (len:%d)  %sLocal Key = %s  %sVersion = %s  %sType = %s%s"
        % (
            devicename,
            productKey,
            note,
            term.subbold,
            ip,
            term.cyan,
            gwId,
            len(gwId),
            term.red,
            dkey,
            term.yellow,
            version,
            term.cyan,
            devicetype,
            suffix
        )
    )

    if extra_message:
        print( extra_message )


# Scan function
def devices(verbose=False, scantime=None, color=True, poll=True, forcescan=False, byID=False, show_timer=None, 
            discover=True, wantips=None, wantids=None, snapshot=None, assume_yes=False, tuyadevices=[], 
            maxdevices=0): # pylint: disable=W0621, W0102
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        scantime = The time to wait to pick up UDP from all devices (ignored when discover=False))
        color = True or False, print output in color [Default: True]
        poll = True or False, poll dps status for devices if possible
        forcescan = True, False, or a list of networks to force scan for device IP addresses
        byID = True or False, return dictionary by ID, otherwise by IP (default)
        show_timer = True or False, if True then timer will be displayed even when verbose=False
        discover = True or False, when False, UDP broadcast packets will be ignored
        wantips = A list of IP addresses we want.  Scan will stop early if all are found
        wantids = A list of Device IDs we want.  Scan will stop early if all are found
        snapshot = A dict of devices with IP addresses as keys.  These devices will be force-scanned
        assume_yes = True or False, do not prompt to confirm auto-detected network ranges
        tuyadevices = contents of devices.json, to prevent re-loading it if we already have it
        maxdevices = Stop scanning after this many devices are found.  0 for no limit

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
    # Terminal formatting
    termcolors = tinytuya.termcolor(color)
    #(bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = termcolors
    term = TermColors( *termcolors )

    # Lookup Tuya device info by (id) returning (name, key)
    def tuyaLookup(deviceid):
        for i in tuyadevices:
            if "id" in i and i["id"] == deviceid:
                return (i["name"], i["key"], i["mac"] if "mac" in i else "")
        return ("", "", "")

    havekeys = False
    if not tuyadevices:
        # Check to see if we have additional Device info
        try:
            # Load defaults
            with open(DEVICEFILE) as f:
                tuyadevices = json.load(f)
                havekeys = True
                log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
        except:
            # No Device info
            pass

    if forcescan and len(tuyadevices) == 0:
        if discover:
            print(term.alert + 'Warning: Force-scan requires keys in %s but no keys were found.  Disabling force-scan.' % DEVICEFILE + term.normal)
            forcescan = False
        else:
            raise RuntimeError('Force-scan requires keys in %s but no keys were found.' % DEVICEFILE)

    if discover:
        # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT not available
            pass
        client.bind(("", UDPPORT))
        #client.settimeout(TIMEOUT)

        # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
        clients = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            clients.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT not available
            pass
        clients.bind(("", UDPPORTS))
        #clients.settimeout(TIMEOUT)

        # Enable UDP listening broadcasting mode on encrypted UDP port 7000 - App
        clientapp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        clientapp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            clientapp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            # SO_REUSEPORT not available
            pass
        clientapp.bind(("", UDPPORTAPP))
    else:
        client = clients = clientapp = None
        # no broadcast and no force scan???
        #if not forcescan:
        scantime = 0.1

    if scantime is None:
        scantime = tinytuya.SCANTIME

    if show_timer is None:
        show_timer = verbose

    if verbose:
        print(
            "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
            % (term.bold, term.normal, term.dim, tinytuya.__version__)
        )
        if havekeys:
            print("%s[Loaded devices.json - %d devices]\n" % (term.dim, len(tuyadevices)))
        if discover:
            print(
                "%sScanning on UDP ports %s and %s and %s for devices for %d seconds...%s\n"
                % (term.subbold, UDPPORT, UDPPORTS, UDPPORTAPP, scantime, term.normal)
            )

    #debug_ips = ['172.20.10.144', '172.20.10.91', '172.20.10.51', '172.20.10.136']
    debug_ips = []
    networks = []
    scanned_devices = {}
    broadcasted_devices = {}
    broadcast_messages = {}
    broadcasted_apps = {}
    devicelist = []
    read_socks = []
    write_socks = []
    spinnerx = 0
    spinner = "|/-\\|"
    connect_this_round = []
    connect_next_round = []
    ip_wantips = bool(wantips)
    ip_wantids = bool(wantids)
    ip_force_wants_end = False
    ip_scan = False
    ip_scan_running = False
    ip_scan_delay = False
    scan_end_time = time.time() + scantime
    device_end_time = 0
    log.debug("Listening for Tuya devices on UDP ports %d, %d and %d", UDPPORT, UDPPORTS, UDPPORTAPP)
    start_time = time.time()
    timeout_time = time.time() + 5
    scan_ips = None
    current_ip = None
    need_sleep = 0.1
    user_break_count = 0
    client_ip_broadcast_list = {}
    client_ip_broadcast_timer = 0
    options = {
        'connect_timeout': connect_timeout,
        'data_timeout': connect_timeout,
        'termcolors': term,
        'verbose': verbose,
        'retries': 2,
        'tuyadevices': tuyadevices,
        'keylist': [],
    }

    for i in tuyadevices:
        options['keylist'].append( KeyObj( i['id'], i['key'] ) )

    wantips = [] if not wantips else list(wantips) #['192.168.1.3']
    wantids = [] if not wantids else list(wantids) #['abcdef']

    if forcescan:
        if verbose:
            print(term.subbold + "    Option: " + term.dim + "Network force scanning requested.\n")

        # argparse gives us a list of lists
        # the inner list is empty [[]] when no address specified
        add_connected = True
        if isinstance( forcescan, list ) or isinstance( forcescan, tuple ):
            for ip in forcescan:
                if isinstance( ip, list ) or isinstance( ip, tuple ):
                    for ip2 in ip:
                        networks.append( ip2 )
                        add_connected = False
                else:
                    networks.append( ip )
                    add_connected = False

        if isinstance( forcescan, str ) or isinstance( forcescan, bytes ):
            networks.append( forcescan )
            add_connected = False

        if add_connected:
            if (not NETIFLIBS) and (not PSULIBS):
                print(term.alert +
                      '    NOTE: neither module netifaces nor module psutil are available, multi-interface machines will be limited.\n'
                      '           (Requires: `pip install netifaces` or `pip install psutil`)\n' + term.dim)
                try:
                    ip = getmyIP()
                    networks.append( ip )
                except:
                    #traceback.print_exc()
                    networks.append( u''+DEFAULT_NETWORK )
                    log.debug("Unable to get local network, using default %r", DEFAULT_NETWORK)
                    if verbose:
                        print(term.alert +
                              'ERROR: Unable to get your IP address and network automatically, using %s' % DEFAULT_NETWORK +
                              term.normal)
            else:
                networks = getmyIPs( term, verbose, not assume_yes )
                if not networks:
                    print(term.alert + 'No networks to force-scan, exiting.' + term.normal)
                    return None

    if snapshot:
        for ip in snapshot:
            networks.append( ip )
    else:
        snapshot = []

    if networks:
        if verbose:
            log.debug("Force-scanning networks: %r", networks)

        scan_ips = _generate_ip( networks, verbose, term )
        ip_scan = ip_scan_running = True
        if discover:
            ip_scan_delay = time.time() + 5

        # Warn user of scan duration
        if verbose:
            print(term.bold + '\n    Running Scan...' + term.dim)

    # If no scantime value set use default
    if not scantime:
        scantime = 0 if ip_scan_running else tinytuya.SCANTIME

    client_bcast_addrs = get_ip_to_broadcast()
    for bcast in client_bcast_addrs:
        addr = client_bcast_addrs[bcast]
        client_ip_broadcast_list[addr] = { 'broadcast': bcast }

    while ip_scan_running or scan_end_time > time.time() or device_end_time > time.time() or connect_next_round:
        if client:
            read_socks = [client, clients, clientapp]
        else:
            read_socks = []

        write_socks = []
        all_socks = {}
        remove = []
        connect_this_round = connect_next_round
        connect_next_round = []
        device_end_time = 0
        devices_with_timers = ''
        if timeout_time >= scan_end_time:
            do_timeout = True
        else:
            do_timeout = timeout_time <= time.time()
            if do_timeout: timeout_time = time.time() + 1.0 #connect_timeout

        for dev in devicelist:
            if dev.scanned and dev.ip not in scanned_devices:
                scanned_devices[dev.ip] = dev
            if do_timeout and dev.hard_time_limit < time.time():
                dev.stop()
            if dev.remove:
                remove.append(dev)
                #if dev.scanned:
                #    scanned_devices[dev.ip] = dev
                continue
            else:
                if do_timeout and dev.timeo <= time.time():
                    dev.timeout()

                if (not dev.passive) and ((dev.timeo + 1.0) > device_end_time):
                    # if dev.debug:
                    #     print('Resetting device scan end time due to debug ip', dev.ip, device_end_time, dev.timeo)
                    #     if len(devices_with_timers) < 64:
                    #         devices_with_timers += ' ' + str(dev.ip) + ' ' + str(int(dev.timeo))
                    device_end_time = dev.timeo + 1.0

            if not dev.sock:
                continue

            if dev.read:
                read_socks.append(dev.sock)

            if dev.write:
                write_socks.append(dev.sock)

            all_socks[dev.sock] = dev

        for dev in remove:
            devicelist.remove(dev)

        if show_timer:
            if scan_end_time > device_end_time:
                end_time = int(scan_end_time - time.time())
                if end_time < 0: end_time = 0
            else:
                end_time = 'Devs:'+str(len(devicelist))
            tim = 'FS:'+str(current_ip) if ip_scan_running else str(end_time)
            print("%sScanning... %s (%s) %s                                \r" % (term.dim, spinner[spinnerx], tim, devices_with_timers), end="")
            spinnerx = (spinnerx + 1) % 4
            sys.stdout.flush()

        try:
            if ip_scan_running:
                # half-speed the spinner while force-scanning
                need_sleep = 0.2
                # time out any sockets which have not yet connected
                # no need to run this every single time through the loop
                if ip_scan_delay:
                    if ip_scan_delay < time.time():
                        ip_scan_delay = False
                if (not ip_scan_delay) and len(write_socks) < max_parallel:
                    ip_scan_delay = False
                    want = max_parallel - len(write_socks)
                    # only open 10 at most during each pass through select()
                    if want > 10: want = 10
                    for i in range(want):
                        current_ip = next( scan_ips, None )
                        # all done!
                        if current_ip is None:
                            ip_scan_running = False
                            device_end_time = time.time() + connect_timeout + 1.0
                            need_sleep = 0.1
                            break
                        else:
                            if current_ip in broadcasted_devices:
                                continue
                            elif current_ip in snapshot and snapshot[current_ip]['version'] and snapshot[current_ip]['gwId']:
                                ip = current_ip
                                broadcasted_devices[ip] = PollDevice( ip, snapshot[current_ip], options, ip in debug_ips )
                                broadcasted_devices[ip].connect()
                                devicelist.append( broadcasted_devices[ip] )
                                check_end_time = time.time() + connect_timeout
                                if check_end_time > device_end_time: device_end_time = check_end_time
                            else:
                                if current_ip in snapshot:
                                    dev = ForceScannedDevice( current_ip, snapshot[current_ip], options, current_ip in debug_ips )
                                else:
                                    dev = ForceScannedDevice( current_ip, None, options, current_ip in debug_ips )
                                devicelist.append(dev)
                                write_socks.append(dev.sock)
                                all_socks[dev.sock] = dev

                            # we slept here so adjust the loop sleep time accordingly
                            time.sleep(0.02)
                            need_sleep -= 0.02

            if need_sleep > 0:
                time.sleep( need_sleep )

            if len(write_socks) > 0:
                rd, wr, _ = select.select( read_socks, write_socks, [], 0 )
            elif len(read_socks) > 0:
                rd, _, _ = select.select( read_socks, [], [], 0 )
                wr = []
            else:
                # not listening for broadcasts and no open sockets yet
                rd = []
                wr = []
        except KeyboardInterrupt as err:
            log.debug('Keyboard Interrupt')
            if verbose: print("\n**User Break**")
            user_break_count += 1

            if user_break_count == 1:
                ip_scan_running = False
                scan_end_time = 0
            elif user_break_count == 2:
                break
            else:
                log.debug('Keyboard Interrupt - Exiting')
                if verbose: print("\n**User Break** - Exiting")
                sys.exit()

        # these sockets are now writable (just connected) or failed
        for sock in wr:
            if sock in all_socks:
                all_socks[sock].write_data()

        # these sockets are now have data waiting to be read
        for sock in rd:
            # this sock is not a UDP listener
            if sock is not client and sock is not clients and sock is not clientapp:
                # may not exist if user-interrupted
                if sock in all_socks:
                    all_socks[sock].read_data()
                continue

            # if we are here then it is from a UDP listener
            if sock is client:
                tgt_port = UDPPORT
            elif sock is clients:
                tgt_port = UDPPORTS
            elif sock is clientapp:
                tgt_port = UDPPORTAPP
            else:
                tgt_port = '???'

            data, addr = sock.recvfrom(4048)
            ip = addr[0]
            result = b''
            try:
                result = tinytuya.decrypt_udp( data )
                result = json.loads(result)
                log.debug("Received valid UDP packet: %r", result)
            except:
                #traceback.print_exc()
                if verbose:
                    print(term.alertdim + "*  Unexpected payload from %r to port %r:%s %r (%r)\n" % (ip, tgt_port, term.normal, result, data))
                log.debug("Invalid UDP Packet from %r port %r - %r", ip, tgt_port, data)
                continue

            if ip_force_wants_end:
                continue

            if 'from' in result and result['from'] == 'app': #sock is clientapp:
                if ip not in broadcasted_apps:
                    broadcasted_apps[ip] = result
                    if verbose:
                        print( term.alertdim + 'New Broadcast from App at ' + str(ip) + term.dim + ' - ' + str(result) + term.normal )
                continue

            if 'gwId' not in result:
                if verbose:
                    print(term.alertdim + "*  Payload missing required 'gwId' - from %r to port %r:%s %r (%r)\n" % (ip, tgt_port, term.normal, result, data))
                log.debug("UDP Packet payload missing required 'gwId' - from %r port %r - %r", ip, tgt_port, data)
                continue

            # check to see if we have seen this device before and add to devices array
            #if tinytuya.appenddevice(result, deviceslist) is False:
            if ip not in broadcasted_devices:
                (dname, dkey, mac) = tuyaLookup(result['gwId'])
                result["name"] = dname
                result["key"] = dkey
                result["mac"] = mac

                if 'id' not in result:
                    result['id'] = result['gwId']

                if verbose:
                    broadcast_messages[ip] = term.alertdim + term.dim + 'New Broadcast from ' + str(ip) + ' / ' + str(mac) + ' ' + str(result) + term.normal
                    # if False:
                    #     print( data )
                    #     print( result )
                    #     print( broadcast_messages[ip] )

                #if not mac and SCANLIBS:
                #    a = time.time()
                #    mac = get_mac_address(ip=ip, network_request=False)
                #    b = time.time()
                #    if verbose:
                #        print('Discovered MAC', mac, 'in', (b-a))
                #    if mac and mac != '00:00:00:00:00:00':
                #        result["mac"] = mac

                # 20-digit-long IDs are product_idx + MAC
                if not mac and len(result['gwId']) == 20:
                    try:
                        mac = bytearray.fromhex( result['gwId'][-12:] )
                        result["mac"] = '%02x:%02x:%02x:%02x:%02x:%02x' % tuple(mac)
                    except:
                        pass

                broadcasted_devices[ip] = PollDevice( ip, result, options, ip in debug_ips )
                do_poll = False

                if poll:
                    # v3.1 does not require a key for polling, but v3.2+ do
                    if result['version'] != "3.1" and not dkey:
                        broadcasted_devices[ip].message = "%s    No Stats for %s: DEVICE KEY required to poll for status%s" % (term.alertdim, ip, term.dim)
                    elif user_break_count:
                        broadcasted_devices[ip].message = "%s    No Stats for %s: User interrupted scan%s" % (term.alertdim, ip, term.dim)
                    else:
                        # open a connection and dump it into the select()
                        do_poll = True

                if do_poll:
                    # delay at least 100ms
                    connect_next_round.append(ip)
                else:
                    broadcasted_devices[ip].close()

                if ip in wantips:
                    wantips.remove(ip)
                if broadcasted_devices[ip].deviceinfo['gwId'] in wantids:
                    wantids.remove( broadcasted_devices[ip].deviceinfo['gwId'] )
                if maxdevices:
                    maxdevices -= 1
                    if maxdevices == 0:
                        if verbose:
                            print('Found all the devices we wanted, ending scan early')
                        ip_wantips = False
                        ip_wantids = False
                        ip_force_wants_end = True
                        scan_end_time = 0
                        for dev in devicelist:
                            if (not dev.remove) and (not dev.passive) and ((dev.timeo + 1.0) > device_end_time):
                                device_end_time = dev.timeo + 1.0

                for dev in devicelist:
                    if dev.ip == ip:
                        if verbose:
                            print('Aborting force-scan for device', ip, 'due to received broadcast')
                        dev.abort()
                        break

        for ip in connect_this_round:
            broadcasted_devices[ip].connect()
            devicelist.append( broadcasted_devices[ip] )
            check_end_time = time.time() + connect_timeout
            if check_end_time > device_end_time: device_end_time = check_end_time

        if (not ip_scan_running) and wantips and scan_end_time <= time.time() and device_end_time <= time.time() and not user_break_count:
            if verbose:
                print("Not all devices were found by broadcast, starting force-scan for missing devices %r" % wantips)
            scan_ips = (i for i in wantips)
            wantips = None
            ip_scan_running = True

        if ip_wantids and (not bool(wantips)) and (not bool(wantids)):
            if verbose:
                print('Found all the device IDs we wanted, ending scan early')
            ip_wantids = False
            ip_force_wants_end = True
            scan_end_time = 0

        if ip_wantips and (not bool(wantips)) and (not bool(wantids)):
            if verbose:
                print('Found all the device IPs we wanted, ending scan early')
            ip_wantips = False
            ip_force_wants_end = True
            scan_end_time = 0
            for dev in devicelist:
                if (not dev.remove) and (not dev.passive) and ((dev.timeo + 1.0) > device_end_time):
                    device_end_time = dev.timeo + 1.0

        if discover and (not user_break_count) and (not ip_force_wants_end) and time.time() >= client_ip_broadcast_timer:
            client_ip_broadcast_timer = time.time() + BROADCASTTIME
            send_discovery_request( client_ip_broadcast_list )

    for sock in read_socks:
        sock.close()
    for sock in write_socks:
        sock.close()

    if client:
        client.close()
        clients.close()
        clientapp.close()

    for address in client_ip_broadcast_list:
        iface = client_ip_broadcast_list[address]
        if 'socket' in iface:
            iface['socket'].close()
            del iface['socket']

    if verbose:
        print( 'Scan completed in', round( time.time() - start_time, 4 ), 'seconds' )
        #print( len(response_list), response_list )

    ver_count = { '3.1': 0, '3.2': 0, '3.3': 0, '3.4': 0, '3.5': 0 }
    unknown_dev_count = 0
    no_key_count = 0

    for ip in broadcasted_devices:
        if ip in scanned_devices:
            del scanned_devices[ip]
        ver_str = str(broadcasted_devices[ip].deviceinfo['version'])
        if ver_str not in ver_count:
            ver_count[ver_str] = 1
        else:
            ver_count[ver_str] += 1

        if not broadcasted_devices[ip].deviceinfo['name']:
            unknown_dev_count += 1
        elif not broadcasted_devices[ip].deviceinfo['key']:
            no_key_count += 1

        if broadcasted_devices[ip].displayed and ip in broadcast_messages:
            del broadcast_messages[ip]

    for ip in scanned_devices:
        ver_str = str(scanned_devices[ip].deviceinfo['version'])
        if ver_str not in ver_count:
            ver_count[ver_str] = 1
        else:
            ver_count[ver_str] += 1

        if not scanned_devices[ip].deviceinfo['name']:
            unknown_dev_count += 1
        elif not scanned_devices[ip].deviceinfo['key']:
            no_key_count += 1

        if scanned_devices[ip].displayed and ip in broadcast_messages:
            # remove the "Received Broadcast from ..." line
            del broadcast_messages[ip]

        if scanned_devices[ip].sock or not scanned_devices[ip].displayed:
            scanned_devices[ip].stop()

    found_count = len(broadcasted_devices)+len(scanned_devices)

    if verbose:
        print(
            "                    \n%sScan Complete!  Found %s devices."
            % (term.normal, found_count)
        )
        print( 'Broadcasted:', len(broadcasted_devices) )
        if ip_scan:
            key_found = gwid_found = err_found = invalid = unmatched = 0
            for ip in scanned_devices:
                dev = scanned_devices[ip]
                if dev.key_found: key_found += 1
                if dev.gwid_found: gwid_found += 1
                if (not dev.key_found) and (not dev.gwid_found): unmatched += 1
                if dev.err_found: err_found += 1
                if not dev.ver_found: invalid += 1
            print( 'Force-Scanned:', len(scanned_devices), ' - Matched GWID:', gwid_found,'Matched Key:', key_found, 'Unmatched:', unmatched )
            if err_found or invalid:
                print( 'Force-Scan Errors: Connection Errors:', err_found, 'Version Detect Failed:', invalid )

        ver_found = ''
        for i in sorted(ver_count.keys()):
            if ver_count[i]:
                ver_found += ', %s: %s' % (i, ver_count[i])
        print( 'Versions:', ver_found[2:] )

        if unknown_dev_count:
            print( '%sUnknown Devices: %s%s' % (term.alert, unknown_dev_count, term.normal) )

        if no_key_count:
            print( '%sMissing Local Key: %s%s' % (term.alert, no_key_count, term.normal) )

        if wantips:
            print('%s%sDid not find %s devices by IP Address: %r%s' % (term.alert, term.yellow, len(wantips), wantips, term.normal))
        if wantids:
            print('%s%sDid not find %s devices by DevID: %r%s' % (term.alert, term.yellow, len(wantids), wantids, term.normal))

        if broadcast_messages:
            print('%sUndisplayed Broadcasts:%s' % (term.alert, term.normal))
            for ip in broadcast_messages:
                print( broadcast_messages[ip] )

    if byID:
        k = 'gwId'
    else:
        k = 'ip'
    devices = {} # pylint: disable=W0621
    for ip in broadcasted_devices:
        dev = broadcasted_devices[ip].deviceinfo
        dev['ip'] = ip
        dev['origin'] = 'broadcast'
        dkey = dev[k]
        devices[dkey] = dev

    for ip in scanned_devices:
        dev = scanned_devices[ip].deviceinfo
        dev['ip'] = ip
        dev['origin'] = 'forcescan'
        dkey = dev[k]
        if scanned_devices[ip].found and dkey not in devices:
            devices[dkey] = dev

    if verbose:
        # Save polling data into snapshot format
        devicesarray = list(devices.values())
        # Add devices from devices.json even if they didn't poll
        for item in tuyadevices:
            k = item["id"]
            if not any(d['gwId'] == k for d in devicesarray):
                tmp = item
                tmp["gwId"] = item["id"]
                tmp["ip"] = ''
                tmp['origin'] = 'cloud'
                devicesarray.append(tmp)
        save_snapshotfile( SNAPSHOTFILE, devicesarray, term )

    log.debug("Scan complete with %s devices found", found_count)
    return devices

def _get_gwid( old ):
    if 'gwId' in old and old['gwId']:
        return old["gwId"]
    if 'id' in old and old['id']:
        return old["id"]
    return 0

def _build_item( old, new ):
    item = {}
    item['id'] = item['gwId'] = _get_gwid( old )
    ip = ver = 0
    items = { 'ip':0, 'version':0, 'name':'', 'key':'', 'mac':None }
    for itm in items:
        if new and itm in new and new[itm]:
            item[itm] = new[itm]
        elif itm in old and old[itm]:
            item[itm] = old[itm]
        else:
            item[itm] = items[itm]
    return item

def _display_status( item, dps, term ):
    name = item['name']
    if name == "":
        name = item['gwId']
    ip = item['ip']
    if not ip:
        print("    %s[%-25.25s] %sError: No IP found%s" %
              (term.subbold, name, term.alert, term.normal))
    elif not dps:
        print("    %s[%-25.25s] %s%-18s - %sNo Response" %
              (term.subbold, name, term.dim, ip, term.alert))
    else:
        if '1' in dps or '20' in dps:
            state = term.alertdim + "[Off]" + term.dim
            if '1' in dps and dps['1'] is True:
                state = term.bold + "[On] " + term.dim
            elif '20' in dps and dps['20'] is True:
                state = term.bold + "[On] " + term.dim
            print("    %s[%-25.25s] %s%-18s - %s - DPS: %r" %
                  (term.subbold, name, term.dim, ip, state, dps))
        else:
            print("    %s[%-25.25s] %s%-18s - DPS: %r" %
                  (term.subbold, name, term.dim, ip, dps))

def _snapshot_load_item( itm ):
    # normalize all the fields
    itm['id'] = itm['gwId'] = _get_gwid( itm )
    if 'ver' in itm and itm['ver']:
        itm['version'] = float(itm['ver'])
        del itm['ver']
    elif 'version' in itm and itm['version']:
        itm['version'] = float(itm['version'])
    else:
        itm['version'] = 0.0
    return itm

def _snapshot_save_item( old ):
    # normalize all the fields
    # "version" is prefered over "ver", but saved as "ver"
    # "gwId" is prefered over "id", but saved as "id"
    item = {}
    item['id'] = _get_gwid( old )
    items = { 'ip':'', 'ver':'', 'origin':'', 'name':'', 'key':'', 'mac':'' }
    for itm in old:
        item[itm] = old[itm]

    for itm in items:
        if itm not in item or not item[itm]:
            item[itm] = items[itm]

    if 'version' in old:
        if old['version']:
            item['ver'] = old['version']
        del item['version']

    if 'gwId' in item:
        del item['gwId']

    item['ver'] = str(item['ver'])

    return item

def load_snapshotfile(fname):
    if (not fname) or (not isinstance(fname, str)):
        fname = SNAPSHOTFILE
    with open(fname) as json_file:
        data = json.load(json_file)
    devices = [] # pylint: disable=W0621
    if data and 'devices' in data:
        for dev in data['devices']:
            devices.append( _snapshot_load_item(dev) )
    if data:
        data['devices'] = devices
    return data

def save_snapshotfile(fname, data, term=None):
    if (not fname) or (not isinstance(fname, str)):
        fname = SNAPSHOTFILE
    if term:
        norm = term.normal
        bold = term.bold
    else:
        norm = bold = ''
    devices = [] # pylint: disable=W0621
    if type(data) == dict:
        data = list(data.values())
    for itm in data:
        devices.append( _snapshot_save_item(itm) )
    current = {'timestamp' : time.time(), 'devices' : devices}
    output = json.dumps(current, indent=4)
    print(bold + "\n>> " + norm + "Saving device snapshot data to " + fname + "\n")
    with open(fname, "w") as outfile:
        outfile.write(output)

# Scan Devices in snapshot.json
def snapshot(color=True, assume_yes=False, skip_poll=None):
    """Uses snapshot.json to scan devices

    Parameters:
        color = True or False, print output in color [Default: True]
        assume_yes = True or False, auto-answer 'yes' to "Poll local devices?" (ignored when skip_poll is set)
        skip_poll = True or False, auto-answer 'no' to "Poll local devices?" (overrides assume_yes)
    """
    # Terminal formatting
    termcolors = tinytuya.termcolor(color)
    term = TermColors( *termcolors )

    print(
        "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
        % (term.bold, term.normal, term.dim, tinytuya.__version__)
    )

    try:
        data = load_snapshotfile(SNAPSHOTFILE)
    except Exception as e:
        #traceback.print_exc(0)
        print("%s ERROR: Missing %s file:%s %s: %s\n" % (term.alert, SNAPSHOTFILE, term.normal, type(e).__name__, e))
        return

    print("%sLoaded %s - %d devices:\n" % (term.dim, SNAPSHOTFILE, len(data["devices"])))

    # Print a table with all devices
    table = []
    print("%s%-25s %-24s %-15s %-17s %-5s" % (term.normal, "Name","ID", "IP","Key","Version"))
    print(term.dim)
    by_ip = {}
    devicesx = sorted(data["devices"], key=lambda x: x['name'])
    for idx in devicesx:
        device = _build_item( idx, None )
        ips = device['ip'].ljust(15) if device['ip'] else (term.alert + "E: No IP found " + term.normal)
        dname = device['name']
        if dname == "":
            dname = device['gwId']
        print("%s%-25.25s %s%-24s %s%s %s%-17s %s%-5s" %
            (term.dim, dname, term.cyan, device['gwId'], term.subbold, ips, term.red, device['key'], term.yellow, device['version']))
        if device['ip']:
            by_ip[device['ip']] = device

    # Find out if we should poll all devices
    if skip_poll:
        answer = 'n'
    elif assume_yes:
        answer = 'y'
    else:
        answer = input(term.subbold + '\nPoll local devices? ' + term.normal + '(Y/n): ')
    if answer.lower().find('n') < 0:
        print("")
        print("%sPolling %s local devices from last snapshot..." % (term.normal, len(devicesx)))
        result = devices(verbose=False, color=color, poll=True, byID=True, discover=False, snapshot=by_ip)

        for i in devicesx:
            gwId = _get_gwid( i )
            if not gwId or gwId not in result:
                item = _build_item( i, None )
                _display_status( item, None, term )
            else:
                item = _build_item( i, result[gwId] )
                if 'dps' in result[gwId] and 'dps' in result[gwId]['dps'] and result[gwId]['dps']['dps']:
                    _display_status( item, result[gwId]['dps']['dps'], term )
                else:
                    _display_status( item, None, term )

        # for loop
    # if poll
    print("%s\nDone.\n" % term.dim)
    return


# Scan All Devices in devices.json
def alldevices(color=True, scantime=None, forcescan=False, discover=True, assume_yes=False, skip_poll=None):
    """Uses devices.json to scan devices

    Parameters:
        color = True or False, print output in color [Default: True]
    """
    # Terminal formatting
    #(bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)
    termcolors = tinytuya.termcolor(color)
    term = TermColors( *termcolors )

    print(
        "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
        % (term.bold, term.normal, term.dim, tinytuya.__version__)
    )
    # Check to see if we have additional Device info
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tuyadevices = json.load(f)
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
    except:
        print("%s ERROR: Missing %s file\n" % (term.alert, DEVICEFILE))
        return

    print("%sLoaded %s - %d devices:" % (term.dim, DEVICEFILE, len(tuyadevices)))

    # Display device list
    print("\n\n" + term.bold + "Device Listing\n" + term.dim)
    output = json.dumps(sorted(tuyadevices,key=lambda x: x['name']), indent=4)
    print(output)

    # Find out if we should poll all devices
    if skip_poll:
        answer = 'n'
    elif assume_yes:
        answer = 'y'
    else:
        answer = input(term.subbold + '\nPoll local devices? ' + term.normal + '(Y/n): ')
    if answer.lower().find('n') < 0:
        poll_and_display( tuyadevices, color=color, scantime=scantime, snapshot=True, forcescan=forcescan, discover=discover )

    print("%s\nDone.\n" % term.dim)
    return

def poll_and_display( tuyadevices, color=True, scantime=None, snapshot=False, forcescan=False, discover=True ): # pylint: disable=W0621
    termcolors = tinytuya.termcolor(color)
    term = TermColors( *termcolors )

    by_id = [x['id'] for x in tuyadevices]
    # Scan network for devices and provide polling data
    print(term.normal + "\nScanning local network for Tuya devices...")
    result = devices(verbose=False, poll=True, byID=True, scantime=scantime, wantids=by_id, show_timer=True, forcescan=forcescan, tuyadevices=tuyadevices, discover=discover)
    print("    %s%s local devices discovered%s" % (term.dim, len(result), term.normal))
    print("")

    polling = []
    print("Polling local devices...")
    # devices = sorted(data["devices"], key=lambda x: x['name'])
    for idx in sorted(tuyadevices, key=lambda x: x['name']):
        gwId = _get_gwid( idx )
        if gwId and gwId in result:
            item = _build_item( idx, result[gwId] )
            if 'dps' in result[gwId] and 'dps' in result[gwId]['dps']:
                _display_status( item, result[gwId]['dps']['dps'], term )
            else:
                _display_status( item, None, term )
        else:
            item = _build_item( idx, None )
            _display_status( item, None, term )
        polling.append(item)
    # for loop

    if snapshot:
        # Save polling data snapsot
        save_snapshotfile( SNAPSHOTFILE, result, term )

    return polling

# Scan Devices in tuyascan.json - respond in JSON
def snapshotjson():
    """Uses snapshot.json to scan devices - respond with json
    """
    polling = []

    try:
        data = load_snapshotfile(SNAPSHOTFILE)
    except:
        current = {'timestamp' : time.time(), 'error' : 'Could not load JSON snapshot file: %s' % SNAPSHOTFILE}
        output = json.dumps(current, indent=4)
        print(output)
        return

    devicesx = sorted(data["devices"], key=lambda x: x['name'])
    by_ip = {}
    for idx in devicesx:
        if 'ip' in idx and idx['ip']:
            device = _build_item( idx, None )
            by_ip[idx['ip']] = device

    resp = devices(verbose=False, scantime=0, poll=True, byID=True, discover=False, snapshot=by_ip)

    for idx in devicesx:
        gwId = _get_gwid( idx )

        if gwId and gwId in resp:
            item = _build_item( idx, resp[gwId] )
        else:
            item = _build_item( idx, None )
        if not item['ip']:
            item['error'] = "No IP"
        elif gwId not in resp or 'dps' not in resp[gwId] or 'dps' not in resp[gwId]['dps'] or not resp[gwId]['dps']['dps']:
            item['error'] = "No Response"
        else:
            item['dps'] = resp[gwId]['dps']['dps']
        polling.append(item)
    # for loop
    current = {'timestamp' : time.time(), 'devices' : polling}
    output = json.dumps(current, indent=4)
    print(output)
    return


if __name__ == '__main__':

    try:
        scan()
    except KeyboardInterrupt:
        pass
