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
from colorama import init
from hashlib import sha256
import hmac
import base64
import tinytuya

import traceback

# Optional libraries required for forced scanning
try:
    from getmac import get_mac_address
    SCANLIBS = True
except:
    SCANLIBS = False

# Backward compatability for python2
try:
    input = raw_input
except NameError:
    pass

try:
    import netifaces
    NETIFLIBS = True
except:
    NETIFLIBS = False

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
TIMEOUT = tinytuya.TIMEOUT          # Socket Timeout
SCANTIME = tinytuya.SCANTIME        # How many seconds to wait before stopping

max_parallel = 300
connect_timeout = 3

devinfo_keys = ('ip', 'mac', 'name', 'key', 'gwId', 'active', 'ablilty', 'encrypt', 'productKey', 'version', 'token', 'wf_cfg' )
# id ver

TermColors = namedtuple("TermColors", "bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow")

FSCAN_NOT_STARTED = 0
FSCAN_INITIAL_CONNECT = 1
FSCAN_v3x_PROVOKE_RESPONSE = 2
FSCAN_v34_BRUTE_FORCE_ACTIVE = 3
FSCAN_v33_BRUTE_FORCE_ACQUIRE = 4
FSCAN_v31_PASSIVE_LISTEN = 5
#FSCAN_ = 6
FSCAN_FINAL_POLL = 100


# Logging
log = logging.getLogger(__name__)

# Helper Functions
def getmyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    return str(r)

def getmyIPs( term, ask ):
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
                answer = input( '%sScan network %s from interface %s?%s (Y/n): ' % (term.bold, k, str(interface), term.normal) )
                if answer[0:1].lower() == 'n':
                    continue
                print(term.dim + 'Adding Network', k, 'to the force-scan list')
            ips[k] = True
    return ips.keys()

class KeyObj(object):
    def __init__( self, key ):
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
        self.cur_key = None
        self.hard_time_limit = time.time() + 30
        self.initial_connect_retries = options['retries']

        if not deviceinfo:
            deviceinfo = {}
        self.deviceinfo = deviceinfo
        for k in devinfo_keys:
            if k not in deviceinfo:
                self.deviceinfo[k] = ''

        if not self.deviceinfo['version']:
            self.deviceinfo['version']  = 3.1
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
        self.device = tinytuya.OutletDevice( self.deviceinfo['gwId'], self.ip, key, version=float(self.deviceinfo['version']))
        self.device.set_socketPersistent(True)
        self.device.socket = self.sock


    def close( self ):
        if self.sock: self.sock.close()
        self.sock = None
        self.read = self.write = False
        self.remove = True

    def stop(self):
        if self.sock:
            self.close()

    def get_peer(self):
        try:
            # getpeername() blows up with "OSError: [Errno 107] Transport endpoint is
            # not connected" if the connection was refused
            addr = self.sock.getpeername()[0]
        except:
            addr = None
            if self.debug:
                print('Debug sock', self.ip, 'failed!')
                print(self.sock)
                print(traceback.format_exc())

        # connection failed
        if not addr:
            # sometimes the devices accept the connection, but then immediately close it
            # so, retry if that happens
            try:
                # this should throw either ConnectionResetError or ConnectionRefusedError
                r = self.sock.recv( 5000 )
                if self.debug:
                    print('recv:', r)
            # ugh, ConnectionResetError and ConnectionRefusedError are not available on python 2.7
            #except ConnectionResetError:
            except OSError as e:
                if self.initial_connect_retries and e.errno == errno.ECONNRESET:
                    self.initial_connect_retries -= 1
                    # connected, but then closed
                    return False
                else:
                    if self.debug:
                        print('failed 1', self.ip, e.errno, errno.ECONNRESET)
                        print(traceback.format_exc())
                    return None
            except:
                if self.debug:
                    print('failed 2', self.ip)
                    print(traceback.format_exc())
                self.close()
                return None
            # we should never get here
            return False
        return addr

    def v34_negotiate_sess_key_start( self ):
        if self.debug:
            print('v3.4 trying key', self.ip, self.device.real_local_key)
        self.device.local_nonce = b'0123456789abcdef'
        self.device.remote_nonce = b''
        self.device.local_key = self.device.real_local_key
        self.sock.sendall( self.device._encode_message( tinytuya.MessagePayload(tinytuya.SESS_KEY_NEG_START, self.device.local_nonce) ) )
        if self.debug:
            print('v3.4 session key neg start, debug ip', self.ip)


    def v34_negotiate_sess_key_step_2( self, rkey ):
        if not rkey or type(rkey) != tinytuya.TuyaMessage or len(rkey.payload) < 48:
            # error
            self.deviceinfo["err"] = 'v3.4 device session key negotiation failed on step 1'
            log.debug(self.deviceinfo["err"])
            return False

        lastloglevel = log.level
        if self.debug:
            log.setLevel(logging.DEBUG)

        payload = rkey.payload
        try:
            log.debug("decrypting=%r", payload)
            cipher = tinytuya.AESCipher(self.device.real_local_key)
            payload = cipher.decrypt(payload, False, decode_text=False)
        except:
            self.deviceinfo["err"] = 'v3.4 device session key step 2 decrypt failed, payload=%r (len:%d) l-key:%r l-nonce:%r' % (payload, len(payload), self.device.real_local_key, self.device.local_nonce)
            log.warning(self.deviceinfo["err"], exc_info=True)
            log.setLevel(lastloglevel)
            return False

        log.debug("decrypted session key negotiation step 2 payload=%r", payload)
        log.debug("payload type = %s len = %d", type(payload), len(payload))

        if len(payload) < 48:
            self.deviceinfo["err"] = "v3.4 device session key negotiation step 2 failed, too short response"
            log.debug(self.deviceinfo["err"])
            log.setLevel(lastloglevel)
            return False

        self.device.remote_nonce = payload[:16]
        hmac_check = hmac.new(self.device.local_key, self.device.local_nonce, sha256).digest()

        if hmac_check != payload[16:48]:
            log.debug("session key negotiation step 2 failed HMAC check! wanted=%r but got=%r", binascii.hexlify(hmac_check), binascii.hexlify(payload[16:48]))

        log.debug("session local nonce: %r remote nonce: %r", self.device.local_nonce, self.device.remote_nonce)

        rkey_hmac = hmac.new(self.device.local_key, self.device.remote_nonce, sha256).digest()
        self.sock.sendall( self.device._encode_message( tinytuya.MessagePayload(tinytuya.SESS_KEY_NEG_FINISH, rkey_hmac) ) )

        if tinytuya.IS_PY2:
            k = [ chr(ord(a)^ord(b)) for (a,b) in zip(self.device.local_nonce,self.device.remote_nonce) ]
            self.device.local_key = ''.join(k)
        else:
            self.device.local_key = bytes( [ a^b for (a,b) in zip(self.device.local_nonce,self.device.remote_nonce) ] )
        log.debug("Session nonce XOR'd: %r" % self.device.local_key)

        cipher =  tinytuya.AESCipher(self.device.real_local_key)
        self.device.local_key = cipher.encrypt(self.device.local_key, False, pad=False)
        log.debug("Session key negotiate success! session key: %r", self.device.local_key)
        log.setLevel(lastloglevel)
        return True


class ForceScannedDevice(DeviceDetect):
    def __init__( self, ip, deviceinfo, options, debug ):
        super(ForceScannedDevice, self).__init__( ip, deviceinfo, options, debug )
        self.retries = 0
        self.keygen = None
        self.brute_force_data = []

        self.connect()

    def stop( self ):
        super(ForceScannedDevice, self).stop()

        if self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
            self.brute_force_v3x()

        if self.options['verbose'] and self.found and not self.displayed:
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan, FORCED STOP', self.options['termcolors'], self.message )
            self.displayed = True

    def timeout( self, forced=False ):
        if self.remove:
            return

        if self.step == FSCAN_NOT_STARTED:
            self.remove = True
            self.err_found = True
            if self.debug:
                print('Debug sock', self.ip, 'timed out!')
                print(dict(self))
        elif self.step == FSCAN_INITIAL_CONNECT:
            if self.retries < 2:
                self.retries += 1
                if self.debug:
                    print('Debug sock', self.ip, 'socket send failed')
                self.connect()
            else:
                if self.debug:
                    print('closed thrice:', self.ip)
                # closed twice, probably a v3.4 device!
                self.retries = 0
                self.step = FSCAN_v34_BRUTE_FORCE_ACTIVE
                self.deviceinfo['version'] = self.deviceinfo['ver'] = 3.4
                self.keygen = (i for i in self.options['keylist'] if not i.used)
                self.cur_key = next( self.keygen, None )
                if self.debug:
                    print('keygen gave:', self.cur_key, self.ip)
                if self.cur_key is None:
                    self.remove = True
                else:
                    self.connect()
        elif self.step == FSCAN_v34_BRUTE_FORCE_ACTIVE:
            if not forced:
                # actual timeout, connect failed
                if self.retries == 0:
                    self.retries += 1
                    self.connect()
                else:
                    self.err_found = True
                    self.message = "%s    Polling %s Failed: Device stopped responding before key was found" % (self.options['termcolors'].alertdim, self.ip)
                    _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message )
                    self.displayed = True
                    self.close()
                    return
            # brute-forcing the key
            self.cur_key = next( self.keygen, None )
            if self.debug:
                print('trying next key', self.ip, self.cur_key.key)
            if self.cur_key is None:
                # Keep trying.  Go through the list again but include "already-used" keys as well
                #self.remove = True
                self.passive = True
                self.keygen = (i for i in self.options['keylist'])
                self.cur_key = next( self.keygen, None )
                if self.cur_key is None:
                    self.remove = True
                else:
                    self.connect()
            else:
                self.connect()
        elif forced:
            self.err_found = True
            self.message = "%s    Polling %s Failed: Unexpected close during read/write operation" % (self.options['termcolors'].alertdim, self.ip)
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message )
            self.displayed = True
            self.remove = True
        elif self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
            if not self.brute_force_v3x():
                # passively wait for async status updates
                self.timeo = time.time() + 5.0
                self.passive = True
        else:
            self.remove = True
            _print_device_info( self.deviceinfo, 'Failed to Force-Scan', self.options['termcolors'], self.message )
            self.displayed = True

        if self.remove:
            self.close()

    def write_data( self ):
        # get_peer() returns:
        #  'None' on connection refused
        #  'False' when connection was made but then closed
        #  The IP address when the connection is still open
        addr = self.get_peer()
        if addr is None:
            # refused
            self.close()
            return
        elif addr is False:
            # sometimes the devices immediately close the connection, so retry
            if self.debug:
                print('retrying', self.ip)
            self.sock.close()
            self.connect()
            return

        # connection succeeded!
        #self.timeo = time.time() + self.options['data_timeout']
        self.timeo = time.time() + 1.0
        self.found = True

        if len(self.send_queue) > 0:
            self.sock.sendall( self.device._encode_message( self.send_queue[0] ) )
            self.send_queue = self.send_queue[1:]
            if len(self.send_queue) == 0:
                self.write = False
                self.read = True
            return

        self.write = False
        self.read = True
        #mac = get_mac_address(ip=self.ip,network_request=False) if SCANLIBS else None
        mac = ''
        if not self.deviceinfo['mac']: self.deviceinfo['mac'] = mac
        log.debug("Force-Scan Found Device %s", self.ip)
        #if self.options['verbose'] and self.step == 0:
        if self.debug and self.step == 0:
            print(" Force-Scan Found Device %s" % (self.ip,))

        if self.step == FSCAN_NOT_STARTED:
            self.scanned = True
            self.step = FSCAN_INITIAL_CONNECT
            # try to figure out what version device it is by sending an unencrypted status request
            # v3.1 devices will return the status
            # v3.2 devices will ???
            # v3.3 devices will return an encrypted rejection message
            # v3.4 devices will slam the door in our face by dropping the connection
            msg = self.device._encode_message( tinytuya.MessagePayload(tinytuya.DP_QUERY, b'') )
            self.sock.sendall( msg )
        elif self.step == FSCAN_v34_BRUTE_FORCE_ACTIVE:
            # try to brute-force the key
            self.v34_negotiate_sess_key_start()

    def read_data( self ):
        try:
            data = self.sock.recv( 5000 )
        except:
            data = b''

        if self.debug:
            print(self.ip, 'got step', self.step, 'data:', data )

        if len(data) ==	0:
            self.timeout( True )
            return

        while len(data):
            try:
                prefix_offset = data.find(tinytuya.PREFIX_BIN)
                if prefix_offset > 0:
                    data = data[prefix_offset:]
                hmac_key = self.device.local_key if self.deviceinfo['version'] == 3.4 else None
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
                self.ver_found = True
                self.deviceinfo['key'] = self.cur_key.key
                self.found_key()
                self.cur_key.used = True
                self.send_queue.append(self.device.generate_payload(tinytuya.DP_QUERY))
                return

            if msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
                self.deviceinfo['version'] = self.deviceinfo['ver'] = 3.1
                payload = msg.payload[len(tinytuya.PROTOCOL_VERSION_BYTES_31)+16 :]
                self.ver_found = True
            elif msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                self.deviceinfo['version'] = self.deviceinfo['ver'] = 3.3
                payload = msg.payload[len(tinytuya.PROTOCOL_33_HEADER) :]
                self.ver_found = True
            else:
                payload = msg.payload

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
                        # there is no good way of brute-forcing this one, so listen passively in hopes of receiving a message containing the gwId
                        self.step = FSCAN_v31_PASSIVE_LISTEN
                        self.passive = True
                        have_err_string = True
                except:
                    pass

                if not have_err_string:
                    # encrypted response, probably v3.3
                    self.device.set_version(3.3)
                    self.deviceinfo['version'] = self.deviceinfo['ver'] = 3.3
                    self.step = FSCAN_v33_BRUTE_FORCE_ACQUIRE
                    self.brute_force_data.append( payload )

            elif self.step == FSCAN_v33_BRUTE_FORCE_ACQUIRE:
                # no timout resetting for this one, let self.timeout() process the data
                self.brute_force_data.append( payload )

            elif self.step == FSCAN_v31_PASSIVE_LISTEN:
                if msg.cmd == tinytuya.STATUS and msg.retcode == 0:
                    try:
                        self.brute_force_data.append( base64.b64decode( payload ) )
                        self.brute_force_v3x()
                    except:
                        pass

            elif self.step == FSCAN_FINAL_POLL:
                result = self.device._decode_payload( msg.payload )
                if self.debug:
                    print(self.ip, self.step, payload)
                    print(result)

                finished = False
                if 'dps' in result:
                    if len(result['dps']) > 2:
                        finished = True
                    self.message = "%s    Status: %s" % (self.options['termcolors'].dim, result["dps"])
                elif 'Error' in result:
                    self.message = "%s    Error: %s" % (self.options['termcolors'].alertdim, result)
                else:
                    self.message = "%s    Status: %s" % (self.options['termcolors'].dim, result)

                if self.options['verbose'] and finished:
                    _print_device_info( self.deviceinfo, 'Force-Scanned', self.options['termcolors'], self.message )
                    self.displayed = True

                if finished:
                    self.close()
                return
            
    def brute_force_v3x( self ):
        if len( self.brute_force_data ) == 0:
            return False

        for key in (i for i in self.options['keylist'] if not i.used):
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
                        print(' ', self.ip, 'decrypted:', text)
                    matched = cipher.key
                except:
                    pass

                if not matched:
                    bad = True
                    break

            if matched and not bad:
                if self.debug: #self.options['verbose']:
                    print(' v3.3 brute forced key', matched, 'for', self.ip)
                self.brute_force_data = []
                self.read = True
                self.write = False
                self.ver_found = True
                self.deviceinfo['key'] = matched.decode()
                self.found_key()
                self.device.local_key = self.device.real_local_key = matched
                self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )
                self.step = FSCAN_FINAL_POLL
                key.used = True
                return True

        self.brute_force_data =	[]
        return False

    def found_key( self ):
        for dev in self.options['tuyadevices']:
            if dev['key'] == self.deviceinfo['key']:
                self.deviceinfo['name'] = dev['name']
                self.deviceinfo['id'] = self.deviceinfo['gwId'] = dev['id']
                self.device.id = dev['id']
                self.key_found = True
                return


class PollDevice(DeviceDetect):
    def __init__( self, ip, deviceinfo, options, debug ):
        super(PollDevice, self).__init__( ip, deviceinfo, options, debug )
        self.broadcasted = True
        self.retries = options['retries']

    def close(self):
        super(PollDevice, self).close()
        mac = get_mac_address(ip=self.ip,network_request=False) if SCANLIBS else None
        if mac:
            self.deviceinfo['mac'] = mac

        if self.options['verbose']:
            _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'], self.message )

    def	timeout( self ):
        if self.retries > 0:
            if self.debug:
                print('Timeout for debug ip', self.ip, '- reconnecting, retries', self.retries)
            self.retries -= 1
            self.sock.close()
            self.connect()
            self.timeo = time.time() + tinytuya.TIMEOUT
            if self.debug:
                print('New timeo:', self.timeo)
        else:
            if self.debug:
                print('Final timeout for debug ip', self.ip, 'aborting')
            self.message = "%s    Polling %s Failed: %s" % (self.options['termcolors'].alertdim, self.ip, self.deviceinfo["err"])
            self.close()

    def write_data( self ):
        addr = self.get_peer()
        if not addr:
            if ("err" not in self.deviceinfo) or (not self.deviceinfo["err"]):
                self.deviceinfo["err"] = "Connect Failed"
            if self.debug:
                print('Debug sock', self.ip, 'failed!')
                print(addr)
                print(self.sock)
                print(traceback.format_exc())
            self.timeout()
            return

        # connection succeeded!
        self.timeo = time.time() + self.options['data_timeout']
        if self.debug:
            print('WD New timeo:', self.timeo)

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
            if self.device.version == 3.4 :
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
                hmac_key = self.device.local_key if self.device.version == 3.4 else None
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
                log.debug("raw unpacked message = %r", msg)
                result = self.device._decode_payload(msg.payload)
            except:
                log.debug("error unpacking or decoding tuya JSON payload")
                result = tinytuya.error_json(tinytuya.ERR_PAYLOAD)

            # Did we detect a device22 device? Return ERR_DEVTYPE error.
            if dev_type != self.device.dev_type:
                log.debug(
                    "Device22 detected and updated (%s -> %s) - Update payload and try again",
                    dev_type,
                    self.device.dev_type,
                )
                self.sock.sendall( self.device._encode_message( self.device.generate_payload(tinytuya.DP_QUERY) ) )
                break

            self.finished = True
            self.deviceinfo['type'] = self.device.dev_type

            if not result or "dps" not in result:
                if result and "Error" in result:
                    self.message = "%s    Access rejected by %s: %s: %s" % (self.options['termcolors'].alertdim, self.ip, result["Error"], result["Payload"])
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
def scan(scantime=None, color=True, forcescan=False):
    """Scans your network for Tuya devices with output to stdout"""
    devices(verbose=True, scantime=scantime, color=color, poll=True, forcescan=forcescan)

def _generate_ip(networks, verbose, term):
    for netblock in networks:
        if tinytuya.IS_PY2 and type(netblock) == str:
            netblock = netblock.decode('latin1')
        try:
            # Fetch my IP address and assume /24 network
            network = ipaddress.ip_network(netblock)
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

def _print_device_info( result, note, term, extra_message=None ):
        ip = result["ip"]
        gwId = result["gwId"]
        productKey = result["productKey"] if result["productKey"] else '?'
        version = result["version"] if result["version"] and result["version"] != '0.0' else '?'
        devicename = result["name"]
        dkey = result["key"]
        mac = result["mac"]

        suffix = term.dim + ", MAC = " + mac + ""
        if result['name'] == "":
            dname = gwId
            devicename = "Unknown v%s%s Device%s" % (term.normal, version, term.dim)
        else:
            devicename = term.normal + result['name'] + term.dim
        print(
            "%s   Product ID = %s  [%s]:\n    %sAddress = %s,  %sDevice ID = %s, %sLocal Key = %s,  %sVersion = %s%s"
            % (
                devicename,
                productKey,
                note,
                term.subbold,
                ip,
                term.cyan,
                gwId,
                term.red,
                dkey,
                term.yellow,
                version,
                suffix
            )
        )

        if extra_message:
            print( extra_message )


# Scan function
def devices(verbose=False, scantime=None, color=True, poll=True, forcescan=False, byID=False, show_timer=None, discover=True, wantips=None, wantids=None, snapshot=None):
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        scantime = The time to wait to pick up UDP from all devices
        color = True or False, print output in color [Default: True]
        poll = True or False, poll dps status for devices if possible
        forcescan = True or False, force network scan for device IP addresses
        byID = True or False, return dictionary by ID, otherwise by IP (default)

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
    havekeys = False
    tuyadevices = []

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

    if discover:
        # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.bind(("", UDPPORT))
        #client.settimeout(TIMEOUT)
        # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
        clients = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        clients.bind(("", UDPPORTS))
        #clients.settimeout(TIMEOUT)
    else:
        client = clients = None

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
        print(
            "%sScanning on UDP ports %s and %s for devices for %d seconds...%s\n"
            % (term.subbold, UDPPORT, UDPPORTS, scantime, term.normal)
        )

    #debug_ips = ['172.20.10.106','172.20.10.107','172.20.10.114','172.20.10.138','172.20.10.156','172.20.10.166','172.20.10.175','172.20.10.181','172.20.10.191', '172.20.10.67'] #,'172.20.10.102', '172.20.10.1']
    #debug_ips = ['172.20.10.107']
    debug_ips = ["10.0.1.36"] #['172.24.5.112']
    networks = []
    scanned_devices = {}
    broadcasted_devices = {}
    devicelist = []
    read_socks = []
    write_socks = []
    count = 0
    counts = 0
    spinnerx = 0
    spinner = "|/-\\|"
    ip_list = {}
    response_list = {}
    connect_this_round = []
    connect_next_round = []
    ip_wantips = bool(wantips)
    ip_wantids = bool(wantids)
    ip_force_wants_end = False
    ip_scan = False
    ip_scan_running = False
    scan_end_time = time.time() + scantime
    device_end_time = 0
    log.debug("Listening for Tuya devices on UDP 6666 and 6667")
    start_time = time.time()
    timeout_time = time.time() + 5
    current_ip = None
    need_sleep = 0.1
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
        options['keylist'].append( KeyObj( i['key'] ) )

    if not wantips:
        wantips = [] #'172.20.10.3']
    if not wantids:
        wantids = [] #['abcdef']

    if forcescan:
        if verbose:
            print(term.subbold + "    Option: " + term.dim + "Network force scanning requested.\n")

        fstype = type(forcescan)
        if fstype != list and fstype != tuple:
            if not NETIFLIBS:
                print(term.alert +
                      '    NOTE: netifaces module not available, multi-interface machines will be limited.\n'
                      '           (Requires: pip install netifaces)\n' + term.dim)
            else:
                networks = getmyIPs( term, verbose )

            if len(networks) == 0:
                try:
                    ip = getmyIP()+'/24'
                    networks.append( ip )
                except:
                    networks.append( u''+DEFAULT_NETWORK )
                    log.debug("Unable to get local network, using default %r", DEFAULT_NETWORK)
                    if verbose:
                        print(term.alert +
                              'ERROR: Unable to get your IP address and network automatically.'
                              '       (using %s)' % DEFAULT_NETWORK + term.normal)
        else:
            for ip in forcescan:
                networks.append( ip )

    if snapshot:
        for ip in snapshot:
            networks.append( ip )
    else:
        snapshot = []

    if networks:
        scan_ips = _generate_ip( networks, verbose, term )
        ip_scan = ip_scan_running = True

        # Warn user of scan duration
        if verbose:
            print(term.bold + '\n    Running Scan...' + term.dim)

    # If no scantime value set use default
    if not scantime:
        scantime = 0 if ip_scan_running else tinytuya.SCANTIME

    while ip_scan_running or scan_end_time > time.time() or device_end_time > time.time() or connect_next_round:
        if client:
            read_socks = [client, clients]
        else:
            read_socks = []

        write_socks = []
        all_socks = {}
        remove = []
        connect_this_round = connect_next_round
        connect_next_round = []
        device_end_time = 0
        devices_with_timers = ''
        if timeout_time > scan_end_time:
            do_timeout = True
        else:
            do_timeout = timeout_time < time.time()
            if do_timeout: timeout_time = time.time() + 1.0 #connect_timeout

        for dev in devicelist:
            if do_timeout and dev.hard_time_limit < time.time():
                dev.stop()
            if dev.remove:
                remove.append(dev)
                if dev.scanned:
                    scanned_devices[dev.ip] = dev
                continue
            else:
                if do_timeout and dev.timeo < time.time():
                    dev.timeout()

                if (not dev.passive) and ((dev.timeo + 1.0) > device_end_time):
                    if dev.debug:
                        print('Resetting device scan end time due to debug ip', dev.ip, device_end_time, dev.timeo)
                    device_end_time = dev.timeo + 1.0
                    #if len(devices_with_timers) < 64:
                    #    devices_with_timers += ' ' + str(dev.ip) + ' ' + str(int(dev.timeo))

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
            end_time = int((scan_end_time if scan_end_time > device_end_time else device_end_time) - time.time())
            if end_time < 0: end_time = 0
            tim = 'FS:'+str(current_ip) if ip_scan_running else str(end_time)
            print("%sScanning... %s (%s) %s                                \r" % (term.dim, spinner[spinnerx], tim, devices_with_timers), end="")
            spinnerx = (spinnerx + 1) % 4
            sys.stdout.flush()

        if ip_scan_running:
            # half-speed the spinner while force-scanning
            need_sleep = 0.2
            # time out any sockets which have not yet connected
            # no need to run this every single time through the loop
            if len(write_socks) < max_parallel:
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
                            pass
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

        try:
            if need_sleep > 0:
                time.sleep( need_sleep )
            if len(write_socks) > 0:
                rd, wr, _ = select.select( read_socks, write_socks, [], 0 )
            else:
                rd, _, _ = select.select( read_socks, [], [], 0 )
                wr = []
        except KeyboardInterrupt as err:
            log.debug("Keyboard Interrupt - Exiting")
            if verbose: print("\n**User Break**")
            sys.exit()

        # these sockets are now writable (just connected) or failed
        for sock in wr:
            all_socks[sock].write_data()

        # these sockets are now have data waiting to be read
        for sock in rd:
            # this sock is not a UDP listener
            if sock is not client and sock is not clients:
                all_socks[sock].read_data()
                continue

            # if we are here then it is from a UDP listener
            data, addr = sock.recvfrom(4048)
            ip = addr[0]
            try:
                result = data[20:-8]
                try:
                    result = tinytuya.decrypt_udp(result)
                except:
                    result = result.decode()

                result = json.loads(result)
                log.debug("Received valid UDP packet: %r", result)
            except:
                if verbose:
                    print(term.alertdim + "*  Unexpected payload=%r\n" + term.normal, result)
                log.debug("Invalid UDP Packet: %r", result)
                continue

            if ip_force_wants_end:
                continue

            # check to see if we have seen this device before and add to devices array
            #if tinytuya.appenddevice(result, deviceslist) is False:
            if ip not in broadcasted_devices:
                (dname, dkey, mac) = tuyaLookup(result['gwId'])
                result["name"] = dname
                result["key"] = dkey
                result["mac"] = mac
                #print( 'adding:', result)

                broadcasted_devices[ip] = PollDevice( ip, result, options, ip in debug_ips )
                do_poll = False

                if poll:
                    # v3.1 does not require a key for polling, but v3.2+ do
                    if result['version'] != "3.1" and not dkey:
                        broadcasted_devices[ip].message = "%s    No Stats for %s: DEVICE KEY required to poll for status%s" % (term.alertdim, ip, term.dim)
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

        for ip in connect_this_round:
            broadcasted_devices[ip].connect()
            devicelist.append( broadcasted_devices[ip] )
            check_end_time = time.time() + connect_timeout
            if check_end_time > device_end_time: device_end_time = check_end_time

        if (not ip_scan_running) and wantips and scan_end_time <= time.time() and device_end_time <= time.time():
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

    for sock in read_socks:
        sock.close()
    for sock in write_socks:
        sock.close()

    if client:
        client.close()
        clients.close()

    if verbose:
        print( 'Scanned in', time.time() - start_time )
        #print( len(response_list), response_list )

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

        if wantips:
            print('%s%sDid not find %s devices by ip: %r%s' % (term.alert, term.yellow, len(wantips), wantips, term.normal))
        if wantids:
            print('%s%sDid not find %s devices by ID: %r%s' % (term.alert, term.yellow, len(wantids), wantids, term.normal))

    if byID:
        k = 'gwId'
    else:
        k = 'ip'
    devices = {}
    for ip in broadcasted_devices:
        dev = broadcasted_devices[ip].deviceinfo
        dev['ip'] = ip
        dkey = dev[k]
        devices[dkey] = dev

    for ip in scanned_devices:
        dev = scanned_devices[ip].deviceinfo
        dev['ip'] = ip
        dkey = dev[k]
        if scanned_devices[ip].found and dkey not in devices:
            devices[dkey] = dev

    if verbose:
        # Save polling data into snapshot format
        devicesarray = list(devices.values())
        for item in tuyadevices:
            k = item["id"]
            if k not in devices:
                tmp = item
                tmp["gwId"] = item["id"]
                tmp["ip"] = ''
                devicesarray.append(tmp)
        current = {'timestamp' : time.time(), 'devices' : devicesarray}
        output = json.dumps(current, indent=4)
        print(term.bold + "\n>> " + term.normal + "Saving device snapshot data to " + SNAPSHOTFILE + "\n")
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

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
    items = { 'ip':0, 'version':0, 'ver':0, 'name':'', 'key':'', 'mac':None }
    for itm in items:
        if new and itm in new and new[itm]:
            item[itm] = new[itm]
        elif itm in old and old[itm]:
            item[itm] = old[itm]
        else:
            item[itm] = items[itm]
    if item['version']:
        item['ver'] = item['version']
    elif item['ver']:
        item['version'] = item['ver']
    return item

def _display_status( item, dps, term ):
    name = item['name']
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

# Scan Devices in tuyascan.json
def snapshot(color=True):
    """Uses snapshot.json to scan devices

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

    try:
        with open(SNAPSHOTFILE) as json_file:
            data = json.load(json_file)
    except:
        print("%s ERROR: Missing %s file\n" % (term.alert, SNAPSHOTFILE))
        return

    print("%sLoaded %s - %d devices:\n" % (term.dim, SNAPSHOTFILE, len(data["devices"])))

    # Print a table with all devices
    table = []
    print("%s%-25s %-24s %-18s %-17s %-5s" % (term.normal, "Name","ID", "IP","Key","Version"))
    print(term.dim)
    by_ip = {}
    devicesx = sorted(data["devices"], key=lambda x: x['name'])
    for idx in devicesx:
        device = _build_item( idx, None )
        ips = device['ip'] if device['ip'] else (term.alert + "Error: No IP found" + term.normal)
        print("%s%-25.25s %s%-24s %s%-18s %s%-17s %s%-5s" %
            (term.dim, device['name'], term.cyan, device['gwId'], term.subbold, ips, term.red, device['key'], term.yellow, device['version']))
        if device['ip']:
            by_ip[device['ip']] = device

    # Find out if we should poll all devices
    answer = 'y' #input(subbold + '\nPoll local devices? ' + term.normal + '(Y/n): ')
    if answer[0:1].lower() != 'n':
        print("")
        print("%sPolling %s local devices from last snapshot..." % (term.normal, len(devicesx)))
        result = devices(verbose=False, scantime=0, color=color, poll=True, byID=True, discover=False, snapshot=by_ip)

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
def alldevices(color=True, scantime=None):
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
    answer = 'y' #input(term.subbold + '\nPoll local devices? ' + term.normal + '(Y/n): ')
    if answer[0:1].lower() != 'n':
        by_id = [x['id'] for x in tuyadevices]
        # Scan network for devices and provide polling data
        print(term.normal + "\nScanning local network for Tuya devices...")
        result = devices(verbose=False, poll=True, byID=True, scantime=scantime, wantids=by_id, show_timer=True)
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

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4)
        print(term.bold + "\n>> " + term.normal + "Saving device snapshot data to " + SNAPSHOTFILE)
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

    print("%s\nDone.\n" % term.dim)
    return


# Scan Devices in tuyascan.json - respond in JSON
def snapshotjson():
    """Uses snapshot.json to scan devices - respond with json
    """
    polling = []

    try:
        with open(SNAPSHOTFILE) as json_file:
            data = json.load(json_file)
    except:
        current = {'timestamp' : time.time(), 'error' : 'Missing %s' % SNAPSHOTFILE}
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
