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

# Logging
log = logging.getLogger(__name__)

# Helper Functions
def getmyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    return str(r)

def getmyIPs():
    ips = {}
    interfaces = netifaces.interfaces()
    try:
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
            ips[k] = True
    return ips.keys()

class DeviceDetect():
    def __init__(self, deviceinfo):
        self.ip = None
        self.deviceinfo = None
        self.device = None
        self.ver = 0
        self.scanned = False
        self.broadcasted = False
        self.found = False
        self.msgs = []
        self.sock = None
        self.read = False
        self.write = False
        self.remove = False
        self.timeo = 0

        if not deviceinfo:
            deviceinfo = []
        self.deviceinfo = deviceinfo
        for k in devinfo_keys:
            if k not in deviceinfo:
                self.deviceinfo[k] = None


    def connect( self ):
        if self.debug:
            print('Connecting to debug ip', self.ip)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.settimeout(TCPTIMEOUT)
        self.sock.setblocking(False)
        self.sock.connect_ex( (str(self.ip), TCPPORT) )
        self.read = False
        self.write = True
        self.send_queue = []
        self.timeo = time.time() + self.options['connect_timeout']
        self.device = tinytuya.OutletDevice( self.deviceinfo['gwId'], self.ip, self.deviceinfo['key'], version=float(self.deviceinfo['version']))
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

    def v34_negotiate_sess_key_start( self ):
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
        super(ForceScannedDevice, self).__init__( deviceinfo )
        self.ip = ip
        self.options = options
        self.debug = debug
        self.retries = 0
        self.ver_detect = 0

        self.connect()

    def timeout( self ):
        if self.debug:
            print('Debug sock', self.ip, 'timed out!')
            print(self)
        self.close()

    def write_data( self ):
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
                print('recv:', r)
            # ugh, ConnectionResetError and ConnectionRefusedError are not available on python 2.7
            #except ConnectionResetError:
            except OSError as e:
                if e.errno == errno.ECONNRESET:
                    # connected, but then closed.  retry
                    print('retrying', self.ip)
                    self.sock.close()
                    self.connect()
                else:
                    if self.debug:
                        print('failed 1', self.ip, e.errno, errno.ECONNRESET)
                        print(traceback.format_exc())
                    self.close()
            except:
                if self.debug:
                    print('failed 2', self.ip)
                    print(traceback.format_exc())
                self.close()
            return

        # connection succeeded!
        self.timeo = time.time() + self.options['data_timeout']
        self.scanned = True
        self.write = False
        mac = get_mac_address(ip=self.ip,network_request=False) if SCANLIBS else None
        self.deviceinfo['ip'] = self.ip
        self.deviceinfo['mac'] = mac
        log.debug("Found Device %s [%s] (total devices: %d)", self.ip, mac, 0) # FIXME
        if self.options['verbose']:
            print(" Force-Scan Found Device %s [%s]" % (self.ip, mac))

        # try to figure out what version device it is by sending an unencrypted status request
        # v3.1 devices will return the status
        # v3.2 devices will ???
        # v3.3 devices will return an encrypted rejection message
        # v3.4 devices will slam the door in our face by dropping the connection






        ## since we do not have a MAC address to match against, try and get a response so we can brute-force the key
        #if not mac:
        #    try:
        #        sock.sendall( self.options['provoke_response'] )
        #        self.read = True
        #    except:
        #        #print(traceback.format_exc())
        #        self.close()
        ## we have a MAC address, so no need to get anything else
        #else:
        #    self.found = True
        #    self.close()

        self.ver_detect = 1
        d._generate_message( tinytuya.SESS_KEY_NEG_START, d.local_nonce, check_socket=False )

    def read_data( self ):
        try:
            data = self.sock.recv( 5000 )
        except:
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

            #data = data[tinytuya.message_length(msg.payload):]
            data = data[len(msg.payload)+8:]

            # ignore NULL packets
            if len(msg.payload) == 0:
                continue

            self.msgs.append(msg)
            if msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
                self.ver = 3.1
            elif msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                self.ver = 3.3
            #elif msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_34):
            #    self.ver = 3.4

            if self.deviceinfo['version']:
                self.close()
                break




class PollDevice(DeviceDetect):
    def __init__( self, ip, deviceinfo, options, debug ):
        super(PollDevice, self).__init__( deviceinfo )
        self.ip = ip
        self.options = options
        self.debug = debug
        self.broadcasted = True
        self.retries = options['retries']
        self.message = None

    def close(self):
        super(PollDevice, self).close()
        mac = get_mac_address(ip=self.ip,network_request=False) if SCANLIBS else None
        if mac:
            self.deviceinfo['mac'] = mac

        if self.options['verbose']:
            _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'] )
            if self.message:
                print(self.message)

    def	timeout( self ):
        if self.retries > 0:
            if self.debug:
                print('Timeout for debug ip', self.ip, 'reconnecting, retries', self.retries)
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
        try:
            # getpeername() blows up with "OSError: [Errno 107] Transport endpoint is
            # not connected" if the connection was refused                                                                                                                                          
            addr = self.sock.getpeername()[0]
        except:
            addr = None
            if "err" not in self.deviceinfo or len(self.deviceinfo["err"]) == 0:
                self.deviceinfo["err"] = "Connect Failed"
            if self.debug:
                print('Debug sock', self.ip, 'failed!')
                print(self.sock)
                print(traceback.format_exc())

        if not addr:
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

                #self.message = repr(msg)
                #self.close()
                #return

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
        try:
            # Fetch my IP address and assume /24 network
            network = ipaddress.IPv4Interface(netblock).network
            log.debug("Starting brute force network scan %r", network)
        except:
            log.debug("Unable to get network for %r, ignoring", netblock)
            if verbose:
                print(term.alert +
                    'ERROR: Unable to get network for %r, ignoring.' % netblock + term.normal)
            continue

        if verbose:
            print(term.bold + '    Starting Scan for network %r' % netblock + term.dim)
        # Loop through each host
        for addr in ipaddress.IPv4Network(network):
            yield str(addr)

def _print_device_info( result, note, term ):
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
    #debug_ips = ['172.20.10.67']
    debug_ips = []
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
    provoke_response = tinytuya.pack_message( tinytuya.TuyaMessage(0, tinytuya.DP_QUERY, 0, b'', 0) )
    log.debug("Listening for Tuya devices on UDP 6666 and 6667")
    start_time = time.time()
    timeout_time = time.time() + 5
    current_ip = None
    need_sleep = 0.1
    options = {
        'connect_timeout': connect_timeout,
        'data_timeout': connect_timeout,
        'provoke_response': provoke_response,
        'termcolors': term,
        'verbose': verbose,
        'retries': 2,
        'tuyadevices': tuyadevices,
    }

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
                networks = getmyIPs()

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
        if timeout_time > scan_end_time:
            do_timeout = True
        else:
            do_timeout = timeout_time < time.time()
            if do_timeout: timeout_time = time.time() + 1.0 #connect_timeout

        for dev in devicelist:
            if do_timeout and dev.timeo < time.time():
                dev.timeout()

            if dev.remove:
                remove.append(dev)
                if dev.scanned:
                    scanned_devices[dev.ip] = dev
                continue
            elif (dev.timeo + 1.0) > device_end_time:
                if dev.debug:
                    print('Resetting device scan end time due to debug ip', dev.ip, device_end_time, dev.timeo)
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

        if show_timer:
            end_time = int((scan_end_time if scan_end_time > device_end_time else device_end_time) - time.time())
            if end_time < 0: end_time = 0
            tim = 'FS:'+str(current_ip) if ip_scan_running else str(end_time)
            print("%sScanning... %s (%s)                 \r" % (term.dim, spinner[spinnerx], tim), end="")
            spinnerx = (spinnerx + 1) % 4
            sys.stdout.flush()

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
                if (not dev.remove) and ((dev.timeo + 1.0) > device_end_time):
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

    # no broadcast or MAC address, we are going to need to brute-force the key
    # if we found a broadcast or MAC, clean it out of the 'unknown' lists

    # Add Force Scan Devices
    if False and havekeys and len(response_list) > 0:
        print( 'Brute forcing device IDs for unknown force-scanned devices...' )
        used_keys = []
        keylist = []
        for ip in deviceslist:
            if 'key' in deviceslist[ip] and deviceslist[ip]['key']:
                used_keys.append( deviceslist[ip]['key'] )
        for item in tuyadevices:
            if 'key' in item and item['key']: # and (item['key'] not in used_keys):
                k = tinytuya.AESCipher( item['key'].encode('utf8') )
                keylist.append( k )
        for ip in response_list:
            del ip_list[ip]
            matched = False
            ver = '0.0'

            for resp in response_list[ip]:
                payload = resp.payload

                if payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
                    ver = '3.1'
                    payload = payload[len(tinytuya.PROTOCOL_VERSION_BYTES_31)+16 :]
                elif payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                    ver = '3.3'
                    payload = payload[len(tinytuya.PROTOCOL_33_HEADER) :]

                if not matched:
                    for cipher in keylist:
                        try:
                            text = cipher.decrypt( payload, False, True )
                        except:
                            continue

                        if len(text) == 0:
                            continue

                        #print( len(response_list[ip][0].payload), len(text), text)
                        matched = cipher.key.decode()
                        break
                if matched and ver != '0.0':
                    break
            if matched:
                matches[ip] = (matched, ver)
                #keylist.remove( cipher )

        for ip in matches:
            del response_list[ip]
            matched = False
            for item in tuyadevices:
                if 'key' in item and item['key'] and item['key'] == matches[ip][0]:
                    matched = True
                    ver = matches[ip][1]
                    result = {'ip': ip, 'id': item['id'], 'gwId': item['id'], 'active': -1, 'ablilty': -1, 'encrypt': True, 'productKey': None, 'version': ver}
                    if ver and ver != '0.0': result['version'] = ver
                    if tinytuya.appenddevice(result, deviceslist) is False:
                        # Try to pull name and key data
                        (dname, dkey, mac) = tuyaLookup(item['id'])
                        deviceslist[ip]["name"] = dname
                        deviceslist[ip]["key"] = dkey
                        deviceslist[ip]["mac"] = mac
                        if verbose:
                            _print_device_info( result, 'Force Scanned', term )
                    break
            if not matched:
                print( '!!! We have a key but no corrosponding device entry? !!!', ip )

        print('Done!')

    # at this point:
    #  ip_list contains a list of devices which did not respond to our DP_QUERY and also have an unknown MAC
    #  response_list contains a list of devices for which we do not have a key
    #  matches contains a list of devices which we (probably) added to deviceslist

    found_count = len(broadcasted_devices)+len(scanned_devices)

    if verbose:
        print(
            "                    \n%sScan Complete!  Found %s devices."
            % (term.normal, found_count)
        )
        print( 'Broadcasted:', len(broadcasted_devices) )
        if ip_scan:
            print( 'Force-Scanned:', len(scanned_devices), ' - Matched MAC:', 0,'Matched Key:', 0, 'Unmatched:', 0, 'Invalid:', 0 )

        #if len(response_list) > 0:
        #    print("\nUnmatched Entries:", response_list)

        #if len(ip_list) > 0:
        #    print("\nInvalid Entries:", ip_list)

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
def alldevices(color=True, retries=None):
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
        result = devices(verbose=False, poll=True, byID=True, wantids=by_id, show_timer=True)
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
