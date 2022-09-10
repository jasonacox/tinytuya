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

TermColors = namedtuple("TermColors", "bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow")

# Logging
log = logging.getLogger(__name__)

# Helper Functions
def getmyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    return r

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

class ForceScannedDevice():
    def __init__( self, ip, options, debug ):
        self.ip = ip
        self.deviceinfo = None
        self.ver = 0
        self.scanned = False
        self.broadcasted = False
        self.msgs = []
        self.options = options
        self.sock = None
        self.read = False
        self.write = False
        self.remove = False
        self.debug = debug
        self.timeo = 0
        self.retries = 0
        self.connect()

    def connect( self ):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.settimeout(TCPTIMEOUT)
        self.sock.setblocking(False)
        self.sock.connect_ex( (str(self.ip), TCPPORT) )
        self.write = True
        self.timeo = time.time() + options['connect_timeout']


    def timeout( self ):
        if self.debug:
            print('Debug sock', self.ip, 'timed out!')
            print(self)
        self.close()

    def close( self ):
        self.sock.close()
        self.sock = None
        self.read = self.write = False
        self.remove = True

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
        self.scanned = True
        self.write = False
        mac = get_mac_address(ip=self.ip) if SCANLIBS else None
        self.deviceinfo = { 'ip': self.ip, 'mac': mac }
        log.debug("Found Device %s [%s] (total devices: %d)", self.ip, mac, 0) # FIXME
        if self.options['verbose']:
            print(" Force-Scan Found Device %s [%s]" % (self.ip, mac))

        # since we do not have a MAC address to match against, try and get a response so we can brute-force the key
        if not mac:
            try:
                sock.sendall( self.options['provoke_response'] )
                self.read = True
            except:
                #print(traceback.format_exc())
                self.close()
        # we have a MAC address, so no need to get anything else
        else:
            self.close()

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
                msg = tinytuya.unpack_message(data)
            except:
                break

            data = data[tinytuya.message_length(msg.payload):]

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

            if self.ver:
                self.close()
                break


class PollDevice():
    def __init__( self, ip, ttdev, deviceinfo, options, debug ):
        self.ip = ip
        self.deviceinfo = deviceinfo
        self.options = options
        self.device = ttdev
        self.scanned = False
        self.broadcasted = True
        self.msgs = []
        self.sock = None
        self.read = False
        self.write = False
        self.remove = False
        self.debug = debug
        self.timeo = 0
        self.retries = options['retries']
        self.connect()

    def connect( self ):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.settimeout(TCPTIMEOUT)
        self.sock.setblocking(False)
        self.sock.connect_ex( (str(self.ip), TCPPORT) )
        self.read = False
        self.write = True
        self.timeo = time.time() + self.options['connect_timeout']

    def	timeout( self ):
        if self.retries > 0:
            self.retries -= 1
            self.sock.close()
            self.connect()
            self.timeo = time.time() + tinytuya.TIMEOUT
        else:
            self.close()
            mac = get_mac_address(ip=self.ip) if SCANLIBS else None
            if mac:
                self.deviceinfo['mac'] = mac

            if self.options['verbose']:
                _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'] )
                print("%s    Polling %s Failed: %s" % (self.options['termcolors'].alertdim, self.ip, self.deviceinfo["err"]))

    def close( self ):
        self.sock.close()
        self.sock = None
        self.read = self.write = False
        self.remove = True

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

        if not addr:
            self.timeout()
            return

        # connection succeeded!
        self.write = False
        try:
	    # connected, send the query
            self.sock.sendall( self.device.generate_payload(tinytuya.DP_QUERY) )
            self.read = True
            #deviceslist[ip]["err"] = "Check DEVICE KEY - Invalid response"
            self.deviceinfo["err"] = "No response"
        except:
            self.deviceinfo["err"] = "Send Poll failed"
            #print(traceback.format_exc())
            self.timeout()

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
                msg = tinytuya.unpack_message(data)
            except:
                break

            data = data[tinytuya.message_length(msg.payload):]

            # ignore NULL packets
            if len(msg.payload) == 0:
                continue

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
                self.sock.sendall( self.device.generate_payload(tinytuya.DP_QUERY) )
                break

            finished = True
            self.deviceinfo['type'] = self.device.dev_type
            mac2 = get_mac_address(ip=self.ip) if SCANLIBS else None
            if mac2:
                self.deviceinfo["mac"] = mac2

            if not result or "dps" not in result:
                if self.options['verbose']:
                    _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'] )
                    if result and "Error" in result:
                        print("%s    Access rejected by %s: %s" % (self.options['termcolors'].alertdim, self.ip, result["Error"]))
                    else:
                        print("%s    Check DEVICE KEY - Invalid response from %s: %r" % (self.options['termcolors'].alertdim, self.ip, result))
                self.deviceinfo["err"] = "Unable to poll"
            else:
                self.deviceinfo["dps"] = result
                self.deviceinfo["err"] = ""
                if self.options['verbose']:
                    _print_device_info( self.deviceinfo, 'Valid Broadcast', self.options['termcolors'] )
                    print(self.options['termcolors'].dim + "    Status: %s" % result["dps"])
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
                print(alert +
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
def devices(verbose=False, scantime=None, color=True, poll=True, forcescan=False, byID=False):
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

    # If no scantime value set use default
    if scantime is None:
        scantime = tinytuya.SCANTIME

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

    debug_ips = ['172.20.10.106','172.20.10.107','172.20.10.114','172.20.10.138','172.20.10.156','172.20.10.166','172.20.10.175','172.20.10.181','172.20.10.191'] #,'172.20.10.102', '172.20.10.1']
    deviceslist = {}
    devicelist = []
    count = 0
    counts = 0
    spinnerx = 0
    spinner = "|/-\\|"
    ip_list = {}
    response_list = {}
    ip_scan_running = False
    scan_end_time = time.time() + scantime
    provoke_response = tinytuya.pack_message( tinytuya.TuyaMessage(0, tinytuya.DP_QUERY, 0, b'', 0) )
    log.debug("Listening for Tuya devices on UDP 6666 and 6667")
    start_time = time.time()
    reap_time = time.time() + 5
    current_ip = None
    need_sleep = 0.1
    options = {
        'connect_timeout': connect_timeout,
        'provoke_response': provoke_response,
        'termcolors': term,
        'verbose': verbose,
        'retries': 3,
    }

    if forcescan:
        if verbose:
            print(term.subbold + "    Option: " + term.dim + "Network force scanning requested.\n")

        if not NETIFLIBS:
            print(alert +
                  '    NOTE: netifaces module not available, multi-interface machines will be limited.\n'
                  '           (Requires: pip install netifaces)\n' + term.dim)
            networks = []
        else:
            networks = getmyIPs()

        if len(networks) == 0:
            try:
                ip = u'172.20.10.0/24' # u''+getmyIP()+'/24'
                networks.append( ip )
            except:
                networks.append( u''+DEFAULT_NETWORK )
                log.debug("Unable to get local network, using default %r", DEFAULT_NETWORK)
                if verbose:
                    print(alert +
                          'ERROR: Unable to get your IP address and network automatically.'
                          '       (using %s)' % DEFAULT_NETWORK + term.normal)

        scan_ips = _generate_ip( networks, verbose, term )
        ip_scan_running = True

        # Warn user of scan duration
        if verbose:
            print(term.bold + '\n    Running Scan...' + term.dim)

    while ip_scan_running or scan_end_time > time.time():
        read_socks = [client, clients]
        write_socks = []
        all_socks = {}
        remove = []
        do_reap = reap_time < time.time()
        if do_reap: reap_time = time.time() + connect_timeout

        for dev in devicelist:
            if do_reap and dev.timeo < time.time():
                dev.timeout()
                if dev.timeo > scan_end_time:
                    scan_end_time = dev.timeo

            if dev.remove:
                remove.append(dev)
                continue

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
                        # reset the end time to the larger of scantime or connect_timeout
                        scan_end_time = time.time() + (scantime if scantime > connect_timeout else connect_timeout)
                        need_sleep = 0.1
                        break
                    else:
                        dev = ForceScannedDevice( current_ip, options, current_ip in debug_ips )
                        # we slept here so adjust the loop sleep time accordingly
                        time.sleep(0.02)
                        need_sleep -= 0.02

        if verbose:
            tim = 'FS:'+str(current_ip) if ip_scan_running else str(int(scan_end_time - time.time()))
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
                result["id"] = result['gwId']
                result["ver"] = result['version']
            except:
                if verbose:
                    print(term.alertdim + "*  Unexpected payload=%r\n" + term.normal, result)
                log.debug("Invalid UDP Packet: %r", result)
                continue

            # check to see if we have seen this device before and add to devices array
            #if tinytuya.appenddevice(result, deviceslist) is False:
            if ip not in deviceslist:
                deviceslist[ip] = result
                # Try to pull name and key data
                mac2 = get_mac_address(ip=ip) if SCANLIBS else None
                (dname, dkey, mac) = tuyaLookup(result['gwId'])
                deviceslist[ip]["name"] = dname
                deviceslist[ip]["key"] = dkey
                deviceslist[ip]["mac"] = mac2 if mac2 else mac

                if poll:
                    # v3.1 does not require a key for polling, but v3.2+ do
                    if result['version'] != "3.1" and not dkey:
                        if verbose:
                            _print_device_info( deviceslist[ip], 'Valid Broadcast', term )
                            print(
                                "%s    No Stats for %s: DEVICE KEY required to poll for status%s"
                                % (term.alertdim, ip, term.dim)
                            )
                    else:
                        # open a connection and dump it into the select()
                        ttdev = tinytuya.OutletDevice(result['gwId'], ip, dkey)
                        ttdev.set_version(float(result['version']))
                        dev = PollDevice( ip, ttdev, deviceslist[ip], options, ip in debug_ips )
                        devicelist.append( dev )
                elif verbose:
                    _print_device_info( result, 'Valid Broadcast', term )


    for sock in read_socks:
        sock.close()
    for sock in write_socks:
        sock.close()

    if verbose:
        print( 'Scanned in', time.time() - start_time )
        #print( len(response_list), response_list )

    found = []
    mac_matches = 0
    matches = {}
    for ip in ip_list:
        # first check to see if we have received a valid broadcast from this device
        if ip in deviceslist and 'mac' in deviceslist[ip] and deviceslist[ip]['mac']:
            # we received a broadcast from this device, so ignore it
            found.append(ip)
            continue
        # next, if we have a MAC address for this device, match on that
        if ip_list[ip]:
            for item in tuyadevices:
                if 'mac' in item and item['mac'] and item['mac'] == ip_list[ip]:
                    # found it
                    mac_matches += 1
                    found.append(ip)
                    ver = '0.0'
                    # see if we got some data from it which we can use to detect the version
                    if ip in response_list:
                        for resp in response_list[ip]:
                            if resp.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
                                ver = '3.1'
                                break
                            elif resp.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                                ver = '3.3'
                                break
                    result = {'ip': ip, 'id': item['id'], 'gwId': item['id'], 'active': -1, 'ablilty': -1, 'encrypt': True, 'productKey': None, 'version': ver}
                    if ver and ver != '0.0': result['ver'] = ver
                    if tinytuya.appenddevice(result, deviceslist) is False:
                        # Try to pull name and key data
                        (dname, dkey, mac) = tuyaLookup(item['id'])
                        deviceslist[ip]["name"] = dname
                        deviceslist[ip]["key"] = dkey
                        deviceslist[ip]["mac"] = mac
                        if verbose:
                            _print_device_info( result, 'Force Scanned', term )
                    break
        # no broadcast or MAC address, we are going to need to brute-force the key
    # if we found a broadcast or MAC, clean it out of the 'unknown' lists
    for ip in found:
        del ip_list[ip]
        if ip in response_list:
            del response_list[ip]

    broadcast_matches = len(deviceslist) - mac_matches

    # Add Force Scan Devices
    if havekeys and len(response_list) > 0:
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

    if verbose:
        print(
            "                    \n%sScan Complete!  Found %s devices."
            % (term.normal, len(deviceslist))
        )
        print('Broadcasted:', broadcast_matches, 'Matched MAC:', mac_matches,'Matched Key:', len(matches), 'Unmatched:', len(response_list), 'Invalid:', len(ip_list) )

        if len(response_list) > 0:
            print("\nUnmatched Entries:", response_list)

        if len(ip_list) > 0:
            print("\nInvalid Entries:", ip_list)

        # Save polling data into snapshot format
        devicesarray = []
        for item in deviceslist:
            devicesarray.append(deviceslist[item])
        for item in tuyadevices:
            if next((x for x in devicesarray if x["id"] == item["id"]), False) is False:
                tmp = item
                tmp["gwId"] = item["id"]
                tmp["ip"] = 0
                devicesarray.append(tmp)
        current = {'timestamp' : time.time(), 'devices' : devicesarray}
        output = json.dumps(current, indent=4)
        print(term.bold + "\n>> " + term.normal + "Saving device snapshot data to " + SNAPSHOTFILE + "\n")
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

    log.debug("Scan complete with %s devices found", len(deviceslist))

    if byID:
        # Create dictionary by id
        ids = {}
        for device in deviceslist:
            idx=deviceslist[device]['gwId']
            ids[idx] = deviceslist[device]
        return ids
    else:
        return deviceslist


# Scan Devices in tuyascan.json
def snapshot(color=True):
    """Uses snapshot.json to scan devices

    Parameters:
        color = True or False, print output in color [Default: True]
    """
    # Terminal formatting
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)

    print(
        "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
        % (bold, normal, dim, tinytuya.__version__)
    )

    try:
        with open(SNAPSHOTFILE) as json_file:
            data = json.load(json_file)
    except:
        print("%s ERROR: Missing %s file\n" % (alert, SNAPSHOTFILE))
        return

    print("%sLoaded %s - %d devices:\n" % (dim, SNAPSHOTFILE, len(data["devices"])))

    # Print a table with all devices
    table = []
    print("%s%-25s %-24s %-16s %-17s %-5s" % (normal, "Name","ID", "IP","Key","Version"))
    print(dim)
    for idx in sorted(data["devices"], key=lambda x: x['name']):
        device = idx
        ver = ip = ""
        if "ver"  in device:
            ver = device["ver"]
        if "ip"  in device:
            ip = device["ip"]
        name = device["name"]
        gwId = device["id"]
        key = device["key"]
        print("%s%-25.25s %s%-24s %s%-16s %s%-17s %s%-5s" %
            (dim, name, cyan, gwId, subbold, ip, red, key, yellow, ver))

    devicesx = sorted(data["devices"], key=lambda x: x['name'])

    # Find out if we should poll all devices
    answer = input(subbold + '\nPoll local devices? ' +
                   normal + '(Y/n): ')
    if answer[0:1].lower() != 'n':
        print("")
        print("%sPolling %s local devices from last snapshot..." % (normal, len(devicesx)))
        for i in devicesx:
            item = {}
            name = i['name']
            ip = ver = 0
            if "ip" in i:
                ip = i['ip']
            if "ver" in i:
                ver = i['ver']
            item['name'] = name
            item['ip'] = ip
            item['ver'] = ver
            item['id'] = i['id']
            item['key'] = i['key']
            if ip == 0:
                print("    %s[%s] - %s%s - %sError: No IP found%s" %
                      (subbold, name, dim, ip, alert, normal))
            else:
                try:
                    d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                    d.set_version(float(ver))
                    data = d.status()
                    if 'dps' in data:
                        item['dps'] = data
                        state = alertdim + "Off" + dim
                        try:
                            if '1' in data['dps'] or '20' in data['dps']:
                                if '1' in data['dps']:
                                    if data['dps']['1'] is True:
                                        state = bold + "On" + dim
                                if '20' in data['dps']:
                                    if data['dps']['20'] is True:
                                        state = bold + "On" + dim
                                print("    %s[%s] - %s%s - %s - DPS: %r" %
                                    (subbold, name, dim, ip, state, data['dps']))
                            else:
                                print("    %s[%s] - %s%s - DPS: %r" %
                                    (subbold, name, dim, ip, data['dps']))
                        except:
                            print("    %s[%s] - %s%s - %sNo Response" %
                                  (subbold, name, dim, ip, alert))
                    else:
                        print("    %s[%s] - %s%s - %sNo Response" %
                              (subbold, name, dim, ip, alert))
                except:
                    print("    %s[%s] - %s%s - %sNo Response" %
                          (subbold, name, dim, ip, alert))
        # for loop
    # if poll
    print("%s\nDone.\n" % dim)
    return


# Scan All Devices in devices.json
def alldevices(color=True, retries=None):
    """Uses devices.json to scan devices

    Parameters:
        color = True or False, print output in color [Default: True]
    """
    # Terminal formatting
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)

    print(
        "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
        % (bold, normal, dim, tinytuya.__version__)
    )
    # Check to see if we have additional Device info
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tuyadevices = json.load(f)
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
            # If no maxretry value set, base it on number of devices
            if retries is None:
                retries = len(tuyadevices) + tinytuya.MAXCOUNT
    except:
        print("%s ERROR: Missing %s file\n" % (alert, DEVICEFILE))
        return

    print("%sLoaded %s - %d devices:" % (dim, DEVICEFILE, len(tuyadevices)))

    # Display device list
    print("\n\n" + bold + "Device Listing\n" + dim)
    output = json.dumps(sorted(tuyadevices,key=lambda x: x['name']), indent=4)
    print(output)

    # Find out if we should poll all devices
    answer = input(subbold + '\nPoll local devices? ' +
                   normal + '(Y/n): ')
    if answer[0:1].lower() != 'n':
        # Set retries based on number of devices if undefined
        if retries is None:
            retries = len(tuyadevices)+10+tinytuya.MAXCOUNT

        # Scan network for devices and provide polling data
        print(normal + "\nScanning local network for Tuya devices (retry %d times)..." % retries)
        allx = devices(False, retries)
        print("    %s%s local devices discovered%s" %
              (dim, len(allx), normal))
        print("")

        def getIP(d, gwid):
            for ip in d:
                if 'gwId' in d[ip]:
                    if gwid == d[ip]['gwId']:
                        return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("Polling local devices...")
        # devices = sorted(data["devices"], key=lambda x: x['name'])
        for i in sorted(tuyadevices, key=lambda x: x['name']):
            item = {}
            name = i['name']
            (ip, ver) = getIP(allx, i['id'])
            item['name'] = name
            item['ip'] = ip
            item['ver'] = ver
            item['id'] = i['id']
            item['key'] = i['key']
            if "mac" in i:
                item['mac'] = i['mac']
            if ip == 0:
                print("    %s[%s] - %s%s - %sError: No IP found%s" %
                      (subbold, name, dim, ip, alert, normal))
            else:
                try:
                    d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                    d.set_version(float(ver))
                    data = d.status()
                    if 'dps' in data:
                        item['dps'] = data
                        state = alertdim + "Off" + dim
                        try:
                            if '1' in data['dps'] or '20' in data['dps']:
                                if '1' in data['dps']:
                                    if data['dps']['1'] is True:
                                        state = bold + "On" + dim
                                if '20' in data['dps']:
                                    if data['dps']['20'] is True:
                                        state = bold + "On" + dim
                                print("    %s[%s] - %s%s - %s - DPS: %r" %
                                    (subbold, name, dim, ip, state, data['dps']))
                            else:
                                print("    %s[%s] - %s%s - DPS: %r" %
                                    (subbold, name, dim, ip, data['dps']))
                        except:
                            print("    %s[%s] - %s%s - %sNo Response" %
                                  (subbold, name, dim, ip, alert))
                    else:
                        print("    %s[%s] - %s%s - %sNo Response" %
                              (subbold, name, dim, ip, alert))
                except:
                    print("    %s[%s] - %s%s - %sNo Response" %
                          (subbold, name, dim, ip, alert))
            polling.append(item)
        # for loop

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4)
        print(bold + "\n>> " + normal + "Saving device snapshot data to " + SNAPSHOTFILE)
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

    print("%s\nDone.\n" % dim)
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

    for i in devicesx:
        item = {}
        name = i['name']
        ip = ver = 0
        if "ip" in i:
            ip = i['ip']
        if "ver" in i:
            ver = i['ver']
        item['name'] = name
        item['ip'] = ip
        item['ver'] = ver
        item['id'] = i['id']
        item['key'] = i['key']
        if "mac" in i:
            item['mac'] = i['mac']
        if ip == 0:
            item['error'] = "No IP"
        else:
            try:
                d = tinytuya.OutletDevice(i['id'], ip, i['key'])
                d.set_version(float(ver))
                data = d.status()
                if 'dps' in data:
                    item['dps'] = data
                else:
                    item['error'] = "No Response"
            except:
                item['error'] = "No Response"
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
