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
import asyncio
from collections import namedtuple
import ipaddress
import json
import logging
import socket
import sys
import time
import errno
import base64
import traceback
import tinytuya

#tinytuya.set_debug()
#from .core import *
#from . import core
#import .core as core
#tinytuya = sys.modules['tinytuya']
#print(sys.modules)
#for m in sys.modules:
#    print(m)
#print(tinytuya.DEVICEFILE)

#from .scanner_classes import *

try:
    from colorama import init
    HAVE_COLORAMA = True
except ImportError:
    HAVE_COLORAMA = False

HAVE_COLOR = HAVE_COLORAMA or not sys.platform.startswith('win')


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
if HAVE_COLORAMA:
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

FoundDevice = namedtuple( 'FoundDevice', 'data, time' )

# Logging
log = logging.getLogger(__name__)

scanner = None

async def scanfor( did, timeout=True ):
    global scanner
    if scanner is None:
        print('creating new scanner')
        scanner = Scanner()

    return await scanner.scanfor( did, timeout )

# Helper Functions
def getmyIPaddr():
    # Fetch my IP address and assume /24 network
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = str(s.getsockname()[0])
    s.close()
    return r

def getmyIP():
    r = getmyIPaddr().split('.')
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

    ip_to_broadcast['255.255.255.255'] = getmyIPaddr()
    return ip_to_broadcast

def send_discovery_request( iface_list=None ):
    close_sockets = False

    if not tinytuya.AESCipher.CRYPTOLIB_HAS_GCM:
        # GCM is required for discovery requests
        return False

    if not iface_list:
        close_sockets = True
        iface_list = {}
        client_bcast_addrs = get_ip_to_broadcast()
        for bcast in client_bcast_addrs:
            addr = client_bcast_addrs[bcast]
            iface_list[addr] = { 'broadcast': bcast }

    at_least_one_succeeded = False
    bcast_error_messages = []
    for address in iface_list:
        iface = iface_list[address]
        if 'socket' not in iface:
            iface['socket'] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            iface['socket'].setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                iface['socket'].bind( (address,0) )
            except:
                log.debug( 'Failed to bind to address %r for discovery broadcasts, skipping interface!', address, exc_info=True )
                continue

        if 'payload' not in iface:
            bcast = json.dumps( {"from":"app","ip":address} ).encode()
            bcast_msg = tinytuya.TuyaMessage( 0, tinytuya.REQ_DEVINFO, None, bcast, 0, True, tinytuya.PREFIX_6699_VALUE, True )
            iface['payload'] = tinytuya.pack_message( bcast_msg, hmac_key=tinytuya.udpkey )

        if 'port' not in iface:
            iface['port'] = 7000

        log.debug( 'Sending discovery broadcast from %r to %r on port %r', address, iface['broadcast'], iface['port'] )
        try:
            iface['socket'].sendto( iface['payload'], (iface['broadcast'], iface['port']) )
            at_least_one_succeeded = True
        except socket.error as e:
            log.debug( f"Failed to send discovery broadcast from {address} to {iface['broadcast']}:{iface['port']}: {e}" )
            bcast_error_messages.append( f"Failed to send discovery broadcast from {address} to {iface['broadcast']}:{iface['port']}: {e}" )

        if close_sockets:
            iface['socket'].close()
            del iface['socket']

    if not at_least_one_succeeded:
        if log.level != logging.DEBUG:
            for line in bcast_error_messages:
                log.error( line )
        log.error( 'Sending broadcast discovery packet failed, certain v3.5 devices will not be found!' )

    return iface_list

def _generate_ip(networks, verbose, term):
    for netblock in networks:
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

class UDPProtocol:
    def __init__(self, scanner):
        self.scanner = scanner
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        print('connection_made', transport)

    def datagram_received(self, data, addr):
        #print("datagram_received: Received:", addr, data)
        try:
            ip = addr[0]
            tgt_port = addr[1]
            result = tinytuya.decrypt_udp( data )
            result = json.loads(result)
            log.debug("Received valid UDP packet: %r", result)
        except:
            log.debug("Invalid UDP Packet from %r port %r - %r", ip, tgt_port, data)
            return

        if 'from' in result:
            # from app
            pass
        elif 'gwId' in result:
            # from device
            devid = result['gwId']
            self.scanner.found_devices[devid] = FoundDevice( result, time.time() )
            if devid in self.scanner.device_listeners:
                for fut in self.scanner.device_listeners[devid]:
                    fut.set_result( result )

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Connection closed", exc)

class UDPProtocolClient(UDPProtocol):
    pass

class UDPProtocolClients(UDPProtocol):
    pass

class UDPProtocolApp(UDPProtocol):
    pass


class Scanner():
    def __init__( self, forcescan=False, discover=True ):
        self.forcescan = forcescan
        self.discover = discover
        self.found_devices = {}
        self.device_listeners = {}
        self.loop = asyncio.get_running_loop()
        self.start = asyncio.Event()

        self.task = asyncio.create_task( self.background_scan() )

    async def reload_tuyadevices(self):
        pass

    async def scanfor( self, devid, timeout=True, use_cache=True ):
        print('scanfor adding device:', devid)
        self.start.set() # start it now in case we need to expire old data
        if use_cache and devid in self.found_devices:
            print('scanfor returning cached data:', devid, self.found_devices[devid])
            return self.found_devices[devid].data
        future = self.loop.create_future()
        if devid not in self.device_listeners:
            self.device_listeners[devid] = [future]
        else:
            self.device_listeners[devid].append( future )
        if timeout is True:
            timeout = tinytuya.SCANTIME
        if timeout:
            try:
                await asyncio.wait_for(future, timeout=timeout)
                result = future.result()
            except:
                result = None
        else:
            result = await future
        print('scanfor got result:', result)
        self.device_listeners[devid].remove( future )
        if not self.device_listeners[devid]:
            del self.device_listeners[devid]
        return result

    async def background_scan(self):
        #if scantime is None:
        self.scantime = 2 #tinytuya.SCANTIME
        self.start.set() # start it now to fill the cache
        tuyadevices = []
        discoverers = []
        client_ip_broadcast_list = {}

        while self.device_listeners or await self.start.wait():
            print('starting scan!')
            self.start.clear()
            await self.reload_tuyadevices()

            if self.forcescan and not self.tuyadevices:
                # print warning
                # print(term.alert + 'Warning: Force-scan requires keys in %s but no keys were found.  Disabling force-scan.' % DEVICEFILE + term.normal)
                if not self.discover:
                    continue

            if self.discover:
                # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
                #client.bind(("", UDPPORT))                
                discoverers.append( await self.loop.create_datagram_endpoint( lambda: UDPProtocolClient(self), local_addr=('0.0.0.0',UDPPORT), reuse_port=True, allow_broadcast=True ) )

                # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
                #clients.bind(("", UDPPORTS))
                discoverers.append( await self.loop.create_datagram_endpoint( lambda: UDPProtocolClients(self), local_addr=('0.0.0.0',UDPPORTS), reuse_port=True, allow_broadcast=True ) )

                # Enable UDP listening broadcasting mode on encrypted UDP port 7000 - App
                #clientapp.bind(("", UDPPORTAPP))
                discoverers.append( await self.loop.create_datagram_endpoint( lambda: UDPProtocolApp(self), local_addr=('0.0.0.0',UDPPORTAPP), reuse_port=True, allow_broadcast=True ) )

            for i in tuyadevices:
                options['keylist'].append( KeyObj( i['id'], i['key'] ) )

            if False: #forcescan:
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

                if networks:
                    if verbose:
                        log.debug("Force-scanning networks: %r", networks)

                    scan_ips = _generate_ip( networks, verbose, term )
                    ip_scan = ip_scan_running = True
                    if discover:
                        ip_scan_delay = time.time() + 5

            ## If no scantime value set use default
            #if not scantime:
            #    scantime = 0 if ip_scan_running else tinytuya.SCANTIME

            client_bcast_addrs = get_ip_to_broadcast()
            for bcast in client_bcast_addrs:
                addr = client_bcast_addrs[bcast]
                client_ip_broadcast_list[addr] = { 'broadcast': bcast }


            if False:
                if 'from' in result and result['from'] == 'app': #sock is clientapp:
                    if ip not in broadcasted_apps:
                        broadcasted_apps[ip] = result
                        if verbose:
                            print( term.alertdim + 'New Broadcast from App at ' + str(ip) + term.dim + ' - ' + str(result) + term.normal )
                        #continue

            while self.device_listeners:
                await asyncio.sleep( 2 )

            # keep going for at least this long to refresh the cache
            await asyncio.sleep( self.scantime )

            for client, protocol in discoverers:
                client.close()
            discoverers = []

            self.start.clear()
            continue

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
    color = color and HAVE_COLOR
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
    color = color and HAVE_COLOR
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
    color = color and HAVE_COLOR
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
