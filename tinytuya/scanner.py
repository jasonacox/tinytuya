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
else:
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
    ret = []
    return ret

# Scan function shortcut
def scan(scantime=None, color=True, forcescan=False):
    """Scans your network for Tuya devices with output to stdout"""
    devices(verbose=True, scantime=scantime, color=color, poll=True, forcescan=forcescan)

def _generate_ip_connected(networks, verbose, termcolors, connect=True):
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = termcolors
    for netblock in networks:
        try:
            # Fetch my IP address and assume /24 network
            network = ipaddress.IPv4Interface(netblock).network
            log.debug("Starting brute force network scan %r", network)
        except:
            log.debug("Unable to get network for %r, ignoring", netblock)
            if verbose:
                print(alert +
                    'ERROR: Unable to get network for %r, ignoring.' % netblock + normal)
            continue

        if verbose:
            print(bold + '\n    Starting Scan for network %r' % netblock + dim)
        # Loop through each host
        for addr in ipaddress.IPv4Network(network):
            if connect:
                a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #a_socket.settimeout(TCPTIMEOUT)
                a_socket.setblocking(False)
                a_socket.connect_ex( (str(addr), TCPPORT) )
                yield str(addr), a_socket
            else:
                yield str(addr), None

def _print_device_info( result, note, termcolors ):
        (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = termcolors
        ip = result["ip"]
        gwId = result["gwId"]
        productKey = result["productKey"] if result["productKey"] else '?'
        version = result["version"] if result["version"] and result["version"] != '0.0' else '?'
        devicename = result["name"]
        dkey = result["key"]
        mac = result["mac"]

        suffix = dim + ", MAC = " + mac + ""
        if result['name'] == "":
            dname = gwId
            devicename = "Unknown v%s%s Device%s" % (normal, version, dim)
        else:
            devicename = normal + result['name'] + dim
            print(
                "%s   Product ID = %s  [%s]:\n    %sAddress = %s,  %sDevice ID = %s, %sLocal Key = %s,  %sVersion = %s%s"
                % (
                    devicename,
                    productKey,
                    note,
                    subbold,
                    ip,
                    cyan,
                    gwId,
                    red,
                    dkey,
                    yellow,
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
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = termcolors

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
            % (bold, normal, dim, tinytuya.__version__)
        )
        if havekeys:
            print("%s[Loaded devices.json - %d devices]\n" % (dim, len(tuyadevices)))
        print(
            "%sScanning on UDP ports %s and %s for devices for %d seconds...%s\n"
            % (subbold, UDPPORT, UDPPORTS, scantime, normal)
        )

    debug_ips = ['172.20.10.106','172.20.10.107','172.20.10.114','172.20.10.138','172.20.10.156','172.20.10.166','172.20.10.175','172.20.10.181','172.20.10.191'] #,'172.20.10.102', '172.20.10.1']
    deviceslist = {}
    count = 0
    counts = 0
    spinnerx = 0
    spinner = "|/-\\|"
    ip_list = {}
    response_list = {}
    socktimeouts = {}
    poll_devices = {}
    ip_scan_running = False
    scan_end_time = time.time() + scantime
    provoke_response = tinytuya.pack_message( tinytuya.TuyaMessage(0, tinytuya.DP_QUERY, 0, b'', 0) )

    if forcescan:
        if verbose:
            print(subbold + "    Option: " + dim + "Network force scanning requested.\n")

        if not NETIFLIBS:
             print(alert +
                    '    NOTE: netifaces module not available, multi-interface machines will be limited.\n'
                    '           (Requires: pip install netifaces)\n' + dim)
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
                          '       (using %s)' % DEFAULT_NETWORK + normal)

        scan_ips = _generate_ip_connected( networks, verbose, termcolors )
        ip_scan_running = True
        reap_time = time.time() + 5

        # Warn user of scan duration
        if verbose:
            print(bold + '\n    Running Scan...' + dim)

    log.debug("Listening for Tuya devices on UDP 6666 and 6667")
    start_time = time.time()
    read_socks = [client, clients]
    write_socks = []
    debug_socks = {}
    sock_ips = {} # doubles as a retry flag
    current_ip = None
    need_sleep = 0.1
    while ip_scan_running or scan_end_time > time.time():
        if ip_scan_running:
            # half-speed the spinner while force-scanning
            need_sleep = 0.2
            # time out any sockets which have not yet connected
            if reap_time < time.time():
                # no need to run this every single time through the loop
                reap_time = time.time() + connect_timeout
                rem = []
                for k in socktimeouts:
                    if socktimeouts[k] < time.time():
                        if k in debug_socks:
                            print('Debug sock', debug_socks[k], 'timed out!')
                            print(k)
                        rem.append(k)
                for k in rem:
                    del socktimeouts[k]
                    write_socks.remove(k)
                    if k in sock_ips:
                        del sock_ips[k]
                    k.close()
            if len(write_socks) < max_parallel:
                want = max_parallel - len(write_socks)
                # only open 10 at most during each pass through select()
                if want > 10: want = 10
                for i in range(want):
                    current_scan = next( scan_ips, None )
                    # all done!
                    if current_scan is None:
                        ip_scan_running = False
                        # reset the end time to the larger of scantime or connect_timeout
                        scan_end_time = time.time() + (scantime if scantime > connect_timeout else connect_timeout)
                        need_sleep = 0.1
                        break
                    else:
                        current_ip = current_scan[0]
                        write_socks.append( current_scan[1] )
                        sock_ips[current_scan[1]] = current_ip
                        socktimeouts[current_scan[1]] = time.time() + connect_timeout
                        if current_ip in debug_ips:
                            debug_socks[current_scan[1]] = current_ip
                        # we slept here so adjust the loop sleep time accordingly
                        time.sleep(0.02)
                        need_sleep -= 0.02

        if verbose:
            tim = 'FS:'+str(current_ip) if ip_scan_running else str(int(scan_end_time - time.time()))
            print("%sScanning... %s (%s)                 \r" % (dim, spinner[spinnerx], tim), end="")
            spinnerx = (spinnerx + 1) % 4
            sys.stdout.flush()

        for sock in poll_devices:
            # if a device poll sock has been removed from both read_socks and write_socks then it was closed, so retry
            if (sock not in read_socks) and (sock not in write_socks):
                # connection failed, retry
                if poll_devices[sock]['retries'] > 0:
                    poll_devices[sock]['retries'] -= 1
                    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    a_socket.setblocking(False)
                    a_socket.connect_ex( (poll_devices[sock]['ip'], TCPPORT) )
                    poll_devices[sock]['timeout'] = timeo = time.time() + tinytuya.TIMEOUT
                    if scan_end_time < timeo:
                        scan_end_time = timeo
                    poll_devices[a_socket] = poll_devices[sock]
                    del poll_devices[sock]
                    write_socks.append( a_socket )
                else:
                    ip = poll_devices[sock]['ip']
                    if verbose:
                        _print_device_info( deviceslist[ip], 'Valid Broadcast', termcolors )
                        print("%s    Polling %s Failed: %s" % (alertdim, ip, deviceslist[ip]["err"]))
                    del poll_devices[sock]

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
            write_socks.remove(sock)
            if sock in socktimeouts:
                del socktimeouts[sock]
            try:
                # getpeername() blows up with "OSError: [Errno 107] Transport endpoint is
                # not connected" if the connection was refused
                addr = sock.getpeername()[0]
            except:
                addr = None
                if sock in debug_socks:
                    print('Debug sock', debug_socks[sock], 'failed!')
                    print(sock)
                    print(traceback.format_exc())

            # connection failed
            if not addr:
                # connection failed while trying to poll a device
                if sock in poll_devices:
                    # close it and let the loop retry it
                    ip = poll_devices[sock]['ip']
                    deviceslist[ip]["err"] = "Connection Failed"

                # if it is in sock_ips then we can retry
                elif sock in sock_ips:
                    # sometimes the devices accept the connection, but then immediately close it
                    # so, retry if that happens
                    try:
                        # this should throw either ConnectionResetError or ConnectionRefusedError
                        r = sock.recv( 5000 )
                        print('recv:', r)
                    # ugh, ConnectionResetError and ConnectionRefusedError are not available on python 2.7
                    #except ConnectionResetError:
                    except OSError as e:
                        if e.errno == errno.ECONNRESET:
                            # connected, but then closed.  retry
                            print('retrying', sock_ips[sock])
                            a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            a_socket.setblocking(False)
                            a_socket.connect_ex( (sock_ips[sock], TCPPORT) )
                            write_socks.append(a_socket)
                            socktimeouts[a_socket] = time.time() + connect_timeout
                        elif sock in debug_socks:
                            print('failed 1', sock_ips[sock], e.errno, errno.ECONNRESET)
                            print(traceback.format_exc())
                    except:
                        if sock in debug_socks:
                            print('failed 2', sock_ips[sock])
                            print(traceback.format_exc())

                sock.close()
                continue

            # connection succeeded!
            # see if we are trying to poll this device
            if sock in poll_devices:
                ip = poll_devices[sock]['ip']
                try:
                    # connected, send the query
                    sock.sendall( poll_devices[sock]['device'].generate_payload(tinytuya.DP_QUERY) )
                    read_socks.append(sock)
                    #deviceslist[ip]["err"] = "Check DEVICE KEY - Invalid response"
                    deviceslist[ip]["err"] = "No response"
                except:
                    deviceslist[ip]["err"] = "Send Poll failed"
                    #print(traceback.format_exc())
                    sock.close()

                continue

            # not polling, so it is from force-scanning
            ip = "%s" % addr
            # get the MAC address if it is available
            mac = get_mac_address(ip=ip) if SCANLIBS else None
            ip_list[ip] = mac
            log.debug("Found Device %s [%s] (total devices: %d)", ip, mac, len(ip_list))
            if verbose:
                print(" Force-Scan Found Device %s [%s]" % (ip, mac))

            # since we do not have a MAC address to match against, try and get a response so we can brute-force the key
            if not mac:
                try:
                    sock.sendall( provoke_response )
                    read_socks.append( sock )
                except:
                    #print(traceback.format_exc())
                    sock.close()
            # we have a MAC address, so no need to get anything else
            else:
                sock.close()

        # these sockets are now have data waiting to be read
        for sock in rd:
            # this sock is not a UDP listener
            if sock is not client and sock is not clients:
                try:
                    addr = sock.getpeername()[0]
                    ip = "%s" % addr
                    data = sock.recv( 5000 )
                    msgs = []
                    finished = False

                    while len(data):
                        try:
                            msg = tinytuya.unpack_message(data)
                            msgs.append(msg)
                        except:
                            break

                        data = data[tinytuya.message_length(msg.payload):]

                    for msg in msgs:
                        # ignore NULL packets
                        if len(msg.payload) == 0:
                            continue

                        if sock in poll_devices:
                            dev_type = poll_devices[sock]['device'].dev_type
                            try:
                                # Data available: seqno cmd retcode payload crc
                                log.debug("raw unpacked message = %r", msg)
                                result = poll_devices[sock]['device']._decode_payload(msg.payload)
                            except:
                                log.debug("error unpacking or decoding tuya JSON payload")
                                result = error_json(ERR_PAYLOAD)

                            # Did we detect a device22 device? Return ERR_DEVTYPE error.
                            if dev_type != poll_devices[sock]['device'].dev_type:
                                log.debug(
                                    "Device22 detected and updated (%s -> %s) - Update payload and try again",
                                    dev_type,
                                    poll_devices[sock]['device'].dev_type,
                                )
                                sock.sendall( poll_devices[sock]['device'].generate_payload(tinytuya.DP_QUERY) )
                                break

                            finished = True
                            if sock in poll_devices:
                                del poll_devices[sock]

                            if not result or "dps" not in result:
                                if verbose:
                                    _print_device_info( deviceslist[ip], 'Valid Broadcast', termcolors )
                                    if result and "Error" in result:
                                        print("%s    Access rejected by %s: %s" % (alertdim, ip, result["Error"]))
                                    else:
                                        print("%s    Check DEVICE KEY - Invalid response from %s: %r" % (alertdim, ip, result))
                                deviceslist[ip]["err"] = "Unable to poll"
                            else:
                                deviceslist[ip]["dps"] = result
                                if verbose:
                                    _print_device_info( deviceslist[ip], 'Valid Broadcast', termcolors )
                                    print(dim + "    Status: %s" % result["dps"])
                        else:
                            #print(ip, msg.payload)
                            #msg2 = (msg, data)
                            if ip in response_list:
                                response_list[ip].append(msg)
                            else:
                                response_list[ip] = [msg]

                            # we now have the version, so close it since there is nothing else we can get
                            if msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31) or msg.payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_33):
                                finished = True
                                if sock in sock_ips:
                                    del sock_ips[sock]
                    if finished:
                        sock.close()
                        read_socks.remove( sock )

                # connection lost??
                except:
                    #print(traceback.format_exc())
                    sock.close()
                    if sock in read_socks:
                        read_socks.remove(sock)
                    # FIXME should we retry?
                    if sock in sock_ips:
                        del sock_ips[sock]

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
                    print(alertdim + "*  Unexpected payload=%r\n" + normal, result)
                log.debug("Invalid UDP Packet: %r", result)
                continue

            # check to see if we have seen this device before and add to devices array
            if tinytuya.appenddevice(result, deviceslist) is False:
                # Try to pull name and key data
                (dname, dkey, mac) = tuyaLookup(result['gwId'])
                deviceslist[ip]["name"] = dname
                deviceslist[ip]["key"] = dkey
                deviceslist[ip]["mac"] = mac

                if poll:
                    # v3.1 does not require a key for polling, but v3.2+ do
                    if result['version'] != "3.1" and not dkey:
                        if verbose:
                            _print_device_info( result, 'Valid Broadcast', termcolors )
                            print(
                                "%s    No Stats for %s: DEVICE KEY required to poll for status%s"
                                % (alertdim, ip, dim)
                            )
                    else:
                        # open a connection and dump it into the select()
                        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        a_socket.setblocking(False)
                        a_socket.connect_ex( (ip, TCPPORT) )
                        timeo = time.time() + tinytuya.TIMEOUT
                        if scan_end_time < timeo:
                            scan_end_time = timeo
                        d = tinytuya.OutletDevice(result['gwId'], ip, dkey)
                        d.set_version(float(result['version']))
                        poll_devices[a_socket] = {'ip': ip, 'timeout': timeo, 'retries': 3, 'device': d}
                        write_socks.append( a_socket )
                elif verbose:
                    _print_device_info( result, 'Valid Broadcast', termcolors )



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
                            _print_device_info( result, 'Force Scanned', termcolors )
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
                            _print_device_info( result, 'Force Scanned', termcolors ) # note
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
            % (normal, len(deviceslist))
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
        print(bold + "\n>> " + normal + "Saving device snapshot data to " + SNAPSHOTFILE + "\n")
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
