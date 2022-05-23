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
import sys
import time

import tinytuya

try:
    # Optional libraries required for forced scanning
    from getmac import get_mac_address
    SCANLIBS = True
except:
    # Disable nmap scanning
    SCANLIBS = False

# Required module: pycryptodome
try:
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes

# Backward compatability for python2
try:
    input = raw_input
except NameError:
    pass

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

# Logging
log = logging.getLogger(__name__)

# Helper Functions
def getmyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    return r


# Scan function shortcut
def scan(maxretry=None, color=True, forcescan=False):
    """Scans your network for Tuya devices with output to stdout"""
    # Terminal formatting
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)
    devices(verbose=True, maxretry=maxretry, color=color, poll=True, forcescan=forcescan)


# Scan function
def devices(verbose=False, maxretry=None, color=True, poll=True, forcescan=False, byID=False):
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        maxretry = The number of loops to wait to pick up UDP from all devices
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
    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)

    # Lookup Tuya device info by (id) returning (name, key)
    def tuyaLookup(deviceid):
        for i in tuyadevices:
            if i["id"] == deviceid:
                if "mac" in i:
                    return (i["name"], i["key"], i["mac"])
                else:
                    return (i["name"], i["key"], "")
        return ("", "", "")

    # Check to see if we have additional Device info
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tuyadevices = json.load(f)
            havekeys = True
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
            # If no maxretry value set, base it on number of devices
            if maxretry is None:
                maxretry = len(tuyadevices) + tinytuya.MAXCOUNT
    except:
        # No Device info
        pass

    # If no maxretry value set use default
    if maxretry is None:
        maxretry = tinytuya.MAXCOUNT

    # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", UDPPORT))
    client.settimeout(TIMEOUT)
    # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.3 Devices
    clients = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clients.bind(("", UDPPORTS))
    clients.settimeout(TIMEOUT)

    if verbose:
        print(
            "\n%sTinyTuya %s(Tuya device scanner)%s [%s]\n"
            % (bold, normal, dim, tinytuya.__version__)
        )
        if havekeys:
            print("%s[Loaded devices.json - %d devices]\n" % (dim, len(tuyadevices)))
        print(
            "%sScanning on UDP ports %s and %s for devices (%s retries)...%s\n"
            % (subbold, UDPPORT, UDPPORTS, maxretry, normal)
        )

    if forcescan:
        if not SCANLIBS:
            if verbose:
                print(alert +
                    '    ERROR: force network scanning requested but not available - disabled.\n'
                    '           (Requires: pip install getmac)\n' + dim)
            forcescan = False
        else:
            if verbose:
                print(subbold + "    Option: " + dim + "Network force scanning requested.\n")

    deviceslist = {}
    count = 0
    counts = 0
    spinnerx = 0
    spinner = "|/-\\|"
    ip_list = {}

    if forcescan:
        # Force Scan - Get list of all local ip addresses
        try:
            # Fetch my IP address and assume /24 network
            ip = getmyIP()
            network = ipaddress.IPv4Interface(u''+ip+'/24').network
            log.debug("Starting brute force network scan %r", network)
        except:
            network = DEFAULT_NETWORK
            ip = None
            log.debug("Unable to get local network, using default %r", network)
            if verbose:
                print(alert +
                    'ERROR: Unable to get your IP address and network automatically.'
                    '       (using %s)' % network + normal)

        try:
            # Warn user of scan duration
            if verbose:
                print("\n" + bold + "Scanning local network.  This may take a while..." + dim)
                print(bold + '\n    Running Scan...' + dim)
            # Loop through each host
            for addr in ipaddress.IPv4Network(network):
                # Fetch my IP address and assume /24 network
                if verbose:
                    print(dim + '\r      Host: ' + subbold + '%s ...' % addr + normal, end='')
                a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                a_socket.settimeout(TCPTIMEOUT)
                location = (str(addr), TCPPORT)
                result_of_check = a_socket.connect_ex(location)
                if result_of_check == 0:
                    # TODO: Verify Tuya Device
                    ip = "%s" % addr
                    mac = get_mac_address(ip=ip)
                    ip_list[ip] = mac
                    log.debug("Found Device [%s]", mac)
                    if verbose:
                        print(" Found Device [%s]" % mac)
                a_socket.close()

            if verbose:
                print(dim + '\r      Done                           ' +normal +
                            '\n\nDiscovered %d Tuya Devices\n' % len(ip_list))

        except:
            log.debug("Error scanning network - Ignoring")
            if verbose:
                print('\n' + alert + '    Error scanning network - Ignoring' + dim)
            forcescan = False

    log.debug("Listening for Tuya devices on UDP 6666 and 6667")
    while (count + counts) <= maxretry:
        note = "invalid"
        if verbose:
            print("%sScanning... %s\r" % (dim, spinner[spinnerx]), end="")
            spinnerx = (spinnerx + 1) % 4
            sys.stdout.flush()
            time.sleep(0.1)

        if count <= counts:  # alternate between 6666 and 6667 ports
            try:
                data, addr = client.recvfrom(4048)
            except KeyboardInterrupt as err:
                log.debug("Keyboard Interrupt - Exiting")
                if verbose:
                    print("\n**User Break**")
                sys.exit()
            except Exception as err:
                # Timeout
                count = count + 1
                continue
        else:
            try:
                data, addr = clients.recvfrom(4048)
            except KeyboardInterrupt as err:
                log.debug("Keyboard Interrupt - Exiting")
                if verbose:
                    print("\n**User Break**")
                sys.exit()
            except Exception as err:
                # Timeout
                counts = counts + 1
                continue
        ip = addr[0]
        gwId = productKey = version = dname = dkey = mac = mac2 = suffix = ""
        result = data
        try:
            result = data[20:-8]
            try:
                result = tinytuya.decrypt_udp(result)
            except:
                result = result.decode()

            result = json.loads(result)
            log.debug("Received valid UDP packet: %r", result)

            note = "Valid"
            ip = result["ip"]
            gwId = result["gwId"]
            productKey = result["productKey"]
            version = result["version"]
        except:
            if verbose:
                print(alertdim + "*  Unexpected payload=%r\n" + normal, result)
            result = {"ip": ip}
            note = "Unknown"
            log.debug("Invalid UDP Packet: %r", result)

        # check to see if we have seen this device before and add to devices array
        if tinytuya.appenddevice(result, deviceslist) is False:

            # new device found - back off count if we keep getting new devices
            if version == "3.1":
                count = tinytuya.floor(count - 1)
            else:
                counts = tinytuya.floor(counts - 1)
            # check if we have MAC address
            if havekeys:
                try:
                    # Try to pull name and key data
                    (dname, dkey, mac2) = tuyaLookup(gwId)
                except:
                    pass
            if mac2 == "" and ip in ip_list:
                mac = ip_list[ip]
            else:
                mac = mac2
            suffix = dim + ", MAC = " + mac + ""
            if verbose:
                if dname == "":
                    dname = gwId
                    devicename = "Unknown v%s%s Device%s" % (normal, version, dim)
                else:
                    devicename = normal + dname + dim
                print(
                    "%s   Product ID = %s  [%s payload]:\n    %sAddress = %s,  %sDevice ID = %s, %sLocal Key = %s,  %sVersion = %s%s"
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

            try:
                if poll:
                    time.sleep(0.1)  # give device a break before polling
                    if version == "3.1":
                        # Version 3.1 - no device key requires - poll for status data points
                        d = tinytuya.OutletDevice(gwId, ip, dkey)
                        d.set_version(3.1)
                        dpsdata = d.status()
                        if "dps" not in dpsdata:
                            if verbose:
                                if "Error" in dpsdata:
                                    print(
                                        "%s    Access rejected by %s: %s"
                                        % (alertdim, ip, dpsdata["Error"])
                                    )
                                else:
                                    print(
                                        "%s    Invalid response from %s: %r"
                                        % (alertdim, ip, dpsdata)
                                    )
                            deviceslist[ip]["err"] = "Unable to poll"
                        else:
                            deviceslist[ip]["dps"] = dpsdata
                            if verbose:
                                print(dim + "    Status: %s" % dpsdata["dps"])
                    else:
                        # Version 3.3+ requires device key
                        if dkey != "":
                            d = tinytuya.OutletDevice(gwId, ip, dkey)
                            d.set_version(3.3)
                            dpsdata = d.status()
                            if "dps" not in dpsdata:
                                if verbose:
                                    if "Error" in dpsdata:
                                        print(
                                            "%s    Access rejected by %s: %s"
                                            % (alertdim, ip, dpsdata["Error"])
                                        )
                                    else:
                                        print(
                                            "%s    Check DEVICE KEY - Invalid response from %s: %r"
                                            % (alertdim, ip, dpsdata)
                                        )
                                deviceslist[ip]["err"] = "Unable to poll"
                            else:
                                deviceslist[ip]["dps"] = dpsdata
                                if verbose:
                                    print(dim + "    Status: %s" % dpsdata["dps"])
                        else:
                            if verbose:
                                print(
                                    "%s    No Stats for %s: DEVICE KEY required to poll for status%s"
                                    % (alertdim, ip, dim)
                                )
                    # else
                # if poll
            except:
                if verbose:
                    print(alertdim + "    Unexpected error for %s: Unable to poll" % ip)
                deviceslist[ip]["err"] = "Unable to poll"
            if dname != "":
                deviceslist[ip]["name"] = dname
                deviceslist[ip]["key"] = dkey
            if mac != "":
                deviceslist[ip]["mac"] = mac
            deviceslist[ip]["id"] = gwId
            deviceslist[ip]["ver"] = version
        else:
            if version == "3.1":
                count = count + 1
            else:
                counts = counts + 1

    # Add Force Scan Devices
    for ip in ip_list:
        deviceslist[ip]["mac"] = ip_list[ip]
    if verbose:
        print(
            "                    \n%sScan Complete!  Found %s devices."
            % (normal, len(deviceslist))
        )
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
    clients.close()
    client.close()
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
                    if ver == "3.3":
                        d.set_version(3.3)
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
                    if ver == "3.3":
                        d.set_version(3.3)
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
                if ver == "3.3":
                    d.set_version(3.3)
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
