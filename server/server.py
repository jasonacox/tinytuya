# TinyTuya API Server
# -*- coding: utf-8 -*-
"""
TinyTuya API Server for Tuya based WiFi smart devices

Author: Jason A. Cox
Date: June 11, 2023
For more information see https://github.com/jasonacox/tinytuya

Description
    Server continually listens for Tuya UDP discovery packets and updates the database of devices
    and uses devices.json to determine metadata about devices.
    Server listens for GET requests on local port 8888:
        /devices                        - List all devices discovered with metadata
        /device/{DeviceID}|{DeviceName} - List specific device metadata
        /numdevices                     - List current number of devices discovered
        /status/{DeviceID}|{DeviceName} - List current device status
        /set/{DeviceID}|{DeviceName}/{Key}|{Code}/{Value}
                                        - Set DPS {Key} or {Code} with {Value}
        /turnon/{DeviceID}|{DeviceName}/{SwitchNo}
                                        - Turn on device, optional {SwtichNo}
        /turnoff/{DeviceID}|{DeviceName}/{SwitchNo}
                                        - Turn off device, optional {SwtichNo}
        /sync                           - Fetches the device list and local keys from the Tuya Cloud API
        /cloudconfig/{apiKey}/{apiSecret}/{apiRegion}/{apiDeviceID}
                                        - Sets the Tuya Cloud API login info
        /offline                        - List of registered devices that are offline
        /delayoff/{DeviceID}|{DeviceName}/{Time}
                                        - Turn off device with delay

"""

# Modules
from __future__ import print_function
import threading
import time
import logging
import json
import socket
try:
    import requests
except ImportError as impErr:
    print("WARN: Unable to import requests library, Cloud functions will not work.")
    print("WARN: Check dependencies. See https://github.com/jasonacox/tinytuya/issues/377")
    print("WARN: Error: {}.".format(impErr.args[0]))
import resource
import signal
import sys
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn 
import ipaddress

# Terminal color capability for all platforms
try:
    from colorama import init
    init()
except:
    pass

import tinytuya
from tinytuya import scanner
import os

BUILD = "p13"

# Defaults from Environment
APIPORT = int(os.getenv("APIPORT", "8888"))
DEVICEFILE = os.getenv("DEVICEFILE", tinytuya.DEVICEFILE)
SNAPSHOTFILE = os.getenv("SNAPSHOTFILE", tinytuya.SNAPSHOTFILE)
CONFIGFILE = os.getenv("CONFIGFILE", tinytuya.CONFIGFILE)
TCPTIMEOUT = float(os.getenv("TCPTIMEOUT", str(tinytuya.TCPTIMEOUT)))
TCPPORT = int(os.getenv("TCPPORT", str(tinytuya.TCPPORT)))
MAXCOUNT = int(os.getenv("MAXCOUNT", str(tinytuya.MAXCOUNT)))
UDPPORT = int(os.getenv("UDPPORT", str(tinytuya.UDPPORT)))
UDPPORTS = int(os.getenv("UDPPORTS", str(tinytuya.UDPPORTS)))
UDPPORTAPP = int(os.getenv("UDPPORTAPP", str(tinytuya.UDPPORTAPP)))
TIMEOUT = float(os.getenv("TIMEOUT", str(tinytuya.TIMEOUT)))
RETRYTIME = int(os.getenv("RETRYTIME", "30"))
RETRYCOUNT = int(os.getenv("RETRYCOUNT", "5"))
SAVEDEVICEFILE = os.getenv("SAVEDEVICEFILE", "True").lower() == "true"
DEBUGMODE = os.getenv("DEBUGMODE", "no").lower() == "yes"
HOST = os.getenv("HOST", None)
BROADCAST = os.getenv("BROADCAST", None)
NETWORK = None

# If HOST specified, set up broadcast address and calculate network
if HOST:
    if not BROADCAST:
        BROADCAST = HOST.split('.')
        BROADCAST[3] = '255'
        BROADCAST = '.'.join(BROADCAST)
    host_ip = ipaddress.IPv4Address(HOST)
    broadcast_ip = ipaddress.IPv4Address(BROADCAST)
    host_bits = int(host_ip)
    broadcast_bits = int(broadcast_ip)
    mask_length = 32 - (broadcast_bits - host_bits).bit_length()
    NETWORK = str(ipaddress.IPv4Network(f"{host_ip}/{mask_length}", strict=False))

# Logging
log = logging.getLogger(__name__)
if len(sys.argv) > 1 and sys.argv[1].startswith("-d"):
    DEBUGMODE = True
if DEBUGMODE:
    logging.basicConfig(
        format="\x1b[31;1m%(levelname)s [%(asctime)s]:%(message)s\x1b[0m", level=logging.DEBUG, 
        datefmt='%d/%b/%y %H:%M:%S'
    )
    log.setLevel(logging.DEBUG)
    log.debug("TinyTuya Server [%s]", BUILD)
    tinytuya.set_debug(True)

# Signal handler - Exit on SIGTERM
def sig_term_handle(signum, frame):
    raise SystemExit

signal.signal(signal.SIGTERM, sig_term_handle)

# Static Assets
web_root = os.path.join(os.path.dirname(__file__), "web")

# Global Stats
serverstats = {}
serverstats['tinytuya'] = "%s%s" % (tinytuya.version, BUILD)
serverstats['gets'] = 0
serverstats['errors'] = 0
serverstats['timeout'] = 0
serverstats['api'] = {}
serverstats['ts'] = int(time.time())         # Timestamp for Now
serverstats['start'] = int(time.time())      # Timestamp for Start 

# Global Variables
running = True
tuyadevices = []
deviceslist = {}
newdevices = []
retrydevices = {}
retrytimer = 0
cloudconfig = {'apiKey':'', 'apiSecret':'', 'apiRegion':'', 'apiDeviceID':''}
forcescan = False
forcescandone = True
cloudsync = False
cloudsyncdone = True
cloudcreds = True

# Terminal formatting
(bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(True)

# Helpful Functions

def tuyaLookup(deviceid):
    #  Function to Lookup Tuya device info by (id) returning (name, key)
    for i in tuyadevices:
        if i["id"] == deviceid:
            if "mac" in i:
                return (i["name"], i["key"], i["mac"])
            else:
                return (i["name"], i["key"], "")
    return ("", "", "")

def appenddevice(newdevice, devices):
    if newdevice["id"] in devices:
        return True
    devices[newdevice["id"]] = newdevice
    return False

def offlineDevices():
    # return undiscovered devices
    offline={}
    for d in tuyadevices:
        if type(d) != dict:
            continue
        id = d["id"]
        if id not in deviceslist:
            offline[id] = {}
            offline[id]["name"] = d["name"] 
            if "mac" in d:
                offline[id]["mac"] = d["mac"]
    return offline

def formatreturn(value):
    if value is None:
        result = {"status": "OK"}
    elif type(value) is dict:
        result = value
    else:
        result = {"status": value}
    return(json.dumps(result))

def get_static(web_root, fpath):
    if fpath.split('?')[0] == "/":
        fpath = "index.html"
    if fpath.startswith("/"):
        fpath = fpath[1:]
    fpath = fpath.split("?")[0]
    freq = os.path.join(web_root, fpath)
    if os.path.exists(freq):
        if freq.lower().endswith(".js"):
            ftype = "application/javascript"
        elif freq.lower().endswith(".css"):
            ftype = "text/css"
        elif freq.lower().endswith(".png"):
            ftype = "image/png"
        elif freq.lower().endswith(".html"):
            ftype = "text/html"
        else:
            ftype = "text/plain"

        with open(freq, 'rb') as f:
            return f.read(), ftype

    return None, None

def tuyaLoadJson():
    # Check to see if we have additional Device info
    tdevices = []
    try:
        # Load defaults
        with open(DEVICEFILE) as f:
            tdevices = json.load(f)
        log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tdevices))
    except:
        # No Device info
        log.debug("Device file %s could not be loaded", DEVICEFILE)

    return tdevices

def tuyaSaveJson():
    if not SAVEDEVICEFILE:
        return False

    try:
        with open(DEVICEFILE, 'w') as f:
            json.dump(tuyadevices, f, indent=4)
        log.debug("saved=%s [%d devices]", DEVICEFILE, len(tuyadevices))
    except:
        return False

    return True

def tuyaLoadConfig():
    # Check to see if we have Cloud account credentials from wizard
    config = {'apiKey':'', 'apiSecret':'', 'apiRegion':'', 'apiDeviceID':''}
    try:
        # Load defaults
        with open(CONFIGFILE) as f:
            config = json.load(f)
        log.debug("loaded config=%s", CONFIGFILE)
    except:
        # No Device info
        log.debug("No cloud config file found %s", CONFIGFILE)

    return config

tuyadevices = tuyaLoadJson()
cloudconfig = tuyaLoadConfig()

# Start with Cloud API credentials
if cloudconfig['apiKey'] == '' or cloudconfig['apiSecret'] == '' or cloudconfig['apiRegion'] == '' or cloudconfig['apiDeviceID'] == '':
    cloudcreds = False

def tuyaCloudRefresh():
    global tuyadevices
    print(" + Cloud Refresh Requested")
    log.debug("Calling Cloud Refresh")
    if cloudconfig['apiKey'] == '' or cloudconfig['apiSecret'] == '' or cloudconfig['apiRegion'] == '' or cloudconfig['apiDeviceID'] == '':
        log.debug("Cloud API config missing, not loading")
        return {'Error': 'Cloud API config missing'}

    cloud = tinytuya.Cloud( **cloudconfig )
    # on auth error, getdevices() will implode
    if cloud.error:
        return cloud.error
    tuyadevices = cloud.getdevices(verbose=False, oldlist=tuyadevices, include_map=True)
    tuyaSaveJson()
    print(f" - Cloud Refresh Complete: {len(tuyadevices)} devices")
    return {'devices': tuyadevices}

def getDeviceIdByName(name):
    id = False
    nameuq = urllib.parse.unquote(name)
    for key in deviceslist:
        if deviceslist[key]['name'] == nameuq:
            id = deviceslist[key]['id']
            break
    return (id)

# Threads
def tuyalisten(port):
    """
    Thread to listen for Tuya devices UDP broadcast on port 
    """
    global BROADCAST
    log.debug("Started tuyalisten thread on %d", port)
    print(" - tuyalisten %d Running" % port)
    last_broadcast = 0

    # Enable UDP listening broadcasting mode on UDP port 
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        # SO_REUSEPORT not available
        pass
    client.bind(("", port))
    client.settimeout(5)

    iface_list = None
    if HOST:
        iface_list = {}
        iface_list[HOST] = { 'broadcast': BROADCAST }
        log.debug("Using iface_list: %r", iface_list)

    while(running):
        if port == UDPPORTAPP and time.time() - last_broadcast > scanner.BROADCASTTIME:
            log.debug("Sending discovery request to all 3.5 devices on the network")
            if HOST:
                scanner.send_discovery_request(iface_list)
            else:
                scanner.send_discovery_request()
            last_broadcast = time.time()
        try:
            data, addr = client.recvfrom(4048)
        except (KeyboardInterrupt, SystemExit) as err:
            break
        except Exception as err:
            continue
        ip = addr[0]
        gwId = dname = dkey = mac = ""
        result = data
        try:
            result = tinytuya.decrypt_udp( data )
            result = json.loads(result)
            #log.debug("Received valid UDP packet: %r", result)
            ip = result["ip"]
            gwId = result["gwId"]
        except:
            result = {"ip": ip}
            #log.debug("Invalid UDP Packet: %r", result)
        try:
            # Try to pull name and key data
            (dname, dkey, mac) = tuyaLookup(gwId)
        except:
            pass
        if not gwId:
            continue
        # set values
        result["name"] = dname
        result["mac"] = mac
        result["key"] = dkey
        result["id"] = gwId
        result["forced"] = False

        # add device if new
        if not appenddevice(result, deviceslist):
            # Added device to list
            if dname == "" and dkey == "" and result["id"] not in newdevices:
                # If fetching the key failed, save it to retry later
                retrydevices[result["id"]] = RETRYCOUNT
                newdevices.append(result["id"])
    print(' - tuyalisten', port, 'Exit')
    log.debug("tuyalisten server thread on %d stopped", port)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def delayoff(d, sw):
    d.turn_off(switch=sw, nowait=True)
    d.close()

class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if DEBUGMODE:
            sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))
        else:
            pass

    def address_string(self):
        # replace function to avoid lookup delays
        host, hostport = self.client_address[:2]
        return host

    def do_POST(self):
        self.send_response(200)
        message = "Error"
        contenttype = 'application/json'
        # Send headers and payload  
        self.send_header('Content-type',contenttype)
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

    def do_GET(self):
        # pylint: disable=global-variable-not-assigned
        global retrytimer, retrydevices
        global cloudconfig, deviceslist
        global forcescan, forcescandone
        global serverstats, running
        global cloudcreds, cloudsync, cloudsyncdone
        global tuyadevices, newdevices

        self.send_response(200)
        message = "Error"
        contenttype = 'application/json'
        if self.path == '/devices':
            message = json.dumps(deviceslist)
        elif self.path == '/help':
            # show available commands
            cmds = [("/devices","List all devices discovered with metadata"),
                    ("/device/{DeviceID}|{DeviceName}", "List specific device metadata"),
                    ("/numdevices", "List current number of devices discovered"),
                    ("/status/{DeviceID}|{DeviceName}", "List current device status"),
                    ("/set/{DeviceID}|{DeviceName}/{Key}|{Code}/{Value}", "Set DPS {Key} or {Code} with {Value}"),
                    ("/turnon/{DeviceID}|{DeviceName}/{SwitchNo}", "Turn on device, optional {SwtichNo}"),
                    ("/turnoff/{DeviceID}|{DeviceName}/{SwitchNo}", "Turn off device, optional {SwtichNo}"),
                    ("/delayoff/{DeviceID}|{DeviceName}/{SwitchNo}/{Time}", "Turn off device with delay of 10 secs, optional {SwitchNo}/{Time}"),
                    ("/sync", "Fetches the device list and local keys from the Tuya Cloud API"),
                    ("/cloudconfig/{apiKey}/{apiSecret}/{apiRegion}/{apiDeviceID}", "Sets the Tuya Cloud API login info"),
                    ("/offline", "List of registered devices that are offline")]
            message = json.dumps(cmds)
        elif self.path == '/stats':
            # Give Internal Stats
            serverstats['ts'] = int(time.time())
            serverstats['mem'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            serverstats['cloudcreds'] = cloudcreds
            serverstats['cloudsync'] = cloudsync
            serverstats['cloudsyncdone'] = cloudsyncdone
            serverstats['forcescan'] = forcescan
            serverstats['forcescandone'] = forcescandone
            message = json.dumps(serverstats)
        elif self.path.startswith('/set/'):
            try:
                # ['', 'set', 'deviceid', 'key', 'value']
                (ignore1, ignore2, id, dpsKey, dpsValue) = self.path.split('/')
                # convert to correct types
                dpsValue = urllib.parse.unquote(dpsValue)
                if dpsValue.lower() == "true":
                    dpsValue = True
                elif dpsValue.lower() == "false":
                    dpsValue = False
                elif dpsValue.startswith('"'):
                    dpsValue = dpsValue.split('"')[1]
                elif dpsValue.isnumeric():
                    dpsValue = int(dpsValue)
                if(id not in deviceslist):
                    id = getDeviceIdByName(id)
                if not dpsKey.isnumeric():
                    for x in tuyadevices:
                        if x['id'] == id:
                            if 'mapping' in x:
                                for i in x['mapping']:
                                    if x['mapping'][i]['code'] == str(dpsKey):
                                        dpsKey = i
                                        break
                log.debug("Set dpsKey: %s dpsValue: %s" % (dpsKey,dpsValue))
                if(id in deviceslist):
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.set_value(dpsKey,dpsValue,nowait=True))
                    d.close()
                else:
                    message = json.dumps({"Error": "Device ID not found.", "id": id})
                    log.debug("Device ID not found: %s" % id)
            except:
                message = json.dumps({"Error": "Syntax error in set command URL.", "url": self.path})
                log.debug("Syntax error in set command URL: %s" % self.path)
        elif self.path.startswith('/device/'):
            id = self.path.split('/device/')[1]
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if(id in deviceslist):
                message = json.dumps(deviceslist[id])
            else:
                jout={}
                [name, key, mac] = tuyaLookup(id) 
                if name != "":
                    jout["name"] = name
                    jout["mac"] = mac
                    jout["key"] = key
                    jout["id"] = id
                    message = json.dumps(jout)
                else:
                    message = json.dumps({"Error": "Device ID not found.", "id": id})
                    log.debug("Device ID not found: %s" % id)
        elif self.path.startswith('/turnoff/'):
            id = self.path.split('/turnoff/')[1]
            sw = 1
            if "/" in id:
                try:
                    (id, sw) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in turnoff command.", "url": self.path})
                    log.debug("Syntax error in in turnoff command: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.turn_off(switch=sw, nowait=True))
                    d.close()
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device: %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})      
                log.debug("Device ID not found: %s" % id)      
        elif self.path.startswith('/delayoff/'):
            id = self.path.split('/delayoff/')[1]
            sw = 1
            delay = 10
            if "/" in id:
                try:
                    (id, sw, delay) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in delayoff command.", "url": self.path})
                    log.debug("Syntax error in in delayoff command: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))

                    timer = threading.Timer(int(delay), delayoff, args = (d, sw))
                    timer.start()

                    message = json.dumps({"OK": "Turning of in %s seconds." % (delay), "url": self.path})
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})
                log.debug("Device ID not found: %s" % id)
        elif self.path.startswith('/turnon/'):
            id = self.path.split('/turnon/')[1]
            sw = 1
            if "/" in id:
                try:
                    (id, sw) = id.split("/")
                except:
                    id = ""
                    message = json.dumps({"Error": "Invalid syntax in turnon command.", "url": self.path})
                    log.debug("Syntax error in turnon command URL: %s" % self.path)
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if id in deviceslist:
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    message = formatreturn(d.turn_on(switch=sw, nowait=True))
                    d.close()
                except:
                    message = json.dumps({"Error": "Error sending command to device.", "id": id})
                    log.debug("Error sending command to device %s" % id)
            elif id != "":
                message = json.dumps({"Error": "Device ID not found.", "id": id})     
                log.debug("Device ID not found: %s" % id)        
        elif self.path == '/numdevices':
            jout = {}
            jout["found"] = len(deviceslist)
            jout["registered"] = len(tuyadevices)
            jout["forcescan"] = forcescan
            jout["forcescandone"] = forcescandone
            jout["cloudsync"] = cloudsync
            jout["cloudsyncdone"] = cloudsyncdone
            jout["cloudcreds"] = cloudcreds
            message = json.dumps(jout)
        elif self.path.startswith('/status/'):
            id = self.path.split('/status/')[1]
            if(id not in deviceslist):
                id = getDeviceIdByName(id)
            if(id in deviceslist):
                try:
                    d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
                    d.set_version(float(deviceslist[id]["version"]))
                    response = d.status()
                    for x in tuyadevices:
                        if x['id'] == id:
                            if 'mapping' in x:
                                response["dps_mapping"] = x['mapping']
                            else:
                                response["dps_mapping"] = []
                            break
                    message = formatreturn(response)
                    d.close()
                except:
                    message = json.dumps({"Error": "Error polling device.", "id": id})
                    log.debug("Error polling device %s" % id)
            else:
                message = json.dumps({"Error": "Device ID not found.", "id": id})
                log.debug("Device ID not found: %s" % id)  
        elif self.path == '/sync':
            if cloudconfig['apiKey'] == '' or cloudconfig['apiSecret'] == '' or cloudconfig['apiRegion'] == '' or cloudconfig['apiDeviceID'] == '':
                message = json.dumps({"Error": "Cloud API config missing."})
                log.debug("Cloud API config missing")
            else:
                message = json.dumps({"OK": "Cloud Sync Started."})
            cloudsync = True
            cloudsyncdone = False
            retrytimer = 0
            retrydevices['*'] = 1
        elif self.path.startswith('/cloudconfig/'):
            cfgstr = self.path.split('/cloudconfig/')[1]
            cfg = cfgstr.split('/')
            if len(cfg) != 4:
                message = json.dumps({"Error": "Syntax error in cloud config command URL."})
                log.debug("Syntax error in cloud config command URL %s" % self.path)
            else:
                cloudconfig['apiKey'] = cfg[0]
                cloudconfig['apiSecret'] = cfg[1]
                cloudconfig['apiRegion'] = cfg[2]
                cloudconfig['apiDeviceID'] = cfg[3]
                message = json.dumps(tuyaCloudRefresh())
                retrytimer = time.time() + RETRYTIME
                retrydevices['*'] = 1
                cloudcreds = all(cfg)
        elif self.path == '/offline':
            message = json.dumps(offlineDevices())
        elif self.path == '/scan':
            # Force Scan for new devices
            forcescan = True
            forcescandone = False
            message = json.dumps({"OK": "Forcing a scan for new devices."})
        else:
            # Serve static assets from web root first, if found.
            fcontent, ftype = get_static(web_root, self.path)
            if fcontent:
                self.send_header('Content-type','{}'.format(ftype))
                self.send_header('Content-Length', str(len(fcontent)))
                self.end_headers()
                self.wfile.write(fcontent)
                return

        # Counts
        if "Error" in message:
            serverstats['errors'] = serverstats['errors'] + 1
        serverstats['gets'] = serverstats['gets'] + 1

        # Send headers and payload
        self.send_header('Content-type',contenttype)
        self.send_header('Content-Length', str(len(message)))
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

def api(port):
    """
    API Server - Thread to listen for commands on port 
    """
    log.debug("Started api server thread on %d", port)
    print(" - api %d Running" % port)

    with ThreadingHTTPServer(('', port), handler) as server:
        try:
            # server.serve_forever()
            while running:
                server.handle_request()
        except:
            print(' CANCEL \n')
    print(' - api', port, 'Exit')
    log.debug("API server thread on %d stopped", port)

# MAIN Thread
if __name__ == "__main__":
    # creating thread
    tuyaUDP = threading.Thread(target=tuyalisten, args=(UDPPORT,))
    tuyaUDPs = threading.Thread(target=tuyalisten, args=(UDPPORTS,))
    tuyaUDP7 = threading.Thread(target=tuyalisten, args=(UDPPORTAPP,))
    apiServer = threading.Thread(target=api, args=(APIPORT,))

    print(
        "\n%sTinyTuya %s(Server)%s [%s%s]\n"
        % (bold, normal, dim, tinytuya.__version__, BUILD)
    )

    # IP Address
    print("%sConfiguration Settings:" % dim)
    if HOST:
        print("   Using Host IP: %s%s%s" % (cyan, HOST, dim))
    if BROADCAST:
        print("   Using Broadcast IP: %s%s%s" % (cyan, BROADCAST, dim))
    if NETWORK:
        print("   Using Network: %s%s%s" % (cyan, NETWORK, dim))
    print("   UDP Ports: %s%d%s, %s%d%s, %s%d%s" % (cyan, UDPPORT, dim, cyan, UDPPORTS, dim, cyan, UDPPORTAPP, dim))
    print("   TCP Port: %s%d%s" % (cyan, TCPPORT, dim))
    print("   API Port: %s%d%s" % (cyan, APIPORT, dim))
    print("   Device File: %s%s%s" % (cyan, DEVICEFILE, dim))
    print("   Snapshot File: %s%s%s" % (cyan, SNAPSHOTFILE, dim))
    print("   Config File: %s%s%s" % (cyan, CONFIGFILE, dim))
    print("   TCP Timeout: %s%s%s" % (cyan, TCPTIMEOUT, dim))
    print("   UDP Timeout: %s%s%s" % (cyan, TIMEOUT, dim))
    print("   Max Devices: %s%s%s" % (cyan, MAXCOUNT, dim))
    print("   Retry Time: %s%s%s" % (cyan, RETRYTIME, dim))
    print("   Retry Count: %s%s%s" % (cyan, RETRYCOUNT, dim))
    print("   Save Device File: %s%s%s" % (cyan, SAVEDEVICEFILE, dim))
    print("   Debug Mode: %s%s%s" % (cyan, DEBUGMODE, dim))
    print("")

    if len(tuyadevices) > 0:
        print("%s[Loaded devices.json - %d devices]%s\n" % (dim, len(tuyadevices), normal))
    else:
        print("%sWARNING: No devices.json found - limited functionality.%s\n" % (alertdim,normal))

    # start threads
    print("Starting threads...")
    log.debug("Starting threads")
    tuyaUDP.start()
    tuyaUDPs.start()
    tuyaUDP7.start()
    apiServer.start()

    print(" * API and UI Endpoint on http://localhost:%d" % APIPORT)
    log.debug("Server URL http://localhost:%d" % APIPORT)

    try:
        while(True):
            log.debug("Discovered Devices: %d   " % len(deviceslist))
            if forcescan:
                print(" + ForceScan: Scan for new devices started...")
                forcescan = False
                retrytimer = time.time() + RETRYTIME
                # def devices(verbose=False, scantime=None, color=True, poll=True, forcescan=False, byID=False, show_timer=None, 
                #   discover=True, wantips=None, wantids=None, snapshot=None, assume_yes=False, tuyadevices=[], 
                #   maxdevices=0)
                try:
                    if NETWORK:
                        found = scanner.devices(forcescan=[NETWORK], verbose=False, discover=False, assume_yes=True, tuyadevices=tuyadevices)
                    else:
                        found = scanner.devices(forcescan=True, verbose=False, discover=False, assume_yes=True, tuyadevices=tuyadevices)
                except Exception as err:
                    log.error(f"Error during scanner.devices() {err}")
                    found = []
                forcescandone = True
                print(f" - ForceScan: Found {len(found)} devices")
                for f in found:
                    log.debug(f"   - {found[f]}")
                    gwId = found[f]["id"]
                    result = {}
                    dname = dkey = mac = ""
                    try:
                        # Try to pull name and key data
                        (dname, dkey, mac) = tuyaLookup(gwId)
                    except:
                        pass
                    # set values
                    result["name"] = dname
                    result["mac"] = mac
                    result["key"] = dkey
                    result["id"] = gwId
                    result["ip"] = found[f]["ip"]
                    result["version"] = found[f]["version"]
                    result["forced"] = True

                    # add device if new
                    if not appenddevice(result, deviceslist):
                        # Added device to list
                        if dname == "" and dkey == "" and result["id"] not in newdevices:
                            # If fetching the key failed, save it to retry later
                            retrydevices[result["id"]] = RETRYCOUNT
                            newdevices.append(result["id"])

            if cloudsync:
                cloudsync = False
                cloudsyncdone = False
                tuyaCloudRefresh()
                cloudsyncdone = True
                print(" - Cloud Sync Complete")
                retrytimer = time.time() + RETRYTIME
                retrydevices['*'] = 1

            if retrytimer <= time.time() or '*' in retrydevices:
                if len(retrydevices) > 0:
                    # only refresh the cloud if we are not here because /sync was called
                    if '*' not in retrydevices:
                        cloudsyncdone = False
                        tuyaCloudRefresh()
                        retrytimer = time.time() + RETRYTIME
                        cloudsyncdone = True
                    found = []
                    # Try all unknown devices, even if the retry count expired
                    for devid in newdevices:
                        dname = dkey = mac = ""
                        try:
                            (dname, dkey, mac) = tuyaLookup(devid)
                        except:
                            pass

                        if dname != "" or dkey != "":
                            #print('found!', devid, dname, dkey)
                            deviceslist[devid]['name'] = dname
                            deviceslist[devid]['key'] = dkey
                            deviceslist[devid]['mac'] = mac
                            found.append(devid)
                            if devid in retrydevices:
                                del retrydevices[devid]
                    for devid in found:
                        newdevices.remove(devid)

                    # Decrement retry count
                    expired = []
                    for devid in retrydevices:
                        retrydevices[devid] -= 1
                        if retrydevices[devid] < 1:
                            expired.append(devid)
                    for devid in expired:
                        del retrydevices[devid]
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        running = False
        # Close down API thread
        print("Stopping threads...")
        log.debug("Stoppping threads")
        requests.get('http://localhost:%d/stop' % APIPORT, timeout=5)
    except Exception as err:
        log.error(f"Error in main loop: {err}")
        running = False
        # Close down API thread
        print("Stopping threads...")
        log.debug("Stoppping threads")
        requests.get('http://localhost:%d/stop' % APIPORT, timeout=5)
