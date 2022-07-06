# TinyTuya Interactive User Interface
# -*- coding: utf-8 -*-
"""
TinyTuya API Server for Tuya based WiFi smart devices

Author: Jason A. Cox
Date: June 11, 2022
For more information see https://github.com/jasonacox/tinytuya

Description
    Interactive User Interface to Tuya devices

"""

# Modules
from __future__ import print_function
import threading
import time
import logging
import json
import socket
import requests
import sys
import os
import tinytuya

# Required module: pycryptodome
try:
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes

# Defaults
DEBUGMODE = False
DEVICEFILE = tinytuya.DEVICEFILE
SNAPSHOTFILE = tinytuya.SNAPSHOTFILE
TCPTIMEOUT = tinytuya.TCPTIMEOUT    # Seconds to wait for socket open for scanning
TCPPORT = tinytuya.TCPPORT          # Tuya TCP Local Port
MAXCOUNT = tinytuya.MAXCOUNT        # How many tries before stopping
UDPPORT = tinytuya.UDPPORT          # Tuya 3.1 UDP Port
UDPPORTS = tinytuya.UDPPORTS        # Tuya 3.3 encrypted UDP Port
TIMEOUT = tinytuya.TIMEOUT          # Socket Timeout

# Static Assets
web_root = os.path.join(os.path.dirname(__file__), "web")

# Logging
log = logging.getLogger(__name__)

# Global Variables
running = True
havekeys = False
tuyadevices = []
deviceslist = {}

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
    """
    for i in devices:
        if i['ip'] == newdevice['ip']:
                return True
    """
    devices[newdevice["id"]] = newdevice
    return False

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

# Debug Mode
tinytuya.set_debug(DEBUGMODE)

# Threads
def tuyalisten(port):
    """
    Thread to listen for Tuya devices UDP broadcast on port 
    """
    log.debug("Started tuyalisten thread on %d", port)

    # Enable UDP listening broadcasting mode on UDP port 
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", port))
    client.settimeout(port)

    while(running):
        try:
            data, addr = client.recvfrom(4048)
        except KeyboardInterrupt as err:
            break
        except Exception as err:
            continue
        ip = addr[0]
        gwId = dname = dkey = mac = ""
        result = data
        try:
            result = data[20:-8]
            try:
                result = tinytuya.decrypt_udp(result)
            except:
                result = result.decode()
            result = json.loads(result)
            #log.debug("Received valid UDP packet: %r", result)
            ip = result["ip"]
            gwId = result["gwId"]
        except:
            result = {"ip": ip}
            #log.debug("Invalid UDP Packet: %r", result)
        if havekeys:
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

        # add device if new
        appenddevice(result, deviceslist)


def set(id, dpsKey, dpsValue):
    # convert to correct types
    if dpsValue.lower() == "true":
        dpsValue = True
    if dpsValue.lower() == "false":
        dpsValue = False
    if dpsValue.isnumeric():
        dpsValue = int(dpsValue)
    if(id in deviceslist):
        d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
        d.set_version(float(deviceslist[id]["version"]))
        message = formatreturn(d.set_value(dpsKey,dpsValue,nowait=True))
        d.close()
    else:
        message = json.dumps({"Error": "Device ID not found.", "id": id})
    return(message)

def details(id):
    if(id in deviceslist):
        message = json.dumps(deviceslist[id])
    else:
        message = json.dumps({"Error": "Device ID not found.", "id": id})
    return(message)
        
def turnoff(id, sw=1):        
    if id in deviceslist:
        try:
            d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
            d.set_version(float(deviceslist[id]["version"]))
            message = formatreturn(d.turn_off(switch=sw, nowait=True))
            d.close()
        except:
            message = json.dumps({"Error": "Error sending command to device.", "id": id})
    return(message)

def turnon(id, sw=1):
    if id in deviceslist:
        try:
            d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
            d.set_version(float(deviceslist[id]["version"]))
            message = formatreturn(d.turn_on(switch=sw, nowait=True))
            d.close()
        except:
            message = json.dumps({"Error": "Error sending command to device.", "id": id})
    return(message)

def numdevices():
    jout = {}
    jout["numdevices"] = len(deviceslist)
    message = json.dumps(jout)
    return(message)

def status(id):
    if(id in deviceslist):
        try:
            d = tinytuya.OutletDevice(id, deviceslist[id]["ip"], deviceslist[id]["key"])
            d.set_version(float(deviceslist[id]["version"]))
            message = formatreturn(d.status())
            d.close()
        except:
            message = json.dumps({"Error": "Error polling device.", "id": id})
    return(message)

def devices():
    message = json.dumps(deviceslist, indent=4)
    return(message)

# MAIN Thread
if __name__ == "__main__":
    # creating thread
    tuyaUDP = threading.Thread(target=tuyalisten, args=(UDPPORT,))
    tuyaUDPs = threading.Thread(target=tuyalisten, args=(UDPPORTS,))
    
    print(
        "\n%sTinyTuya %s(Server)%s [%s]\n"
        % (bold, normal, dim, tinytuya.__version__)
    )
    if havekeys:
        print("%s[Loaded devices.json - %d devices]%s\n" % (dim, len(tuyadevices), normal))
    
    # start threads
    print("Starting threads...")
    tuyaUDP.start()
    tuyaUDPs.start()
    
    CMDS = "devices, status, numdevices, turnon, turnoff, details, set"
    try:
        while(True):
            print("\n\nCommands: %s\n[%d Devices] > " % (CMDS, len(deviceslist)), end='')
            user = input()
            if user == "exit":
                running = False
                break
            if user == "devices":
                print(devices())
            if user == "status":
                print("Enter ID")
                print(status(input()))
            if user == "numdevices":
                print(numdevices())
            if user == "turnon":
                print("Enter ID")
                print(turnon(input()))
            if user == "turnoff":
                print("Enter ID")
                print(turnoff(input()))
            if user == "details":
                print("Enter ID")
                print(details(input()))
            if user == "set":
                print("Enter ID")
                id = input()
                print("Enter DPS key:")
                key = input()
                print("Enter DPS value:")
                value = input()
                print(set(id, key, value))


    except KeyboardInterrupt:
        running = False
        # Close down API thread

    # both threads completely executed
    print("Done!")