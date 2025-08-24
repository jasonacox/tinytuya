# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Core Classes and Helper Functions

 Classes
  * AESCipher - Cryptography Helpers
  * XenonDevice(...) - Base Tuya Objects and Functions
        XenonDevice(dev_id, address=None, local_key="", dev_type="default", connection_timeout=5, 
            version="3.1", persist=False, cid/node_id=None, parent=None, connection_retry_limit=5, 
            connection_retry_delay=5, max_simultaneous_dps=0)
  * Device(XenonDevice) - Tuya Class for Devices

 Module Functions
    set_debug(toggle, color)                    # Activate verbose debugging output
    pack_message(msg, hmac_key=None)            # Packs a TuyaMessage() into a network packet, encrypting or adding a CRC if protocol requires
    unpack_message(data, hmac_key=None, header=None, no_retcode=False)
                                                # Unpacks a TuyaMessage() from a network packet, decrypting or checking the CRC if protocol requires
    parse_header(data)                          # Unpacks just the header part of a message into a TuyaHeader()
    find_device(dev_id=None, address=None)      # Scans network for Tuya devices with either ID = dev_id or IP = address
    device_info(dev_id)                         # Searches DEVICEFILE (usually devices.json) for devices with ID = dev_id and returns just that device
    assign_dp_mappings(tuyadevices, mappings)   # Adds mappings to all the devices in the tuyadevices list
    decrypt_udp(msg)                            # Decrypts a UDP network broadcast packet
    merge_dps_results(dest, src)                # Merge multiple receive() responses into a single dict
                                                #   `src` will be combined with and merged into `dest`

 Device Functions
    json = status()                    # returns json payload
    json = cached_status(historic=False, nowait=False)
                                       # When a persistent connection is open, this will return a cached version of the device status
                                       #   if historic=True, all seen DPs are returned even if their values might be out of date
                                       #   if historic=False, only DPs which are current are returned
                                       #   if nowait=False (the default), a status() call will be made if no cached status is available.
                                       #   if nowait=True, `None` will be returned immediately if no cached status is available.
    cache_clear()                      # Clears the cache, causing cached_status() to either call status() or return None
    subdev_query(nowait)               # query sub-device status (only for gateway devices)
    set_version(version)               # 3.1 [default], 3.2, 3.3 or 3.4
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]
    set_socketRetryLimit(integer)      # retry count limit [default 5]
    set_socketRetryDelay(integer)      # retry delay [default 5]
    set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
    set_dpsUsed(dps_to_request)        # add data points (DPS) to request
    add_dps_to_request(index)          # add data point (DPS) index set to None
    set_retry(retry=True)              # retry if response payload is truncated
    set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
    set_value(index, value, nowait)    # Set int value of any index.
    set_multiple_values(index_value_dict, nowait)
                                       # Set multiple values with a single request
    heartbeat(nowait)                  # Send heartbeat to device
    updatedps(index=[1], nowait)       # Send updatedps command to device
    turn_on(switch=1, nowait)          # Turn on device / switch #
    turn_off(switch=1, nowait)         # Turn off
    set_timer(num_secs, nowait)        # Set timer for num_secs
    set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
    detect_available_dps()             # Return list of DPS available from device
    generate_payload(command, data,...)# Generate TuyaMessage payload for command with data
    send(payload)                      # Send payload to device (do not wait for response)
    receive()                          # Receive payload from device

 Credits
  * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    For protocol reverse engineering
  * PyTuya https://github.com/clach04/python-tuya by clach04
    The origin of this python module (now abandoned)
  * LocalTuya https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
    Updated pytuya to support devices with Device IDs of 22 characters
  * Tuya Protocol 3.4 and 3.5 Support by uzlonewolf
    Enhancement to TuyaMessage logic for multi-payload messages

"""

# Modules
from __future__ import print_function  # python 2.7 support
import logging
import sys

try:
    from colorama import init
    HAVE_COLORAMA = True
except ImportError:
    HAVE_COLORAMA = False

HAVE_COLOR = HAVE_COLORAMA or not sys.platform.startswith('win')

from .crypto_helper import AESCipher

# Backward compatibility for python2
try:
    input = raw_input
except NameError:
    pass


# Colorama terminal color capability for all platforms
if HAVE_COLORAMA:
    init()

version_tuple = (1, 17, 4)  # Major, Minor, Patch
version = __version__ = "%d.%d.%d" % version_tuple
__author__ = "jasonacox"

log = logging.getLogger(__name__)


# Python 2 Support
IS_PY2 = sys.version_info[0] == 2


# Misc Helpers
def bin2hex(x, pretty=False):
    if pretty:
        space = " "
    else:
        space = ""
    if IS_PY2:
        result = "".join("%02X%s" % (ord(y), space) for y in x)
    else:
        result = "".join("%02X%s" % (y, space) for y in x)
    return result

def hex2bin(x):
    if IS_PY2:
        return x.decode("hex")
    else:
        return bytes.fromhex(x)

def set_debug(toggle=True, color=True):
    """Enable tinytuya verbose logging"""
    color = color and HAVE_COLOR
    if toggle:
        if color:
            logging.basicConfig(
                format="\x1b[31;1m%(levelname)s:%(message)s\x1b[0m", level=logging.DEBUG
            )
        else:
            logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.DEBUG)
        log.setLevel(logging.DEBUG)
        log.debug("TinyTuya [%s]\n", __version__)
        log.debug("Python %s on %s", sys.version, sys.platform)
        if not AESCipher.CRYPTOLIB_HAS_GCM:
            log.debug("Using %s %s for crypto", AESCipher.CRYPTOLIB, AESCipher.CRYPTOLIB_VER)
            log.debug("Warning: Crypto library does not support AES-GCM, v3.5 devices will not work!")
        else:
            log.debug("Using %s %s for crypto, GCM is supported", AESCipher.CRYPTOLIB, AESCipher.CRYPTOLIB_VER)
    else:
        log.setLevel(logging.NOTSET)


def assign_dp_mappings( tuyadevices, mappings ):
    """ Adds mappings to all the devices in the tuyadevices list

    Parameters:
        tuyadevices = list of devices
        mappings = dict containing the mappings

    Response:
        Nothing, modifies tuyadevices in place
    """
    if type(mappings) != dict:
        raise ValueError( '\'mappings\' must be a dict' )

    if (not mappings) or (not tuyadevices):
        return

    for dev in tuyadevices:
        try:
            devid = dev['id']
            productid = dev['product_id']
        except:
            # we need both the device id and the product id to download mappings!
            log.debug( 'Cannot add DP mapping, no device id and/or product id: %r', dev )
            continue

        if productid in mappings:
            dev['mapping'] = mappings[productid]
        else:
            log.debug( 'Device %s has no mapping!', devid )
            dev['mapping'] = None



########################################################
#             Core Classes and Functions
########################################################

# Utility Functions

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


def appenddevice(newdevice, devices):
    if newdevice["ip"] in devices:
        return True
    devices[newdevice["ip"]] = newdevice
    return False

# Terminal color helper
def termcolor(color=True):
    color = color and HAVE_COLOR
    if color is False:
        # Disable Terminal Color Formatting
        bold = subbold = normal = dim = alert = alertdim = cyan = red = yellow = ""
    else:
        # Terminal Color Formatting
        bold = "\033[0m\033[97m\033[1m"
        subbold = "\033[0m\033[32m"
        normal = "\033[97m\033[0m"
        dim = "\033[0m\033[97m\033[2m"
        alert = "\033[0m\033[91m\033[1m"
        alertdim = "\033[0m\033[91m\033[2m"
        cyan = "\033[0m\033[36m"
        red = "\033[0m\033[31m"
        yellow = "\033[0m\033[33m"
    return bold,subbold,normal,dim,alert,alertdim,cyan,red,yellow


# Scan function shortcut
def scan(maxretry=None, color=True, forcescan=False):
    """Scans your network for Tuya devices with output to stdout"""
    from .. import scanner
    scanner.scan(scantime=maxretry, color=color, forcescan=forcescan)


# Scan function
def deviceScan(verbose=False, maxretry=None, color=True, poll=True, forcescan=False, byID=False):
    """Scans your network for Tuya devices and returns dictionary of devices discovered
        devices = tinytuya.deviceScan(verbose)

    Parameters:
        verbose = True or False, print formatted output to stdout [Default: False]
        maxretry = The number of loops to wait to pick up UDP from all devices
        color = True or False, print output in color [Default: True]
        poll = True or False, poll dps status for devices if possible
        forcescan = True or False, force network scan for device IP addresses

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
    from .. import scanner

    return scanner.devices(verbose=verbose, scantime=maxretry, color=color, poll=poll, forcescan=forcescan, byID=byID)
