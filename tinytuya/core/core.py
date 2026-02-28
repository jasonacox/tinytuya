# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya
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

version_tuple = (1, 17, 6)  # Major, Minor, Patch
version = __version__ = "%d.%d.%d" % version_tuple

__author__ = "jasonacox"
__copyright__ = '2026, Jason A. Cox'
__project__ = 'TinyTuya'


log = logging.getLogger(__name__)


# Python 2 Support
IS_PY2 = sys.version_info[0] == 2


# Misc Helpers
def bin2hex(x, pretty=False):
    """Turns binary data into hex string

    Args:
        x (bytes): Data to convert
        pretty (bool): Insert a space character between bytes

    Returns:
        str
    """
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
    """Turns a hex string into binary

    Args:
        x (str): Hex string as "AA BB CC" or "AABBCC"

    Returns:
        bytes
    """
    if IS_PY2:
        return x.decode("hex")
    else:
        return bytes.fromhex(x)

def set_debug(toggle=True, color=True):
    """Enable tinytuya verbose logging

    Args:
        toggle (bool): Enable debug logging
        color (bool): Output terminal control codes for color
    """
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

    Args:
        tuyadevices (list or tuple): list of devices
        mappings (dict) = dict containing the mappings

    Returns:
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
    """Pads a string to be a multiple of 16 chars

    .. deprecated:: v0.x

    Args:
        s (str): input string to pad

    Returns:
        str: input padded to a multiple of 16 chars

    :meta private:
    """
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    """Un-pads a string that was padded to be a multiple of 16 chars

    .. deprecated:: v0.x

    Args:
        s (str): input string to unpad

    Returns:
        str

    :meta private:
    """
    return s[: -ord(s[len(s) - 1 :])]


def appenddevice(newdevice, devices):
    """Appends a device to a devicelist using the IP address as a key

    If there is already a device with that IP then the new device is not appended.

    .. deprecated:: v0.x

    Args:
        newdevice (dict): New device
        devices (dict): Existing list of devices by IP address

    Returns:
        bool: True if device already exists and was skipped

    :meta private:
    """
    if newdevice["ip"] in devices:
        return True
    devices[newdevice["ip"]] = newdevice
    return False

# Terminal color helper
def termcolor(color=True):
    """Returns a tuple containing terminal color/formatting codes if color is supported and enabled.

    Color is supported if colorama is installed or if the platform is not Windows

    Args:
        color (bool): If false, disables color even if color support is detected

    Returns:
        tuple: Format codes (bold,subbold,normal,dim,alert,alertdim,cyan,red,yellow)

    :meta private:
    """
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
    """Scans your network for Tuya devices with output to stdout

    .. deprecated:: v0.x Use the :py:mod:`~tinytuya.scanner` module instead

    Args:
        maxretry (float or int or None): When a number, stop scanning after that many seconds
        color (bool): Display output in color if color support is detected
        forcescan (bool): Brute force scan the :py:data:`~tinytuya.core.const.DEFAULT_NETWORK` network

    Returns:
        Nothing, the scan result is displayed

    :meta private:
    """
    from .. import scanner
    scanner.scan(scantime=maxretry, color=color, forcescan=forcescan)


# Scan function
def deviceScan(verbose=False, maxretry=None, color=True, poll=True, forcescan=False, byID=False):
    """Scans your network for Tuya devices and returns dictionary of devices discovered

    .. deprecated:: v0.x Use the :py:mod:`~tinytuya.scanner` module instead

    Args:
        verbose (bool): Print formatted output to stdout [Default: False]
        maxretry (float or int or None): When a number, stop scanning after that many seconds
        color (bool): Display output in color if color support is detected
        poll (bool): True or False, poll dps status for devices
        forcescan (bool): Brute force scan the :py:data:`~tinytuya.core.const.DEFAULT_NETWORK` network
        byID (bool): Returned dict keys are the Device ID (`True`) or IP address (`False`)

    Returns:
        devices (dict): Dictionary of all devices found, by DevID or IP

    To unpack the returned data, you can do something like this:

    .. code-block:: py

       devices = tinytuya.deviceScan()
       for ip in devices:
           devid = devices[ip]['id']
           key = devices[ip]['name']
           key = devices[ip]['key']
           vers = devices[ip]['version']
           dps = devices[ip]['dps']
    """
    from .. import scanner

    return scanner.devices(verbose=verbose, scantime=maxretry, color=color, poll=poll, forcescan=forcescan, byID=byID)
