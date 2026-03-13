# TinyTuya Module
# -*- coding: utf-8 -*-

import json
import logging

from .const import DEVICEFILE
from . import command_types as CT

log = logging.getLogger(__name__)

def find_device(dev_id=None, address=None):
    """Scans network for Tuya devices with either ID = dev_id or IP = address

    Args:
      dev_id (str, optional): The specific Device ID you are looking for
      address (str, optional): The IP address you are tring to find the Device ID for

    Returns:
      dict or None: `{'ip':<ip>, 'version':<version>, 'id':<id>, 'product_id':<product_id>, 'data':<broadcast data>}`
    """
    if dev_id is None and address is None:
        return {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}

    from .. import scanner

    want_ids = (dev_id,) if dev_id else None
    want_ips = (address,) if address else None
    all_results = scanner.devices(verbose=False, poll=False, forcescan=False, byID=True, wantids=want_ids, wantips=want_ips)
    ret = None

    for gwId in all_results:
        # Check to see if we are only looking for one device
        if dev_id and gwId != dev_id:
            continue
        if address and address != all_results[gwId]['ip']:
            continue

        # We found it!
        result = all_results[gwId]
        product_id = '' if 'productKey' not in result else result['productKey']
        ret = {'ip':result['ip'], 'version':result['version'], 'id':gwId, 'product_id':product_id, 'data':result}
        break

    if ret is None:
        ret = {'ip':None, 'version':None, 'id':None, 'product_id':None, 'data':{}}
    log.debug( 'find() is returning: %r', ret )
    return ret

def device_info( dev_id ):
    """Searches the :py:data:`~tinytuya.DEVICEFILE` file for devices with ID == dev_id

    Parameters:
      dev_id (str): The specific Device ID you are looking for

    Returns:
      dict or None: Device dict containing the the device info, or None if not found
    """
    devinfo = None
    try:
        # Load defaults
        with open(DEVICEFILE, 'r') as f:
            tuyadevices = json.load(f)
            log.debug("loaded=%s [%d devices]", DEVICEFILE, len(tuyadevices))
            for dev in tuyadevices:
                if 'id' in dev and dev['id'] == dev_id:
                    log.debug("Device %r found in %s", dev_id, DEVICEFILE)
                    devinfo = dev
                    break
    except:
        # No DEVICEFILE
        pass

    return devinfo

def merge_dps_results(dest, src):
    """Merge multiple receive() responses into a single dict

    `src` will be combined with and merged into `dest`

    Args:
      dest (dict): Destination dict to merge into
      src (dict): Source dict to merge from

    Returns:
      None: Nothing, dest dict is modified in-place
    """
    if src and isinstance(src, dict) and 'Error' not in src and 'Err' not in src:
        for k in src:
            if k == 'dps' and src[k] and isinstance(src[k], dict):
                if 'dps' not in dest or not isinstance(dest['dps'], dict):
                    dest['dps'] = {}
                for dkey in src[k]:
                    dest['dps'][dkey] = src[k][dkey]
            elif k == 'data' and src[k] and isinstance(src[k], dict) and 'dps' in src[k] and isinstance(src[k]['dps'], dict):
                if k not in dest or not isinstance(dest[k], dict):
                    dest[k] = {'dps': {}}
                if 'dps' not in dest[k] or not isinstance(dest[k]['dps'], dict):
                    dest[k]['dps'] = {}
                for dkey in src[k]['dps']:
                    dest[k]['dps'][dkey] = src[k]['dps'][dkey]
            else:
                dest[k] = src[k]

# Tuya Device Dictionary - Command and Payload Overrides
#
# 'default' devices require the 0a command for the DP_QUERY request
# 'device22' devices require the 0d command for the DP_QUERY request and a list of
#            dps used set to Null in the request payload
#
# Any command not defined in payload_dict will be sent as-is with a
#  payload of {"gwId": "", "devId": "", "uid": "", "t": ""}

payload_dict = {
    # Default Device
    "default": {
        CT.AP_CONFIG: {  # [BETA] Set Control Values on Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CT.CONTROL: {  # Set Control Values on Device
            "command": {"devId": "", "uid": "", "t": ""},
        },
        CT.STATUS: {  # Get Status from Device
            "command": {"gwId": "", "devId": ""},
        },
        CT.HEART_BEAT: {"command": {"gwId": "", "devId": ""}},
        CT.DP_QUERY: {  # Get Data Points from Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CT.CONTROL_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        CT.DP_QUERY_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        CT.UPDATEDPS: {"command": {"dpId": [18, 19, 20]}},
        CT.LAN_EXT_STREAM: { "command": { "reqType": "", "data": {} }},
    },
    # Special Case Device with 22 character ID - Some of these devices
    # Require the 0d command as the DP_QUERY status request and the list of
    # dps requested payload
    "device22": {
        CT.DP_QUERY: {  # Get Data Points from Device
            "command_override": CT.CONTROL_NEW,  # Uses CONTROL_NEW command for some reason
            "command": {"devId": "", "uid": "", "t": ""},
        },
    },
    # v3.3+ devices do not need devId/gwId/uid
    "v3.4": {
        CT.CONTROL: {
            "command_override": CT.CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
            },
        CT.CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        CT.DP_QUERY: {
            "command_override": CT.DP_QUERY_NEW,
            "command": {} #"protocol":4, "t": "int", "data": {}}
        },
        CT.DP_QUERY_NEW: {
            "command": {}
        },
    },
    # v3.5 is just a copy of v3.4
    "v3.5": {
        CT.CONTROL: {
            "command_override": CT.CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        CT.CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        CT.DP_QUERY: {
            "command_override": CT.DP_QUERY_NEW,
            "command": {}
        },
        CT.DP_QUERY_NEW: {
            "command": {}
        },
    },
    # placeholders, not yet needed
    "gateway": { },
    "gateway_v3.4": { },
    "gateway_v3.5": { },
    "zigbee": {
        CT.CONTROL: { "command": {"t": "int", "cid": ""} },
        CT.DP_QUERY: { "command": {"t": "int", "cid": ""} },
    },
    "zigbee_v3.4": {
        CT.CONTROL: {
            "command_override": CT.CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CT.CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
    "zigbee_v3.5": {
        CT.CONTROL: {
            "command_override": CT.CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CT.CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
}
