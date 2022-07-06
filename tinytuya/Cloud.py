# TinyTuya Cloud Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    Cloud(apiRegion, apiKey, apiSecret, apiDeviceID, new_sign_algorithm)

 Functions
    Cloud
        setregion(apiRegion)
        getdevices(verbose=False)
        getstatus(deviceid)
        getfunctions(deviceid)
        getproperties(deviceid)
        getdps(deviceid)
        sendcommand(deviceid, commands)
"""

from .core import *

import hashlib
import hmac
import json
import time
import requests

########################################################
#             Cloud Classes and Functions
########################################################

class Cloud(object):
    def __init__(self, apiRegion=None, apiKey=None, apiSecret=None, apiDeviceID=None, new_sign_algorithm=True):
        """
        Tuya Cloud IoT Platform Access

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.

        Playload Construction - Header Data:
            Parameter 	  Type    Required	Description
            client_id	  String     Yes	client_id
            signature     String     Yes	HMAC-SHA256 Signature (see below)
            sign_method	  String	 Yes	Message-Digest Algorithm of the signature: HMAC-SHA256.
            t	          Long	     Yes	13-bit standard timestamp (now in milliseconds).
            lang	      String	 No	    Language. It is zh by default in China and en in other areas.
            access_token  String     *      Required for service management calls

        Signature Details:
            * OAuth Token Request: signature = HMAC-SHA256(KEY + t, SECRET).toUpperCase()
            * Service Management: signature = HMAC-SHA256(KEY + access_token + t, SECRET).toUpperCase()

        URIs:
            * Get Token = https://openapi.tuyaus.com/v1.0/token?grant_type=1
            * Get UserID = https://openapi.tuyaus.com/v1.0/devices/{DeviceID}
            * Get Devices = https://openapi.tuyaus.com/v1.0/users/{UserID}/devices

        REFERENCE:
            * https://images.tuyacn.com/smart/docs/python_iot_code_sample.py
            * https://iot.tuya.com/cloud/products/detail
        """
        # Class Variables
        self.CONFIGFILE = 'tinytuya.json'
        self.apiRegion = apiRegion
        self.apiKey = apiKey
        self.apiSecret = apiSecret
        self.apiDeviceID = apiDeviceID
        self.urlhost = ''
        self.uid = None     # Tuya Cloud User ID
        self.token = None
        self.new_sign_algorithm = new_sign_algorithm

        if apiKey is None or apiSecret is None:
            try:
                # Load defaults from config file if available
                config = {}
                with open(self.CONFIGFILE) as f:
                    config = json.load(f)
                    self.apiRegion = config['apiRegion']
                    self.apiKey = config['apiKey']
                    self.apiSecret = config['apiSecret']
                    self.apiDeviceID = config['apiDeviceID']
            except:
                return error_json(
                    ERR_CLOUDKEY,
                    "Tuya Cloud Key and Secret required",
                )

        self.setregion(apiRegion)
        # Attempt to connect to cloud and get token
        self.token = self._gettoken()

    def setregion(self, apiRegion=None):
        # Set hostname based on apiRegion
        if apiRegion is None:
            apiRegion = self.apiRegion
        self.apiRegion = apiRegion.lower()
        self.urlhost = "openapi.tuyacn.com"          # China Data Center
        if self.apiRegion == "us":
            self.urlhost = "openapi.tuyaus.com"      # Western America Data Center
        if self.apiRegion == "us-e":
            self.urlhost = "openapi-ueaz.tuyaus.com" # Eastern America Data Center
        if self.apiRegion == "eu":
            self.urlhost = "openapi.tuyaeu.com"      # Central Europe Data Center
        if self.apiRegion == "eu-w":
            self.urlhost = "openapi-weaz.tuyaeu.com" # Western Europe Data Center
        if self.apiRegion == "in":
            self.urlhost = "openapi.tuyain.com"      # India Datacenter

    def _tuyaplatform(self, uri, action='GET', post=None, ver='v1.0', recursive=False):
        """
        Handle GET and POST requests to Tuya Cloud
        """
        # Build URL and Header
        url = "https://%s/%s/%s" % (self.urlhost, ver, uri)
        headers = {}
        body = {}
        if action == 'POST':
            body = json.dumps(post)
            headers['Content-type'] = 'application/json'
        else:
            action = 'GET'
        now = int(time.time()*1000)
        headers = dict(list(headers.items()) + [('Signature-Headers', ":".join(headers.keys()))]) if headers else {}
        if self.token is None:
            payload = self.apiKey + str(now)
            headers['secret'] = self.apiSecret
        else:
            payload = self.apiKey + self.token + str(now)

        # If running the post 6-30-2021 signing algorithm update the payload to include it's data
        if self.new_sign_algorithm:
            payload += ('%s\n' % action +                                                # HTTPMethod
                hashlib.sha256(bytes((body or "").encode('utf-8'))).hexdigest() + '\n' + # Content-SHA256
                ''.join(['%s:%s\n'%(key, headers[key])                                   # Headers
                            for key in headers.get("Signature-Headers", "").split(":")
                            if key in headers]) + '\n' +
                '/' + url.split('//', 1)[-1].split('/', 1)[-1])
        # Sign Payload
        signature = hmac.new(
            self.apiSecret.encode('utf-8'),
            msg=payload.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest().upper()

        # Create Header Data
        headers['client_id'] = self.apiKey
        headers['sign'] = signature
        headers['t'] = str(now)
        headers['sign_method'] = 'HMAC-SHA256'

        if self.token is not None:
            headers['access_token'] = self.token

        # Send Request to Cloud and Get Response
        if action == 'GET':
            response = requests.get(url, headers=headers)
            log.debug(
                "GET: response code=%d text=%s token=%s", response.status_code, response.text, self.token
            )
        else:
            log.debug(
                "POST: URL=%s HEADERS=%s DATA=%s", url, headers, body,
            )
            response = requests.post(url, headers=headers, data=body)

        # Check to see if token is expired
        if "token invalid" in response.text:
            if recursive is True:
                log.debug("Failed 2nd attempt to renew token - Aborting")
                return None
            log.debug("Token Expired - Try to renew")
            token = self._gettoken()
            if "err" in token:
                log.debug("Failed to renew token")
                return None
            else:
                return self._tuyaplatform(uri, action, post, ver, True)

        try:
            response_dict = json.loads(response.content.decode())
        except:
            try:
                response_dict = json.loads(response.content)
            except:
                return error_json(
                    ERR_CLOUDKEY,
                    "Cloud _tuyaplatform() invalid response: %r" % response.content,
                )
        # Check to see if token is expired
        return response_dict

    def _gettoken(self):
        # Get Oauth Token from tuyaPlatform
        self.token = None
        response_dict = self._tuyaplatform('token?grant_type=1')

        if not response_dict['success']:
            return error_json(
                ERR_CLOUDTOKEN,
                "Cloud _gettoken() failed: %r" % response_dict['msg'],
            )

        self.token = response_dict['result']['access_token']
        return self.token

    def _getuid(self, deviceid=None):
        # Get user ID (UID) for deviceid
        if deviceid is None:
            return error_json(
                ERR_PARAMS,
                "_getuid() requires deviceID parameter"
            )
        uri = 'devices/%s' % deviceid
        response_dict = self._tuyaplatform(uri)

        if not response_dict['success']:
            log.debug(
                "Error from Tuya Cloud: %r", response_dict['msg'],
            )
            return None
        uid = response_dict['result']['uid']
        return uid

    def getdevices(self, verbose=False):
        """
        Return dictionary of all devices.
        If verbose is true, return full Tuya device
        details.
        """
        uid = self._getuid(self.apiDeviceID)
        if uid is None:
            return error_json(
                ERR_CLOUD,
                "Unable to get device list"
            )
        # Use UID to get list of all Devices for User
        uri = 'users/%s/devices' % uid
        json_data = self._tuyaplatform(uri)

        # Use Device ID to get MAC addresses
        uri = 'devices/factory-infos?device_ids=%s' % (",".join(i['id'] for i in json_data['result']))
        json_mac_data = self._tuyaplatform(uri)

        if verbose:
            return json_data
        else:
            # Filter to only Name, ID and Key
            tuyadevices = []
            for i in json_data['result']:
                item = {}
                item['name'] = i['name'].strip()
                item['id'] = i['id']
                item['key'] = i['local_key']
                if 'mac' in i:
                    item['mac'] = i['mac']
                else:
                    try:
                        item['mac'] = next((m['mac'] for m in json_mac_data['result'] if m['id'] == i['id']), "N/A")
                    except:
                        pass
                tuyadevices.append(item)
                
            return tuyadevices

    def _getdevice(self, param='status', deviceid=None):
        if deviceid is None:
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID Parameter"
            )
        uri = 'iot-03/devices/%s/%s' % (deviceid, param)
        response_dict = self._tuyaplatform(uri)

        if not response_dict['success']:
            log.debug(
                "Error from Tuya Cloud: %r", response_dict['msg'],
            )
        return response_dict

    def getstatus(self, deviceid=None):
        """
        Get the status of the device.
        """
        return self._getdevice('status', deviceid)

    def getfunctions(self, deviceid=None):
        """
        Get the functions of the device.
        """
        return self._getdevice('functions', deviceid)

    def getproperties(self, deviceid=None):
        """
        Get the properties of the device.
        """
        return self._getdevice('specification', deviceid)

    def getdps(self, deviceid=None):
        """
        Get the specifications including DPS IDs of the device.
        """
        if deviceid is None:
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID Parameter"
            )
        uri = 'devices/%s/specifications' % (deviceid)
        response_dict = self._tuyaplatform(uri, ver='v1.1')

        if not response_dict['success']:
            log.debug(
                "Error from Tuya Cloud: %r", response_dict['msg'],
            )
        return response_dict

    def sendcommand(self, deviceid=None, commands=None):
        """
        Send a command to the device
        """
        if deviceid is None or commands is None:
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID and Command Parameters"
            )
        uri = 'iot-03/devices/%s/commands' % (deviceid)
        response_dict = self._tuyaplatform(uri,action='POST',post=commands)

        if not response_dict['success']:
            log.debug(
                "Error from Tuya Cloud: %r", response_dict['msg'],
            )
        return response_dict
       
    def getconnectstatus(self, deviceid=None):
        """
        Get the device Cloud connect status. 
        """
        if deviceid is None:
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID Parameter"
            )
        uri = 'devices/%s' % (deviceid)
        response_dict = self._tuyaplatform(uri, ver='v1.0')

        if not response_dict['success']:
            log.debug(
                    "Error from Tuya Cloud: %r" % response_dict['msg'],
            )
        return(response_dict["result"]["online"])
