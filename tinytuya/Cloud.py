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
        cloudrequest(url, action=[POST if post else GET], post={}, query={})
        getdevices(verbose=False)
        getstatus(deviceid)
        getfunctions(deviceid)
        getproperties(deviceid)
        getdps(deviceid)
        sendcommand(deviceid, commands)
        getconnectstatus(deviceid)
        getdevicelog(deviceid, start=[now - 1 day], end=[now], evtype="1,2,3,4,5,6,7,8,9,10", size=100, params={})
          -> when start or end are negative, they are the number of days before "right now"
             i.e. "start=-1" is 1 day ago, "start=-7" is 7 days ago
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
        self.error = None
        self.new_sign_algorithm = new_sign_algorithm
        self.server_time_offset = 0

        if (not apiKey) or (not apiSecret):
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
                self.error = error_json(
                    ERR_CLOUDKEY,
                    "Tuya Cloud Key and Secret required",
                )
                #return self.error
                raise TypeError('Tuya Cloud Key and Secret required')

        self.setregion(apiRegion)
        # Attempt to connect to cloud and get token
        self._gettoken()

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

    def _tuyaplatform(self, uri, action='GET', post=None, ver='v1.0', recursive=False, query=None):
        """
        Handle GET and POST requests to Tuya Cloud
        """
        # Build URL and Header
        if ver:
            url = "https://%s/%s/%s" % (self.urlhost, ver, uri)
        elif uri[0] == '/':
            url = "https://%s%s" % (self.urlhost, uri)
        else:
            url = "https://%s/%s" % (self.urlhost, uri)
        headers = {}
        body = {}
        sign_url = url
        if post is not None:
            body = json.dumps(post)
            headers['Content-type'] = 'application/json'
        if action not in ('GET', 'POST', 'PUT', 'DELETE'):
            action = 'POST' if post else 'GET'
        if query:
            # note: signature must be calculated before URL-encoding!
            if type(query) == str:
                # if it's a string then assume no url-encoding is needed
                if query[0] == '?':
                    url += query
                else:
                    url += '?' + query
                sign_url = url
            else:
                # dicts are unsorted, however Tuya requires the keys to be in alphabetical order for signing
                #  as per https://developer.tuya.com/en/docs/iot/singnature?id=Ka43a5mtx1gsc
                if type(query) == dict:
                    sorted_query = []
                    for k in sorted(query.keys()):
                        sorted_query.append( (k, query[k]) )
                    query = sorted_query
                    # calculate signature without url-encoding
                    sign_url += '?' + '&'.join( [str(x[0]) + '=' + str(x[1]) for x in query] )
                    req = requests.Request(action, url, params=query).prepare()
                    url = req.url
                else:
                    req = requests.Request(action, url, params=query).prepare()
                    sign_url = url = req.url
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
                '/' + sign_url.split('//', 1)[-1].split('/', 1)[-1])
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
            self._gettoken()
            if not self.token:
                log.debug("Failed to renew token")
                return None
            else:
                return self._tuyaplatform(uri, action, post, ver, True)

        try:
            response_dict = json.loads(response.content.decode())
            self.error = None
        except:
            try:
                response_dict = json.loads(response.content)
            except:
                self.error = error_json(
                    ERR_CLOUDKEY,
                    "Cloud _tuyaplatform() invalid response: %r" % response.content,
                )
                return self.error
        # Check to see if token is expired
        return response_dict

    def _gettoken(self):
        # Get Oauth Token from tuyaPlatform
        self.token = None
        response_dict = self._tuyaplatform('token?grant_type=1')

        if not response_dict or 'success' not in response_dict or not response_dict['success']:
            self.error = error_json(
                ERR_CLOUDTOKEN,
                "Cloud _gettoken() failed: %r" % response_dict['msg'],
            )
            return self.error

        if 't' in response_dict:
            # round it to 2 minutes to try and factor out any processing delays
            self.server_time_offset = round( ((response_dict['t'] / 1000.0) - time.time()) / 120 )
            self.server_time_offset *= 120
            log.debug("server_time_offset: %r", self.server_time_offset)

        self.token = response_dict['result']['access_token']
        return self.token

    def _getuid(self, deviceid=None):
        # Get user ID (UID) for deviceid
        if not self.token:
            return self.error
        if not deviceid:
            return error_json(
                ERR_PARAMS,
                "_getuid() requires deviceID parameter"
            )
        uri = 'devices/%s' % deviceid
        response_dict = self._tuyaplatform(uri)

        if not response_dict['success']:
            if 'code' not in response_dict:
                response_dict['code'] = -1
            if 'msg' not in response_dict:
                response_dict['msg'] = 'Unknown Error'
            log.debug(
                "Error from Tuya Cloud: %r", response_dict['msg'],
            )
            return error_json(
                ERR_CLOUD,
                "Error from Tuya Cloud: Code %r: %r" % (response_dict['code'], response_dict['msg'])
            )

        uid = response_dict['result']['uid']
        return uid

    def cloudrequest(self, url, action=None, post=None, query=None):
        """
        Make a generic cloud request and return the results.

        Args:
          url:    Required.  The URL to fetch, i.e. "/v1.0/devices/0011223344556677/logs"
          action: Optional.  GET, POST, DELETE, or PUT.  Defaults to GET, unless POST data is supplied.
          post:   Optional.  POST body data.  Will be fed into json.dumps() before posting.
          query:  Optional.  A dict containing query string key/value pairs.
        """
        if not self.token:
            return self.error
        if action is None:
            action = 'POST' if post else 'GET'
        return self._tuyaplatform(url, action=action, post=post, ver=None, query=query)

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
                "Unable to get uid for device list"
            )
        elif isinstance( uid, dict):
            return uid

        # Use UID to get list of all Devices for User
        uri = 'users/%s/devices' % uid
        json_data = self._tuyaplatform(uri)

        if verbose:
            return json_data
        elif not json_data or 'result' not in json_data:
            return error_json(
                ERR_CLOUD,
                "Unable to get device list"
            )
        else:
            # Filter to only Name, ID and Key
            return self.filter_devices( json_data['result'] )

    def filter_devices( self, devs, ip_list=None ):
        # Use Device ID to get MAC addresses
        uri = 'devices/factory-infos?device_ids=%s' % (",".join(i['id'] for i in devs))
        json_mac_data = self._tuyaplatform(uri)

        tuyadevices = []
        icon_host = 'https://images.' + self.urlhost.split( '.', 1 )[1] + '/'

        for i in devs:
            item = {}
            item['name'] = i['name'].strip()
            item['id'] = i['id']
            item['key'] = i['local_key']
            if 'mac' in i:
                item['mac'] = i['mac']
            else:
                try:
                    item['mac'] = next((m['mac'] for m in json_mac_data['result'] if m['id'] == i['id']), "")
                except:
                    pass

            if ip_list and 'mac' in item and item['mac'] in ip_list:
                item['ip'] = ip_list[item['mac']]

            for k in DEVICEFILE_SAVE_VALUES:
                if k in i:
                    if k == 'icon':
                        item[k] = icon_host + i[k]
                    else:
                        item[k] = i[k]

            tuyadevices.append(item)

        return tuyadevices

    def _getdevice(self, param='status', deviceid=None):
        if not self.token:
            return self.error
        if not deviceid:
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
        if not self.token:
            return self.error
        if not deviceid:
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
        if not self.token:
            return self.error
        if (not deviceid) or (not commands):
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID and/or Command Parameters"
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
        if not self.token:
            return self.error
        if not deviceid:
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

    def getdevicelog(self, deviceid=None, start=None, end=None, evtype=None, size=100, params={}):
        """
        Get the logs for a device.

        Note: The cloud only returns logs for DPs in the "official" DPS list.
          If the device specifications are wrong then not all logs will be returned!
          This is a limitation of Tuya's servers and there's nothing we can do about it.

        Args:
          devid:  Required.  Device ID
          start:  Optional.  Get logs starting from this time.  Defaults to yesterday
          end:    Optional.  Get logs until this time.  Defaults to the current time
          evtype: Optional.  Limit to events of this type.  1 = Online, 7 = DP Reports.  Defaults to all events.
          size:   Optional.  Maximum number of log entries to return.  Defaults to 100.
          params: Optional.  Additional values to include in the query string.  Defaults to an empty dict.

        Returns:
          Response from server
        """
        if not deviceid:
            return error_json(
                ERR_PARAMS,
                "Missing DeviceID Parameter"
            )

        # server expects times as unixtime * 1000
        if not end:
            end = int((time.time() + self.server_time_offset) * 1000)
        elif end < 0:
            end = int(((time.time() + self.server_time_offset) + (end * 86400) ) * 1000)
        else:
            end = Cloud.format_timestamp( end )
        if not start:
            start = end - (86400*1000)
        elif start < 0:
            start = int(((time.time() + self.server_time_offset) + (start * 86400) ) * 1000)
        else:
            start = Cloud.format_timestamp( start )
        if start > end:
            tmp = start
            start = end
            end = tmp
        if not evtype:
            # get them all by default
            # 1 = device online, 7 = DP report
            # https://developer.tuya.com/en/docs/cloud/0a30fc557f?id=Ka7kjybdo0jse
            evtype = '1,2,3,4,5,6,7,8,9,10'
        if type(params) != dict:
            params = {}
        if 'start_time' not in params:
            params['start_time'] = start
        if 'end_time' not in params:
            params['end_time'] = end
        if 'type' not in params:
            params['type'] = evtype
        if 'size' not in params:
            params['size'] = size
        if 'query_type' not in params:
            params['query_type'] = 1

        return self.cloudrequest( '/v1.0/devices/%s/logs' % deviceid, query=params)

    @staticmethod
    def format_timestamp( ts ):
        # converts a 10-digit unix timestamp to the 13-digit stamp the servers expect
        if type(ts) != int:
            if len(str(int(ts))) == 10:
                ts = int( ts * 1000 )
            else:
                ts = int( ts )
        elif len(str(ts)) == 10:
            ts *= 1000
        return ts
