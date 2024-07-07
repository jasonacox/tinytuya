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
        sendcommand(deviceid, commands [, uri])
        getconnectstatus(deviceid)
        getdevicelog(deviceid, start=[now - 1 day], end=[now], evtype="1,2,3,4,5,6,7,8,9,10", size=100, params={})
          -> when start or end are negative, they are the number of days before "right now"
             i.e. "start=-1" is 1 day ago, "start=-7" is 7 days ago

 Reference
    * https://developer.tuya.com/en/docs/cloud/device-connection-service?id=Kb0b8geg6o761

"""

import hashlib
import hmac
import json
import time
try:
    import requests
except ImportError as impErr:
    print("WARN: Unable to import requests library, Cloud functions will not work.")
    print("WARN: Check dependencies. See https://github.com/jasonacox/tinytuya/issues/377")
    print("WARN: Error: {}.".format(impErr.args[0]))

from .core import * # pylint: disable=W0401, W0614

########################################################
#             Cloud Classes and Functions
########################################################

class Cloud(object):
    def __init__(self, apiRegion=None, apiKey=None, apiSecret=None, apiDeviceID=None, new_sign_algorithm=True, initial_token=None, **extrakw):
        """
        Tuya Cloud IoT Platform Access

        Args:
            initial_token: The auth token from a previous run.  It will be refreshed if it has expired

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
        self.token = initial_token
        self.error = None
        self.new_sign_algorithm = new_sign_algorithm
        self.server_time_offset = 0
        self.use_old_device_list = True
        self.mappings = None

        if (not apiKey) or (not apiSecret):
            try:
                # Load defaults from config file if available
                config = {}
                with open(self.CONFIGFILE) as f:
                    config = json.load(f)
                    self.apiRegion = config['apiRegion']
                    self.apiKey = config['apiKey']
                    self.apiSecret = config['apiSecret']
                    if 'apiDeviceID' in config:
                        self.apiDeviceID = config['apiDeviceID']
            except:
                self.error = error_json(
                    ERR_CLOUDKEY,
                    "Tuya Cloud Key and Secret required",
                )
                #return self.error
                raise TypeError('Tuya Cloud Key and Secret required') # pylint: disable=W0707

        self.setregion(apiRegion)

        if not self.token:
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

    def _tuyaplatform(self, uri, action='GET', post=None, ver='v1.0', recursive=False, query=None, content_type=None):
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
        if action not in ('GET', 'POST', 'PUT', 'DELETE'):
            action = 'POST' if post else 'GET'
        if action == 'POST' and content_type is None:
            content_type = 'application/json'
        if content_type:
            headers['Content-type'] = content_type
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
        headers['mode'] = 'cors'

        if self.token is not None:
            headers['access_token'] = self.token

        # Send Request to Cloud and Get Response
        if action == 'GET':
            response = requests.get(url, headers=headers)
            log.debug(
                "GET: URL=%s HEADERS=%s response code=%d text=%s token=%s", url, headers, response.status_code, response.text, self.token
            )
        else:
            log.debug(
                "POST: URL=%s HEADERS=%s DATA=%s", url, headers, body,
            )
            response = requests.post(url, headers=headers, data=body)
            log.debug(
                "POST RESPONSE: code=%d text=%s token=%s", response.status_code, response.text, self.token
            )

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

    # merge device list 'result2' into 'result1'
    # if result2 has a device which is not in result1 then it will be added
    # if result2 has a key which does not exist or is empty in result1 then that key will be copied over
    def _update_device_list( self, result1, result2 ):
        for new_device in result2:
            if 'id' not in new_device or not new_device['id']:
                continue
            found = False
            for existing_device in result1:
                if 'id' in existing_device and existing_device['id'] == new_device['id']:
                    found = True
                    for k in new_device:
                        if k not in existing_device or not existing_device[k]:
                            existing_device[k] = new_device[k]
            if not found:
                result1.append( new_device )

    def _get_all_devices( self, uid=None, device_ids=None ):
        fetches = 0
        our_result = { 'result': [] }
        last_row_key = None
        has_more = True
        total = 0

        if uid:
            # get device list for specified user id
            query = {'page_size':'75', 'source_type': 'tuyaUser', 'source_id': uid}
            # API docu: https://developer.tuya.com/en/docs/cloud/dc413408fe?id=Kc09y2ons2i3b
            uri = '/v1.3/iot-03/devices'
            if device_ids:
                if isinstance( device_ids, tuple ) or isinstance( device_ids, list ):
                    query['device_ids'] = ','.join(device_ids)
                else:
                    query['device_ids'] = device_ids
        else:
            # get all devices
            query = {'size':'50'}
            # API docu: https://developer.tuya.com/en/docs/cloud/fc19523d18?id=Kakr4p8nq5xsc
            uri = '/v1.0/iot-01/associated-users/devices'

        while has_more:
            result = self.cloudrequest( uri, query=query )
            fetches += 1
            has_more = False

            if type(result) == dict:
                log.debug( 'Cloud response:' )
                log.debug( json.dumps( result, indent=2 ) )
            else:
                log.debug( 'Cloud response: %r', result )

            # format it the same as before, basically just moves result->devices into result
            for i in result:
                if i == 'result':
                    # by-user-id has the result in 'list' while all-devices has it in 'devices'
                    if 'list' in result[i] and 'devices' not in result[i]:
                        our_result[i] += result[i]['list']
                    elif 'devices' in result[i]:
                        our_result[i] += result[i]['devices']

                    if 'total' in result[i]: total = result[i]['total']
                    if 'last_row_key' in result[i]:
                        query['last_row_key'] = result[i]['last_row_key']
                    if 'has_more' in result[i]:
                        has_more = result[i]['has_more']
                else:
                    our_result[i] = result[i]

        our_result['fetches'] = fetches
        our_result['total'] = total

        return our_result

    def getdevices(self, verbose=False, oldlist=[], include_map=False):
        """
        Return dictionary of all devices.

        Args: 
            verbose - Returns raw JSON data from Tuya Cloud
            oldlist - List of devices from previous run
            include_map - Include the DPS mapping in the device list
        """
        old_devices = {}
        if oldlist:
            for dev in oldlist:
                dev_id = dev['id']
                old_devices[dev_id] = dev

        if self.apiDeviceID and self.use_old_device_list:
            json_data = {}
            uid_list = {}

            # apiDeviceID can be a comma-separated list, so process them all
            for dev_id in self.apiDeviceID.split(','):
                dev_id = dev_id.strip()
                if not dev_id:
                    continue
                uid = self._getuid( dev_id )
                if not uid:
                    # no user for this device?
                    continue
                if isinstance( uid, dict ):
                    # it's an error_json dict
                    return uid
                else:
                    uid_list[uid] = True

            if not uid_list:
                return error_json(
                    ERR_CLOUD,
                    "Unable to get uid for device list"
                )

            for uid in uid_list:
                # Use UID to get list of all Devices for User
                uri = 'users/%s/devices' % uid
                json_run = self._tuyaplatform(uri)
                # merge the dicts
                for k in json_run:
                    if (k not in json_data) or (k != 'result'):
                        # replace if key is not 'result'
                        json_data[k] = json_run[k]
                    else:
                        # merge 'result' keys
                        json_data[k] += json_run[k]
        else:
            json_data = self._get_all_devices()
            users = {}
            # loop through all devices and build a list of user IDs
            for dev in json_data['result']:
                if 'uid' in dev:
                    users[dev['uid']] = True
            if users:
                # we have at least 1 user id, so fetch the device list again to make sure we have the local key
                # this also gets us the gateway_id for child devices
                for uid in users.keys():
                    json_data2 = self._get_all_devices( uid=uid )
                    self._update_device_list( json_data['result'], json_data2['result'] )

        if verbose:
            return json_data
        elif not json_data or 'result' not in json_data:
            return error_json(
                ERR_CLOUD,
                "Unable to get device list"
            )

        self.getdevices_raw = json_data
        devs = json_data['result']
        changed_devices = []
        unchanged_devices = []

        # check to see if anything has changed.  if so, re-download factory-infos and DP mapping
        for dev in devs:
            dev_id = dev['id']
            if dev_id not in old_devices:
                # newly-added device
                changed_devices.append( dev )
                continue
            old = old_devices[dev_id]
            if 'key' not in old or old['key'] != dev['local_key']:
                # local key changed
                changed_devices.append( dev )
                continue
            if (('icon' not in old) and ('icon' in dev)) or (include_map and ('mapping' not in old or old['mapping'] is None)):
                # icon or mapping added
                changed_devices.append( dev )
                continue
            is_same = True
            for k in DEVICEFILE_SAVE_VALUES:
                if k in dev and k != 'icon' and k != 'last_ip' and (k not in old or old[k] != dev[k]):
                    is_same = False
                    break
            if not is_same:
                changed_devices.append( dev )
                continue
            unchanged_devices.append( old )

        if include_map:
            mappings = self.getmappings( changed_devices )
            for productid in mappings:
                for dev in changed_devices:
                    if 'product_id' in dev and dev['product_id'] == productid:
                        dev['mapping'] = mappings[productid]
                # also set unchanged devices just in case the mapping changed
                for dev in unchanged_devices:
                    if 'product_id' in dev and dev['product_id'] == productid:
                        dev['mapping'] = mappings[productid]

        log.debug( 'changed: %d', len(changed_devices) )
        log.debug( 'unchanged: %d', len(unchanged_devices) )

        # Filter to only Name, ID and Key
        return self.filter_devices( changed_devices ) + unchanged_devices

    def _get_hw_addresses( self, maclist, devices ):
        while devices:
            # returns id, mac, uuid (and sn if available)
            uri = 'devices/factory-infos?device_ids=%s' % (",".join(devices[:50]))
            result = self._tuyaplatform(uri)
            log.debug( json.dumps( result, indent=2 ) )
            if 'result' in result:
                for dev in result['result']:
                    if 'id' in dev:
                        dev_id = dev['id']
                        del dev['id']
                        maclist[dev_id] = dev
            devices = devices[50:]

    def filter_devices( self, devs, ip_list=None ):
        json_mac_data = {}
        # mutable json_mac_data will be modified
        self._get_hw_addresses( json_mac_data, [i['id'] for i in devs] )

        tuyadevices = []
        icon_host = 'https://images.' + self.urlhost.split( '.', 1 )[1] + '/'

        for i in devs:
            dev_id = i['id']
            item = {
                'name': '' if 'name' not in i else i['name'].strip(),
                'id': dev_id,
                'key': '' if 'local_key' not in i else i['local_key'],
                'mac': '' if 'mac' not in i else i['mac']
            }

            if dev_id in json_mac_data:
                for k in ('mac','uuid','sn'):
                    if k in json_mac_data[dev_id]:
                        item[k] = json_mac_data[dev_id][k]

            if ip_list and 'mac' in item and item['mac'] in ip_list:
                item['ip'] = ip_list[item['mac']]

            for k in DEVICEFILE_SAVE_VALUES:
                if k in i:
                    if k == 'icon':
                        item[k] = icon_host + i[k]
                    else:
                        item[k] = i[k]

            if 'gateway_id' in i:
                k = 'gateway_id'
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

    def sendcommand(self, deviceid=None, commands=None, uri='iot-03/devices/'):
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
        uri += '%s/commands' % (deviceid)
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
            log.debug("Error from Tuya Cloud: %r", response_dict['msg'])
        return(response_dict["result"]["online"])

    def getdevicelog(self, deviceid=None, start=None, end=None, evtype=None, size=0, max_fetches=50, start_row_key=None, params=None):
        """
        Get the logs for a device.
        https://developer.tuya.com/en/docs/cloud/0a30fc557f?id=Ka7kjybdo0jse

        Note: The cloud only returns logs for DPs in the "official" DPS list.
          If the device specifications are wrong then not all logs will be returned!
          This is a limitation of Tuya's servers and there is nothing we can do about it.

        Args:
          devid:  Required.  Device ID
          start:  Optional.  Get logs starting from this time.  Defaults to yesterday
          end:    Optional.  Get logs until this time.  Defaults to the current time
          evtype: Optional.  Limit to events of this type.  1 = Online, 7 = DP Reports.  Defaults to all events.
          size:   Optional.  Target number of log entries to return.  Defaults to 0 (all, up to max_fetches*100).
                               Actual number of log entries returned will be between "0" and "size * 2 - 1"
          max_fetches: Optional. Maximum number of queries to send to the server.  Tuya's server has a hard limit
                               of 100 records per query, so the maximum number of logs returned is "max_fetches * 100"
          start_row_key: Optional. The "next_row_key" from a previous run.
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
            evtype = '1,2,3,4,5,6,7,8,9,10'
        elif type(evtype) == str:
            pass
        elif type(evtype) == bytes:
            evtype = evtype.decode('utf8')
        elif type(evtype) == int:
            evtype = str(evtype)
        elif type(evtype) == list or type(evtype) == tuple:
            evtype = ','.join( [str(i) for i in evtype] )
        else:
            raise ValueError( "Unhandled 'evtype' type %s - %r" % (type(evtype), evtype) )
        want_size = size
        if not size:
            size = 100
        elif size > 100:
            size = 100
            #if (want_size / size) * 2 > max_fetches:
            #    max_fetches = round( (want_size / size) * 2 ) + 1
        if not max_fetches or max_fetches < 1:
            max_fetches = 50
        params = {} if type(params) != dict else params.copy()
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
        if start_row_key:
            params['start_row_key'] = start_row_key

        ret = self.cloudrequest( '/v1.0/devices/%s/logs' % deviceid, query=params)
        max_fetches -= 1
        fetches = 1

        if ret and 'result' in ret:
            # ret['result'] is a dict so the 'result' below will be a reference, not a copy
            result = ret['result']
            again = True
            next_row_key = ''
            while (
                    again and max_fetches and
                    'logs' in result and
                    'has_next' in result and result['has_next'] and
                    (not want_size or len(result['logs']) < size) and
                    'next_row_key' in result and result['next_row_key'] and next_row_key != result['next_row_key']
            ):
                again =	False
                max_fetches -= 1
                fetches += 1
                params['start_row_key'] = result['next_row_key']
                next_row_key = result['next_row_key']
                result['next_row_key'] = None
                result['has_next'] = False
                res = self.cloudrequest( '/v1.0/devices/%s/logs' % deviceid, query=params)
                if res and 'result' in res:
                    result2 = res['result']
                    if 'logs' in result2:
                        result['logs'] += result2['logs']
                        again = True
                    if 'has_next' in result2:
                        result['has_next'] = result2['has_next']
                    if 'next_row_key' in result2:
                        result['next_row_key'] = result2['next_row_key']
                else:
                    break

            ret['fetches'] = fetches

        return ret

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

    @staticmethod
    def _build_mapping( src, dst ):
        # merge multiple DPS sets from result['status'] and result['functions'] into a single result
        for mapp in src:
            try:
                code = mapp['code']
                dp_id = code if 'dp_id' not in mapp else str(mapp['dp_id'])
                if dp_id in dst:
                    continue
                data = { 'code': code, 'type': mapp['type'] }
                if mapp['type'].lower() == 'string':
                    values = mapp['values']
                else:
                    try:
                        values = json.loads( mapp['values'] )
                    except:
                        values = mapp['values']
                if values and type(values) == dict and 'unit' in values:
                    if values['unit']:
                        # normalize some unicode and temperature units
                        # not sure what a good replacement for '份' is (seen in a pet feeder)
                        values['unit'] = values['unit'].replace('℉','°F').replace('℃','°C').replace('f','°F').replace('c','°C').replace('秒','s')

                # Tuya's 'JSON' mapping type is an ordered dict, but python's dict is not!  so, save the raw value as well
                if mapp['type'].lower() == 'json':
                    data['raw_values'] = mapp['values']
                data['values'] = values
                dst[dp_id] = data
            except:
                log.debug( 'Parse mapping item failed!', exc_info=True )

    def getmapping( self, productid, deviceid=None ):
        # return a mapping for the given product id, or download it from the cloud using a device id
        # Return value: None on failure, or a dict on success (may be an empty dict if device does not have DPs)
        if not self.mappings:
            self.mappings = {} #load_mappings()

        if productid in self.mappings:
            # already have this product id, so just return it
            return self.mappings[productid]

        if deviceid:
            # we do not have this product id yet, so download it via this device id
            result = self.getdps(deviceid)

            if result:
                if 'result' in result:
                    result = result['result']
                    dps = {}
                    # merge result['status'] and result['functions'] into a single result
                    if 'status' in result:
                        self._build_mapping( result['status'], dps )
                    if 'functions' in result:
                        self._build_mapping( result['functions'], dps )
                    self.mappings[productid] = dps
                    log.debug( 'Downloaded mapping for device %r: %r', deviceid, dps)
                elif ('code' in result and result['code'] == 2009) or ('msg' in result and result['msg'] == 'not support this device'):
                    # this device does not have any DPs!
                    self.mappings[productid] = {}

        if productid in self.mappings:
            # download success, so return it
            return self.mappings[productid]

        # no device id, or download failed
        return None

    def setmappings( self, mappings ):
        # sets an initial mapping set so we do not need to download everything
        if type(mappings) == dict:
            self.mappings = mappings

    def getmappings( self, devices ):
        # get all mappings for all tuya devices
        # returns a dict with product ids as keys
        if not self.mappings:
            self.mappings = {}

        for dev in devices:
            try:
                devid = dev['id']
                productid = dev['product_id']
            except:
                # we need both the device id and the product id to download mappings!
                continue

            if productid not in self.mappings:
                self.getmapping( productid, devid )

        return self.mappings
