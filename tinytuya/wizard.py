# TinyTuya Setup Wizard
# -*- coding: utf-8 -*-
"""
TinyTuya Setup Wizard Tuya based WiFi smart devices

Author: Jason A. Cox
For more information see https://github.com/jasonacox/tinytuya

Description
    Setup Wizard will prompt the user for Tuya IoT Developer credentials and will gather all
    registered Device IDs and their Local KEYs.  It will save the credentials and the device
    data in the tinytuya.json and devices.json configuration files respectively. The Wizard
    will then optionally scan the local devices for status.

    HOW to set up your Tuya IoT Developer account: iot.tuya.com:
    https://github.com/jasonacox/tinytuya#get-the-tuya-device-local-key

Credits
* Tuya API Documentation
    https://developer.tuya.com/en/docs/iot/open-api/api-list/api?id=K989ru6gtvspg
* TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    The TuyAPI/CLI wizard inspired and informed this python version.
"""
# Modules
from __future__ import print_function
import hmac
import hashlib
import ipaddress
import json
import socket
import time
import requests

import tinytuya

try:
    from getmac import get_mac_address
    SCANLIBS = True
except:
    # Disable force scanning
    SCANLIBS = False

# Backward compatability for python2
try:
    input = raw_input
except NameError:
    pass

# Configuration Files
DEVICEFILE = tinytuya.DEVICEFILE
SNAPSHOTFILE = tinytuya.SNAPSHOTFILE
CONFIGFILE = tinytuya.CONFIGFILE
RAWFILE = tinytuya.RAWFILE

# Global Network Configs
DEFAULT_NETWORK = tinytuya.DEFAULT_NETWORK
TCPTIMEOUT = tinytuya.TCPTIMEOUT    # Seconds to wait for socket open for scanning
TCPPORT = tinytuya.TCPPORT          # Tuya TCP Local Port

# Helper Functions
def getmyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    r = s.getsockname()[0]
    s.close()
    return r

def tuyaPlatform(apiRegion, apiKey, apiSecret, uri, token=None, new_sign_algorithm=True, body=None, headers=None, version="1.0"):
    """Tuya IoT Platform Data Access

    Parameters:
        * region     Tuya API Server Region: us, eu, cn, in, us-e, eu-w
        * apiKey     Tuya Platform Developer ID
        * apiSecret  Tuya Platform Developer secret
        * uri        Tuya Platform URI for this call
        * token      Tuya OAuth Token

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
        * Get Device info = https://openapi.tuyaus.com/v1.0/devices/factory-infos

    REFERENCE: https://images.tuyacn.com/smart/docs/python_iot_code_sample.py

    """
    # Set hostname based on apiRegion
    apiRegion = apiRegion.lower()
    urlhost = "openapi.tuyacn.com"          # China Data Center
    if apiRegion == "us":
        urlhost = "openapi.tuyaus.com"      # Western America Data Center
    if apiRegion == "us-e":
        urlhost = "openapi-ueaz.tuyaus.com" # Eastern America Data Center
    if apiRegion == "eu":
        urlhost = "openapi.tuyaeu.com"      # Central Europe Data Center
    if apiRegion == "eu-w":
        urlhost = "openapi-weaz.tuyaeu.com" # Western Europe Data Center
    if apiRegion == "in":
        urlhost = "openapi.tuyain.com"      # India Datacenter

    # Build URL
    url = "https://%s/v%s/%s" % (urlhost, version, uri)

    # Build Header
    now = int(time.time()*1000)
    headers = dict(list(headers.items()) + [('Signature-Headers', ":".join(headers.keys()))]) if headers else {}
    if token is None:
        payload = apiKey + str(now)
        headers['secret'] = apiSecret
    else:
        payload = apiKey + token + str(now)

    # If running the post 6-30-2021 signing algorithm update the payload to include it's data
    if new_sign_algorithm:
        payload += ('GET\n' +                                                                # HTTPMethod
                    hashlib.sha256(bytes((body or "").encode('utf-8'))).hexdigest() + '\n' + # Content-SHA256
                    ''.join(['%s:%s\n'%(key, headers[key])                                   # Headers
                             for key in headers.get("Signature-Headers", "").split(":")
                             if key in headers]) + '\n' +
                    '/' + url.split('//', 1)[-1].split('/', 1)[-1])
    # Sign Payload
    signature = hmac.new(
        apiSecret.encode('utf-8'),
        msg=payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

    # Create Header Data
    headers['client_id'] = apiKey
    headers['sign'] = signature
    headers['t'] = str(now)
    headers['sign_method'] = 'HMAC-SHA256'

    if token is not None:
        headers['access_token'] = token

    # Get Token
    response = requests.get(url, headers=headers)
    try:
        response_dict = json.loads(response.content.decode())
    except:
        try:
            response_dict = json.loads(response.content)
        except:
            print("Failed to get valid JSON response")

    return response_dict

def wizard(color=True, retries=None, forcescan=False):
    """
    TinyTuya Setup Wizard Tuya based WiFi smart devices

    Parameter:
        color = True or False, print output in color [Default: True]
        retries = Number of retries to find IP address of Tuya Devices
        forcescan = True or False, force network scan for device IP addresses

    Description
        Setup Wizard will prompt user for Tuya IoT Developer credentials and will gather all of
        the Device IDs and their Local KEYs.  It will save the credentials and the device
        data in the tinytuya.json and devices.json configuration files respectively.

        HOW to set up your Tuya IoT Developer account: iot.tuya.com:
        https://github.com/jasonacox/tinytuya#get-the-tuya-device-local-key

    Credits
    * Tuya API Documentation
        https://developer.tuya.com/en/docs/iot/open-api/api-list/api?id=K989ru6gtvspg
    * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
        The TuyAPI/CLI wizard inspired and informed this python version.
    """

    config = {}
    ip_list = {}
    config['apiKey'] = ''
    config['apiSecret'] = ''
    config['apiRegion'] = ''
    config['apiDeviceID'] = ''
    needconfigs = True
    try:
        # Load defaults
        with open(CONFIGFILE) as f:
            config = json.load(f)
    except:
        # First Time Setup
        pass

    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)

    print(bold + 'TinyTuya Setup Wizard' + dim + ' [%s]' % (tinytuya.version) + normal)
    print('')

    if forcescan:
        if not SCANLIBS:
            print(alert +
                '    ERROR: force network scanning requested but not available - disabled.\n'
                '           (Requires: pip install getmac)\n' + dim)
            forcescan = False
        else:
            print(subbold + "    Option: " + dim + "Network force scanning requested.\n")

    if (config['apiKey'] != '' and config['apiSecret'] != '' and
            config['apiRegion'] != '' and config['apiDeviceID'] != ''):
        needconfigs = False
        print("    " + subbold + "Existing settings:" + dim +
              "\n        API Key=%s \n        Secret=%s\n        DeviceID=%s\n        Region=%s" %
              (config['apiKey'], config['apiSecret'], config['apiDeviceID'],
               config['apiRegion']))
        print('')
        answer = input(subbold + '    Use existing credentials ' +
                       normal + '(Y/n): ')
        if answer[0:1].lower() == 'n':
            needconfigs = True

    if needconfigs:
        # Ask user for config settings
        print('')
        config['apiKey'] = input(subbold + "    Enter " + bold + "API Key" + subbold +
                                 " from tuya.com: " + normal)
        config['apiSecret'] = input(subbold + "    Enter " + bold + "API Secret" + subbold +
                                    " from tuya.com: " + normal)
        config['apiDeviceID'] = input(subbold +
                                      "    Enter " + bold + "any Device ID" + subbold +
                                      " currently registered in Tuya App (used to pull full list): " + normal)
        # TO DO - Determine apiRegion based on Device - for now, ask
        print("\n      " + subbold + "Region List" + dim +
              "\n        cn\tChina Data Center" +
              "\n        us\tUS - Western America Data Center" +
              "\n        us-e\tUS - Eastern America Data Center" +
              "\n        eu\tCentral Europe Data Center" +
              "\n        eu-w\tWestern Europe Data Center" +
              "\n        in\tIndia Data Center\n")
        config['apiRegion'] = input(subbold + "    Enter " + bold + "Your Region" + subbold +
                                    " (Options: cn, us, us-e, eu, eu-w, or in): " + normal)
        # Write Config
        json_object = json.dumps(config, indent=4)
        with open(CONFIGFILE, "w") as outfile:
            outfile.write(json_object)
        print(bold + "\n>> Configuration Data Saved to " + CONFIGFILE)
        print(dim + json_object)

    KEY = config['apiKey']
    SECRET = config['apiSecret']
    DEVICEID = config['apiDeviceID']
    REGION = config['apiRegion']        # us, eu, cn, in

    # Get Oauth Token from tuyaPlatform
    uri = 'token?grant_type=1'
    response_dict = tuyaPlatform(REGION, KEY, SECRET, uri)

    if not response_dict['success']:
        print('\n\n' + bold + 'Error from Tuya server: ' + dim + response_dict['msg'])
        return

    token = response_dict['result']['access_token']

    # Get UID from sample Device ID
    uri = 'devices/%s' % DEVICEID
    response_dict = tuyaPlatform(REGION, KEY, SECRET, uri, token)

    if not response_dict['success']:
        print('\n\n' + bold + 'Error from Tuya server: ' + dim + response_dict['msg'])
        return

    uid = response_dict['result']['uid']

    # Use UID to get list of all Devices for User
    uri = 'users/%s/devices' % uid
    json_data = tuyaPlatform(REGION, KEY, SECRET, uri, token)

    # Use Device ID to get MAC addresses
    uri = 'devices/factory-infos?device_ids=%s' % (",".join(i['id'] for i in json_data['result']))
    json_mac_data = tuyaPlatform(REGION, KEY, SECRET, uri, token)

    if forcescan:
        # Force Scan - Get list of all local ip addresses
        try:
            # Fetch my IP address and assume /24 network
            ip = getmyIP()
            network = ipaddress.IPv4Interface(u''+ip+'/24').network
        except:
            network = DEFAULT_NETWORK
            ip = None
            print(alert +
                'ERROR: Unable to get your IP address and network automatically.\n'
                '       (using %s)' % network + normal)

        try:
            # Warn user of scan duration
            print("\n" + bold + "Scanning local network.  This may take a while..." + dim)
            print(bold + '\n    Running Scan...' + dim)
            # Loop through each host
            for addr in ipaddress.IPv4Network(network):
                # Fetch my IP address and assume /24 network
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
                    print(" Found Device [%s]" % mac)
                a_socket.close()

            print(dim + '\r      Done                           ' +normal +
                        '\n\nDiscovered %d Tuya Devices\n' % len(ip_list))
        except:
            print('\n' + alert + '    Error scanning network - Ignoring' + dim)
            forcescan = False

    # Filter to only Name, ID and Key, IP and mac-address
    tuyadevices = []
    for i in json_data['result']:
        item = {}
        item['name'] = i['name'].strip()
        item['id'] = i['id']
        item['key'] = i['local_key']
        try:
            item['mac'] = next((m['mac'] for m in json_mac_data['result'] if m['id'] == i['id']), "N/A")
            if forcescan:
                item['ip'] = ip_list[item['mac']]
        except:
            pass
        tuyadevices.append(item)

    # Display device list
    print("\n\n" + bold + "Device Listing\n" + dim)
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    print(output)

    # Save list to devices.json
    print(bold + "\n>> " + normal + "Saving list to " + DEVICEFILE)
    with open(DEVICEFILE, "w") as outfile:
        outfile.write(output)
    print(dim + "    %d registered devices saved" % len(tuyadevices))

    # Save raw TuyaPlatform data to tuya-raw.json
    print(bold + "\n>> " + normal + "Saving raw TuyaPlatform response to " + RAWFILE)
    try:
        with open(RAWFILE, "w") as outfile:
            outfile.write(json.dumps(json_data, indent=4))
    except:
        print('\n\n' + bold + 'Unable to save raw file' + dim )

    # Find out if we should poll all devices
    answer = input(subbold + '\nPoll local devices? ' +
                   normal + '(Y/n): ')
    if answer[0:1].lower() != 'n':
        # Set retries based on number of devices if undefined
        if retries is None:
            retries = len(tuyadevices)+10+tinytuya.MAXCOUNT

        # Scan network for devices and provide polling data
        print(normal + "\nScanning local network for Tuya devices (retry %d times)..." % retries)
        devices = tinytuya.deviceScan(False, retries)
        print("    %s%s local devices discovered%s" %
              (dim, len(devices), normal))
        print("")

        def getIP(d, gwid):
            for ip in d:
                if 'gwId' in d[ip]:
                    if gwid == d[ip]['gwId']:
                        return (ip, d[ip]['version'])
            return (0, 0)

        polling = []
        print("Polling local devices...")
        for i in tuyadevices:
            item = {}
            name = i['name']
            (ip, ver) = getIP(devices, i['id'])
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
                                  (subbold, name, dim, ip, alertdim))
                    else:
                        print("    %s[%s] - %s%s - %sNo Response" %
                              (subbold, name, dim, ip, alertdim))
                except:
                    print("    %s[%s] - %s%s - %sNo Response" %
                          (subbold, name, dim, ip, alertdim))
            polling.append(item)
        # for loop

        # Save polling data snapsot
        current = {'timestamp' : time.time(), 'devices' : polling}
        output = json.dumps(current, indent=4)
        print(bold + "\n>> " + normal + "Saving device snapshot data to " + SNAPSHOTFILE)
        with open(SNAPSHOTFILE, "w") as outfile:
            outfile.write(output)

    print("\nDone.\n")
    return


if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass
