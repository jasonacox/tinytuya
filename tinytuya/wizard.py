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
import json
from colorama import init
from datetime import datetime
import tinytuya

# Backward compatibility for python2
try:
    input = raw_input
except NameError:
    pass

# Colorama terminal color capability for all platforms
init()

# Configuration Files
DEVICEFILE = tinytuya.DEVICEFILE
SNAPSHOTFILE = tinytuya.SNAPSHOTFILE
CONFIGFILE = tinytuya.CONFIGFILE
RAWFILE = tinytuya.RAWFILE

# Global Network Configs
DEFAULT_NETWORK = tinytuya.DEFAULT_NETWORK
TCPTIMEOUT = tinytuya.TCPTIMEOUT    # Seconds to wait for socket open for scanning
TCPPORT = tinytuya.TCPPORT          # Tuya TCP Local Port

def wizard(color=True, retries=None, forcescan=False, nocloud=False, assume_yes=False, discover=True, credentials=None, skip_poll=None):
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

    config_file = CONFIGFILE
    config_keys = ('apiKey', 'apiSecret', 'apiRegion', 'apiDeviceID')
    config = {}
    config['apiKey'] = ''
    config['apiSecret'] = ''
    config['apiRegion'] = ''
    config['apiDeviceID'] = ''
    needconfigs = True

    if credentials and 'file' in credentials and credentials['file']:
        needconfigs = False
        config_file = credentials['file']

    try:
        # Load defaults
        with open(config_file) as f:
            file_config = json.load(f)
        for k in config_keys:
            if file_config and k in file_config and file_config[k]:
                config[k] = file_config[k]
    except:
        # First Time Setup
        pass

    if credentials:
        for k in config_keys:
            if k in credentials and credentials[k]:
                config[k] = credentials[k]
                needconfigs = False

    if not needconfigs:
        for k in config_keys:
            if not config[k]:
                needconfigs = True

    try:
        # Load the old device list, if available
        with open(DEVICEFILE, "r") as infile:
            old_devices = json.load( infile )
    except:
        old_devices = {}

    (bold, subbold, normal, dim, alert, alertdim, cyan, red, yellow) = tinytuya.termcolor(color)

    print(bold + 'TinyTuya Setup Wizard' + dim + ' [%s]' % (tinytuya.version) + normal)
    print('')

    if (needconfigs and config['apiKey'] != '' and config['apiSecret'] != '' and
            config['apiRegion'] != ''):
        needconfigs = False
        apiDeviceID = '<None>' if ('apiDeviceID' not in config or not config['apiDeviceID']) else config['apiDeviceID']
        print("    " + subbold + "Existing settings:" + dim +
              "\n        API Key=%s \n        Secret=%s\n        DeviceID=%s\n        Region=%s" %
              (config['apiKey'], config['apiSecret'], apiDeviceID,
               config['apiRegion']))
        print('')
        if not assume_yes:
            answer = input(subbold + '    Use existing credentials ' + normal + '(Y/n): ')
            if answer[0:1].lower() == 'n':
                needconfigs = True

    if needconfigs and (not (nocloud and assume_yes)):
        # Ask user for config settings
        print('')
        config['apiKey'] = input(subbold + "    Enter " + bold + "API Key" + subbold +
                                 " from tuya.com: " + normal)
        config['apiSecret'] = input(subbold + "    Enter " + bold + "API Secret" + subbold +
                                    " from tuya.com: " + normal)
        config['apiDeviceID'] = input(subbold +
                                      "    Enter " + bold + "any Device ID" + subbold +
                                      " currently registered in Tuya App (used to pull full list) or 'scan' to scan for one: " + normal)
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
        with open(config_file, "w") as outfile:
            outfile.write(json_object)
        print(bold + "\n>> Configuration Data Saved to " + config_file)
        print(dim + json_object)

    if nocloud:
        tuyadevices = old_devices
    else:
        if 'apiDeviceID' in config and config['apiDeviceID'] and config['apiDeviceID'].strip().lower() == 'scan':
            config['apiDeviceID'] = ''
            print( '\nScanning to find a Device ID...' )
            dev = tinytuya.scanner.devices( verbose=False, poll=False, byID=True, show_timer=False, maxdevices=1 )
            for devid in dev:
                print( '\nScan found Device ID %r' % devid )
                config['apiDeviceID'] = devid
                break
            if not config['apiDeviceID']:
                print('\n\n' + bold + 'Scan failed to detect a device, please enter a Device ID manually' )
                return

        cloud = tinytuya.Cloud( **config )

        # on auth error getdevices() will implode
        if cloud.error:
            err = cloud.error['Payload'] if 'Payload' in cloud.error else 'Unknown Error'
            print('\n\n' + bold + 'Error from Tuya server: ' + dim + err)
            print('Check API Key and Secret')
            return

        # Fetch the DP name mappings for all devices
        if assume_yes:
            answer = 'y'
        else:
            answer = input(subbold + '\nDownload DP Name mappings? ' + normal + '(Y/n): ')
        include_map = not bool( answer[0:1].lower() == 'n' )

        # Get UID from sample Device ID
        tuyadevices = cloud.getdevices( False, oldlist=old_devices, include_map=include_map )

        if type(tuyadevices) != list:
            err = tuyadevices['Payload'] if 'Payload' in tuyadevices else 'Unknown Error'
            print('\n\n' + bold + 'Error from Tuya server: ' + dim + err)
            print('Check DeviceID and Region')
            return

    # The device list does not (always) tell us which device is the parent for a sub-device, so we need to try and figure it out
    # The only link between parent and child appears to be the local key

    # Result:
    # if 'parent' not in device: device is not a sub-device
    # if 'parent' in device: device is a sub-device
    #     if device['parent'] == '': device is a sub-device with an unknown parent
    #     else: device['parent'] == device_id of parent
    for dev in tuyadevices:
        if 'gateway_id' in dev:
            # if the Cloud gave us the parent then just use that
            if dev['gateway_id']:
                dev['parent'] = dev['gateway_id']
            del dev['gateway_id']

        if 'sub' in dev and dev['sub']:
            # no parent from cloud, try to find it via the local key
            if 'parent' in dev and dev['parent']:
                continue

            # Set 'parent' to an empty string in case we can't find it
            dev['parent'] = ''

            # Only try to find the parent if the device has a local key
            if 'key' in dev and dev['key']:
                if 'id' not in dev:
                    dev['id'] = ''
                found = False
                # Loop through all devices again to try and find a non-sub-device with the same local key
                for parent in tuyadevices:
                    if 'id' not in parent or parent['id'] == dev['id']:
                        continue
                    # Check for matching local keys and if device is not a sub-device then assume we found the parent
                    if 'key' in parent and parent['key'] and dev['key'] == parent['key'] and ( 'sub' not in parent or not parent['sub']):
                        found = parent
                        break
                if found:
                    dev['parent'] = found['id']

    # Display device list
    print("\n\n" + bold + "Device Listing\n" + dim)
    output = json.dumps(tuyadevices, indent=4)  # sort_keys=True)
    print(output)

    # Save list to devices.json
    print(bold + "\n>> " + normal + "Saving list to " + DEVICEFILE)
    with open(DEVICEFILE, "w") as outfile:
        outfile.write(output)
    print(dim + "    %d registered devices saved" % len(tuyadevices))

    if not nocloud:
        # Save raw TuyaPlatform data to tuya-raw.json
        print(bold + "\n>> " + normal + "Saving raw TuyaPlatform response to " + RAWFILE)
        cloud.getdevices_raw['file'] = {
            'name': RAWFILE,
            'description': 'Full raw list of Tuya devices.',
            'account': cloud.apiKey,
            'date': datetime.now().isoformat(),
            'tinytuya': tinytuya.version
        }
        try:
            with open(RAWFILE, "w") as outfile:
                outfile.write(json.dumps(cloud.getdevices_raw, indent=4))
        except:
            print('\n\n' + bold + 'Unable to save raw file' + dim )

    # Find out if we should poll all devices
    if skip_poll:
        answer = 'n'
    elif assume_yes:
        answer = 'y'
    else:
        answer = input(subbold + '\nPoll local devices? ' + normal + '(Y/n): ')
    if answer.lower().find('n') < 0:
        tinytuya.scanner.SNAPSHOTFILE = SNAPSHOTFILE
        result = tinytuya.scanner.poll_and_display( tuyadevices, color=color, scantime=retries, snapshot=True, forcescan=forcescan )
        iplist = {}
        found = 0
        for itm in result:
            if 'gwId' in itm and itm['gwId']:
                gwid = itm['gwId']
                ip = itm['ip'] if 'ip' in itm and itm['ip'] else ''
                ver = itm['version'] if 'version' in itm and itm['version'] else ''
                iplist[gwid] = (ip, ver)
        for k in range( len(tuyadevices) ):
            gwid = tuyadevices[k]['id']
            if gwid in iplist:
                tuyadevices[k]['ip'] = iplist[gwid][0]
                tuyadevices[k]['version'] = iplist[gwid][1]
                if iplist[gwid][0]: found += 1
        if found:
            # re-write devices.json now that we have IP addresses
            output = json.dumps(tuyadevices, indent=4)
            print(bold + "\n>> " + normal + "Saving IP addresses to " + DEVICEFILE)
            with open(DEVICEFILE, "w") as outfile:
                outfile.write(output)
            print(dim + "    %d device IP addresses found" % found)

    print("\nDone.\n")
    return


if __name__ == '__main__':

    try:
        wizard()
    except KeyboardInterrupt:
        pass
