# RELEASE NOTES

## v1.16.1 - Scanner Error Handling

* Adds error handling for cases when the scanner broadcasts fails by @x011 in https://github.com/jasonacox/tinytuya/pull/585 and @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/587

## v1.16.0 - Code Refactoring

* This update refactors core.py by splitting it up into smaller, more logical files. It puts it in a `core` directory, so existing code that imports from `tinytuya.core` should be unaffected.
* Add Contrib support for Electric Blankets such as Goldair GPFAEB-Q by @leodenham in https://github.com/jasonacox/tinytuya/pull/528
* Add IoT core service renewal info to the setup wizard in the README by @lorumic in https://github.com/jasonacox/tinytuya/pull/558
* Contributing with a new device ColorfulX7Device by @CheAhMeD in https://github.com/jasonacox/tinytuya/pull/568
* Add WiFi Dual Meter device by @ggardet in https://github.com/jasonacox/tinytuya/pull/569
* Refactoring: split up core.py by @tringenbach in https://github.com/jasonacox/tinytuya/pull/575
* fix: update tests.py to pass, add to github workflow by @tringenbach in https://github.com/jasonacox/tinytuya/pull/576

## v1.15.1 - Scanner Fixes

* Fix scanner broadcast attempting to bind to the wrong IP address, introduced in v1.15.0

## v1.15.0 - Scanner Fixes

* Fix force-scanning bug in scanner introduced in last release and add broadcast request feature to help discover Tuya version 3.5 devices by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/511.
* Server p12 updates:
    * Added "Force Scan" button to cause server to run a network scan for devices not broadcasting.
    * Minor updates to UI for a cleaner title and footer to accommodate button.
    * Added logic to allow settings via environmental variables.
    * Add broadcast request to local network for version 3.5 devices. 
    * Fix bug with cloud sync refresh that was losing device mappings.
    * Added "Cloud Sync" button to poll cloud for updated device data.

## v1.14.0 - Command Line Updates

* PyPI 1.14.0 rewrite of main to use argparse and add additional options by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/503
* Add support for `pipx install tinytuya` as raised by @felipecrs in https://github.com/jasonacox/tinytuya/issues/500 allowing for easier CLI use.
* Note possible breaking change: Running `tinytuya` by itself will now produce a "Usage" page instead of running a scan.  Use `tinytuya scan` or `python -m tinytuya scan`.
* Updated docs to explain timeout as raised by @GamerPeggun in https://github.com/jasonacox/tinytuya/issues/501

## v1.13.2 - Contrib Updates

* Add example for XmCosy+ RGBW patio string lights by @bikerglen in https://github.com/jasonacox/tinytuya/pull/445
* Fix case when the number of colors in the colors list is not exactly six by @bikerglen in https://github.com/jasonacox/tinytuya/pull/446
* Adding support for Presence Detector Device by @mrioan in https://github.com/jasonacox/tinytuya/pull/451
* Makes some tweaks to the recently-added Contrib/PresenceDetectorDevice by @mrioan and Deprecates `Contrib/__init__.py` by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/466
* Add a note about QR code scanning with Dark Reader to the README [#463](https://github.com/jasonacox/tinytuya/issues/463) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/466
* Add option to specify port in XenonDevice class by @unit-404 in https://github.com/jasonacox/tinytuya/pull/468

## v1.13.1 - Cryptography Version

* PyPI 1.13.1
* Require pyca/cryptography>=3.1 or fallback to PyCryptodome
* Add `tools/fake-v35-device.py` script to tools
* Allow pyca/cryptography to GCM decrypt without the tag (makes it match PyCryptodome) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/424

## v1.13.0 - Crypto Library Update

* PyPI 1.13.0
* Updates AESCipher() to make it a bit easier to add additional crypto libraries. It also adds pyca/cryptography as the default. By @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/423
* Fixes issue with tinytuya.find_device() for v3.1 devices and the infinite loop in Contrib/IRRemoteControlDevice.py (Closes #403).
* Officially removes Python 2.7 support.

## v1.12.11 - Bug Fix for _get_socket()

* PyPI 1.12.11
* Fix local variable collision in `_get_socket()` exception handling for device offline conditions.

## v1.12.10 - Various Updates

* PyPI 1.12.10
* Various updates inspired by recent issues by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/397 - Updates to scanner, added error code and helpful troubleshooting messages, make connection/key errors more descriptive, added socketRetryLimit (`connection_retry_limit`) and socketRetryDelay (`connection_retry_limit`) to Device constructor args.
* [[MQTT Gateway for Server](https://github.com/jasonacox/tinytuya/blob/master/server/mqtt/mqtt_gateway.py)] Fixed endless loop causing 100% cpu usage by @michaelmittermair in https://github.com/jasonacox/tinytuya/pull/390


## v1.12.9 - Import Issue with urllib3

* PyPI 1.12.9
* Add graceful handling of issue where urllib3 v2.0 causes `ImportError: urllib3 v2.0 only supports OpenSSL 1.1.1+` error. See https://github.com/jasonacox/tinytuya/issues/377 & https://github.com/jasonacox/tinytuya/pull/379.
* Fix bug in Cloud getdevices() that can error with older `devices.json` versions as raised in https://github.com/jasonacox/tinytuya/issues/381 & https://github.com/jasonacox/tinytuya/pull/382
* [[Server](https://github.com/jasonacox/tinytuya/tree/master/server)] Mapping for DP IDs by @mschlenstedt in https://github.com/jasonacox/tinytuya/pull/353 and https://github.com/jasonacox/tinytuya/pull/363
* [[MQTT Gateway for Server](https://github.com/jasonacox/tinytuya/blob/master/server/mqtt/mqtt_gateway.py)] by @mschlenstedt in https://github.com/jasonacox/tinytuya/pull/364, https://github.com/jasonacox/tinytuya/pull/367 and https://github.com/jasonacox/tinytuya/pull/366
* Add Contrib support for Inverter Heat Pump such as Fairland IPHR55 by @valentindusollier in https://github.com/jasonacox/tinytuya/pull/368

## v1.12.8 - Device DP Mapping

* PyPI 1.12.8
* [[Server](https://github.com/jasonacox/tinytuya/tree/master/server)] - Use {DeviceName} instead of {DeviceID} alternatively for API commands by @mschlenstedt in https://github.com/jasonacox/tinytuya/pull/352
* Wizard - New Cloud functions to download DP Name mappings by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/356

Example device from UPDATED `devices.json` showing new *"mapping"* data:

```json
    {
        "name": "Smart Plug",
        "id": "01234567890abcdef012",
        "key": "abcdef0123456789",
        "mac": "aa:bb:cc:dd:33:11",
        "uuid": "01234567890abcdef012",
        "category": "cz",
        "product_name": "WP1-Smart Socket",
        "product_id": "iXfg9AQVUPhlfyGw",
        "biz_type": 18,
        "model": "WP1/10A/\u5e26\u8ba1\u91cf/gosund",
        "sub": false,
        "icon": "https://images.tuyaus.com/smart/icon/1472009231_0.png",
        "mapping": {
            "1": {
                "code": "switch",
                "type": "Boolean",
                "values": {}
            },
            "4": {
                "code": "cur_current",
                "type": "Integer",
                "values": {
                    "unit": "mA",
                    "min": 0,
                    "max": 30000,
                    "scale": 0,
                    "step": 1
                }
            },
            "5": {
                "code": "cur_power",
                "type": "Integer",
                "values": {
                    "unit": "W",
                    "min": 0,
                    "max": 50000,
                    "scale": 1,
                    "step": 1
                }
            },
            "6": {
                "code": "cur_voltage",
                "type": "Integer",
                "values": {
                    "unit": "V",
                    "min": 0,
                    "max": 5000,
                    "scale": 1,
                    "step": 1
                }
            },
            "2": {
                "code": "countdown_1",
                "type": "Integer",
                "values": {
                    "unit": "s",
                    "min": 0,
                    "max": 86400,
                    "scale": 0,
                    "step": 1
                }
            }
        },
        "ip": "10.20.30.40",
        "version": "3.1"
    }
```

## v1.12.7 - Status Bug Fix

* PyPI 1.12.7
* Fix bug in `detect_available_dps()` to resolve issue where `status()` call for smartbulbs would randomly cause devices to turn off by @xgustavoh in https://github.com/jasonacox/tinytuya/pull/345

## v1.12.6 - Minor Fixes

* PyPI 1.12.6
* Cloud - Bug Fix KeyError: 'has_more' by @Liborsaf in https://github.com/jasonacox/tinytuya/pull/342
* Add Contrib support for IR+RF devices such as the S11 by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/343

## v1.12.5 - Scanner Update

* PyPI 1.12.5
* Remove requirement for PyCryptodome in scanner (allows pyaes for devices < 3.5) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/332
* Added AES library details to debug output.
* README update - Add link to Moonraker support project by @teejo75 in https://github.com/jasonacox/tinytuya/pull/335
* Misc minor updates by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/336: Normalize ability/ablilty in scanner https://github.com/jasonacox/tinytuya/issues/333 - Fix examples/getstatus.py - Cloud device list and Content-Type update https://github.com/jasonacox/tinytuya/issues/324 - Rework examples/async_send_receive.py

## v1.12.4 - Wizard Scan for ID

* PyPI 1.12.4
* Adds option allowing wizard to scan for a Device ID by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/331 - Related to Tuya IoT permission denied issue https://github.com/jasonacox/tinytuya/issues/330 and https://github.com/jasonacox/tinytuya/issues/323

## v1.12.3 - Fix Cloud Device List

* PyPI 1.12.3
* Fix fan_run_time typo in Contrib/ThermostatDevice by @elockman in https://github.com/jasonacox/tinytuya/pull/326
* Cloud device list and Content-Type update by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/324 Bug Fix for https://github.com/jasonacox/tinytuya/issues/323

## v1.12.2 - Gateway/Sub-device Update

* PyPI 1.12.2
* Gateway/sub-device updates, payload_dict reworked, and `subdev_query()` added by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/308
* Add [tools/pcap_parse.py](https://github.com/jasonacox/tinytuya/tree/master/tools) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/311
* [[Server](https://github.com/jasonacox/tinytuya/tree/master/server)] Formatted data into tables and added version information.

## v1.12.1 - Cloud & Wizard Updates

* PyPI 1.12.1
* [[tinytuya.Cloud](https://github.com/jasonacox/tinytuya#tuya-cloud-access)] Added cloud `sendcommand()` parameter for URI by @Syrooo in https://github.com/jasonacox/tinytuya/pull/303
* Wizard and [tinytuya.Cloud](https://github.com/jasonacox/tinytuya#tuya-cloud-access) - Fetch the device list a 2nd time to make sure we have the local key by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/306 - Updated internal `_get_all_devices()` and  `_update_device_list()`

## v1.12.0 - Zigbee Gateway Updates

* PyPI 1.12.0
* Improve detect_available_dps() function by @nyok92 in https://github.com/jasonacox/tinytuya/pull/294
* Tighten up parent device detection in the Wizard by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/296
* Updates for Zigbee Gateway sub-device usage by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/298

## v1.11.0 - Cloud Device Listing

* PyPI 1.11.0
* Simplification and cleanup of math functions in core and IRRemoteControlDevice by @gstein in https://github.com/jasonacox/tinytuya/pull/291
* Rework Cloud device list fetching by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/289 includes new `tuya-raw.json` (backward compatible).

Additional data in tuya-raw.json:

```json
    "file": {
        "name": "tuya-raw.json",
        "description": "Full raw list of Tuya devices.",
        "account": "xxxxxxxxxxxxxxxxxxxx",
        "date": "2023-03-04T19:50:08.879865",
        "tinytuya": "1.11.0"
    }
```

## v1.10.3 - Cloud Updates

* PyPI 1.10.3
* Fix params leak in getdevicelog() as discovered by @klightspeed and @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/219
* Log message formatting by @johnno1962 in https://github.com/jasonacox/tinytuya/pull/285
* Add Cloud IR example, updated docs, and allow an optional initial token to Cloud by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/288


## v1.10.2 - Bug Fix for ThermostatDevice and Misc. Cleanup

* PyPI 1.10.2
* Fix Contrib.ThermostatDevice.SetSetpoint() by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/273
* Added command line -debug flag and code cleanup based on pylint by @jasonacox in https://github.com/jasonacox/tinytuya/pull/276

## v1.10.1 - Bug Fix for BulbDevice and Zigbee Devices

* PyPI 1.10.1
* Fix _process_message() missing parameters discovered via issue https://github.com/jasonacox/tinytuya/issues/266 by @jasonacox in https://github.com/jasonacox/tinytuya/pull/267
* Removed bulb attribute conditional blocking in BulbDevice set_colour(), set_hsv() and set_colourtemp() as some devices do not correctly report capabilities. Conditional provides debug warning message instead by @jasonacox in https://github.com/jasonacox/tinytuya/issues/265

## v1.10.0 - Tuya Protocol v3.5 Device Support / Scanner Rewrite

* PyPI 1.10.0
* Tuya Protocol v3.5 Support by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/256 https://github.com/jasonacox/tinytuya/pull/257 & https://github.com/jasonacox/tinytuya/pull/259
* [[tinytuya.Cloud](https://github.com/jasonacox/tinytuya#tuya-cloud-access)] Updated getdevicelog() to handle fetching more when "has_next" is True by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/236
* [[Server](https://github.com/jasonacox/tinytuya/tree/master/server)] Added delayed-off & help function to server by @cowboy3d in https://github.com/jasonacox/tinytuya/pull/242 & https://github.com/jasonacox/tinytuya/pull/243
* [[Server](https://github.com/jasonacox/tinytuya/tree/master/server)] Added ability to modify device dps using web browser by @cowboy3d in https://github.com/jasonacox/tinytuya/pull/244
* Added nowait parameter to status() and split message parsing into separate function by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/253
* [[Scanner](https://github.com/jasonacox/tinytuya#network-scanner)] Complete rewrite of the scanner for speed improvements and allowing force-scanning of IP ranges by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/252 https://github.com/jasonacox/tinytuya/pull/254 https://github.com/jasonacox/tinytuya/pull/261 & https://github.com/jasonacox/tinytuya/pull/262

```
TinyTuya [1.10.0]

Usage:

    python -m tinytuya <command> [<max_time>] [-nocolor] [-force [192.168.0.0/24 192.168.1.0/24 ...]] [-h]

      wizard         Launch Setup Wizard to get Tuya Local KEYs.
      scan           Scan local network for Tuya devices.
      devices        Scan all devices listed in devices.json file.
      snapshot       Scan devices listed in snapshot.json file.
      json           Scan devices listed in snapshot.json file [JSON].
      <max_time>     Maximum time to find Tuya devices [Default=18]
      -nocolor       Disable color text output.
      -force         Force network scan for device IP addresses.  Auto-detects network range if none provided.
      -no-broadcasts Ignore broadcast packets when force scanning.
      -h             Show usage.
```

## v1.9.1 - Minor Bug Fix for Cloud

* PyPI 1.9.1
* Fix logging for Cloud `_gettoken()` to prevent extraneous output. #229

## v1.9.0 - Zigbee Gateway Support

* PyPI 1.9.0
* Add support for subdevices connected to gateway by @LesTR in https://github.com/jasonacox/tinytuya/pull/222
* Rework Zigbee Gateway handling to support multiple devices with persistent connections by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/226
* Add support for newer IR devices, and several IR format converters by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/228
* Rework Cloud log start/end times, and update documentation by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/229

```python
import tinytuya

# Zigbee Gateway support uses a parent/child model where a parent gateway device is
#  connected and then one or more children are added.

# Configure the parent device
gw = tinytuya.Device( 'eb...4', address=None, local_key='aabbccddeeffgghh', persist=True, version=3.3 )

print( 'GW IP found:', gw.address )

# Configure one or more children.  Every dev_id must be unique!
zigbee1 = tinytuya.OutletDevice( 'eb14...w', cid='0011223344556601', parent=gw )
zigbee2 = tinytuya.OutletDevice( 'eb04...l', cid='0011223344556689', parent=gw )

print(zigbee1.status())
print(zigbee2.status())
```

## v1.8.0 - Expanded Cloud Functions

* PyPI 1.8.0
* Add AtorchTemperatureController by @Poil in https://github.com/jasonacox/tinytuya/pull/213
* Add new Cloud functions to fetch device logs from TuyaCloud (`getdevicelog(id)`), make generic cloud request with custom URL and params (`cloudrequest(url, ...)`) and fetch connection status (`getconnectstatus(id)`) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/219
* Update README for new Cloud functions, and tighter deviceid error checking by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/220

```python
import tinytuya
import json

c = tinytuya.Cloud()
r = c.getdevicelog( '00112233445566778899' )
print( json.dumps(r, indent=2) )
```

## v1.7.2 - Fix Contrib Devices Bug

* PyPI 1.7.2
* Restore reference to 'self' in __init__() functions by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/207
* Misc updates to find_device(), wizard, and repr(device) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/196
* Added socketRetryDelay as parameter instead of fixed value = 5. by @erathaowl in https://github.com/jasonacox/tinytuya/pull/199


## v1.7.1 - Auto-IP Detection Enhancement

* PyPI 1.7.1
* Add Climate device module and simple example for portable air conditioners by @fr3dz10 in https://github.com/jasonacox/tinytuya/pull/189 and https://github.com/jasonacox/tinytuya/pull/192
* Constructor and documentation updates by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/188
* Get local key from devices.json if not provided by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/187
* Rework device finding for auto-IP detection, and unpack_message() retcode fix by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/186
* Standardize indentation for code snippets in the README by @TheOnlyWayUp in https://github.com/jasonacox/tinytuya/pull/184

```python
d = tinytuya.OutletDevice( '0123456789abcdef0123' )
```

## v1.7.0 - Tuya Protocol v3.4 Device Support

* PyPI 1.7.0
* Add support for v3.4 protocol Tuya devices by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/179
* API change with `_send_receive()` - now takes care of the packing and encrypting so it can re-encode whenever the socket is closed and reopened, and _get_socket() now takes care of negotiating the session key (v3.4)
* Optimize detect_available_dps() by @pawel-szopinski in https://github.com/jasonacox/tinytuya/pull/176
* Update ThermostatDevice by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/174
* Add Pronto/NEC/Samsung IR code conversion functions to IRRemoteControlDevice by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/173
* Added DoorbellDevice by @JonesMeUp in https://github.com/jasonacox/tinytuya/issues/162 
* Added ability to set version on constructor for more intuitive use:

```python
d = tinytuya.OutletDevice(
    dev_id='xxxxxxxxxxxxxxxxxxxxxxxx',
    address='x.x.x.x',
    local_key='xxxxxxxxxxxxxxxx',
    version=3.4)

print(d.status())
```

## v1.6.6 - Updated Payload Dictionary and Command List

* PyPI 1.6.6
* Added support for v3.2 protocol Tuya devices
* Added SocketDevice by @Felix-Pi in https://github.com/jasonacox/tinytuya/pull/167
* Skip DPS detection for 3.2 protocol devices if it has already been set by @pawel-szopinski in https://github.com/jasonacox/tinytuya/pull/169

```python
# Example usage of community contributed device modules
from tinytuya.Contrib import SocketDevice

socket = SocketDevice('abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc', version=3.3)

print(socket.get_energy_consumption())
print(socket.get_state())
```

## v1.6.5 - Updated Payload Dictionary and Command List

* PyPI 1.6.5
* Reworked payload_dict and realigned the command list to match [Tuya's API](https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h) by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/166
* Changed socket.send() to socket.sendall() in _send_receive() by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/166
* Created TuyaSmartPlug-example.py by @fajarmnrozaki in https://github.com/jasonacox/tinytuya/pull/163 and https://github.com/jasonacox/tinytuya/pull/165

## v1.6.4 - IRRemoteControlDevice and Read Improvements

* PyPI 1.6.4
* Separates read retries from send retries by @uzlonewolf #158
* IRRemoteControlDevice - New community contributed device module for IR Remote Control devices by @ClusterM in https://github.com/jasonacox/tinytuya/pull/160 - See example: [examples/IRRemoteControlDevice-example.py](https://github.com/jasonacox/tinytuya/blob/master/examples/Contrib/IRRemoteControlDevice-example.py)

```python
# Example usage of community contributed device modules
from tinytuya import Contrib

ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )
```

## v1.6.2 - Cloud, TuyaMessage & ThermostatDevice Improvements

* PyPI 1.6.2
* Add getconnectstatus() function to Cloud class by @Paxy in https://github.com/jasonacox/tinytuya/pull/151
* Improve TuyaMessage Header processing for mulit-payload messages by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/153
* More verbose debug logging on decode error by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/155
* Add schedule editing to [Contrib/ThermostatDevice](https://github.com/jasonacox/tinytuya/blob/master/tinytuya/Contrib/ThermostatDevice.py) and various fixes by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/157

## v1.6.1 - ThermostatDevice - User Contributed Device Module

* PyPI 1.6.1
* Cloud - Fix bug in `getdevices()` to import device mac addresses (same as wizard).
* Break the Outlet/Cover/Bulb/Cloud modules out into separate files by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/142
* Fix logging calls in XenonDevice.detect_available_dps by @pkasprzyk in https://github.com/jasonacox/tinytuya/pull/144
* [TinyTuya API Server](https://github.com/jasonacox/tinytuya/tree/master/server#tinytuya-api-server) - Add Cloud API syncing with auto-retry by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/147
* [TinyTuya API Server](https://github.com/jasonacox/tinytuya/tree/master/server#tinytuya-api-server) - List registered but offline devices via `/offline` and web UI.
* ThermostatDevice - First community contributed device module ThermostatDevice by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/146 - See example: [examples/ThermostatDevice-example.py](https://github.com/jasonacox/tinytuya/blob/master/examples/Contrib/ThermostatDevice-example.py)

```python
# Example usage of community contributed device modules
from tinytuya import Contrib

thermo = Contrib.ThermostatDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )
```


## v1.6.0 - Colorama for Terminal Color

* PyPI 1.6.0
* Add [colorama](https://github.com/tartley/colorama) terminal color capability for all platforms including MS Windows and stdout redirects
* Fix to allow setting socket options to existing open sockets by @uzlonewolf in https://github.com/jasonacox/tinytuya/pull/140
* BETA: Started standalone TinyTuya API Server ([see here](https://github.com/jasonacox/tinytuya/tree/master/server#tinytuya-api-server)). No change to core library.

## v1.5.0 - Add 'nowait' Option to Commands

* PyPI 1.5.0
* Added an optional 'nowait' boolean setting (True/False) to functions to allow sending commands without waiting for a device response. (Issue #74)
* Clean up code to address pylint warnings. (PR #135)

```python
# Example use of nowait option
d.turn_on(nowait=True)
d.set_colour(r, g, b, nowait=True)
d.set_value(201, '9AEmAvQBJgL0ASYCQAYmAkAGJgJABiY', nowait=True)  # send IR command
d.set_value(25, '010e0d0000000000000003e803e8', nowait=True)      # set scene
```

## v1.4.0 - Updated Scanner Functions

* PyPI 1.4.0 - Minor Update to APIs (additional arguments and elements)
* Debug - Updated debug output for payloads to formatted hexadecimal (pull request #98)
* Scan - Terminal color fix for 3.1 devices.
* Error Handling added for `set_timer()` function (Issue #87)
* Add wizard capability to pull mac addresses from TuyaPlatform in devices.json (Issue #117)
* Add wizard `-force` option to perform network scan for device IP addresses (Issue #117)
* Separated scan functions into `scanner.py` file.
* NEW: Added command line functions for scanning:
    * `devices` - Display and poll all registered devices for status (using devices.json). This will force a network scan for IP address changes and will create snapshot.json.
    * `snapshot` - Display and poll all devices as listed snapshot.json. This assume IP address are the same as the last snapshot.
    * `json` - Same as snapshot but respond with a JSON payload.

```bash
# Run wizard using brute force scan for IP addresses
python -m tinytuya wizard -force

# New Interactive Command Line Options
python -m tinytuya devices
python -m tinytuya snapshot

# Non-Interactive poll with JSON response
python -m tinytuya json

```

## v1.3.1 - TuyaCloud API Support

* PyPi Version 1.3.1
* Added TuyaCloud token expiration detection and renewal logic (Issue #94)

## v1.3.0 - TuyaCloud API Support

* PyPi Version 1.3.0
* Code format cleanup and readability improvements (pull request #91)
* Upgrade - Add TuyaCloud API support and functions (#87 #95)

```python
import tinytuya

c = tinytuya.Cloud(
        apiRegion="us", 
        apiKey="xxxxxxxxxxxxxxxxxxxx", 
        apiSecret="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 
        apiDeviceID="xxxxxxxxxxxxxxxxxxID")

# Display list of devices
devices = c.getdevices()
print("Device List: %r" % devices)

# Select a Device ID to Test
id = "xxxxxxxxxxxxxxxxxxID"

# Display DPS IDs of Device
result = c.getdps(id)
print("DPS IDs of device:\n", result)

# Display Status of Device
result = c.getstatus(id)
print("Status of device:\n", result)

# Send Command - This example assumes a basic switch
commands = {
	'commands': [{
		'code': 'switch_1',
		'value': True
	}, {
		'code': 'countdown_1',
		'value': 0
	}]
}
print("Sending command...")
result = c.sendcommand(id,commands)
print("Results\n:", result)
```

## v1.2.11 - Updated Scan and Wizard Retry Logic

* PyPi Version 1.2.11
* Added retries logic to `wizard` and `scan` to honor value set by command line or default to a value based on the number of devices (if known):

```bash
# Explicit value set via command line
python3 -m tinytuya wizard 50   # Set retry to 50 
python3 -m tinytuya scan 50     

# Use automatic computed value
python3 -m tinytuya wizard      # Compute a default
python3 -m tinytuya scan        

# Example output
TinyTuya (Tuya device scanner) [1.2.11]

[Loaded devices.json - 32 devices]

Scanning on UDP ports 6666 and 6667 for devices (47 retries)...
```

## v1.2.10 - Wizard Update for New Tuya Regions 

* PyPi Version 1.2.10
* Added ability to disable device auto-detect (default vs device22) via `d.disabledetect=True`.
* Wizard: Added new data center regions for Tuya Cloud: (Issues #66 #75)

Code | Region | Endpoint
-- | -- | --
cn | China Data Center | https://openapi.tuyacn.com
us | Western America Data Center | https://openapi.tuyaus.com
us-e | Eastern America Data Center | https://openapi-ueaz.tuyaus.com
eu | Central Europe Data Center | https://openapi.tuyaeu.com
eu-w | Western Europe Data Center | https://openapi-weaz.tuyaeu.com
in | India Data Center | https://openapi.tuyain.com

## v1.2.9 - Edge Case Device Support

* PyPi Version 1.2.9
* Added Error Handling in class Device(XenonDevice) for conditions where response is None (Issue #68)
* Added edge-case handler in `_decode_payload()` to decode non-string type decrypted payload (Issue #67)

## v1.2.8 - BulbDevice

* PyPi Version 1.2.8
* Added additional error checking for BulbDevice type selection
* Added TinyTuya version logging for debug mode
* Fix bug in scan when color=False (Issue #63)

## v1.2.7 - New Tuya Cloud IoT Setup Wizard

* PyPi Version 1.2.7
* Updated setup `wizard` to support new Tuya Cloud signing method (Issue #57)
* Added Bulb type C and manual setting function `set_bulb_type(type)` (PR #54)
* Wizard creates `tuya-raw.json` to record raw response from Tuya IoT Platform
* Fixed device22 bug on retry - Now returns ERR_DEVTYPE error, status() includes auto-retry (#56)

## v1.2.6 - Improved Error Handling

* PyPi Version 1.2.6
* Added `wizard` handling to capture and display Tuya API server error responses (PR #45)
* Added better error handling for BulbDevice `state()` function to not crash when dps values are missing in response (PR #46)
* Added async examples using `send()` and `receive()`
* Updated scan output to include device Local Key if known (PR #49 #50)
* Fixed print typo in examples/devices.py (PR #51)

## v1.2.5 - Send and Receive Functions

* PyPi Version 1.2.5
* Added raw mode `send()` and `receive()` function to allow direct control of payload transfers. Useful to monitor constant state changes via threads or continuous loops.  This example opens a Tuya device and watches for state changes (e.g. switch going on and off):

```python
import tinytuya

d = tinytuya.OutletDevice('DEVICEID', 'DEVICEIP', 'DEVICEKEY')
d.set_version(3.3)
d.set_socketPersistent(True)

print(" > Send Initial Query for Status < ")
payload = d.generate_payload(tinytuya.DP_QUERY)
d.send(payload)

while(True):
    # See if any data is available
    data = d.receive()
    print('Received Payload: %r' % data)

    # Send a keyalive heartbeat ping
    print(" > Send Heartbeat Ping < ")
    payload = d.generate_payload(tinytuya.HEART_BEAT)
    d.send(payload)
```

## v1.2.4 - DPS Detection and Bug Fixes

* PyPi Version 1.2.4
* Added detect_available_dps() function
* Fixed bug in json_error() function
* Updated instruction for using Tuya iot.tuya.com to run Wizard
* Added option to disable deviceScan() automatic device polling
* Added better error handling processing Tuya messages (responses) Issue #39
* Fixed display bug in Wizard device polling to show correct On/Off state

## v1.2.3 - Dimmer and Brightness Functions

* PyPi Version 1.2.3
* Added `set_dimmer()` to OutletDevice class.
* Added `set_hsv()` to BulbDevice class.
* Updated `set_brightness()` in BulbDevice to handle *white* and *colour* modes. Issue #30
* BulbDevice determines features of device and presents boolean variables `has_colour`, `has_brightness` and `has_colourtemp` to ignore requests that do not exist (returns error).

## v1.2.2 - Bug Fix for Bulb Functions

* PyPi Version 1.2.2
* Fix bug in set_white_percentage(): added missing self. PR #32
* Fixed set_white_percentage: colour temp was incorrectly computed for B type Bulbs. PR #33
* Moved setup **Wizard** out of module init to standalone import to save import load.

Command line mode is still the same:
```python
python3 -m tinytuya wizard
```

Import now requires additional import to run Wizard programmatically:
```python
import tinytuya
import tinytuya.wizard

tinytuya.wizard.wizard()

```

## v1.2.1 - Bug Fix for Command 0x12 UpdateDPS

* PyPi Version 1.2.1
* Fixed header for 0x12 Update DPS Command (see issue #8)

## v1.2.0 - Error Handling and Bug Fixes

* PyPi Version 1.2.0
* Now decrypting all TuyaMessage responses (not just status)
* Fixed `set_colour(r, g, b)` to work with python2
* Fixed `set_debug()` to toggle on debug logging (with color)
* Added handler for `device22` to automatically detect and `set_dpsUsed()` with available DPS values. 
* Added `set_socketTimeout(s)` for adjustable connection timeout setting (defaults to 5s)
* Added `set_sendWait(s)` for adjustable wait time after sending device commands
* Improved and added additional error handling and retry logic
* Instead of Exceptions, tinytuya responds with Error response codes (potential breaking change):

Example

```python
import tinytuya

tinytuya.set_debug(toggle=False, color=True)

d = tinytuya.OutletDevice('<ID>','<IP>','<KEY>')
d.set_version(3.3)
d.status()
```
```
{u'Payload': None, u'Err': u'905', u'Error': u'Network Error: Device Unreachable'}
```


## v1.1.4 - Update DPS (Command 18)

* PyPi Version 1.1.4
* Added `updatedps()` command 18 function to request device to update DPS values (Issue #8)
* Added `set_debug()` function to activate debug logging 
```python
import tinytuya
import time

tinytuya.set_debug(True)

d = tinytuya.OutletDevice('DEVICEID', 'IP', 'LOCALKEY')
d.set_version(3.3)

print(" > Fetch Status < ")
data = d.status()
time.sleep(5)

print(" > Request Update for DPS indexes 18, 19 and 20 < ")
result = d.updatedps([18, 19, 20])

print(" > Fetch Status Again < ")
data2 = d.status()

print("Before %r" % data)
print("After  %r" % data2)
```

## v1.1.3 - Automatic IP Lookup

* PyPi Version 1.1.3
* Updated device read retry logic for minimum response payload (28 characters) (Issue #17)
* Feature added to do automatic IP address lookup via network scan if _None_ or '0.0.0.0' is specified.  Example:
```python
    import tinytuya
    ID = "01234567890123456789"
    IP = None
    KEY = "0123456789012345"
    d = tinytuya.OutletDevice(ID,IP,KEY)
    d.status()
```

## v1.1.2 - Bug Fix or 3.1 Devices

* PyPi Version 1.1.2
* Bug Fix for 3.1 Devices using CONTROL command - updated to hexdigest[8:][:16]
* See Issue: #11


## v1.1.1 - BulbDevice Class Update

* PyPi Version 1.1.1
* Updated BulbDevice Class to support two types of bulbs with different DPS mappings and functions:
        - Type A - Uses DPS index 1-5 and represents color with RGB+HSV
        - Type B - Uses DPS index 20-27 (no index 1)
* Updated Colour Support -  Index (DPS_INDEX_COLOUR) is assumed to be in the format:
         - (Type A) Index: 5 in hex format: rrggbb0hhhssvv 
         - (Type B) Index: 24 in hex format: hhhhssssvvvv 
* New Functions to help abstract Bulb Type:
        - `set_white_percentage(brightness=100, colourtemp=0):`
        - `set_brightness_percentage(brightness=100):`
        - `set_colourtemp_percentage(colourtemp=100):`
        - `set_mode(mode='white'):`       # white, colour, scene, music
* Example Script https://github.com/jasonacox/tinytuya/blob/master/examples/bulb.py 

## v1.1.0 - Setup Wizard

* PyPi Version 1.1.0
* Added TinyTuya Setup Wizard to help users grab device *LOCAL_KEY* from the Tuya Platform.
* Added formatted terminal color output (optionally disabled with `-nocolor`) for interactive **Wizard** and **Scan** functions.

```python
python3 -m tinytuya wizard
```
s
## v1.0.5 - Persistent Socket Connections

* PyPi Version 1.0.5
* Updated cipher json payload to mirror TuyAPI - hexdigest from `[8:][:16]` to `[8:][:24]`
* Added optional persistent socket connection, NODELAY and configurable retry limit (@elfman03) #5 #6 #7
```python
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]	    
    set_socketRetryLimit(integer)      # retry count limit [default 5]
```
* Add some "scenes" supported by color bulbs (@elfman03) 
```python
    set_scene(scene):             # 1=nature, 3=rave, 4=rainbow
```

## v1.0.4 - Network Scanner

* PyPi Version 1.0.4
* Added `scan()` function to get a list of Tuya devices on your network along with their device IP, ID and VERSION number (3.1 or 3.3):
```
python3 -m tinytuya
```

## v1.0.3 - Device22 Fix

* PyPi Version 1.0.3
* Removed automatic device22 type selection.  The assumption that 22 character ID meant it needed dev_type device22 was discovered to be incorrect and there are Tuya devices with 22 character ID's that behave similar to default devices.  Device22 type is now available via a dev_type specification on initialization:
```
    OutletDevice(dev_id, address, local_key=None, dev_type='default')
    CoverDevice(dev_id, address, local_key=None, dev_type='default')
    BulbDevice(dev_id, address, local_key=None, dev_type='default')
```
* Added Tuya Command Types framework to definitions and payload dictionary per device type.
* Bug fixes (1.0.2):
    * Update SET to CONTROL command
    * Fixed BulbDevice() `__init__`

## v1.0.0 - Initial Release

* PyPi Version 1.0.0
