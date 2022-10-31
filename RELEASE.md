# RELEASE NOTES

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