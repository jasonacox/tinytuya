# TinyTuya API Reference

Developer reference for all public classes, methods, and functions in TinyTuya.

---

## Table of Contents

- [Class Hierarchy](#class-hierarchy)
- [Module-Level Functions](#module-level-functions)
- [XenonDevice (Base Class)](#xenondevice-base-class)
- [Device](#device)
- [OutletDevice](#outletdevice)
- [BulbDevice](#bulbdevice)
- [CoverDevice](#coverdevice)
- [Cloud](#cloud)
- [Error Codes](#error-codes)
- [Command Line Interface](#command-line-interface)
- [Contrib Modules](#contrib-modules)

---

## Class Hierarchy

```
XenonDevice
  └── Device
        ├── OutletDevice
        ├── BulbDevice
        └── CoverDevice
```

All device classes share the constructor signature and connection methods from `XenonDevice`.
`Device` adds commands such as `set_status`, `turn_on`, `set_value`, etc.
Subclasses add device-specific helpers on top.

---

## Module-Level Functions

### `deviceScan(verbose=False, maxretry=15, color=True, poll=True, forcescan=False)`
Scans the local network for Tuya devices and returns a dictionary of results.

```python
import tinytuya
devices = tinytuya.deviceScan()
for ip, info in devices.items():
    print(ip, info.get('gwId'), info.get('version'))
```

### `scan(maxretry=15, color=True, poll=True, forcescan=False)`
Interactive scan that prints discovered devices to stdout.

```python
tinytuya.scan()
```

### `find_device(dev_id=None, address=None)`
Scan the network for a specific device by ID or IP address.

```python
result = tinytuya.find_device(dev_id='01234567891234567890')
print(result)
# {'ip': '10.0.1.50', 'version': '3.3', 'id': '01234567891234567890', 'product_id': '...', 'data': {...}}
```

### `device_info(dev_id)`
Look up a device in the local `devices.json` file.

```python
info = tinytuya.device_info('01234567891234567890')
print(info)  # {'name': 'My Plug', 'id': '...', 'key': '...'}
```

### `assign_dp_mappings(tuyadevices, mappings)`
Attach DP code-to-ID mappings to a list of device dicts (usually from `Cloud.getdevices()`).

```python
tinytuya.assign_dp_mappings(devices, mappings)
```

### `decrypt_udp(msg)`
Decrypt a raw UDP broadcast packet received from a Tuya device.

```python
plaintext = tinytuya.decrypt_udp(raw_bytes)
```

### `set_debug(toggle=True, color=True)`
Enable or disable verbose debug logging.

```python
tinytuya.set_debug(True)
```

---

## XenonDevice (Base Class)

`XenonDevice` is the low-level foundation. You typically use one of its subclasses instead.

### Constructor

```python
XenonDevice(
    dev_id,                   # str  – Device ID
    address=None,             # str  – IP address, or "Auto" to discover
    local_key="",             # str  – Encryption key
    dev_type="default",       # str  – "default" or "device22"
    connection_timeout=5,     # int  – TCP connect timeout (seconds)
    version=3.1,              # float – Tuya protocol version
    persist=False,            # bool – Keep TCP connection open
    cid=None,                 # str  – Sub-device (Zigbee) ID
    node_id=None,             # str  – Alias for cid
    parent=None,              # object – Gateway device for sub-devices
    connection_retry_limit=5, # int
    connection_retry_delay=5, # int
    port=6668,                # int
)
```

> **Total timeout** = `connection_timeout × connection_retry_limit + connection_retry_delay × (connection_retry_limit − 1)`  
> Defaults: `(5 × 5) + (5 × 4) = 45 seconds`

---

### Connection & Socket Methods

> In the examples below, `d` is a device instance:
> ```python
> d = tinytuya.Device('DEVICE_ID', '192.168.1.50', 'LOCAL_KEY', version=3.3)
> ```

#### `set_version(version)`
Set the Tuya protocol version. Must be called before any command.

```python
d.set_version(3.3)
```

#### `set_socketPersistent(persist)`
Keep the TCP socket open between commands (`True`) or close after each one (`False`, default).

```python
d.set_socketPersistent(True)  # good for tight loops
```

#### `set_socketNODELAY(nodelay)`
Enable/disable `TCP_NODELAY` (Nagle's algorithm). Default: `True` (disabled).

```python
d.set_socketNODELAY(True)
```

#### `set_socketRetryLimit(limit)`
Maximum number of reconnect attempts. Default: `5`.

```python
d.set_socketRetryLimit(3)
```

#### `set_socketRetryDelay(delay)`
Seconds to wait between reconnect attempts. Default: `5`.

```python
d.set_socketRetryDelay(2)
```

#### `set_socketTimeout(s)`
TCP connection timeout in seconds. Default: `5`.

```python
d.set_socketTimeout(10)
```

#### `set_sendWait(s)`
Pause (seconds) after sending a command before reading the response. Default: `0.01`.

```python
d.set_sendWait(0.1)
```

#### `set_retry(retry)`
Retry receiving if the response payload appears truncated. Default: `True`.

```python
d.set_retry(False)
```

---

### Status Methods

#### `status(nowait=False)`
Request and return the current device status as a dict.

```python
data = d.status()
print(data)
# {'dps': {'1': True, '2': 0, ...}}

# Non-blocking, fire-and-forget (use receive() later)
d.status(nowait=True)
```

#### `cached_status(historic=False, nowait=False)`
Return the last-known status from cache (requires `persist=True`). Falls back to `status()` if cache is empty and `nowait=False`.

```python
d.set_socketPersistent(True)
data = d.status()              # primes the cache
later = d.cached_status()      # returns cached result
```

#### `receive()`
Read any pending payload from the device buffer. Returns `None` on timeout.

```python
data = d.receive()
```

#### `send(payload)`
Send a raw `MessagePayload` without waiting for a response.

```python
payload = d.generate_payload(tinytuya.CONTROL, {'1': True})
d.send(payload)
```

---

### Data Point (DPS) Methods

#### `set_dpsUsed(dps_to_request)`
Override the set of DPS indices included in status queries.

```python
d.set_dpsUsed({'1': None, '2': None})
```

#### `add_dps_to_request(index)`
Add one or more DPS indices to the request set.

```python
d.add_dps_to_request(18)
d.add_dps_to_request([18, 19, 20])
```

#### `detect_available_dps()`
Probe the device to discover all supported DPS indices. Returns a dict `{dp_id: None}`.

```python
dps = d.detect_available_dps()
print(dps)  # {'1': None, '2': None, ...}
```

---

### Payload Methods

#### `generate_payload(command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None)`
Build a `MessagePayload` object for a given command.
Common commands: `tinytuya.CONTROL`, `tinytuya.DP_QUERY`, `tinytuya.HEART_BEAT`, `tinytuya.UPDATEDPS`.

```python
payload = d.generate_payload(tinytuya.CONTROL, {'1': True})
d.send(payload)
```

#### `heartbeat(nowait=True)`
Send a keep-alive packet to hold a persistent connection open.

```python
d.heartbeat()
```

#### `updatedps(index=[1], nowait=False)`
Ask the device to refresh specific DPS values (useful for power-monitoring plugs).

```python
d.updatedps([18, 19, 20])
```

#### `subdev_query(nowait=False)`
Query sub-device status (gateway devices only).

```python
d.subdev_query()
```

---

## Device

`Device` extends `XenonDevice` with common control commands. All subclasses (Outlet, Bulb, Cover) inherit these.

```python
import tinytuya

d = tinytuya.Device('DEVICE_ID', '192.168.1.50', 'LOCAL_KEY', version=3.3)
```

### `status(nowait=False)`
Inherited from `XenonDevice`. Returns `{'dps': {...}}`.

### `set_status(on, switch=1, nowait=False)`
Set a switch DPS to `True` (on) or `False` (off).

```python
d.set_status(True)        # turn on switch 1
d.set_status(False, 4)    # turn off switch 4
```

### `turn_on(switch=1, nowait=False)`
Convenience wrapper for `set_status(True, ...)`.

```python
d.turn_on()
d.turn_on(switch=2)
```

### `turn_off(switch=1, nowait=False)`
Convenience wrapper for `set_status(False, ...)`.

```python
d.turn_off()
```

### `set_value(index, value, nowait=False)`
Set any DPS index to an arbitrary value.

```python
d.set_value(25, 'scene_data_hex_string')
d.set_value(2, 500)
```

### `set_multiple_values(data, nowait=False)`
Set several DPS indices atomically in one request.

```python
d.set_multiple_values({'20': True, '21': 'colour', '22': 800})
```

### `set_timer(num_secs, dps_id=0, nowait=False)`
Set an on-device countdown timer (seconds). If `dps_id` is 0, the last DPS in the status is used.

```python
d.set_timer(3600)          # 1-hour timer on auto-detected DPS
d.set_timer(600, dps_id=9) # 10-minute timer on DPS 9
```

### `heartbeat(nowait=True)`
Send a HEART_BEAT command.

```python
d.heartbeat()
```

### `product()`
Request AP_CONFIG product info. *(Beta)*

```python
info = d.product()
```

---

## OutletDevice

`OutletDevice` inherits everything from `Device` and adds dimmer support.

```python
import tinytuya

d = tinytuya.OutletDevice(
    dev_id='DEVICE_ID',
    address='192.168.1.50',
    local_key='LOCAL_KEY',
    version=3.3
)
d.turn_on()
d.turn_off()
data = d.status()
print(data['dps']['1'])   # True = on, False = off
```

### `set_dimmer(percentage=None, value=None, dps_id=3, nowait=False)`
Set dimmer level on plugs/switches with dimming support.
- `percentage` – 0–100 (maps to 0–255 raw)
- `value` – raw value 0–255 (alternative to percentage)
- `dps_id` – DPS index for the dimmer (default `3`)

```python
d.set_dimmer(50)            # 50% brightness
d.set_dimmer(value=128)     # raw value
d.set_dimmer(0)             # turns device off via turn_off()
```

---

## BulbDevice

`BulbDevice` inherits from `Device` and auto-detects bulb type (A, B, or C) from DPS:

| Type | Switch DPS | Use |
|------|-----------|-----|
| A    | 1         | Older RGB+CCT (brightness 25–255) |
| B    | 20        | Newer RGB+CCT (brightness 10–1000) |
| C    | 1         | Basic dimmer-only bulbs |

```python
import tinytuya

d = tinytuya.BulbDevice('DEVICE_ID', '192.168.1.51', 'LOCAL_KEY')
d.set_version(3.3)
d.set_socketPersistent(True)
```

---

### On / Off

```python
d.turn_on()
d.turn_off()
```

### `set_mode(mode='white', nowait=False)`
Set operating mode: `'white'`, `'colour'`, `'scene'`, or `'music'`.

```python
d.set_mode('colour')
```

### `set_colour(r, g, b, nowait=False)`
Set colour using RGB values (0–255 each).

```python
d.set_colour(255, 0, 0)       # red
d.set_colour(0, 255, 128)     # seafoam green
```

### `set_hsv(h, s, v, nowait=False)`
Set colour using HSV (all values 0.0–1.0).

```python
d.set_hsv(0.0, 1.0, 1.0)   # pure red
d.set_hsv(0.5, 0.8, 0.9)   # teal
```

### `set_white_percentage(brightness=100, colourtemp=0, nowait=False)`
Set white mode with brightness and colour temperature as percentages (0–100).

```python
d.set_white_percentage(brightness=80, colourtemp=50)
```

### `set_brightness_percentage(brightness=100, nowait=False)`
Set brightness in percent (0–100) without changing colour temp or mode.

```python
d.set_brightness_percentage(60)
```

### `set_colourtemp_percentage(colourtemp=100, nowait=False)`
Set colour temperature in percent (0 = warm, 100 = cool).

```python
d.set_colourtemp_percentage(75)
```

### `set_scene(scene, scene_data=None, nowait=False)`
Activate a preset scene. Type A supports scenes 1–4; Type B supports 1–N.

```python
d.set_scene(1)   # nature
d.set_scene(3)   # rave
d.set_scene(4)   # rainbow
```

### `set_timer(num_secs, dps_id=0, nowait=False)`
Set a countdown timer (seconds).

```python
d.set_timer(1800)   # 30 minutes
```

### `set_musicmode(transition, modify_settings=True, nowait=False)`
Enter music-reactive mode.

```python
d.set_musicmode(tinytuya.BulbDevice.MUSIC_TRANSITION_JUMP)
d.set_musicmode(tinytuya.BulbDevice.MUSIC_TRANSITION_FADE)
```

### `set_music_colour(transition, red, green, blue, brightness=None, colourtemp=None, nowait=False)`
Set a single colour frame while in music mode.

```python
d.set_music_colour(tinytuya.BulbDevice.MUSIC_TRANSITION_FADE, 0, 128, 255)
```

---

### State Getters

#### `state(nowait=False)`
Return a high-level state dict for the bulb.

```python
s = d.state()
print(s)
# {'switch': True, 'mode': 'colour', 'brightness': 800,
#  'colourtemp': 300, 'colour': '00f003e803e8', 'is_on': True, ...}
```

#### `get_mode(state=None, nowait=False)`
Return current mode string (`'white'`, `'colour'`, etc.).

```python
print(d.get_mode())
```

#### `brightness(state=None, nowait=False)`
Return raw brightness value.

```python
print(d.brightness())
```

#### `get_brightness_percentage(state=None, nowait=False)`
Return brightness as a percentage (0–100).

```python
print(d.get_brightness_percentage())
```

#### `colourtemp(state=None, nowait=False)`
Return raw colour temperature value.

#### `get_colourtemp_percentage(state=None, nowait=False)`
Return colour temperature as a percentage.

#### `colour_rgb(state=None, nowait=False)`
Return current colour as `(r, g, b)` tuple (0–255 each).

```python
r, g, b = d.colour_rgb()
```

#### `colour_hsv(state=None, nowait=False)`
Return current colour as `(h, s, v)` tuple (0.0–1.0 each).

```python
h, s, v = d.colour_hsv()
```

---

### Colour Conversion Helpers (Static Methods)

#### `BulbDevice.rgb_to_hexvalue(r, g, b, hexformat)`
Convert RGB (0–255) to Tuya hex string.
- `hexformat='rgb8'` → `'rrggbb0hhhssvv'` (Type A)
- `hexformat='hsv16'` → `'hhhhssssvvvv'` (Type B)

```python
hex_str = tinytuya.BulbDevice.rgb_to_hexvalue(255, 0, 0, 'hsv16')
```

#### `BulbDevice.hsv_to_hexvalue(h, s, v, hexformat)`
Convert HSV (0.0–1.0) to Tuya hex string.

```python
hex_str = tinytuya.BulbDevice.hsv_to_hexvalue(0.0, 1.0, 1.0, 'hsv16')
```

#### `BulbDevice.hexvalue_to_rgb(hexvalue, hexformat=None)`
Convert Tuya hex string back to `(r, g, b)` tuple.

```python
r, g, b = tinytuya.BulbDevice.hexvalue_to_rgb('ff000000ffff')
```

#### `BulbDevice.hexvalue_to_hsv(hexvalue, hexformat=None)`
Convert Tuya hex string back to `(h, s, v)` tuple.

```python
h, s, v = tinytuya.BulbDevice.hexvalue_to_hsv('00000fa003e8')
```

---

### Capability Detection

#### `bulb_has_capability(feature, nowait=False)`
Check if the bulb supports a feature: `'mode'`, `'brightness'`, `'colourtemp'`, `'colour'`, `'scene'`, `'timer'`, `'music'`.

```python
if d.bulb_has_capability('colour'):
    d.set_colour(0, 0, 255)
```

#### `detect_bulb(response=None, nowait=False)`
Auto-detect bulb type from a status response or by calling `status()`.

```python
d.detect_bulb()
print(d.bulb_type)  # 'A', 'B', 'C', or None
```

#### `set_bulb_type(bulb_type=None, mapping=None)`
Manually set the bulb type and DPS mapping.

```python
d.set_bulb_type('B')
```

---

## CoverDevice

`CoverDevice` inherits from `Device` and adds window cover commands.

```python
import tinytuya

d = tinytuya.CoverDevice('DEVICE_ID', '192.168.1.52', 'LOCAL_KEY', version=3.3)
```

### `open_cover(switch=1, nowait=False)`
Send the open command.

```python
d.open_cover()
```

### `close_cover(switch=1, nowait=False)`
Send the close command.

```python
d.close_cover()
```

### `stop_cover(switch=1, nowait=False)`
Stop cover movement.

```python
d.stop_cover()
```

---

## Cloud

Access the Tuya IoT Cloud API to manage devices, query status, and retrieve logs.

> **Note:** The free Tuya Developer Trial account has strict rate limits. Avoid automation that calls the Cloud frequently.

### Constructor

```python
import tinytuya

c = tinytuya.Cloud(
    apiRegion='us',                # Region code: cn, us, us-e, eu, eu-w, in, sg
    apiKey='xxxxxxxxxxxxxxxxxxxx', # Access ID / Client ID
    apiSecret='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    apiDeviceID='xxxxxxxxxxxxxxxxxxID',  # Optional – one of your device IDs
    configFile='tinytuya.json',    # Optional – load credentials from file
)

# Or load credentials automatically from tinytuya.json:
c = tinytuya.Cloud()
```

Supported region codes and their data centers:

| Code | Data Center |
|------|-------------|
| `cn` | China |
| `us` / `az` | Western America |
| `us-e` / `ue` | Eastern America |
| `eu` | Central Europe |
| `eu-w` / `we` | Western Europe |
| `in` | India |
| `sg` | Singapore |

---

### `setregion(apiRegion)`
Switch region after construction.

```python
c.setregion('eu')
```

### `cloudrequest(url, action=None, post=None, query=None)`
Make a raw HTTP request to any Tuya Cloud endpoint.

```python
result = c.cloudrequest('/v1.0/devices/DEVICE_ID/logs', query={'size': 10})
```

### `getdevices(verbose=False, oldlist=[], include_map=False)`
Return a list of all registered devices (name, id, key, etc.).

```python
devices = c.getdevices()
for dev in devices:
    print(dev['name'], dev['id'], dev['key'])
```

### `getstatus(deviceid)`
Get the current DPS status of a device from the cloud.

```python
result = c.getstatus('DEVICE_ID')
print(result)
# {'result': [{'code': 'switch_1', 'value': True}, ...], 'success': True, ...}
```

### `getfunctions(deviceid)`
Get the writable functions/commands supported by a device.

```python
funcs = c.getfunctions('DEVICE_ID')
```

### `getproperties(deviceid)`
Get device specifications (DPS definitions with types, ranges, units).

```python
props = c.getproperties('DEVICE_ID')
```

### `getdps(deviceid)`
Get DPS specifications (v1.1 endpoint, combines status + functions).

```python
dps = c.getdps('DEVICE_ID')
```

### `sendcommand(deviceid, commands, uri='iot-03/devices/')`
Send one or more commands to a device.

```python
commands = {
    'commands': [
        {'code': 'switch_1', 'value': True},
        {'code': 'countdown_1', 'value': 0},
    ]
}
result = c.sendcommand('DEVICE_ID', commands)
print(result['success'])
```

### `getconnectstatus(deviceid)`
Return `True` if the device is currently online in the cloud.

```python
online = c.getconnectstatus('DEVICE_ID')
print('online:', online)
```

### `getdevicelog(deviceid, start=None, end=None, evtype=None, size=0, max_fetches=50, start_row_key=None, params=None)`
Retrieve device event logs from the cloud (up to 7 days).

- `start` / `end` – Unix timestamp, or negative for "N days ago" (e.g. `-1` = yesterday)
- `evtype` – Event type filter: `1` = online, `7` = DP report, or comma-separated string
- `size` – Max log entries per fetch (max 100); `0` = fetch all
- `max_fetches` – Stop after this many API calls (default 50)

```python
import json, tinytuya

c = tinytuya.Cloud()

# Last 24 hours of all events
logs = c.getdevicelog('DEVICE_ID')
print(json.dumps(logs, indent=2))

# Only DP reports for the last 7 days
logs = c.getdevicelog('DEVICE_ID', start=-7, evtype=7)

# Specific time range
logs = c.getdevicelog('DEVICE_ID', start=1706000000, end=1706086400)
```

---

## Error Codes

Functions return an error dict `{"Error": "...", "Err": "NNN", "Payload": ...}` instead of raising exceptions.

```python
result = d.status()
if result and 'Err' in result:
    print('Error', result['Err'], result['Error'])
```

| Code | Constant | Meaning |
|------|----------|---------|
| 900 | `ERR_JSON` | Invalid JSON response from device |
| 901 | `ERR_CONNECT` | Unable to connect |
| 902 | `ERR_TIMEOUT` | Timeout waiting for device |
| 903 | `ERR_RANGE` | Value out of range |
| 904 | `ERR_PAYLOAD` | Unexpected payload |
| 905 | `ERR_OFFLINE` | Device unreachable |
| 906 | `ERR_STATE` | Unknown device state |
| 907 | `ERR_FUNCTION` | Function not supported by device |
| 908 | `ERR_DEVTYPE` | Device22 detected – retry |
| 909 | `ERR_CLOUDKEY` | Missing Cloud key/secret |
| 910 | `ERR_CLOUDRESP` | Invalid JSON from cloud |
| 911 | `ERR_CLOUDTOKEN` | Unable to get cloud token |
| 912 | `ERR_PARAMS` | Missing parameters |
| 913 | `ERR_CLOUD` | Error response from Tuya Cloud |
| 914 | `ERR_KEY_OR_VER` | Wrong device key or protocol version |

---

## Command Line Interface

TinyTuya ships a built-in CLI available as `tinytuya` (pipx) or `python -m tinytuya`.

### Discovery / Wizard Commands

```bash
tinytuya wizard    # Interactive setup – fetches local keys from Tuya Cloud
tinytuya scan      # Broadcast scan to find devices on the LAN
tinytuya devices   # Poll all devices listed in devices.json
tinytuya snapshot  # Poll devices listed in snapshot.json
tinytuya json      # Same as snapshot but outputs raw JSON
```

### Device Listing

```bash
tinytuya list [--json] [-device-file FILE]
```

Lists every device in `devices.json` (name, id, key, ip, version).

| Flag | Description |
|------|-------------|
| `--json` | Output as a JSON array instead of a table |
| `-device-file FILE` | Path to devices JSON file (default: `devices.json`) |

```bash
# Default – table view
tinytuya list

# JSON array
tinytuya list --json
```

### Device Control Commands

Four commands let you control a device directly from the shell.

```
tinytuya on  [--dps N] [--id ID | --name NAME] [--key KEY] [--ip IP] [--version VER] [-device-file FILE]
tinytuya off [--dps N] [--id ID | --name NAME] [--key KEY] [--ip IP] [--version VER] [-device-file FILE]
tinytuya set --dps N --value VALUE [--id ID | --name NAME] [--key KEY] [--ip IP] [--version VER] [-device-file FILE]
tinytuya get [--dps N] [--id ID | --name NAME] [--key KEY] [--ip IP] [--version VER] [-device-file FILE]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--id ID` | Device ID | — |
| `--name NAME` | Device name — looked up in `devices.json` (alternative to `--id`) | — |
| `--key KEY` | Device local encryption key | looked up from `devices.json` |
| `--ip IP` | Device IP address | auto-discovered via LAN scan |
| `--version VER` | Tuya protocol version | `3.3` |
| `--dps N` | DPS index (switch number for `on`/`off`) | `1` for on/off; optional for `get`; required for `set` |
| `--value VALUE` | Value to write (`set` only) | — |
| `-device-file FILE` | Path to devices JSON file | `devices.json` |

**Device resolution order**

1. `--name` is resolved to a device ID via a case-insensitive lookup in `devices.json`. An error is returned if no match is found.
2. `--id` / resolved ID is used to find the matching entry in `devices.json`.
3. Explicitly provided flags (`--key`, `--ip`, `--version`) override file values.
4. `--key` is required if not found in the device file.
5. `--ip` falls back to `Auto` (LAN scan) if absent.
6. `--version` falls back to `3.3` if absent.

**Examples**

```bash
# List all devices as a table
tinytuya list

# List all devices as JSON
tinytuya list --json

# Turn on – key and IP looked up from devices.json by name
tinytuya on --name "Living Room Light"

# Turn on by ID
tinytuya on --id ebfdab91f4ccc82d3elzli

# Turn off switch 3 with explicit credentials
tinytuya off --id DEVICE_ID --key LOCAL_KEY --ip 192.168.1.50 --dps 3

# Set DPS 2 to "500"
tinytuya set --name "Office Plug" --dps 2 --value 500

# Read full device status (no --dps → full JSON)
tinytuya get --id DEVICE_ID --key LOCAL_KEY --ip 192.168.1.50

# Read a single DPS value (--dps → plain value only)
tinytuya get --name "Bedroom Fan" --dps 1
```

**Output**

- `on` / `off` / `set` – prints the device response as JSON, or `OK` if the response is empty.
- `get` without `--dps` – prints full status JSON, e.g. `{"dps": {"1": true, "2": 500}}`.
- `get --dps N` – prints the plain scalar value only, e.g. `true` or `500`.
- Errors print a message to stdout and exit with code `1`.

---

## Contrib Modules

Community-contributed device modules in `tinytuya/Contrib/`:

| Module | Class | Description |
|--------|-------|-------------|
| `ThermostatDevice` | `ThermostatDevice` | 24V WiFi thermostat (e.g. PCT513-TY) |
| `IRRemoteControlDevice` | `IRRemoteControlDevice` | Universal IR blaster |
| `RFRemoteControlDevice` | `RFRemoteControlDevice` | RF remote control |
| `ClimateDevice` | `ClimateDevice` | HVAC / climate controller |
| `BlanketDevice` | `BlanketDevice` | Smart heated blanket |
| `SocketDevice` | `SocketDevice` | Smart socket with energy monitoring |
| `DoorbellDevice` | `DoorbellDevice` | Smart doorbell |
| `WiFiDualMeterDevice` | `WiFiDualMeterDevice` | Dual-channel energy meter (e.g. PJ1103A) |
| `PresenceDetectorDevice` | `PresenceDetectorDevice` | mmWave presence sensor |
| `InverterHeatPumpDevice` | `InverterHeatPumpDevice` | Inverter heat pump |
| `AtorchTemperatureControllerDevice` | `AtorchTemperatureControllerDevice` | Temperature controller |
| `ColorfulX7Device` | `ColorfulX7Device` | Colorful X7 LED controller |

### Usage

```python
from tinytuya.Contrib import ThermostatDevice

thermo = ThermostatDevice.ThermostatDevice(
    dev_id='DEVICE_ID',
    address='192.168.1.53',
    local_key='LOCAL_KEY',
    version=3.3
)
data = thermo.status()
print(data)
```

```python
from tinytuya.Contrib import WiFiDualMeterDevice

meter = WiFiDualMeterDevice.WiFiDualMeterDevice(
    dev_id='DEVICE_ID',
    address='192.168.1.54',
    local_key='LOCAL_KEY',
    version=3.4
)
data = meter.status()
print(data)
```

---

## Persistent Connection Monitor Pattern

Useful for event-driven monitoring without polling.

```python
import tinytuya

d = tinytuya.OutletDevice('DEVICE_ID', 'DEVICE_IP', 'LOCAL_KEY', version=3.3, persist=True)

d.status(nowait=True)   # prime the connection

while True:
    data = d.receive()
    if data:
        print('Update:', data)
    else:
        d.heartbeat()   # keep connection alive
```

---

## Gateway / Sub-Device Pattern

For Zigbee or sub-devices behind a gateway:

```python
import tinytuya

# Create gateway device
gw = tinytuya.Device('GATEWAY_ID', '192.168.1.55', 'GATEWAY_KEY', version=3.3)

# Attach a child sub-device (node_id / cid is the sub-device node ID)
child = tinytuya.Device('SUB_DEVICE_ID', parent=gw, cid='SUB_NODE_ID')

data = child.status()
print(data)
child.set_value(1, True)
```
