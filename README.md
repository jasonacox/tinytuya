# TinyTuya

[![Build Status](https://travis-ci.org/jasonacox/tinytuya.svg?branch=master)](https://travis-ci.org/jasonacox/tinytuya)
[![PyPI version](https://badge.fury.io/py/tinytuya.svg)](https://badge.fury.io/py/tinytuya)

Python module to interface with Tuya WiFi smart devices

## Description

This python module to control and monitor WiFi [Tuya](https://en.tuya.com/) compatible Smart Devices (Plugs, Switches, Lights, Window Covers, etc.).  This is a compatible replacement for the `pytuya` PyPi module.

NOTE This module requires the devices to have already been **activated** by Smart Life App (or similar).

## TinyTuya Setup  

Install pip and python libraries if you haven't already.

```bash
# Install required libraries
 sudo apt-get install python-crypto python-pip  # for RPi, Linux
 python3 -m pip install pycryptodome            # or pycrypto or Crypto or pyaes
 python3 -m pip install tinytuya                # this module 
 ```

## Tuya Device Preparation

Pulling data from Tuya devices on your network requires that you know the Device *IP*, *ID*, *VERSION* and *KEY* (for 3.3 devices). You can use the built in scanner in the `tinytuya` module to find Tuya Devices on your network.  This will scan the network and identify Device's *IP*, *ID* and *VERSION*.  It will _not_ be able to get the local *KEY*.  Since newer 3.3 devices will require the *KEY*, the following steps will help you determine the *KEY*s for your devices:

### Get the Tuya Device Local KEY

1. Download the "Smart Life" - Smart Living app for iPhone or Android. Pair with your smart plug (this is important as you cannot monitor a plug that has not been paired).  
    * https://itunes.apple.com/us/app/smart-life-smart-living/id1115101477?mt=8
    * https://play.google.com/store/apps/details?id=com.tuya.smartlife&hl=en
2. For Device IP, ID and VERSION: Run the tinytuya scan to get a list of Tuya devices on your network along with their device IP, ID and VERSION number (3.1 or 3.3):
    ```bash
    python3 -m tinytuya
    ```
3. Device Local KEY: Devices running the latest protocol version 3.3 (often seen with Firmware 1.0.5 or above) will require a _Device Local KEY_ to read the status. Both 3.1 and 3.3 devices will require a _Device Local KEY_ to control the device. Follow these instructions to get the _Device Local KEY_:

  * **From iot.tuya.com**
    * Create a Tuya developer account on [iot.tuya.com](https://iot.tuya.com/) and log in.
    * Go to Cloud Development -> Create a project  (note the Authorization Key: *ID* & *Secret* for below)
    * Go to Cloud Development -> select your project -> Project Overview -> Linked Device -> Link devices by App Account (tab)
    * Click 'Add App Account' and it will display a QR code. Scan the QR code with the *Smart Life app* on your Phone (see step 1 above) by going to the "Me" tab in the *Smart Life app* and clicking on the QR code button [..] in the upper right hand corner of the app. When you scan the QR code, it will link all of the devices registered in your *Smart Life app* into your Tuya IoT project.
    * Verify under Cloud Development -> select your project -> API Setting that the following API groups have status "Open": Authorization management, Device Management and Device Control ([see here](https://user-images.githubusercontent.com/5875512/92361673-15864000-f132-11ea-9a01-9c715116456f.png))
  * **From your Local Workstation**
    * From your PC/Mac run this to install the Tuya CLI: `npm i @tuyapi/cli -g`
    * Next run: `tuya-cli wizard` and it will prompt you for the API *ID* key and *Secret* from your Tuya IoT project we noted above.  The Virtual ID is the Device ID from step 2 above or in the Device List on your Tuya IoT project.
    * The wizard will take a while but eventually print a JSON looking output that contains the name, id and key of the registered device(s).  This is the _Device Local KEY_ (also called LOCAL_KEY) you will use to poll your device.

Note: If you ever reset or re-pair your smart devices, they will reset their _Device Local KEY_ and you will need to repeat these steps above.

For a helpful video walk-through of getting the KEYS you can also watch this great _Tech With Eddie_ YouTube tutorial: <https://youtu.be/oq0JL_wicKg>.


## Programming with TinyTuya

### TinyTuya Module Classes and Functions 
```
Classes
    OutletDevice(dev_id, address, local_key=None, dev_type='default')
    CoverDevice(dev_id, address, local_key=None, dev_type='default')
    BulbDevice(dev_id, address, local_key=None, dev_type='default')

        dev_id (str): Device ID e.g. 01234567891234567890
        address (str): Device Network IP Address e.g. 10.0.1.99
        local_key (str, optional): The encryption key. Defaults to None.
        dev_type (str): Device type for payload options (see below)

 Functions 
    json = status()                    # returns json payload
    set_version(version)               # 3.1 [default] or 3.3
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]
    set_dpsUsed(dpsUsed)               # set data points (DPs)
    set_retry(retry=True)              # retry if response payload is truncated
    set_status(on, switch=1)           # Set status of the device to 'on' or 'off' (bool)
    set_value(index, value)            # Set int value of any index.
    turn_on(switch=1):
    turn_off(switch=1):
    set_timer(num_secs):

    CoverDevice:
        open_cover(switch=1):  
        close_cover(switch=1):
        stop_cover(switch=1):

    BulbDevice
        set_colour(r, g, b):
        set_white(brightness, colourtemp):
        set_brightness(brightness):
        set_colourtemp(colourtemp):
        set_scene(scene):             # 1=nature, 3=rave, 4=rainbow
        result = brightness():
        result = colourtemp():
        (r, g, b) = colour_rgb():
        (h,s,v) = colour_hsv()
        result = state():
```

### Example Usage

See the sample python script [test.py](test.py) for an OutletDevice example.

```python
    import tinytuya

    d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', 'LOCAL_KEY_HERE')
    d.set_version(3.3)
    data = d.status()  # NOTE this does NOT require a valid key vor version 3.1

    # Show status of first controlled switch on device
    print('Dictionary %r' % data)
    print('State (bool, true is ON) %r' % data['dps']['1'])  

    # Toggle switch state
    switch_state = data['dps']['1']
    data = d.set_status(not switch_state)  # This requires a valid key
    if data:
        print('set_status() result %r' % data)

    # On a switch that has 4 controllable ports, turn the fourth OFF (1 is the first)
    data = d.set_status(False, 4)
    if data:
        print('set_status() result %r' % data)
        print('set_status() extra %r' % data[20:-8])
```

### Encryption notes

These devices uses AES encryption which is not available in the Python standard library. There are three options:

 1) PyCryptodome (recommended)
 2) PyCrypto
 3) pyaes (note Python 2.x support requires https://github.com/ricmoo/pyaes/pull/13)


### Scan Tool 
The function `tinytuya.scan()` will listen to your local network (UDP 6666 and 6667) and identify Tuya devices broadcasting their IP, Device ID, ProductID and Version and will print that and their stats to stdout.  This can help you get a list of compatible devices on your network. The `tinytuya.deviceScan()` function returns all found devices and their stats (via dictionary result).

You can run the scanner from the command line using this:
```bash
python -m tinytuya
```

By default, the scan functions will retry 15 times to find new devices. If you are not seeing all your devices, you can increase max_retries by passing an optional arguments (eg. 50 retries):

```bash
# command line
python -m tinytuya 50
```

```python
# invoke verbose interactive scan
tinytuya.scan(50)

# return payload of devices
devices = tinytuya.deviceScan(false, 50)
```

## Credits

  * TuyaAPI https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
    For protocol reverse engineering, additional protocol reverse engineering from jepsonrob and clach04
  * PyTuya https://github.com/clach04/python-tuya by clach04
    The origin of this python module (now abandoned), nijave pycryptodome support and testing, Exilit for unittests and docstrings, mike-gracia for improved Python version support, samuscherer for RGB Bulb support, magneticflux for improved Python version support, sean6541 for initial PyPi package and Home Assistant support <https://github.com/sean6541/tuya-homeassistant>, ziirish - for resolving a dependency problem related to version numbers at install time
  * https://github.com/rospogrigio/localtuya-homeassistant by rospogrigio
    Updated pytuya to support devices with Device IDs of 22 characters

## Related Projects

  * https://github.com/sean6541/tuyaapi Python API to the web api
  * https://github.com/codetheweb/tuyapi node.js
  * https://github.com/Marcus-L/m4rcus.TuyaCore - .NET
  * https://github.com/SDNick484/rectec_status/ - RecTec pellet smokers control (with Alexa skill)
