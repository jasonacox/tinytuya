# TinyTuya

[![Build Status](https://travis-ci.org/jasonacox/tinytuya.svg?branch=master)](https://travis-ci.org/jasonacox/tinytuya)

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
 ```

## Tuya Device Preparation

Pulling data from Tuya devices on your network requires that you know the Device *IP*, *ID*, *VERSION* and *KEY* (for 3.3 devices). You can use the `tuyapower` module which includes a scanner function to find Smart Devices on your network.  This will scan the network and identify Device's *IP*, *ID* and *VERSION*.  It will _not_ be able to get the local *KEY*.  Since newer 3.3 devices will require the *KEY*, the following steps will help you determine the *KEY*s for your devices:

### Get the Tuya Device KEY

1. Download the "Smart Life" - Smart Living app for iPhone or Android. Pair with your smart plug (this is important as you cannot monitor a plug that has not been paired).  
    * https://itunes.apple.com/us/app/smart-life-smart-living/id1115101477?mt=8
    * https://play.google.com/store/apps/details?id=com.tuya.smartlife&hl=en
2. For Device IP, ID and VERSION: Run the tuyapower scan to get a list of Tuya devices on your network along with their device IP, ID and VERSION number (3.1 or 3.3):
    ```bash
    python3 -m tuyapower
    ```
3. For Device KEY: If your device is running the latest protocol version 3.3 (often seen with Firmware 1.0.5 or above), you will need to obtain the Device Key. This is used to connect with the device and decrypt the response data. The following are instructions to do this and are based on <https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md>:

    * Create a Tuya developer account on [iot.tuya.com](https://iot.tuya.com/) and log in.
    * Go to Cloud Development -> Create a project  (note the Authorization Key: *ID* & *Secret* for below)
    * Go to Cloud Development -> select your project -> Project Overview -> Linked Device -> Link devices by App Account (tab)
    * Click 'Add App Account' and it will display a QR code. Scan the QR code with the *Smart Life app* on your  Phone (see step 1 above) by going to the "Me" tab in the *Smart Life app* and clicking on the QR code button [..] in the upper right hand corner of the app. When you scan the QR code, it will link all of the devices registered in your *Smart Life app* into your Tuya IoT project.
    * From your PC/Mac run this in the command line to install the Tuya CLI: `npm i @tuyapi/cli -g`
    * Next run: `tuya-cli wizard` and it will prompt you for the API *ID* key and *Secret* from your Tuya IoT project we noted above.  The Virtual ID is the Device ID from step 2 above or in the Device List on your Tuya IoT project.
    * The wizard will take a while but eventually print a JSON looking output that contains the name, id and key of the registered device(s).  This is the KEY (PLUGKEY) you will use to poll your device.

Note: If you reset or re-pair your smart devices, they will reset their local KEY and you will need to repeat these steps above.

For a helpful video walk-through of getting the KEYS you can also watch this great _Tech With Eddie_ YouTube tutorial: <https://youtu.be/oq0JL_wicKg>.


## Programming with TinyTuya

### TinyTuya Module Classes and Functions 
```
 Classes
    OutletDevice(dev_id, address, local_key=None)
    CoverDevice(dev_id, address, local_key=None)
    BulbDevice(dev_id, address, local_key=None)

        dev_id (str): Device ID e.g. 01234567891234567890
        address (str): Device Network IP Address e.g. 10.0.1.99
        local_key (str, optional): The encryption key. Defaults to None.

 Functions 
    json = status()          # returns json payload
    set_version(version)     #  3.1 [default] or 3.3
    set_dpsUsed(dpsUsed)     
    set_status(on, switch=1) # Set status of the device to 'on' or 'off' (bool)
    set_value(index, value)  # Set int value of any index.
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

These devices uses AES encryption, this is not available in Python standard library, there are three options:

 1) PyCryptodome
 2) PyCrypto
 3) pyaes (note Python 2.x support requires https://github.com/ricmoo/pyaes/pull/13)

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
