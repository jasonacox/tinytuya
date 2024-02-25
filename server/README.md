# TinyTuya API Server

![Docker Pulls](https://img.shields.io/docker/pulls/jasonacox/tinytuya)

The TinyTuya API Server provides a central service to access all your Tuya devices on your network.  It continually listens for Tuya UDP discovery packets and updates the database of active devices. It uses `devices.json` to poll the devices for status or change their state.

**BETA**: This is under active development. Please reach out if you have suggestions or wish to contribute~

API Functions - The server listens for GET requests on local port 8888:

```
    /help                                      - List all available commands
    /devices                                   - List all devices discovered with metadata   
    /device/{DeviceID}|{DeviceName}            - List specific device metadata
    /numdevices                                - List current number of devices discovered
    /status/{DeviceID}|{DeviceName}            - List current device status
    /set/{DeviceID}|{DeviceName}/{Key}/{Value} - Set DPS {Key} with {Value} 
    /turnon/{DeviceID}/{SwitchNo}              - Turn on device, optional {SwtichNo}
    /turnoff/{DeviceID}/{SwitchNo}             - Turn off device, optional {SwtichNo}
    /delayedoff/{DeviceID}|{DeviceName}/{SwitchNo}/{Seconds} 
                                               - Turn off device with a delay, optional {SwitchNo}/{Delay}
    /sync                                      - Fetches the device list and local keys from the Tuya Cloud API
    /cloudconfig/{apiKey}/{apiSecret}/{apiRegion}/{apiDeviceID}   
                                               - Sets the Tuya Cloud API login info
    /offline                                   - List of registered devices that are offline
```

Note! If you use {DeviceName} instead of {DeviceID}, make sure your Device Names are absolutely unique! Otherwise you will get funny results.

## Quick Start

This folder contains the `server.py` script that runs a simple python based webserver that makes the TinyTuya API calls.  Make sure the `device.json` file is the same directory where you start the server.

```bash
# Start Server - use Control-C to Stop
python3 server.py

# Start Server in Debug Mode
python3 server.py -d
```

```
TinyTuya (Server) [1.10.0t4]

[Loaded devices.json - 39 devices]

Starting threads...
 - API and UI Endpoint on http://localhost:8888
```

## Docker Container

1. Run the Server as a Docker Container listening on port 8888. Make sure your Tinytuya `devices.json` file is located in the directory where you start the container.

    ```bash
    docker run \
    -d \
    -p 8888:8888 \
    -p 6666:6666/udp \
    -p 6667:6667/udp \
    -e DEBUG='no' \
    --mount type=bind,source="$(pwd)"/devices.json,target=/app/devices.json \
    --mount type=bind,source="$(pwd)"/tinytuya.json,target=/app/tinytuya.json \
    --name tinytuya \
    --restart unless-stopped \
    jasonacox/tinytuya
    ```

2. Test the Server

You can load the Web Interface to view all your devices: http://localhost:8888/

Additionally you can use the API server to poll or mange your Tuya devices with simple web service calls:

```bash
# Get Tuya Device Information
curl -i http://localhost:8888/numdevices
curl -i http://localhost:8888/devices
curl -i http://localhost:8888/device/{deviceID}
curl -i http://localhost:8888/status/{deviceID}

# Command Tuya Devices
curl -i http://localhost:8888/turnon/{deviceID}
curl -i http://localhost:8888/turnoff/{deviceID}
curl -i http://localhost:8888/set/{deviceID}/{key}/{value}
```

### Troubleshooting Help

Check the logs. If you see python errors, make sure you entered your credentials correctly in the `server.py` file.  If you didn't, edit that file and restart docker:

```bash
# See the logs
docker logs tinytuya

# Stop the server
docker stop tinytuya

# Start the server
docker start tinytuya
```

## Control Panel

The UI at http://localhost:8888 allows you to view and control the devices.

![image](https://user-images.githubusercontent.com/836718/227736045-adb6e359-c0c1-44b9-b9ad-7e978f6b7b84.png)

![image](https://user-images.githubusercontent.com/836718/227736057-e5392c13-554f-457e-9082-43c4d41a98ed.png)

## Release Notes

### t10 - Remove Import

* Remove unused imports for Crypto.

### t9 - DeviceName Addition

* Use {DeviceName} instead of {DeviceID} alternatively for API commands

### t8 - Mappings

* Mapping for DP IDs in https://github.com/jasonacox/tinytuya/pull/353.

### t7 - Add Control by Name

* Use {`DeviceName`} in addition to {`DeviceID`} for API commands by @mschlenstedt in https://github.com/jasonacox/tinytuya/pull/352

```bash
# by DeviceID
$ curl http://localhost:8888/status/xxxxxxxxxxxxxxxxxx01
{"devId": "xxxxxxxxxxxxxxxxxx01", "dps": {"1": true, "9": 0}}

# by DeviceName
$ curl http://localhost:8888/status/Kitchen%20Light
{"devId": "xxxxxxxxxxxxxxxxxx01", "dps": {"1": true, "9": 0}}
$ curl http://localhost:8888/status/SmartBulb                                
{"devId": "xxxxxxxxxxxxxxxxxx02", "dps": {"20": true, "21": "white", "22": 1000, "24": "000003e803e8", "25":"07464602000003e803e800000000464602007803e803e80000000046460200f003e803e800000000464602003d03e803e80000000046460200ae03e803e800000000464602011303e803e800000000", "26": 0}}
```
