# TinyTuya API Server

![Docker Pulls](https://img.shields.io/docker/pulls/jasonacox/tinytuya)

The TinyTuya API Server provides a central service to access all your Tuya devices on your network.  It continually listens for Tuya UDP discovery packets and updates the database of active devices. It uses `devices.json` to poll the devices for status or change their state.

**BETA**: This is under active development. Please reach out if you have suggestions or wish to contribute~

API Functions - The server listens for GET requests on local port 8888:

```
    /devices                                - List all devices discovered with metadata   
    /device/{DeviceID}                      - List specific device metadata
    /numdevices                             - List current number of devices discovered
    /status/{DeviceID}                      - List current device status
    /set/{DeviceID}/{Key}/{Value}           - Set DPS {Key} with {Value} 
    /turnon/{DeviceID}/{SwitchNo}           - Turn on device, optional {SwtichNo}
    /turnoff/{DeviceID}/{SwitchNo}          - Turn off device, optional {SwtichNo}
    /sync                                   - Fetches the device list and local keys from the Tuya Cloud API
    /cloudconfig/{apiKey}/{apiSecret}/{apiRegion}/{apiDeviceID}   - Sets the Tuya Cloud API login info
```

Docker: docker pull [jasonacox/tinytuya](https://hub.docker.com/r/jasonacox/tinytuya)

## Quick Start

1. Run the Server as a Docker Container listening on port 8888. Make sure your Tinytuya `devices.json` file is located in the directory where you start the container.

    ```bash
    docker run \
    -d \
    -p 8888:8888 \
    -p 6666:6666/udp \
    -p 6667:6667/udp \
    --mount type=bind,source="$(pwd)"/devices.json,target=/app/devices.json \
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

## Run without Docker

This folder contains the `server.py` script that runs a simple python based webserver that makes the TinyTuya API calls.  Make sure the `device.json` file is the same directory where you start the server.

```bash
python3 server.py
```

```
TinyTuya (Server) [1.5.0]

[Loaded devices.json - 34 devices]

Starting threads...
 - API and UI Endpoint on http://localhost:8888
```