# TinyTuya API Server

![Docker Pulls](https://img.shields.io/docker/pulls/jasonacox/tinytuya)

This TinyTuya API Server provides a central service to access all your Tuya devices on your network.  It continually listens for Tuya UDP discovery packets and updates the database of active devices and uses `devices.json` to poll the devices for state or change state.

API Functions - The server listens for GET requests on local port 8888:
    /devices                                - List all devices discovered with metadata   
    /device/{DeviceID}                      - List specific device metadata
    /numdevices                             - List current number of devices discovered
    /status/{DeviceID}                      - List current device status
    /set/{DeviceID}/{Key}/{Value}           - Set DPS {Key} with {Value} 
    /turnon/{DeviceID}/{SwitchNo}           - Turn on device, optional {SwtichNo}
    /turnoff/{DeviceID}/{SwitchNo}          - Turn off device, optional {SwtichNo}

Docker: docker pull [jasonacox/tinytuya](https://hub.docker.com/r/jasonacox/tinytuya)

## Quick Start

1. Run the Docker Container to listen on port 8675. Update the `-e` values for your Powerwall.

    ```bash
    docker run \
    -d \
    -p 8888:8888 \
    --name tinytuya \
    --restart unless-stopped \
    jasonacox/tinytuya
    ```

2. Test the Proxy

    ```bash
    # Get Tuya Device List
    curl -i http://localhost:8888/numdevices
    curl -i http://localhost:8888/devices
    ```

## Build Your Own

This folder contains the `server.py` script that runs a simple python based webserver that makes the TinyTuya API calls.  

The `Dockerfile` here will allow you to containerize the proxy server for clean installation and running.

1. Build the Docker Container

    ```bash
    # Build for local architecture  
    docker build -t tinytuya:latest .

    # Build for all architectures - requires Docker experimental 
    docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t tinytuya:latest . 

    ```

2. Setup the Docker Container to listen on port 8888.

    ```bash
    docker run \
    -d \
    -p 8888:8888 \
    --name tinytuya \
    --restart unless-stopped \
    tinytuya
    ```

3. Test the Proxy

    ```bash
    curl -i http://localhost:8888/numdevices
    curl -i http://localhost:8888/devices
    ```

    Browse to http://localhost:8888/ to see TinyTuya web interface.

## Troubleshooting Help

Check the logs. If you see python errors, make sure you entered your credentials correctly in the `server.py` file.  If you didn't, edit that file and restart docker:

```bash
# See the logs
docker logs tinytuya

# Stop the server
docker stop tinytuya

# Start the server
docker start tinytuya
```
