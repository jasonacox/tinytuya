# TinyTuya Tools

## Packet Capture Parser

A program to read *.pcap files and decrypt the Tuya device traffic.  It requires the dpkt module for PCAP parsing.

Written by uzlonewolf (https://github.com/uzlonewolf)

### Setup

```bash
# Install required python modules
pip install dpkt

# Test and display Help
python3 pcap_parse.py -h
```

### Usage

```
usage: pcap_parse.py [-h] [-z] [-s] -d devices.json INFILE.pcap [INFILE.pcap ...]

Reads PCAP files created by tcpdump and prints the traffic to/from Tuya devices. Local keys 
are loaded from devices.json.

positional arguments:
  INFILE.pcap           Input file(s) to parse

options:
  -h, --help            show this help message and exit
  -z, --hide-zero-len   Hide 0-length heartbeat packets
  -s, --sortable        Output data in a way which is sortable by device ID
  -d devices.json,      devices.json file to read local keys from
```

### Example Usage

```bash
# Capture local traffic - use control-C to end capture
sudo tcpdump -i en0 -w trace.pcap   
^C

# Parse pcap file - make sure to specify location of devices.json
python3 pcap_parse.py -d ../devices.json trace.pcap

# Display output sorted
python3 pcap_parse.py -s -d ../devices.json trace.pcap | sort
```
