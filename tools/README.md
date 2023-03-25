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

### Example Usage

The following example captures LAN traffic using `tcpdump` and parses the output.

```bash
# Capture local traffic - use control-C to end capture
sudo tcpdump -i en0 -w trace.pcap   
^C

# Parse pcap file - make sure to specify location of devices.json
python3 pcap_parse.py -d ../devices.json trace.pcap

# Display output sorted
python3 pcap_parse.py -s -d ../devices.json trace.pcap | sort
```
