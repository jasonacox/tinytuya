# TinyTuya Tools

## Packet Capture Parser

A program to read *.pcap files and decrypt the Tuya device traffic.  It requires the dpkt module for PCAP parsing.

Written by uzlonewolf (https://github.com/uzlonewolf)

### Usage

```bash
# Install required python modules
pip install dpkt

# Help
python3 pcap_parse.py -d

# Parse pcap file
python3 pcap_parse.py -d ../devices.json INFILE.pcap

# Sorted output option
python3 pcap_parse.py -s -d ../devices.json INFILE.pcap | sort
```
