# TinyTuya Module
# -*- coding: utf-8 -*-

# Globals Network Settings
MAXCOUNT = 15       # How many tries before stopping
SCANTIME = 18       # How many seconds to wait before stopping device discovery
UDPPORT = 6666      # Tuya 3.1 UDP Port
UDPPORTS = 6667     # Tuya 3.3 encrypted UDP Port
UDPPORTAPP = 7000   # Tuya app encrypted UDP Port
TCPPORT = 6668      # Tuya TCP Local Port
TIMEOUT = 3.0       # Seconds to wait for a broadcast
TCPTIMEOUT = 0.4    # Seconds to wait for socket open for scanning
DEFAULT_NETWORK = '192.168.0.0/24'

# Configuration Files
CONFIGFILE = 'tinytuya.json'
DEVICEFILE = 'devices.json'
RAWFILE = 'tuya-raw.json'
SNAPSHOTFILE = 'snapshot.json'

DEVICEFILE_SAVE_VALUES = ('category', 'product_name', 'product_id', 'biz_type', 'model', 'sub', 'icon', 'version', 'last_ip', 'uuid', 'node_id', 'sn', 'mapping')
