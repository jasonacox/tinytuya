# TinyTuya Module
# -*- coding: utf-8 -*-

"""
Global Network and File Settings
"""

MAXCOUNT = 15       #: How many tries before stopping
SCANTIME = 18       #: How many seconds to wait before stopping device discovery
UDPKEY = bytes.fromhex('6c1ec8e2bb9bb59ab50b0daf649b410a') #: UDP packet payload decryption - md5("yGAdlopoPVldABfn") - credit to tuya-convert
UDPPORT = 6666      #: Tuya 3.1 UDP Port
UDPPORTS = 6667     #: Tuya 3.3 encrypted UDP Port
UDPPORTAPP = 7000   #: Tuya app encrypted UDP Port
TCPPORT = 6668      #: Tuya TCP Local Port
TIMEOUT = 3.0       #: Seconds to wait for a broadcast
TCPTIMEOUT = 0.4    #: Seconds to wait for socket open for scanning
DEFAULT_NETWORK = '192.168.0.0/24' #: Default IP network to scan when force scanning

# Configuration Files
CONFIGFILE = 'tinytuya.json' #: File to save/load Cloud configuration from
DEVICEFILE = 'devices.json'  #: File to save/load device list from
RAWFILE = 'tuya-raw.json'    #: File to
SNAPSHOTFILE = 'snapshot.json' #: File to save device snapshots to

#: List of additional device properties to save in device list file
DEVICEFILE_SAVE_VALUES = ('category', 'product_name', 'product_id', 'biz_type', 'model', 'sub', 'icon', 'version', 'last_ip', 'uuid', 'node_id', 'sn', 'mapping')
