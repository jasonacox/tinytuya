# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 This network scan will run if calling this module via command line:  
    python -m tinytuya
"""
import tinytuya
import sys

retries = 0

print("TinyTuya (Tuya device scanner) [%s]\n"%(tinytuya.version))

try:
    if len(sys.argv) > 1:
        retries = int(sys.argv[1])
except:
    print("Usage: python -m tinytuya <max_retry>")
    sys.exit(2)

if retries > 0:
    tinytuya.scan(retries)
else:
    tinytuya.scan()