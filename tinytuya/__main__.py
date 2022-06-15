# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Run TinyTuya Setup Wizard:
    python -m tinytuya wizard
 This network scan will run if calling this module via command line:
    python -m tinytuya <max_retry>

"""

# Modules
import sys
import tinytuya
from . import wizard
from . import scanner

retries = tinytuya.MAXCOUNT
state = 0
color = True
retriesprovided = False
force = False

for i in sys.argv:
    if i==sys.argv[0]:
        continue
    if i.lower() == "wizard":
        state = 1
    elif i.lower() == "scan":
        state = 0
    elif i.lower() == "-nocolor":
        color = False
    elif i.lower() == "-force":
        force = True
    elif i.lower() == "snapshot":
        state = 2
    elif i.lower() == "devices":
        state = 3
    elif i.lower() == "json":
        state = 4
    else:
        try:
            retries = int(i)
            retriesprovided = True
        except:
            state = 10

# State 0 = Run Network Scan
if state == 0:
    if retriesprovided:
        scanner.scan(maxretry=retries, color=color, forcescan=force)
    else:
        scanner.scan(color=color, forcescan=force)

# State 1 = Run Setup Wizard
if state == 1:
    if retriesprovided:
        wizard.wizard(color=color, retries=retries, forcescan=force)
    else:
        wizard.wizard(color=color, forcescan=force)

# State 2 = Snapshot Display and Scan
if state == 2:
    scanner.snapshot(color=color)

# State 3 = Scan All Devices
if state == 3:
    if retriesprovided:
        scanner.alldevices(color=color, retries=retries)
    else:
        scanner.alldevices(color=color)

# State 4 = Scan All Devices
if state == 4:
    scanner.snapshotjson()

# State 10 = Show Usage
if state == 10:
    print("TinyTuya [%s]\n" % (tinytuya.version))
    print("Usage:\n")
    print("    python -m tinytuya [command] [<max_retry>] [-nocolor] [-h]")
    print("")
    print("      wizard         Launch Setup Wizard to get Tuya Local KEYs.")
    print("      scan           Scan local network for Tuya devices.")
    print("      devices        Scan all devices listed in devices.json file.")
    print("      snapshot       Scan devices listed in snapshot.json file.")
    print("      json           Scan devices listed in snapshot.json file [JSON].")
    print("      <max_retry>    Maximum number of retries to find Tuya devices [Default=15]")
    print("      -nocolor       Disable color text output.")
    print("      -force         Force network scan for device IP addresses.")
    print("      -h             Show usage.")
    print("")

# End
