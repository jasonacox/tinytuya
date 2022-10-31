#!/usr/bin/env python3
"""
 TinyTuya test for Contrib

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya
"""
import tinytuya
from tinytuya import Contrib

print("TinyTuya (Contrib Import Test) [%s]\n" % tinytuya.__version__)

print("   Contrib Devices Loaded: ")
for i in Contrib.DeviceTypes:
    print("      * %s" % i)

print("   Test ThermostatDevice init(): ")
d = Contrib.ThermostatDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )

exit()
