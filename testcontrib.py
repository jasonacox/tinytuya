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

exit()
