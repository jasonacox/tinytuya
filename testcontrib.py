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
d = Contrib.ThermostatDevice("abcdefghijklmnop123456", "172.28.321.475", "1234567890123abc")

import time
import os

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ModuleNotFoundError:
    pass # dotenv not installed, ignore

IHP_DEVICEID = os.getenv("IHP_DEVICEID", None)
IHP_DEVICEIP = os.getenv("IHP_DEVICEIP", None)
IHP_DEVICEKEY = os.getenv("IHP_DEVICEKEY", None)
IHP_DEVICEVERS = os.getenv("IHP_DEVICEVERS", None)

if IHP_DEVICEID and IHP_DEVICEIP and IHP_DEVICEKEY and IHP_DEVICEVERS:
    print("   Test InverterHeatPumpDevice: ")
    print("      * Device ID: %s" % IHP_DEVICEID)
    print("      * Device IP: %s" % IHP_DEVICEIP)
    print("      * Device Key: %s" % IHP_DEVICEKEY)
    print("      * Device Version: %s" % IHP_DEVICEVERS)
    print()

    device = Contrib.InverterHeatPumpDevice(
        dev_id=IHP_DEVICEID, address=IHP_DEVICEIP, local_key=IHP_DEVICEKEY, version=IHP_DEVICEVERS
    )

    is_on = device.is_on()
    unit = device.get_unit()
    target_water_temp = device.get_target_water_temp()
    lower_limit_target_water_temp = device.get_lower_limit_target_water_temp()
    is_silence_mode = device.is_silence_mode()

    print("      * is_on(): %r" % is_on)
    print("      * get_unit(): %r" % unit)
    print("      * get_inlet_water_temp(): %r" % device.get_inlet_water_temp())
    print("      * get_target_water_temp(): %r" % target_water_temp)
    print("      * get_lower_limit_target_water_temp(): %r" % lower_limit_target_water_temp)
    print("      * get_upper_limit_target_water_temp(): %r" % device.get_upper_limit_target_water_temp())
    print("      * get_heating_capacity_percent(): %r" % device.get_heating_capacity_percent())
    print("      * get_mode(): %r" % device.get_mode())
    print("      * get_mode(raw=True): %r" % device.get_mode(raw=True))
    print("      * get_fault(): %r" % device.get_fault())
    print("      * get_fault(raw=True): %r" % device.get_fault(raw=True))
    print("      * is_silence_mode(): %r" % is_silence_mode)

    time.sleep(10)

    print("    Toggle ON/OFF")
    for power_state in [not is_on, is_on]:
        print("      * Turning %s" % ("ON" if power_state else "OFF"))
        device.turn_on() if power_state else device.turn_off()
        time.sleep(5)
        print("      * is_on(): %r" % device.is_on())
        time.sleep(10)
    
    print("    Toggle unit")
    for unit_value in [not unit.value, unit.value]:
        print("      * Setting unit to %r" % Contrib.TemperatureUnit(unit_value))
        device.set_unit(Contrib.TemperatureUnit(unit_value))
        time.sleep(5)
        print("      * get_unit(): %r" % device.get_unit())
        time.sleep(5)
    
    print("    Set target water temperature to lower limit and previous value")
    for target_water_temp_value in [lower_limit_target_water_temp, target_water_temp]:
        print("      * Setting target water temperature to %r" % target_water_temp_value)
        device.set_target_water_temp(target_water_temp_value)
        time.sleep(5)
        print("      * get_target_water_temp(): %r" % device.get_target_water_temp())
        time.sleep(5)
    
    print("    Toggle silence mode")
    for silence_mode in [not is_silence_mode, is_silence_mode]:
        print("      * Setting silence mode to %r" % silence_mode)
        device.set_silence_mode(silence_mode)
        time.sleep(5)
        print("      * is_silence_mode(): %r" % device.is_silence_mode())
        time.sleep(5)

exit()
