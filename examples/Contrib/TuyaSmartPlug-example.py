# TinyTuya Smart Plug 1-Pack Example
# -*- coding: utf-8 -*-
"""
 Example script using the tinytuya Python module for Tuya Smart Plug 1-Pack
 and stores data in mysql database.

 Author: fajarmnrozaki (https://github.com/fajarmnrozaki)
 For more information see https://github.com/jasonacox/tinytuya
"""

# Import library
import datetime
import tinytuya # code packet for communication between Tuya devices
import time # RTC Real Time Clock
import pymysql # library for sql

# Specifications of Network scanner (the device Tuya must be turned "ON")
Device_Id = 'xxxxxxxxxxxxxxxxxx' # Device Id from Tuya device sensor
Address_Id = 'x.x.x.x' # IP Address connected to Tuya device sensor
Local_Key = 'xxxxxxxxxxxxxxxx' # Local Key generated from  python -m tinytuya wizard
Version = 3.3 #Version of Tuya protocol used

# Checking the connection "Tuya device - sensor"
try:
    smartplug = tinytuya.OutletDevice(Device_Id, Address_Id, Local_Key)
    smartplug.set_version(Version)
    print("Connected to Tuya device sensor")
except:
    print("Disconnected to Tuya device sensor")
    smartplug.close()

# Monitoring a Tuya Smart Plug Device Sensor 
while True:
    try:
        # Time
        timer = datetime.datetime.now()
        print("Time               :",timer.strftime("%Y-%m-%d %H:%M:%S"))
        # Get Status of Tuya device sensor
        data = smartplug.status()
        print("set_status() result", data)
        # Voltage # DPS (Data Points)
        print("Voltage            :", (data['dps']['20'])/10,"Voltage")
        # Current # DPS (Data Points)
        print("Current            :", (data['dps']['18'])/1000,"Ampere")
        # Power # DPS (Data Points)
        print("Power              :", (data['dps']['19'])/10,"Watt")
        print('')

        # Turn On
        smartplug.turn_on()

        # Database Connection
        # in thise example, the data is sent to RDS (Relational Database Service) MySQL
        # Change the [host],[user],[password], [db] and [querry] with your own version

        db = pymysql.connect(host='***',
                             user='***',
                             password='***',
                             db='****',
                             charset='utf8',
                             cursorclass=pymysql.cursors.DictCursor)
        cur = db.cursor()

        add_c0 = "INSERT INTO `tuya_smart_plug`(time, voltage, current, power) VALUES (%s,%s,%s,%s)"
        cur.execute(add_c0,((timer.strftime("%Y-%m-%d %H:%M:%S"),
                             (data['dps']['20'])/10,
                             (data['dps']['18'])/1000,
                             (data['dps']['19'])/10)))
        db.commit()

        time.sleep(60) # this python script example is set for monitoring a Tuya Smart Plug Device Sensor every 60 seconds

    except:
        print("============")
        print("Disconnected")
        print("============")
        # time.sleep(0)
        pass
