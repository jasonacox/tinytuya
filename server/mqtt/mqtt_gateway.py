# TinyTuya MQTT Gateway
# -*- coding: utf-8 -*-
"""
TinyTuya MQTT Gateway for API Server for Tuya based WiFi smart devices

Author: @mschlenstedt
Date: June 11, 2023
For more information see https://github.com/jasonacox/tinytuya

Description

"""

# Modules
import paho.mqtt.client as mqtt
import time
import logging
import json
try:
    import requests
except ImportError as impErr:
    print("WARN: Unable to import requests library, Cloud functions will not work.")
    print("WARN: Check dependencies. See https://github.com/jasonacox/tinytuya/issues/377")
    print("WARN: Error: {}.".format(impErr.args[0]))
import sys
import os
import copy
import concurrent.futures
import threading
from queue import Queue

BUILD = "t2"

# Defaults
DEBUGMODE = False
POLLINGTIME = 5
TOPIC = "tinytuya"
BROKER = "localhost"
BROKERPORT = "1883"
APIPORT = 8888

# Check for Environmental Overrides
debugmode = os.getenv("DEBUG", "no")
if debugmode.lower() == "yes":
    DEBUGMODE = True

# Logging
log = logging.getLogger(__name__)
if len(sys.argv) > 1 and sys.argv[1].startswith("-d"):
    DEBUGMODE = True
if DEBUGMODE:
    logging.basicConfig(
        format="\x1b[31;1m%(levelname)s [%(asctime)s]:%(message)s\x1b[0m", level=logging.DEBUG,
        datefmt='%d/%b/%y %H:%M:%S'
    )
    log.setLevel(logging.DEBUG)
    log.debug("TinyTuya (MQTT Gateway) [%s]", BUILD)
    print("\nTinyTuya (MQTT Gateway) [%s]\n" % BUILD)

# Global Variables
running = True
q=Queue()
mqttconfig = {}
last = 0
devices = {}

# Helpful Functions

def on_connect(client, userdata, flags, rc):
    if rc==0:
        client.connected_flag=True #set flag
        log.debug("Connected OK")
        try:
            client.publish(mqttconfig['topic'] + "/running", str("1"), retain=1)
        except:
            log.debug("Cannot set topic %s", mqttconfig['topic'] + "/running")
    else:
        log.debug("Bad connection, Returned code %s", rc)

def on_message(client, userdata, message):
    q.put(message)

def readconfig():
    config = {}
    try:
        with open('mqtt.json') as f:
            config = json.load(f)
    except:
        print("Cannot read mqtt config - using defaults.")
        log.debug("Cannot read mqtt config - using defaults.")
    if 'topic' not in config:
        config['topic'] = TOPIC
    if 'broker' not in config:
        config['broker'] = BROKER
    if 'port' not in config:
        config['port'] = BROKERPORT
    if 'pollingtime' not in config:
        config['pollingtime'] = POLLINGTIME
    log.debug("Config %s", config)
    return (config)

def getdevices():
    data = {}
    try:
        url = "http://localhost:" + str(APIPORT) + "/devices"
        with requests.get(url) as response:
            response.raise_for_status()
            data = response.json()
    except:
        log.debug("Cannot get devices list from server")
        data = {}
    return(data)

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session

def get_status(id):
    session = get_session()
    try:
        url = "http://localhost:" + str(APIPORT) + "/status/" + id
        with session.get(url) as response:
            response.raise_for_status()
            data = response.json()
        status_raw = data['dps']
        status = copy.deepcopy(status_raw)
        if 'dps_mapping' in data:
            mapping = data['dps_mapping']
            keysList = list(status_raw.keys())
            for i in keysList:
                newname = ""
                for j in mapping:
                    if str(j) == str(i):
                        newname = mapping[j]['code']
                        break
                if newname != "":
                    status[newname] = status.pop(i)
        client.publish(mqttconfig['topic'] + "/" + id + "/status_raw", json.dumps(status_raw), retain=1)
        client.publish(mqttconfig['topic'] + "/" + id + "/status", json.dumps(status), retain=1)
        client.publish(mqttconfig['topic'] + "/" + id + "/last", str(int(time.time())), retain=1)
        for d in devices:
            if str(devices[d]['id']) == str(id):
                client.publish(mqttconfig['topic'] + "/" + id + "/device", json.dumps(devices[d]), retain=1)
                break
    except:
        log.debug("Cannot read status for device %s", str(id))

def get_status_all(sdevices):
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(get_status, sdevices)

def set_dps(url):
    try:
        url = "http://localhost:" + str(APIPORT) + "/set/" + url
        with requests.get(url) as response:
            response.raise_for_status()
            data = response.json()
    except:
        log.debug("Cannot read set dps %s", str(url))

# Main

if __name__ == "__main__":

    mqttconfig = readconfig()

    # Conncect to broker
    client = mqtt.Client()
    client.will_set(mqttconfig['topic'] + "/running", str("0"), 0, True)
    client.connected_flag=False
    client.on_connect = on_connect
    if 'username' in mqttconfig and 'password' in mqttconfig:
        if mqttconfig['username'] != "" and mqttconfig['password'] != "":
            client.username_pw_set(username = mqttconfig['username'],password = mqttconfig['password'])
    log.debug("Connecting to Broker %s on port %s." % (mqttconfig['broker'], str(mqttconfig['port'])))
    client.connect(mqttconfig['broker'], port = int(mqttconfig['port']))

    # Subscribe to the set topic
    stopic =  mqttconfig['topic'] + "/set/#"
    client.subscribe(stopic, qos=0)
    client.on_message = on_message
    client.loop_start()

    # Wait for MQTT connection
    counter=0
    while not client.connected_flag: #wait in loop
        time.sleep(1)
        counter+=1
        if counter > 60:
            print("Cannot connect to Broker %s on port %s." % (mqttconfig['broker'], str(mqttconfig['port'])))
            log.debug("Cannot connect to Broker %s on port %s." % (mqttconfig['broker'], str(mqttconfig['port'])))
            sys.exit(2)

    # Loop
    thread_local = threading.local()
    last = 0
    while(True):
        now = time.time()
        # Check for any subscribed messages in the queue
        while not q.empty():
            message = q.get()
            if message is None or str(message.payload.decode("utf-8")) == "":
                continue
            log.debug("Received: %s at topic %s" % ( str(message.payload.decode("utf-8")), str(message.topic) ))
            id, dpsKey = str(message.topic).replace(mqttconfig['topic'] + "/set/", "").split("/", 1)
            set_dps( str(message.topic).replace(mqttconfig['topic'] + "/set/", "") + "/" + str(message.payload.decode("utf-8")) )
            time.sleep(0.5)
            get_status(id)
        # Get status
        if last + int(mqttconfig['pollingtime']) < now:
            last = time.time()
            devices = getdevices()
            get_status_all(devices)
        # Slow down
        time.sleep(0.1)
