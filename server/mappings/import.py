# -*- coding: utf-8 -*-

"""
TinyTuya Tool to Import DPS mappings from other projects and create mappings file

Author: Michael Schlenstedt
Date: May 23, 2023
For more information see https://github.com/jasonacox/tinytuya
"""

import json
import urllib.request

print ("Importing...")

# From fhempy project: 
url = "https://raw.githubusercontent.com/fhempy/fhempy/master/FHEM/bindings/python/fhempy/lib/tuya/mappings.py"
urllib.request.urlretrieve(url, "schema_fhem.py")

from schema_fhem import knownSchemas
fhemschemata = dict()

for pid in knownSchemas:
    list = []
    for x in knownSchemas[pid]['schema']:
        if 'id' in x:
            list.append({'id': x['id'], 'code': x['code']})
    fhemschemata[pid] = list

# From IO Broker project: 
url = "https://raw.githubusercontent.com/Apollon77/ioBroker.tuya/master/lib/schema.json"
urllib.request.urlretrieve(url, "schema_iobroker.json")

f = open('schema_iobroker.json')
data = json.load(f)
ioschemata = dict()

for pid in data:
    schema = json.loads(data[pid]['schema'])
    list = []
    for x in schema:
        if 'id' in x:
            list.append({'id': x['id'], 'code': x['code']})
    ioschemata[pid] = list

# Compine - Sequence: TinyTuya -> IOBroker -> FHEM
tt=0
io=0
fhem=0

# TinyTuya
f = open('mappings.json')
schemata = json.load(f)
for i in schemata:
    tt += 1

# IO Broker
for pid in ioschemata:
    if pid not in schemata:
        io += 1
        schemata[pid] = ioschemata[pid]

# FHEM Broker
for pid in fhemschemata:
    if pid not in schemata:
        fhem += 1
        schemata[pid] = fhemschemata[pid]

print ("TinyTuya Mappings:             " + str(tt))
print ("Newly included from IO Broker: " + str(io))
print ("Newly included from FHEM:      " + str(fhem))

# intend=4 or intend=None are other options
with open('mappings_new.json', 'w') as fp:
    json.dump(schemata, fp, indent=4)
