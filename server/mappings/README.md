# TinyTuya API Server: DPS Mappings

The file 'mappings.json' includes mappings between DPS (Datapoint IDs) and Codes
(Names). There's a Quick'n'Dirty import script to get new mappings from two
great projects:

- https://github.com/Apollon77/ioBroker.tuya
- https://github.com/fhempy/fhempy/blob/master/FHEM/bindings/python/fhempy/lib/tuya/README.md

Most of the mappings are fromn these two projects. If you would like to add mappings from an
so far unknown device, figure out the Codes from the Tuya Cloud and add the mappings
manually: https://eu.iot.tuya.com/cloud/explorer
