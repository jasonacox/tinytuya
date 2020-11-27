RELEASE NOTES

# v1.1.0 - Setup Wizard

* PyPi Version 1.1.0
* Added TinyTuya Setup Wizard to help users grab device *LOCAL_KEY* from the Tuya Platform.
* Added formatted terminal color output (optionally disabled with `-nocolor`) for interactive **Wizard** and **Scan** functions.

```python
python3 -m tinytuya wizard
```

# v1.0.5 - Persistent Socket Connections

* PyPi Version 1.0.5
* Updated cipher json payload to mirror TuyAPI - hexdigest from `[8:][:16]` to `[8:][:24]`
* Added optional persistent socket connection, NODELAY and configurable retry limit (@elfman03) #5 #6 #7
```python
    set_socketPersistent(False/True)   # False [default] or True
    set_socketNODELAY(False/True)      # False or True [default]	    
    set_socketRetryLimit(integer)      # retry count limit [default 5]
```
* Add some "scenes" supported by color bulbs (@elfman03) 
```python
    set_scene(scene):             # 1=nature, 3=rave, 4=rainbow
```

# v1.0.4 - Network Scanner

* PyPi Version 1.0.4
* Added `scan()` function to get a list of Tuya devices on your network along with their device IP, ID and VERSION number (3.1 or 3.3):
```
python3 -m tinytuya
```

# v1.0.3 - Device22 Fix

* PyPi Version 1.0.3
* Removed automatic device22 type selection.  The assumption that 22 character ID meant it needed dev_type device22 was discovered to be incorrect and there are Tuya devices with 22 character ID's that behave similar to default devices.  Device22 type is now available via a dev_type specification on initialization:
```
    OutletDevice(dev_id, address, local_key=None, dev_type='default')
    CoverDevice(dev_id, address, local_key=None, dev_type='default')
    BulbDevice(dev_id, address, local_key=None, dev_type='default')
```
* Added Tuya Command Types framework to definitions and payload dictionary per device type.
* Bug fixes (1.0.2):
    * Update SET to CONTROL command
    * Fixed BulbDevice() `__init__`

# v1.0.0 - Initial Release

* PyPi Version 1.0.0