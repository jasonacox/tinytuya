# User Contributed Device Modules

In addition to the built-in `OutletDevice`, `BulbDevice` and `CoverDevice` device support, the community is encourage to submit additional device modules which are available here.

## Devices

### ThermostatDevice

*  ThermostatDevice - A community-contributed Python module to add support for Tuya WiFi smart thermostats
* Author: [uzlonewolf](https://github.com/uzlonewolf)
* Example: [examples/ThermostatDevice-example.py](https://github.com/jasonacox/tinytuya/blob/master/examples/Contrib/ThermostatDevice-example.py)

    ```python
    # Example usage of community contributed device modules
    from tinytuya import Contrib

    thermo = Contrib.ThermostatDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )
    ```

### IRRemoteControlDevice

* IRRemoteControlDevice - A community-contributed Python module to add support for Tuya WiFi smart universal remote control simulators
* Author: [Alexey 'Cluster' Avdyukhin](https://github.com/clusterm)
* Example: [examples/IRRemoteControlDevice-example.py](https://github.com/jasonacox/tinytuya/blob/master/examples/Contrib/IRRemoteControlDevice-example.py)

    ```python
    # Example usage of community contributed device modules
    from tinytuya import Contrib

    ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc' )
    button = ir.receive_button(timeout=15)
    ir.send_button(button)
    ```

## Submit Your Device

* We welcome new device modules!
* Follow the template example in [ThermostatDevice.py](ThermostatDevice.py) to add your device.
* Add your module to the [__init__.py](__init__.py) file.
