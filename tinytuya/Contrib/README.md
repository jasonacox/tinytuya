# User Contributed Device Modules

[![Contrib Test](https://github.com/jasonacox/tinytuya/actions/workflows/contrib.yml/badge.svg)](https://github.com/jasonacox/tinytuya/actions/workflows/contrib.yml)

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

### SocketDevice

* SocketDevice - A community-contributed Python module to add support for Tuya WiFi smart sockets
* Author: [Felix Pieschka](https://github.com/Felix-Pi)

    ```python
    # Example usage of community contributed device modules
    from tinytuya.Contrib import SocketDevice

    socket = SocketDevice('abcdefghijklmnop123456', '172.28.321.475', '', version=3.3)
    
    print(socket.get_energy_consumption())
    print(socket.get_state())
    ```

### DoorbellDevice

* DoorbellDevice - A community-contributed Python module to add support for Tuya WiFi doorbells.
* Author: [JonesMeUp](https://github.com/jonesMeUp)
* Note: Most doorbells will not stay online (to preserve battery) so controlling them locally is difficult.

    ```python
    import tinytuya
    from tinytuya.Contrib import DoorbellDevice

    d = DoorbellDevice('abcdefghijklmnop123456', '192.168.178.25', 
        '1234567890123abc', 'device22')
    d.set_version(3.3)
    d.set_socketPersistent(True) # Keep socket connection open between commands

    d.set_volume(3)
    d.set_motion_area(0, 5, 50, 50)
    d.set_motion_area_switch(True)

    print(" > Begin Monitor Loop <")
    while(True):
        # See if any data is available
        data = d.receive()
        print('Data: %r' % data)
        # Send keyalive heartbeat
        print(" > Send Heartbeat Ping < ")
        payload = d.generate_payload(tinytuya.HEART_BEAT)
        d.send(payload)
    ```

### ClimateDevice

* ClimateDevice - A community-contributed Python module to add support for Tuya WiFi portable air conditioners
* Author: [Frédéric Chardon](https://github.com/fr3dz10)

    ```python
    # Example usage of community contributed device modules
    # turn on cooling for up to 2 hours if room temperature is too high
    from tinytuya.Contrib import ClimateDevice

    d = ClimateDevice('tuya_id', '1.2.3.4', 'local_key')

    if d.get_room_temperature() > 22:
        d.set_operating_mode("cold")
        d.set_target_temperature(20)
        d.turn_on()
        d.set_timer(2)
    ```

## Submit Your Device

* We welcome new device modules!
* Follow the template example in [ThermostatDevice.py](ThermostatDevice.py) to add your device.
* Add your module to the [__init__.py](__init__.py) file.
