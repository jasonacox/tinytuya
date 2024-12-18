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
    # Example 1 -usage of community contributed device modules
    from tinytuya import Contrib

    ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '10.2.3.4', '1234567890123abc' )
    button = ir.receive_button(timeout=15)
    ir.send_button(button)
    ```

    ```python
    # Example 2 - Aubess WiFi IR Controller S16 for Sony TV - Issue #492
    from tinytuya import Contrib

    # Pull the Device Log from Tuya cloud while using Tuya Smart App and pressing PWR button on controller:
    # SONY Tuya Device Debug Log: IR send{"control":"send_ir","head":"xxxx","key1":"003xxx)","type":0,"delay":300}
    head = 'xxx'
    key1 = '003xxx'

    ir = Contrib.IRRemoteControlDevice( 'abcdefghijklmnop123456', '10.2.3.4', '1234567890123abc', persist=True )
    ir.send_key( head, key1 )

    # NOTE: If it doesn't work, try removing a leading zero from key1. Depending on what DPS set the device 
    # uses the key1 from the debug logs could have an extra 0.
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

### InverterHeatPumpDevice

* InverterHeatPumpDevice - A community-contributed Python module to add support for Tuya WiFi smart inverter heat pump
* Author: [Valentin Dusollier](https://github.com/valentindusollier)
* Tested: Fairland Inverter+ 21kW (IPHR55)

    ```python
    from tinytuya import Contrib

    device = Contrib.InverterHeatPumpDevice(dev_id="devid", address="ip", local_key="key", version="3.3")

    device.set_unit(Contrib.TemperatureUnit.CELSIUS)

    if device.get_fault() != Contrib.InverterHeatPumpFault.NOMINAL:
        print("The inverter can't work normally. Turning off...")
        device.turn_off()
        exit()

    if device.get_inlet_water_temp() < 26:
        device.set_silence_mode(True)
        device.set_target_water_temp(28)
    ```

### PresenceDetectorDevice

* PresenceDetectorDevice - A community-contributed Python module to add support for Tuya WiFi smart presence detector device
* Author: [Mario Antollini](https://github.com/mrioan)
* Tested: [MmWave Human Presence Sensor](https://www.amazon.com/gp/product/B0BZCRNY14)

    ```python
    from tinytuya.Contrib import PresenceDetectorDevice
    import time

    device_id = 'XXXX'                                                                  
    device_ip = 'YYYY'                                                                           
    local_key = 'ZZZZ'

    device = PresenceDetectorDevice.PresenceDetectorDevice(device_id, address=device_ip, local_key=local_key)

    print(" >>>> Begin Monitor Loop <<<< ")
    while(True):
        presence = device.get_presence_state()
        if (presence == 'presence'):
            print('Presence detected!')
        else:
            print('no presence, sleep...') 
        time.sleep(20)
    ```

### BlanketDevice

* BlanketDevice - A community-contributed Python module to add support for Tuya WiFi smart electric blankets
* Author: [Leo Denham](https://github.com/leodenham)
* Tested: [Goldair Platinum Electric Blanket GPFAEB-Q](https://www.target.com.au/p/goldair-platinum-electric-blanket-gpfaeb-q/8300270020_white)

  ```python
  from tinytuya.Contrib import BlanketDevice
  import time

  device = BlanketDevice.BlanketDevice(dev_id="XXXX", address="Y.Y.Y.Y", local_key="ZZZZ", version=3.3)

  device.turn_on()

  # Heat up for 20 minutes then maintain nice temperature overnight.
  device.set_body_level(6)
  time.sleep(60*20)
  device.set_body_level(2)
  device.set_body_time(12)
  ```

### ColorfulX7Device

* ColorfulX7Device - A community-contributed Python module to add support for Tuya Smart WiFi Zigbee BT 'Colorful-X7' LED Music Controller
* Author: [Ahmed Chehaibi](https://github.com/CheAhMeD)
* Tested: [Colorful-X7 mini](https://www.superlightingled.com/colorful-x7-mini-smart-wifi-addressable-rgb-led-music-controller-p-6494.html)

  ```python
    from tinytuya.Contrib import ColorfulX7Device
    import time
    
    EQUILIZER_DEVICE_ID  = 'XXXXXxx'                                                                  
    EQUILIZER_DEVICE_IP  = 'Y.Y.Y.Y'                                                                           
    EQUILIZER_DEVICE_KEY = 'ZzZzZzZ'
    
    controller = ColorfulX7Device.ColorfulX7Device(
        dev_id=EQUILIZER_DEVICE_ID, 
        address=EQUILIZER_DEVICE_IP, 
        local_key=EQUILIZER_DEVICE_KEY, 
        version="3.5")
    
    controller.switch_off()
    state = "ON" if controller.is_on() else "OFF"
    print("Colorful-X7 Status: {}".format(state))
    time.sleep(0.5)
    controller.switch_on()
    state = "ON" if controller.is_on() else "OFF"
    print("Colorful-X7 Status: {}".format(state))
    # Set up the controller for 16x16 WS2811 led matrix
    controller.set_segments_number(16)
    controller.set_leds_PerSegment(16)
    controller.set_led_brand("WS2811")
    # Loop through the dynamic modes
    controller.set_work_mode('DYNAMIC')
    for i in range(1, 180):
        controller.set_dynamic_mode(i)
        time.sleep(2)
  
  ```

### WiFiDualMeterDevice

* WiFiDualMeterDevice - A community-contributed Python module to add support for Tuya WiFi Dual Meter device
* Author: [Guillaume Gardet](https://github.com/ggardet)

```
from tinytuya.Contrib import WiFiDualMeterDevice

wdm = WiFiDualMeterDevice.WiFiDualMeterDevice(
      dev_id='YOUR_DEV_ID',
      address='192.168.XX.YY',      # Or set to 'Auto' to auto-discover IP address
      local_key='LOCAL_KEY',
      version=3.4)

# Print all known values
wdm.print_all()

# Only print Voltage and frequency
print(wdm.get_freq())
print(wdm.get_voltage())


## Submit Your Device

* We welcome new device modules!
* Follow the template example in [ThermostatDevice.py](ThermostatDevice.py) to add your device.
