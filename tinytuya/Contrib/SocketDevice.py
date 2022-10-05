# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya Socket Devices

 Author: Felix Pieschka
 For more information see https://github.com/Felix-Pi

 Local Control Classes
    SocketDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    SocketDevice:
        get_energy_consumption()
        get_current()
        get_power()
        get_get_voltage()
        get_state()
    Inherited
        json = status()                    # returns json payload
        set_version(version)               # 3.1 [default] or 3.3
        set_socketPersistent(False/True)   # False [default] or True
        set_socketNODELAY(False/True)      # False or True [default]
        set_socketRetryLimit(integer)      # retry count limit [default 5]
        set_socketTimeout(timeout)         # set connection timeout in seconds [default 5]
        set_dpsUsed(dps_to_request)        # add data points (DPS) to request
        add_dps_to_request(index)          # add data point (DPS) index set to None
        set_retry(retry=True)              # retry if response payload is truncated
        set_status(on, switch=1, nowait)   # Set status of switch to 'on' or 'off' (bool)
        set_value(index, value, nowait)    # Set int value of any index.
        heartbeat(nowait)                  # Send heartbeat to device
        updatedps(index=[1], nowait)       # Send updatedps command to device
        turn_on(switch=1, nowait)          # Turn on device / switch #
        turn_off(switch=1, nowait)         # Turn off
        set_timer(num_secs, nowait)        # Set timer for num_secs
        set_debug(toggle, color)           # Activate verbose debugging output
        set_sendWait(num_secs)             # Time to wait after sending commands before pulling response
        detect_available_dps()             # Return list of DPS available from device
        generate_payload(command, data)    # Generate TuyaMessage payload for command with data
        send(payload)                      # Send payload to device (do not wait for response)
        receive()
"""

from ..core import Device


class SocketDevice(Device):
    """
    Represents a Tuya based Socket
    """

    DPS_STATE = '1'
    DPS_CURRENT = '18'
    DPS_POWER = '19'
    DPS_VOLTAGE = '20'

    def get_energy_consumption(self):
        data = self.status()
        return {**self.get_current(data), **self.get_power(data), **self.get_voltage(data)}

    def get_current(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        current = status_data['dps'][self.DPS_CURRENT]

        return {'current_raw': current,
                'current_fmt': str(current) + ' mA', }

    def get_power(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        power = status_data['dps'][self.DPS_POWER] / 10

        return {'power_raw': power,
                'power_fmt': str(power) + ' W', }

    def get_voltage(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        voltage = status_data['dps'][self.DPS_VOLTAGE] / 10

        return {'voltage_raw': voltage,
                'voltage_fmt': str(voltage) + ' V'}

    def get_state(self):
        return {'on': self.status()['dps'][self.DPS_STATE]}
