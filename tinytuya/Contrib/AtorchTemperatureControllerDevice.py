# TinyTuya Outlet Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya ATORCH-Temperature Controller (S1TW)

 Author: Benjamin DUPUIS
 For more information see https://github.com/poil

 Local Control Classes
    AtorchTemperatureController(...)
        See OutletDevice() for constructor arguments

 Functions
    AtorchTemperatureControllerDevice:
        get_energy_consumption()
        get_current()
        get_power()
        get_get_voltage()
        get_state()
        get_temp()
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


class AtorchTemperatureControllerDevice(Device):
    """
    Represents a Tuya based Socket
    """

    DPS_MODE = '101'
    DPS_CUR_TEMP = '102'
    DPS_SWITCH_STATE = '103'
    DPS_CURRENT = '108'
    DPS_POWER = '109'
    DPS_VOLTAGE = '110'
    DPS_TEMP_UNIT = '118'
    DPS_TOTAL_POWER = '111' # kwh
    # TODO
    # DPS_HEATING_START_TEMP = 104
    # DPS_COOLING_START_TEMP = 105
    # DPS_HEATING_STOP_TEMP = 106
    # DPS_COOLING_STOP_TEMP = 107
    # DPS_POWER_COST = 112
    # DPS_OVER_VOLTAGE_LIMIT = 113
    # DPS_OVER_INTENSITY_LIMIT = 114
    # DPS_OVER_POWER_LIMIT = 115
    # DPS_CHILD_LOCK = 116 # bool
    # DPS_TEMP_CALIBRATION = 117
    # DPS_CURRENT_COST = 125

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

        power = status_data['dps'][self.DPS_POWER] / 100

        return {'power_raw': power,
                'power_fmt': str(power) + ' W', }

    def get_total_power(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        power = status_data['dps'][self.DPS_TOTAL_POWER]

        return {'total_power_raw': power,
                'total_power_fmt': str(power) + ' W', }

    def get_voltage(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        voltage = status_data['dps'][self.DPS_VOLTAGE] / 100

        return {'voltage_raw': voltage,
                'voltage_fmt': str(voltage) + ' V'}

    def get_temp_unit(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        unit = status_data['dps'][self.DPS_TEMP_UNIT]
        return unit

    def get_temp(self, status_data=None):
        if status_data is None:
            status_data = self.status()

        temp = status_data['dps'][self.DPS_CUR_TEMP] / 10

        return {'cur_temp_raw': temp,
                'cur_temp_fmt': f"{str(temp)} {self.get_temp_unit()}"}

    def get_state(self):
        cur_mode = self.status()['dps'][self.DPS_MODE]
        if cur_mode == 'socket':
            return {
                    'mode': cur_mode,
                    'status': "on" if self.status()['dps'][self.DPS_SWITCH_STATE] else "off"
            }
        else:
            return {'mode': cur_mode}
