# TinyTuya WiFi Dual Meter Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi Dual Meter Devices

 Author: Guillaume Gardet

 Local Control Classes
    WiFiDualMeterDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    WiFiDualMeterDevice:
        get_current_b()
        get_total_power()
        get_voltage_calibration()
        get_current_calibration_a()
        get_power_calibration_a()
        get_energy_calibration_a()
        get_power_factor_b()
        get_current_calibration_b()
        get_power_calibration_b()
        get_energy_calibration_b()
        get_energy_reverse_calibration_a()
        get_energy_reverse_calibration_b()
        get_report_rate()
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

class WiFiDualMeterDevice(Device):

    DPS_FORWARD_ENERGY_TOTAL          =   '1'
    DPS_REVERSE_ENERGY_TOTAL          =   '2'
    DPS_POWER_A                       = '101'
    DPS_DIR_CUR_A                     = '102'
    DPS_DIR_CUR_B                     = '104'
    DPS_POWER_B                       = '105'
    DPS_ENERGY_FORWARD_A              = '106'
    DPS_ENERGY_REVERSE_A              = '107'
    DPS_ENERGY_FORWARD_B              = '108'
    DPS_ENERGY_REVERSE_B              = '109'
    DPS_POWER_FACTOR_A                = '110'
    DPS_FREQ                          = '111'
    DPS_VOLTAGE                       = '112'
    DPS_CURRENT_A                     = '113'
    DPS_CURRENT_B                     = '114'
    DPS_TOTAL_POWER                   = '115'
    DPS_VOLTAGE_CALIBRATION           = '116'
    DPS_CURRENT_CALIBRATION_A         = '117'
    DPS_POWER_CALIBRATION_A           = '118'
    DPS_ENERGY_CALIBRATION_A          = '119'
    DPS_POWER_FACTOR_B                = '121'
    DPS_FREQUENCY_CALIBRATION         = '122'
    DPS_CURRENT_CALIBRATION_B         = '123'
    DPS_POWER_CALIBRATION_B           = '124'
    DPS_ENERGY_CALIBRATION_B          = '125'
    DPS_ENERGY_CALIBRATION_REVERSE_A  = '127'
    DPS_ENERGY_CALIBRATION_REVERSE_B  = '128'
    DPS_REPORT_RATE                   = '129'

    dps_data = {
        DPS_FORWARD_ENERGY_TOTAL:         { 'name': 'forward_energy_total', 'unit': 'kWh', 'scale': 100 },
        DPS_REVERSE_ENERGY_TOTAL:         { 'name': 'reverse_energy_total', 'unit': 'kWh', 'scale': 100 },
        DPS_POWER_A:                      { 'name': 'power_a', 'unit': 'W', 'scale': 10 },
        DPS_DIR_CUR_A:                    { 'name': 'dir_curent_a', 'enum': ['FORWARD', 'REVERSE'] },
        DPS_DIR_CUR_B:                    { 'name': 'dir_current_b', 'enum': ['FORWARD', 'REVERSE'] },
        DPS_POWER_B:                      { 'name': 'power_b', 'unit': 'W', 'scale': 10 },
        DPS_ENERGY_FORWARD_A:             { 'name': 'forward_energy_a', 'unit': 'kWh', 'scale': 100 },
        DPS_ENERGY_REVERSE_A:             { 'name': 'reverse_energy_a', 'unit': 'kWh', 'scale': 100 },
        DPS_ENERGY_FORWARD_B:             { 'name': 'forward_energy_b', 'unit': 'kWh', 'scale': 100 },
        DPS_ENERGY_REVERSE_B:             { 'name': 'reverse_energy_b', 'unit': 'kWh', 'scale': 100 },
        DPS_POWER_FACTOR_A:               { 'name': 'power_factor_a', 'scale': 100 },
        DPS_FREQ:                         { 'name': 'ac_frequency', 'unit': 'Hz', 'scale': 100 },
        DPS_VOLTAGE:                      { 'name': 'ac_voltage', 'unit': 'V', 'scale': 10 },
        DPS_CURRENT_A:                    { 'name': 'current_a', 'unit': 'mA'},
        DPS_CURRENT_B:                    { 'name': 'current_b', 'unit': 'mA'},
        DPS_TOTAL_POWER:                  { 'name': 'total_power', 'unit': 'W', 'scale': 10 },
        DPS_VOLTAGE_CALIBRATION  :        { 'name': 'voltage_calibration', 'scale': 1000 },
        DPS_CURRENT_CALIBRATION_A:        { 'name': 'current_calibration_a', 'scale': 1000 },
        DPS_POWER_CALIBRATION_A:          { 'name': 'power_calibration_a', 'scale': 1000 },
        DPS_ENERGY_CALIBRATION_A:         { 'name': 'energy_calibration_a', 'scale': 1000 },
        DPS_POWER_FACTOR_B:               { 'name': 'power_factor_b', 'scale': 100 },
        DPS_CURRENT_CALIBRATION_B:        { 'name': 'current_calibration_b', 'scale': 1000 },
        DPS_POWER_CALIBRATION_B:          { 'name': 'power_calibration_b', 'scale': 1000 },
        DPS_ENERGY_CALIBRATION_B:         { 'name': 'energy_calibration_b', 'scale': 1000 },
        DPS_ENERGY_CALIBRATION_REVERSE_A: { 'name': 'energy_calibration_reverse_a', 'scale': 1000 },
        DPS_ENERGY_CALIBRATION_REVERSE_B: { 'name': 'energy_calibration_reverse_b', 'scale': 1000 },
        DPS_REPORT_RATE:                  { 'name': 'report_rate', 'unit': 's' },
    }

    def get_value(self, dps_code, status_data=None):
        if status_data is None:
            status_data = self.status()
        name = self.dps_data[dps_code]['name']
        try:
            scale = self.dps_data[dps_code]['scale']
        except KeyError:
            scale = 1
        try:
            unit = self.dps_data[dps_code]['unit']
        except KeyError:            
            unit = ""
        val = status_data['dps'][dps_code]
        if isinstance(val, int):
            val = val / scale
        return {name+'_raw': val,
                name+'_fmt': str(val) + ' '+ unit}

    def get_forward_energy_total(self, status_data=None):
        return self.get_value(dps_code=self.DPS_FORWARD_ENERGY_TOTAL)

    def get_reverse_energy_total(self, status_data=None):
        return self.get_value(dps_code=self.DPS_REVERSE_ENERGY_TOTAL)

    def get_power_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_A)

    def get_dir_cur_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_DIR_CUR_A)

    def get_dir_cur_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_DIR_CUR_B)

    def get_power_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_B)

    def get_energy_forward_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_FORWARD_A)

    def get_energy_reverse_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_REVERSE_A)

    def get_energy_forward_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_FORWARD_B)

    def get_energy_reverse_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_REVERSE_B)

    def get_power_factor_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_FACTOR_A)

    def get_freq(self, status_data=None):
        return self.get_value(dps_code=self.DPS_FREQ)

    def get_voltage(self, status_data=None):
        return self.get_value(dps_code=self.DPS_VOLTAGE)

    def get_current_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_CURRENT_A)

    def get_current_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_CURRENT_B)

    def get_total_power(self, status_data=None):
        return self.get_value(dps_code=self.DPS_TOTAL_POWER)

    def get_voltage_calibration(self, status_data=None):
        return self.get_value(dps_code=self.DPS_VOLTAGE_CALIBRATION)

    def get_current_calibration_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_CURRENT_CALIBRATION_A)

    def get_power_calibration_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_CALIBRATION_A)

    def get_energy_calibration_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_CALIBRATION_A)

    def get_power_factor_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_FACTOR_B)

    def get_current_calibration_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_CURRENT_CALIBRATION_B)

    def get_power_calibration_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_POWER_CALIBRATION_B)

    def get_energy_calibration_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_CALIBRATION_B)

    def get_energy_reverse_calibration_a(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_CALIBRATION_REVERSE_A)

    def get_energy_reverse_calibration_b(self, status_data=None):
        return self.get_value(dps_code=self.DPS_ENERGY_CALIBRATION_REVERSE_B)

    def get_report_rate(self, status_data=None):
        return self.get_value(dps_code=self.DPS_REPORT_RATE)

    def print_all(self, status_data=None):
        if status_data is None:
            status_data = self.status()
        print(self.get_forward_energy_total(status_data))
        print(self.get_reverse_energy_total(status_data))
        print(self.get_power_a(status_data))
        print(self.get_dir_cur_a(status_data))
        print(self.get_dir_cur_b(status_data))
        print(self.get_power_b(status_data))
        print(self.get_energy_forward_a(status_data))
        print(self.get_energy_reverse_a(status_data))
        print(self.get_energy_forward_b(status_data))
        print(self.get_energy_reverse_b(status_data))
        print(self.get_power_factor_a(status_data))
        print(self.get_freq(status_data))
        print(self.get_voltage(status_data))
        print(self.get_current_a(status_data))
        print(self.get_current_b(status_data))
        print(self.get_total_power(status_data))
        print(self.get_voltage_calibration(status_data))
        print(self.get_current_calibration_a(status_data))
        print(self.get_power_calibration_a(status_data))
        print(self.get_energy_calibration_a(status_data))
        print(self.get_power_factor_b(status_data))
        print(self.get_power_calibration_b(status_data))
        print(self.get_energy_calibration_b(status_data))
        print(self.get_energy_reverse_calibration_a(status_data))
        print(self.get_energy_reverse_calibration_b(status_data))
        print(self.get_report_rate(status_data))

