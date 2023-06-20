"""
 Python module to interface with Tuya WiFi smart inverter heat pump

 Author: Valentin Dusollier (https://github.com/valentindusollier)
 Tested: Fairland Inverter+ 21kW (IPHR55)
 
 Local Control Classes
    InverterHeatPumpDevice(...)
        See Device() for constructor arguments

    Functions
        InverterHeatPumpDevice:
            is_on()                             # Returns True if the inverter is on
            get_unit()                          # Returns the unit of the temperature
                                                # (TemperatureUnit.CELSIUS or TemperatureUnit.FAHRENHEIT)
            get_inlet_water_temp()              # Returns the inlet water temperature
            get_target_water_temp()             # Returns the target water temperature
            get_lower_limit_target_water_temp() # Returns the lower limit of the target water temperature
            get_upper_limit_target_water_temp() # Returns the upper limit of the target water temperature
            get_heating_capacity_percent()      # Returns the heating capacity in percent
            get_mode(raw=True/False)            # Returns the current InverterHeatPumpMode(Enum) if raw=False
                                                # (default value), otherwise returns the string mode
            get_fault(raw=True/False)           # Returns the current InverterHeatPumpFault(Enum) if raw=False
                                                # (default value), otherwise returns the integer fault code
            is_silence_mode()                   # Returns True if the silence mode is on
            
            set_unit(TemperatureUnit)           # Set the unit of the temperature
                                                # (TemperatureUnit.CELSIUS or TemperatureUnit.FAHRENHEIT)
            set_target_water_temp(integer)      # Set the target water temperature. Must be between
                                                # get_lower_limit_target_water_temp() and
                                                # get_upper_limit_target_water_temp()
            set_silence_mode(True/False)        # Set the silence mode on (True) or off (False)
            
        Inherited
            json = status()                     # returns json payload
            set_version(version)                # 3.1 [default] or 3.3
            set_socketPersistent(False/True)    # False [default] or True
            set_socketNODELAY(False/True)       # False or True [default]
            set_socketRetryLimit(integer)       # retry count limit [default 5]
            set_socketTimeout(timeout)          # set connection timeout in seconds [default 5]
            set_dpsUsed(dps_to_request)         # add data points (DPS) to request
            add_dps_to_request(index)           # add data point (DPS) index set to None
            set_retry(retry=True)               # retry if response payload is truncated
            set_status(on, switch=1, nowait)    # Set status of switch to 'on' or 'off' (bool)
            set_value(index, value, nowait)     # Set int value of any index.
            heartbeat(nowait)                   # Send heartbeat to device
            updatedps(index=[1], nowait)        # Send updatedps command to device
            turn_on(switch=1, nowait)           # Turn on device / switch #
            turn_off(switch=1, nowait)          # Turn off
            set_timer(num_secs, nowait)         # Set timer for num_secs
            set_debug(toggle, color)            # Activate verbose debugging output
            set_sendWait(num_secs)              # Time to wait after sending commands before pulling response
            detect_available_dps()              # Return list of DPS available from device
            generate_payload(command, data)     # Generate TuyaMessage payload for command with data
            send(payload)                       # Send payload to device (do not wait for response)
            receive()

 Additional Classes
    TemperatureUnit(Enum)
        Enum to represent the unit of the temperature (C° or F°)
        
    ExtendedEnum(Enum)
        Internal use only.
        
    InverterHeatPumpMode(ExtendedEnum)
        Enum to represent the mode of the inverter. There is no documentation
        about the modes, therefore only the known ones are listed. Feel free
        to contribute if you know more about these modes.
    
    InverterHeatPumpFault(ExtendedEnum)
        Enum to represent the fault of the inverter. There is no documentation
        about the fault codes, therefore only the known ones are listed. Feel
        free to contribute if you know more about these codes.
"""

from enum import Enum
from ..core import Device


class InverterHeatPumpDevice(Device):

    DPS = "dps"
    ON_DP = "1"
    INLET_WATER_TEMP_DP = "102"
    UNIT_DP = "103"
    HEATING_CAPACITY_PERCENT_DP = "104"
    MODE_DP = "105"
    TARGET_WATER_TEMP_DP = "106"
    LOWER_LIMIT_TARGET_WATER_TEMP_DP = "107"
    UPPER_LIMIT_TARGET_WATER_TEMP_DP = "108"
    FAULT_DP = "115"
    FAULT2_DP = "116"
    SILENCE_MODE_DP = "117"

    def is_on(self):
        return self.status()[self.DPS][self.ON_DP]

    def get_unit(self):
        return TemperatureUnit(self.status()[self.DPS][self.UNIT_DP])

    def get_inlet_water_temp(self):
        return self.status()[self.DPS][self.INLET_WATER_TEMP_DP]

    def get_target_water_temp(self):
        return self.status()[self.DPS][self.TARGET_WATER_TEMP_DP]

    def get_lower_limit_target_water_temp(self):
        return self.status()[self.DPS][self.LOWER_LIMIT_TARGET_WATER_TEMP_DP]

    def get_upper_limit_target_water_temp(self):
        return self.status()[self.DPS][self.UPPER_LIMIT_TARGET_WATER_TEMP_DP]

    def get_heating_capacity_percent(self):
        return self.status()[self.DPS][self.HEATING_CAPACITY_PERCENT_DP]

    def get_mode(self, raw=False):
        """There is no documentation about the modes. Therefore, your device
        could push unkown modes and this method will return
        InverterHeatPumpMode.UNKNOWN. You can use raw=True to get pushed value.
        Feel free to contribute if you get unknown modes.
        """
        string_mode = self.status()[self.DPS][self.MODE_DP]

        if raw:
            return string_mode

        if InverterHeatPumpMode.is_known(string_mode):
            return InverterHeatPumpMode(string_mode)

        return InverterHeatPumpMode.UNKNOWN

    def get_fault(self, raw=False):
        """There is no documentation about the fault codes. Therefore, your
        device could push unkown fault codes and this method will return
        InverterHeatPumpFault.UNKNOWN. You can use raw=True to get pushed value.
        Feel free to contribute if you get unknown fault codes.
        """
        fault = self.status()[self.DPS][self.FAULT_DP]

        if raw:
            return fault

        if InverterHeatPumpFault.is_known(fault):
            return InverterHeatPumpFault(fault)

        return InverterHeatPumpFault.UNKNOWN

    def is_silence_mode(self):
        """Paradoxically, the silence mode is on when SILENCE_MODE_DP is False"""
        return not self.status()[self.DPS][self.SILENCE_MODE_DP]

    def set_unit(self, unit):
        self.set_value(self.UNIT_DP, unit.value)

    def set_target_water_temp(self, target_water_temp):
        sts = self.status()[self.DPS]
        lower_limit, upper_limit = (
            sts[self.LOWER_LIMIT_TARGET_WATER_TEMP_DP],
            sts[self.UPPER_LIMIT_TARGET_WATER_TEMP_DP],
        )
        if lower_limit <= target_water_temp <= upper_limit:
            self.set_value(self.TARGET_WATER_TEMP_DP, target_water_temp)
        else:
            raise ValueError("Target water temperature must be between {} and {}".format(lower_limit, upper_limit))

    def set_silence_mode(self, silence_mode):
        """Paradoxically, the silence mode is on when SILENCE_MODE_DP is False"""
        self.set_value(self.SILENCE_MODE_DP, not silence_mode)

class TemperatureUnit(Enum):
    CELSIUS = True
    FAHRENHEIT = False
    
class ExtendedEnum(Enum):
    @classmethod
    def is_known(self, value):
        return value in self._value2member_map_

class InverterHeatPumpMode(ExtendedEnum):
    UNKNOWN = "unknown"
    HEATING = "warm"


class InverterHeatPumpFault(ExtendedEnum):
    UNKNOWN = -1
    NOMINAL = 0
    NO_WATER_FLOW = 4
