#
# Note: This file has been deprecated, please do not add new modules to it.
# Instead, import new modules with `from tinytuya.Contrib import YourNewModule`
#  and call with `YourNewModule.YourNewModule(...)`
#

from .ThermostatDevice import ThermostatDevice
from .IRRemoteControlDevice import IRRemoteControlDevice
from .SocketDevice import SocketDevice
from .DoorbellDevice import DoorbellDevice
from .ClimateDevice import ClimateDevice
from .AtorchTemperatureControllerDevice import AtorchTemperatureControllerDevice
from .InverterHeatPumpDevice import InverterHeatPumpDevice, TemperatureUnit, InverterHeatPumpMode, InverterHeatPumpFault

DeviceTypes = ["ThermostatDevice", "IRRemoteControlDevice", "SocketDevice", "DoorbellDevice", "ClimateDevice", "AtorchTemperatureControllerDevice", "InverterHeatPumpDevice"]
