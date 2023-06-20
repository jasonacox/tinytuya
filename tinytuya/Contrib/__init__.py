
from .ThermostatDevice import ThermostatDevice
from .IRRemoteControlDevice import IRRemoteControlDevice
from .SocketDevice import SocketDevice
from .DoorbellDevice import DoorbellDevice
from .ClimateDevice import ClimateDevice
from .AtorchTemperatureControllerDevice import AtorchTemperatureControllerDevice
from .InverterHeatPumpDevice import InverterHeatPumpDevice, TemperatureUnit, InverterHeatPumpMode, InverterHeatPumpFault

DeviceTypes = ["ThermostatDevice", "IRRemoteControlDevice", "SocketDevice", "DoorbellDevice", "ClimateDevice", "AtorchTemperatureControllerDevice", "InverterHeatPumpDevice"]
