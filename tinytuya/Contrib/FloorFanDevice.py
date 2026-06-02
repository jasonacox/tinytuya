from tinytuya.core import Device

"""
 Python module to interface with Tuya Floor Standing Fan devices

 Local Control Classes
    FloorFanDevice(..., version=3.3)
        This class uses a default version of 3.3
        See OutletDevice() for the other constructor arguments

 Functions
    FloorFanDevice:
        status_json()
        get_power()
        set_power()
        get_mode()
        set_mode()
        get_speed()
        set_speed()
        get_oscillation()
        set_oscillation()
        get_timer()
        set_timer()
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


class FloorFanDevice(Device):
    """
    Represents a Tuya based Floor Standing Fan
    """

    DPS_POWER = "1"
    DPS_MODE = "2"
    DPS_SPEED = "3"
    DPS_OSCILLATION = "5"
    DPS_STATUS_FLAG = "13"
    DPS_TIMER = "22"

    def __init__(self, *args, **kwargs):
        # set the default version to 3.3
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.3
        super(FloorFanDevice, self).__init__(*args, **kwargs)

    def status_json(self):
        """Wrapper around status() that replace DPS indices with human readable labels."""
        status = self.status()["dps"]
        return {
            "Power": status.get(self.DPS_POWER),
            "Mode": status.get(self.DPS_MODE),
            "Speed": status.get(self.DPS_SPEED),
            "Oscillation": status.get(self.DPS_OSCILLATION),
            "Timer": status.get(self.DPS_TIMER),
        }

    def get_power(self):
        """Get the power status of the fan."""
        status = self.status()["dps"]
        return status[self.DPS_POWER]

    def set_power(self, on):
        """Set the power status of the fan.
        
        Args:
            on (bool): True to turn on, False to turn off
        """
        self.set_status(on, self.DPS_POWER)

    def get_mode(self):
        """Get the current wind mode.
        
        Returns:
            str: One of 'normal', 'nature', or 'sleep'
        """
        status = self.status()["dps"]
        return status[self.DPS_MODE]

    def set_mode(self, mode):
        """Set the wind mode.
        
        Args:
            mode (str): One of 'normal', 'nature', or 'sleep'
        """
        if mode not in ("normal", "nature", "sleep"):
            return
        self.set_value(self.DPS_MODE, mode)

    def get_speed(self):
        """Get the current fan speed level.
        
        Returns:
            int: Speed level from 1 to 5
        """
        status = self.status()["dps"]
        return status[self.DPS_SPEED]

    def set_speed(self, speed):
        """Set the fan speed level.
        
        Args:
            speed (int): Speed level from 1 to 5
        """
        if speed not in (1, 2, 3, 4, 5):
            return
        self.set_value(self.DPS_SPEED, speed)

    def get_oscillation(self):
        """Get the oscillation/swing status.
        
        Returns:
            bool: True if oscillation is on, False otherwise
        """
        status = self.status()["dps"]
        return status[self.DPS_OSCILLATION]

    def set_oscillation(self, on):
        """Set the oscillation/swing status.
        
        Args:
            on (bool): True to enable oscillation, False to disable
        """
        self.set_status(on, self.DPS_OSCILLATION)

    def get_timer(self):
        """Get the current sleep timer setting.
        
        Returns:
            str: One of 'cancel', '1h', '2h', ..., '12h'
        """
        status = self.status()["dps"]
        return status[self.DPS_TIMER]

    def set_timer(self, timer):
        """Set the sleep timer.
        
        Args:
            timer (str): One of 'cancel', '1h', '2h', '3h', '4h', '5h', '6h', 
                        '7h', '8h', '9h', '10h', '11h', or '12h'
        """
        valid_timers = [
            "cancel", "1h", "2h", "3h", "4h", "5h", "6h",
            "7h", "8h", "9h", "10h", "11h", "12h"
        ]
        if timer not in valid_timers:
            return
        self.set_value(self.DPS_TIMER, timer)
