# TinyTuya Cover Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    CoverDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    CoverDevice:
        open_cover(switch=None, nowait=False)       # Open the cover (switch defaults to DPS_INDEX_MOVE)
        close_cover(switch=None, nowait=False)      # Close the cover (switch defaults to DPS_INDEX_MOVE)
        stop_cover(switch=None, nowait=False)       # Stop the cover motion (switch defaults to DPS_INDEX_MOVE)
        set_cover_command_type(use_open_close=True) # Manually set command type

 Notes
    CoverDevice will automatically detect the command type used by the device:
    - Some devices use "open"/"close" commands
    - Other devices use "on"/"off" commands
    Detection occurs on first open_cover() or close_cover() call by checking
    the device status. Defaults to "on"/"off" for backward compatibility.

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

from .core import Device

class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }

    def __init__(self, *args, **kwargs):
        super(CoverDevice, self).__init__(*args, **kwargs)
        self._cover_commands_detected = False
        self._use_open_close = False  # Default to "on"/"off"

    def _detect_cover_commands(self, switch=None):
        """
        Lazy detection of cover command type by checking device status.
        Some devices use "open"/"close", others use "on"/"off".
        This method is called automatically on first open/close command.
        
        Args:
            switch (str/int): The DPS index to check for command type detection.
                            Defaults to DPS_INDEX_MOVE if not specified.
        """
        if self._cover_commands_detected:
            return

        if switch is None:
            switch = self.DPS_INDEX_MOVE

        try:
            result = self.status()
            if result and 'dps' in result:
                dps_key = str(switch)
                dps_value = result['dps'].get(dps_key)
                if dps_value in ['open', 'close']:
                    self._use_open_close = True
                # else: keep default False (use "on"/"off")
        except Exception:
            # If status check fails, stick with default "on"/"off"
            pass

        self._cover_commands_detected = True

    def set_cover_command_type(self, use_open_close=True):
        """
        Manually set the cover command type.
        
        Args:
            use_open_close (bool): If True, uses "open"/"close" commands.
                                   If False, uses "on"/"off" commands.
        
        Example:
            cover.set_cover_command_type(True)   # Use "open"/"close"
            cover.set_cover_command_type(False)  # Use "on"/"off"
        """
        self._use_open_close = use_open_close
        self._cover_commands_detected = True  # Prevent auto-detection

    def open_cover(self, switch=None, nowait=False):
        """Open the cover"""
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        self._detect_cover_commands(switch)
        command = "open" if self._use_open_close else "on"
        self.set_status(command, switch, nowait=nowait)

    def close_cover(self, switch=None, nowait=False):
        """Close the cover"""
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        self._detect_cover_commands(switch)
        command = "close" if self._use_open_close else "off"
        self.set_status(command, switch, nowait=nowait)

    def stop_cover(self, switch=None, nowait=False):
        """Stop the motion of the cover"""
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        self.set_status("stop", switch, nowait=nowait)
