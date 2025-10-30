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
        continue_cover(switch=None, nowait=False)   # Continue cover motion (if supported)
        set_cover_type(cover_type)                  # Manually set cover type (1-8)

 Notes
    CoverDevice automatically detects the device type (1-8) based on status response:
    
    Type 1: ["open", "close", "stop", "continue"] - Most curtains, blinds, roller shades
    Type 2: [true, false]                         - Simple relays, garage doors, locks  
    Type 3: ["0", "1", "2"]                       - String-numeric position/state
    Type 4: [1, 2, 3]                             - Integer-numeric position/state
    Type 5: ["fopen", "fclose"]                   - Directional binary (no stop)
    Type 6: ["on", "off", "stop"]                 - Switch-lexicon open/close
    Type 7: ["up", "down", "stop"]                - Vertical-motion (lifts, hoists)
    Type 8: ["ZZ", "FZ", "STOP"]                  - Vendor-specific (Abalon-style)
    
    Credit for discovery: @make-all in https://github.com/jasonacox/tinytuya/issues/653
    Detection occurs on first command by checking device status. You can manually
    override using set_cover_type(type_id) if needed.

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
    
    Supports 8 different command types with automatic detection.
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }

    # Cover type command mappings
    COVER_TYPES = {
        1: {  # Comprehensive movement class
            'open': 'open',
            'close': 'close',
            'stop': 'stop',
            'continue': 'continue',
            'detect_values': ['open', 'close', 'stop', 'continue']
        },
        2: {  # Binary on/off class
            'open': True,
            'close': False,
            'stop': None,  # Not supported
            'continue': None,
            'detect_values': [True, False]
        },
        3: {  # String-numeric index class
            'open': '1',
            'close': '2',
            'stop': '0',
            'continue': None,
            'detect_values': ['0', '1', '2']
        },
        4: {  # Integer-numeric index class
            'open': 1,
            'close': 2,
            'stop': 0,
            'continue': 3,
            'detect_values': [0, 1, 2, 3]
        },
        5: {  # Directional binary class
            'open': 'fopen',
            'close': 'fclose',
            'stop': None,  # Not supported
            'continue': None,
            'detect_values': ['fopen', 'fclose']
        },
        6: {  # Switch-lexicon class
            'open': 'on',
            'close': 'off',
            'stop': 'stop',
            'continue': None,
            'detect_values': ['on', 'off', 'stop']
        },
        7: {  # Vertical-motion class
            'open': 'up',
            'close': 'down',
            'stop': 'stop',
            'continue': None,
            'detect_values': ['up', 'down', 'stop']
        },
        8: {  # Vendor-specific class (Abalon-style)
            'open': 'ZZ',
            'close': 'FZ',
            'stop': 'STOP',
            'continue': None,
            'detect_values': ['ZZ', 'FZ', 'STOP']
        }
    }

    def __init__(self, *args, **kwargs):
        super(CoverDevice, self).__init__(*args, **kwargs)
        self._cover_type_detected = False
        self._cover_type = None  # Will be set to 1-8 after detection

    def _detect_cover_type(self, switch=None):
        """
        Automatically detect the cover device type (1-8) by checking device status.
        
        Args:
            switch (str/int): The DPS index to check. Defaults to DPS_INDEX_MOVE.
        """
        if self._cover_type_detected:
            return

        if switch is None:
            switch = self.DPS_INDEX_MOVE

        # Set default to Type 6 (on/off/stop) before attempting detection
        self._cover_type = 6

        try:
            result = self.status()
            if result and 'dps' in result:
                dps_key = str(switch)
                dps_value = result['dps'].get(dps_key)
                
                # Try to match the current value to a known cover type
                if dps_value is not None:
                    for type_id, type_info in self.COVER_TYPES.items():
                        if dps_value in type_info['detect_values']:
                            self._cover_type = type_id
                            break
                    
        except Exception:
            # If status check fails, use default Type 6 (on/off/stop)
            pass
        
        self._cover_type_detected = True

    def set_cover_type(self, cover_type):
        """
        Manually set the cover device type.
        
        Args:
            cover_type (int): Cover type ID (1-8).
        
        Raises:
            ValueError: If cover_type is not between 1 and 8.
        
        Example:
            cover.set_cover_type(1)  # Set to Type 1 (open/close/stop/continue)
            cover.set_cover_type(6)  # Set to Type 6 (on/off/stop)
        """
        if cover_type not in self.COVER_TYPES:
            raise ValueError(f"Invalid cover_type: {cover_type}. Must be between 1 and 8.")
        
        self._cover_type = cover_type
        self._cover_type_detected = True

    def _get_command(self, action, switch=None):
        """
        Get the appropriate command for the detected cover type.
        
        Args:
            action (str): The action to perform ('open', 'close', 'stop', 'continue').
            switch (str/int): The DPS index. Defaults to DPS_INDEX_MOVE.
        
        Returns:
            The command value for the detected cover type, or None if not supported.
        """
        if not self._cover_type_detected:
            self._detect_cover_type(switch)
        
        if self._cover_type and self._cover_type in self.COVER_TYPES:
            return self.COVER_TYPES[self._cover_type].get(action)
        
        return None

    def open_cover(self, switch=None, nowait=False):
        """
        Open the cover.
        
        Args:
            switch (str/int): The DPS index. Defaults to DPS_INDEX_MOVE.
            nowait (bool): Don't wait for device response.
        """
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        
        command = self._get_command('open', switch)
        if command is not None:
            self.set_value(switch, command, nowait=nowait)

    def close_cover(self, switch=None, nowait=False):
        """
        Close the cover.
        
        Args:
            switch (str/int): The DPS index. Defaults to DPS_INDEX_MOVE.
            nowait (bool): Don't wait for device response.
        """
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        
        command = self._get_command('close', switch)
        if command is not None:
            self.set_value(switch, command, nowait=nowait)

    def stop_cover(self, switch=None, nowait=False):
        """
        Stop the cover motion.
        
        Args:
            switch (str/int): The DPS index. Defaults to DPS_INDEX_MOVE.
            nowait (bool): Don't wait for device response.
        
        Note:
            Not all cover types support stop. Types 2 and 5 do not have a stop command.
        """
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        
        command = self._get_command('stop', switch)
        if command is not None:
            self.set_value(switch, command, nowait=nowait)

    def continue_cover(self, switch=None, nowait=False):
        """
        Continue the cover motion (if supported).
        
        Args:
            switch (str/int): The DPS index. Defaults to DPS_INDEX_MOVE.
            nowait (bool): Don't wait for device response.
        
        Note:
            Only Type 1 and Type 4 support the continue command.
        """
        if switch is None:
            switch = self.DPS_INDEX_MOVE
        
        command = self._get_command('continue', switch)
        if command is not None:
            self.set_value(switch, command, nowait=nowait)
