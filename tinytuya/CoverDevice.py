# TinyTuya Cover Device
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya
"""

from .core import Device

class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.
    
    Supports 8 different command types with automatic detection.
    """

    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"
    DEFAULT_COVER_TYPE = 1  # Default to Type 1 (most common)

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
        4: {  # Zero-prefixed numeric index class
            'open': '01',
            'close': '02',
            'stop': '00',
            'continue': '03',
            'detect_values': ['00', '01', '02', '03']
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
        Uses priority ordering to handle overlapping values (e.g., 'stop' appears in Types 1, 6, 7).
        Type 1 has highest priority as it's the most comprehensive.
        
        Args:
            switch (str/int): The DPS index to check. Defaults to DPS_INDEX_MOVE.
        """
        if self._cover_type_detected:
            return

        if switch is None:
            switch = self.DPS_INDEX_MOVE

        # Set default to Type 1 (most comprehensive) before attempting detection
        self._cover_type = self.DEFAULT_COVER_TYPE

        try:
            result = self.status()
            if result and 'dps' in result:
                dps_key = str(switch)
                dps_value = result['dps'].get(dps_key)
                
                # Try to match the current value to a known cover type
                # Priority order: 1, 8, 3, 4, 5, 7, 2, 6 (most common to least common)
                # Type 1: Most common (comprehensive standard)
                # Type 8: Second most common (older vendor standard)
                # Type 3: Third most common (string-numeric)
                # Others: Rare variations
                if dps_value is not None:
                    priority_order = [1, 8, 3, 4, 5, 7, 2, 6]
                    for type_id in priority_order:
                        type_info = self.COVER_TYPES[type_id]
                        if dps_value in type_info['detect_values']:
                            self._cover_type = type_id
                            break
                    
        except Exception:
            # If status check fails, use default Type 1
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
