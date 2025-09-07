# TinyTuya Cover Device
# -*- coding: utf-8 -*-
"""
 TinyTuya - Cover Device Wrapper

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 This is a thin wrapper that provides the original synchronous interface
 while delegating all work to the async implementation using AsyncRunner.

 Local Control Classes
    CoverDevice(...)
        See OutletDevice() for constructor arguments

 Functions
    CoverDevice:
        open_cover(switch=1):
        close_cover(switch=1):
        stop_cover(switch=1):

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

from .CoverDeviceAsync import CoverDeviceAsync
from .core import Device


class CoverDevice(Device):
    """
    Represents a Tuya based Smart Window Cover.
    
    Inherits from Device but uses CoverDeviceAsync implementation for cover-specific functionality.
    Uses the new AsyncWrapper architecture for automatic method delegation.
    """

    def __init__(self, *args, **kwargs):
        """Initialize CoverDevice with CoverDeviceAsync implementation"""
        # Initialize AsyncWrapper directly with CoverDeviceAsync instead of calling super()
        # because super() would create DeviceAsync, but we want CoverDeviceAsync
        from .core.AsyncWrapper import AsyncWrapper
        AsyncWrapper.__init__(self, CoverDeviceAsync, *args, **kwargs)
        
        # Set the attributes that Device/XenonDevice would normally set
        # Extract from args/kwargs for backward compatibility
        if args:
            self.id = args[0]  # dev_id is first argument
        else:
            self.id = kwargs.get('dev_id')
        
        self.address = kwargs.get('address') if 'address' in kwargs else (args[1] if len(args) > 1 else None)
        self.cid = kwargs.get('cid') or kwargs.get('node_id')
        self.port = kwargs.get('port', 6668)
        
        # Initialize the async implementation to handle Auto-IP and device.json lookup
        self._runner.run(self._async_impl.initialize())

    # ---- Cover-Specific Constants ----
    DPS_INDEX_MOVE = "1"
    DPS_INDEX_BL = "101"

    DPS_2_STATE = {
        "1": "movement",
        "101": "backlight",
    }
