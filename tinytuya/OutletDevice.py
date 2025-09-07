# TinyTuya Outlet Device (Sync Wrapper)
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices (Sync wrapper)

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Local Control Classes
    OutletDevice(dev_id, address=None, local_key=None, dev_type='default', connection_timeout=5, version=3.1, persist=False
        dev_id (str): Device ID e.g. 01234567891234567890
        address (str, optional): Device Network IP Address e.g. 10.0.1.99, or None to try and find the device
        local_key (str, optional): The encryption key. Defaults to None. If None, key will be looked up in DEVICEFILE if available
        dev_type (str, optional): Device type for payload options (see below)
        connection_timeout (float, optional): The default socket connect and data timeout
        version (float, optional): The API version to use. Defaults to 3.1
        persist (bool, optional): Make a persistant connection to the device

 Functions
    OutletDevice:
        set_dimmer(percentage):

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

from .OutletDeviceAsync import OutletDeviceAsync
from .core import Device


class OutletDevice(Device):
    """
    Represents a Tuya based Smart Plug or Switch.
    
    Inherits from Device but uses OutletDeviceAsync implementation for outlet-specific functionality.
    Uses the new AsyncWrapper architecture for automatic method delegation.
    """

    def __init__(self, *args, **kwargs):
        """Initialize OutletDevice with OutletDeviceAsync implementation"""
        # Initialize AsyncWrapper directly with OutletDeviceAsync instead of calling super()
        # because super() would create DeviceAsync, but we want OutletDeviceAsync
        from .core.AsyncWrapper import AsyncWrapper
        AsyncWrapper.__init__(self, OutletDeviceAsync, *args, **kwargs)
        
        # Set the attributes that Device/XenonDevice would normally set
        # Extract from args/kwargs for backward compatibility
        if args:
            self.id = args[0]  # dev_id is first argument
        else:
            self.id = kwargs.get('dev_id')
        
        self.address = kwargs.get('address') if 'address' in kwargs else (args[1] if len(args) > 1 else None)
        self.cid = kwargs.get('cid') or kwargs.get('node_id')
        self.port = kwargs.get('port', 6668)
