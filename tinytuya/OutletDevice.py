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

from .core.XenonDevice import XenonDevice
from .OutletDeviceAsync import OutletDeviceAsync


class OutletDevice(XenonDevice):
    """
    Synchronous wrapper for OutletDeviceAsync.
    
    Represents a Tuya based Smart Plug or Switch.
    All methods delegate to the async implementation using AsyncRunner.
    """

    def __init__(self, *args, **kwargs):
        """Initialize OutletDevice wrapper"""
        # Initialize with OutletDeviceAsync instead of XenonDeviceAsync
        super().__init__(*args, **kwargs)
        # Replace the base async implementation with outlet-specific one
        self._async_impl = OutletDeviceAsync(*args, **kwargs)
        
        # Expose key attributes for backward compatibility
        self.id = self._async_impl.id
        self.address = self._async_impl.address

    def __del__(self):
        """Cleanup when object is destroyed"""
        try:
            if '_runner' in self.__dict__:
                self._runner.cleanup()
        except (AttributeError, RuntimeError):
            # Ignore cleanup errors during shutdown
            pass

    def __repr__(self):
        """String representation of the device"""
        return repr(self._async_impl)

    # ---- Attribute Delegation ----
    
    def __getattr__(self, name):
        """Delegate attribute access to async implementation"""
        return getattr(self._async_impl, name)
    
    def __setattr__(self, name, value):
        """Handle attribute setting for both wrapper and async impl"""
        if name.startswith('_') or name in ('id', 'address'):
            # Set on wrapper
            super().__setattr__(name, value)
        else:
            # Delegate to async implementation
            if hasattr(self, '_async_impl'):
                setattr(self._async_impl, name, value)
            else:
                # During __init__, before _async_impl exists
                super().__setattr__(name, value)

    # ---- OutletDevice-Specific Methods ----

    def status(self, nowait=False):
        """Get device status"""
        return self._runner.run(self._async_impl.status(nowait))

    def set_status(self, on, switch=1, nowait=False):
        """Set device status"""
        return self._runner.run(self._async_impl.set_status(on, switch, nowait))

    def turn_on(self, switch=1, nowait=False):
        """Turn device on"""
        return self._runner.run(self._async_impl.turn_on(switch, nowait))

    def turn_off(self, switch=1, nowait=False):
        """Turn device off"""
        return self._runner.run(self._async_impl.turn_off(switch, nowait))

    def cached_status(self, historic=False, nowait=False):
        """Get cached device status"""
        return self._runner.run(self._async_impl.cached_status(historic, nowait))

    def heartbeat(self, nowait=False):
        """Send heartbeat to device"""
        return self._runner.run(self._async_impl.heartbeat(nowait))

    def _send_receive(self, payload, minresponse=28, getresponse=True, decode_response=True):
        """Send payload to device and receive response"""
        return self._runner.run(self._async_impl._send_receive(payload, minresponse, getresponse, decode_response))

    def generate_payload(self, command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None):
        """Generate message payload"""
        return self._async_impl.generate_payload(command, data, gwId, devId, uid, rawData, reqType)

    def _encode_message(self, msg):
        """Encode message for transmission"""
        return self._async_impl._encode_message(msg)

    def _negotiate_session_key_generate_step_1(self):
        """Generate step 1 of session key negotiation"""
        return self._async_impl._negotiate_session_key_generate_step_1()

    def _negotiate_session_key_generate_step_3(self, rkey):
        """Generate step 3 of session key negotiation"""
        return self._async_impl._negotiate_session_key_generate_step_3(rkey)

    def _negotiate_session_key_generate_finalize(self):
        """Finalize session key negotiation"""
        return self._async_impl._negotiate_session_key_generate_finalize()

    def set_dimmer(self, percentage=None, value=None, dps_id=3, nowait=False):
        """Set dimmer value"""
        return self._runner.run(self._async_impl.set_dimmer(percentage, value, dps_id, nowait))

    # ---- Context Manager Support ----

    def __enter__(self):
        """Enter synchronous context manager"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit synchronous context manager"""
        self._runner.run(self._async_impl.close())
