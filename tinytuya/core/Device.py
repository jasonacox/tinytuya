# TinyTuya Module - Device (Sync Wrapper)
# -*- coding: utf-8 -*-
"""
Device - Synchronous wrapper around DeviceAsync

This module provides backward-compatible synchronous API by delegating all operations
to the async implementation via AsyncRunner.
"""

import logging

from .async_runner import AsyncRunner
from .DeviceAsync import DeviceAsync
from .XenonDevice import XenonDevice

log = logging.getLogger(__name__)


class Device(XenonDevice):
    """
    Synchronous wrapper for DeviceAsync.
    
    Inherits from XenonDevice and overrides the async implementation to use DeviceAsync.
    This provides the DeviceAsync-specific functionality while maintaining sync API.
    """

    def __init__(self, *args, **kwargs):
        """Initialize Device wrapper"""
        # Create the DeviceAsync implementation instead of XenonDeviceAsync
        self._async_impl = DeviceAsync(*args, **kwargs)
        self._runner = AsyncRunner()
        
        # Initialize parent class attributes but don't override our async_impl
        # We need to manually set the attributes that XenonDevice.__init__ would set
        self.id = self._async_impl.id
        self.address = self._async_impl.address
        self.local_key = self._async_impl.local_key
        self.version = self._async_impl.version
        self.port = self._async_impl.port
        self.connection_timeout = self._async_impl.connection_timeout

    # ---- DeviceAsync-Specific Methods ----
    # These methods are specific to DeviceAsync and not available in XenonDeviceAsync
    
    def set_status(self, on, switch=1, nowait=False):
        """Set status of the device to 'on' or 'off'"""
        return self._runner.run(self._async_impl.set_status(on, switch, nowait))

    def product(self):
        """Request AP_CONFIG Product Info from device"""
        return self._runner.run(self._async_impl.product())

    def heartbeat(self, nowait=True):
        """Send a keep-alive HEART_BEAT command"""
        return self._runner.run(self._async_impl.heartbeat(nowait))

    def updatedps(self, index=None, nowait=False):
        """Request device to update DPS values"""
        return self._runner.run(self._async_impl.updatedps(index, nowait))

    def set_value(self, index, value, nowait=False):
        """Set device DPS value"""
        return self._runner.run(self._async_impl.set_value(index, value, nowait))

    def set_multiple_values(self, data, nowait=False):
        """Set multiple DPS values"""
        return self._runner.run(self._async_impl.set_multiple_values(data, nowait))

    def turn_on(self, switch=1, nowait=False):
        """Turn the device on"""
        return self._runner.run(self._async_impl.turn_on(switch, nowait))

    def turn_off(self, switch=1, nowait=False):
        """Turn the device off"""
        return self._runner.run(self._async_impl.turn_off(switch, nowait))

    def set_timer(self, num_secs, dps_id=0, nowait=False):
        """Set a timer"""
        return self._runner.run(self._async_impl.set_timer(num_secs, dps_id, nowait))

    # ---- Context Manager Support ----

    def __enter__(self):
        """Enter synchronous context manager"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit synchronous context manager"""
        self._runner.run(self._async_impl.close())
