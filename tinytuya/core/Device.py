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

log = logging.getLogger(__name__)


class Device(object):
    """
    Synchronous wrapper for DeviceAsync.
    
    All methods delegate to the async implementation using AsyncRunner.
    This maintains full backward compatibility while eliminating code duplication.
    """

    def __init__(self, *args, **kwargs):
        """Initialize Device wrapper"""
        # Create the async implementation
        self._async_impl = DeviceAsync(*args, **kwargs)
        
        # Create the async runner for delegation
        self._runner = AsyncRunner()
        
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

    # ---- Device-Specific Methods ----

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

    # ---- Inherited methods from XenonDevice (delegated automatically via __getattr__)----
    # status, cached_status, close, set_version, generate_payload, etc. all work automatically

    # ---- Context Manager Support ----

    def __enter__(self):
        """Enter synchronous context manager"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit synchronous context manager"""
        self._runner.run(self._async_impl.close())
