# TinyTuya Module - Device (Sync Wrapper)
# -*- coding: utf-8 -*-
"""
Device - Synchronous wrapper around DeviceAsync

This module provides backward-compatible synchronous API by delegating all operations
to the async implementation via AsyncRunner.
"""

import logging

from .DeviceAsync import DeviceAsync
from .XenonDevice import XenonDevice

log = logging.getLogger(__name__)


class Device(XenonDevice):
    """
    Synchronous wrapper for DeviceAsync.
    
    Inherits from XenonDevice but uses DeviceAsync implementation instead.
    This provides DeviceAsync-specific functionality while maintaining the clean inheritance chain.
    """

    def __init__(self, *args, **kwargs):
        """Initialize Device wrapper with DeviceAsync implementation"""
        # We need to initialize AsyncWrapper directly with DeviceAsync instead of calling super()
        # because super() would create XenonDeviceAsync, but we want DeviceAsync
        from .AsyncWrapper import AsyncWrapper
        AsyncWrapper.__init__(self, DeviceAsync, *args, **kwargs)
        
        # Set the attributes that XenonDevice would normally set
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
