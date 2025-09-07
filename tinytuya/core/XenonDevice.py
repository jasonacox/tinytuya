# TinyTuya Module - XenonDevice (Sync Wrapper)
# -*- coding: utf-8 -*-
"""
XenonDevice - Synchronous wrapper around XenonDeviceAsync

This module provides backward-compatible synchronous API by delegating all operations
to the async implementation via AsyncRunner.
"""

import logging
import sys

from .async_runner import AsyncRunner
from .AsyncWrapper import AsyncWrapper
from .XenonDeviceAsync import XenonDeviceAsync, find_device_async, device_info_async, merge_dps_results

log = logging.getLogger(__name__)

# Python 2 Support
IS_PY2 = sys.version_info[0] == 2

def find_device(dev_id=None, address=None):
    """Scans network for Tuya devices with either ID = dev_id or IP = address

    Parameters:
        dev_id = The specific Device ID you are looking for
        address = The IP address you are tring to find the Device ID for

    Response:
        {'ip':<ip>, 'version':<version>, 'id':<id>, 'product_id':<product_id>, 'data':<broadcast data>}
    """
    runner = AsyncRunner()
    return runner.run(find_device_async(dev_id, address))

def device_info(dev_id):
    """Get device info from devicefile"""
    runner = AsyncRunner()
    return runner.run(device_info_async(dev_id))


class XenonDevice(AsyncWrapper):
    """
    Synchronous wrapper for XenonDeviceAsync.
    
    Uses the new AsyncWrapper architecture for automatic method delegation
    and simplified maintenance.
    """

    def __init__(
            self, dev_id, address=None, local_key="", dev_type="default", connection_timeout=5,
            version=3.1, # pylint: disable=W0621
            persist=False, cid=None, node_id=None, parent=None,
            connection_retry_limit=5, connection_retry_delay=5, port=6668,
            max_simultaneous_dps=0
    ):
        """
        Represents a Tuya device.

        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            cid (str): Optional sub device id. Default to None.
            node_id (str): alias for cid
            parent (object): gateway device this device is a child of

        Attributes:
            port (int): The port to connect to.
        """
        # Initialize the async wrapper with proper parent handling
        parent_async = parent._async_impl if parent and hasattr(parent, '_async_impl') else parent
        
        super().__init__(
            XenonDeviceAsync,
            dev_id=dev_id, address=address, local_key=local_key,
            dev_type=dev_type, connection_timeout=connection_timeout,
            version=version, persist=persist, cid=cid, node_id=node_id,
            parent=parent_async,
            connection_retry_limit=connection_retry_limit,
            connection_retry_delay=connection_retry_delay,
            port=port, max_simultaneous_dps=max_simultaneous_dps
        )
        
        # For backward compatibility, expose key attributes directly
        self.id = dev_id
        self.address = address
        self.cid = cid if cid else node_id
        self.port = port
    
    def _register_child(self, child):
        """Register a child device (for gateway devices)"""
        # Need to register the child's async implementation
        child_async = child._async_impl if hasattr(child, '_async_impl') else child
        self._async_impl._register_child(child_async)


# Module-level constants for backward compatibility
TCPPORT = 6668  # Default port
