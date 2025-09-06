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


class XenonDevice(object):
    """
    Synchronous wrapper for XenonDeviceAsync.
    
    All methods delegate to the async implementation using AsyncRunner.
    This maintains full backward compatibility while eliminating code duplication.
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
        # Create the async implementation
        self._async_impl = XenonDeviceAsync(
            dev_id=dev_id, address=address, local_key=local_key,
            dev_type=dev_type, connection_timeout=connection_timeout,
            version=version, persist=persist, cid=cid, node_id=node_id,
            parent=parent._async_impl if parent else None,
            connection_retry_limit=connection_retry_limit,
            connection_retry_delay=connection_retry_delay,
            port=port, max_simultaneous_dps=max_simultaneous_dps
        )
        
        # Create the async runner for delegation
        self._runner = AsyncRunner()
        
        # For backward compatibility, expose key attributes directly
        self.id = dev_id
        self.address = address
        self.cid = cid if cid else node_id
        self.port = port

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
        if name.startswith('_') or name in ('id', 'address', 'cid', 'port'):
            # Set on wrapper
            super().__setattr__(name, value)
        else:
            # Delegate to async implementation
            if hasattr(self, '_async_impl'):
                setattr(self._async_impl, name, value)
            else:
                # During __init__, before _async_impl exists
                super().__setattr__(name, value)

    # ---- Core Communication Methods ----

    def status(self, nowait=False):
        """Get device status"""
        return self._runner.run(self._async_impl.status(nowait))

    def cached_status(self, historic=False, nowait=False):
        """Get cached device status"""
        return self._runner.run(self._async_impl.cached_status(historic, nowait))

    def heartbeat(self, nowait=False):
        """Send heartbeat to device"""
        return self._runner.run(self._async_impl.heartbeat(nowait))

    def subdev_query(self, nowait=False):
        """Query sub-device status (for gateway devices)"""
        return self._runner.run(self._async_impl.subdev_query(nowait))

    def updatedps(self, index=None, nowait=False):
        """Request device to update DPS values"""
        return self._runner.run(self._async_impl.updatedps(index, nowait))

    def set_value(self, index, value, nowait=False):
        """Set device DPS value"""
        return self._runner.run(self._async_impl.set_value(index, value, nowait))

    def set_multiple_values(self, dps_dict, nowait=False):
        """Set multiple DPS values"""
        return self._runner.run(self._async_impl.set_multiple_values(dps_dict, nowait))

    def turn_on(self, switch=1, nowait=False):
        """Turn device on"""
        return self._runner.run(self._async_impl.turn_on(switch, nowait))

    def turn_off(self, switch=1, nowait=False):
        """Turn device off"""
        return self._runner.run(self._async_impl.turn_off(switch, nowait))

    def set_timer(self, num_secs, dps_id=1, nowait=False):
        """Set device timer"""
        return self._runner.run(self._async_impl.set_timer(num_secs, dps_id, nowait))

    def generate_payload(self, command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None):
        """Generate payload for command"""
        return self._async_impl.generate_payload(command, data, gwId, devId, uid, rawData, reqType)

    # ---- Connection Management ----

    def close(self):
        """Close connection"""
        return self._runner.run(self._async_impl.close())

    # ---- Configuration Methods ----

    def set_version(self, version):
        """Set protocol version"""
        self._async_impl.set_version(version)

    def set_socketPersistent(self, persist):
        """Set socket persistence"""
        self._async_impl.set_socketPersistent(persist)

    def set_socketNODELAY(self, nodelay):
        """Set socket NODELAY option"""
        self._async_impl.set_socketNODELAY(nodelay)

    def set_socketTimeout(self, timeout):
        """Set socket timeout"""
        self._async_impl.set_socketTimeout(timeout)

    def set_sendWait(self, wait_time):
        """Set send wait time"""
        self._async_impl.set_sendWait(wait_time)

    def set_dpsUsed(self, dps_to_request):
        """Set DPS values to request"""
        self._async_impl.set_dpsUsed(dps_to_request)

    def set_retry(self, retry):
        """Set retry flag"""
        self._async_impl.set_retry(retry)

    # ---- Cache Management ----

    def cache_clear(self):
        """Clear device status cache"""
        self._async_impl.cache_clear()

    def add_dps_to_request(self, dp_indices):
        """Add DPS indices to request cache"""
        self._async_impl.add_dps_to_request(dp_indices)

    # ---- Advanced Methods ----

    def detect_available_dps(self):
        """Detect available DPS values"""
        return self._runner.run(self._async_impl.detect_available_dps())

    def receive(self):
        """Receive data from device"""
        return self._runner.run(self._async_impl.receive())

    def _send_receive(self, payload, minresponse=28, getresponse=True, decode_response=True):
        """Send payload to device and receive response"""
        return self._runner.run(self._async_impl._send_receive(payload, minresponse, getresponse, decode_response))

    def _send_receive_quick(self, payload, minresponse=28, getresponse=True):
        """Send payload to device and receive response (quick mode)"""  
        return self._runner.run(self._async_impl._send_receive_quick(payload, minresponse, getresponse))

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

    # ---- Child Device Management (for gateways) ----

    def _register_child(self, child):
        """Register a child device (for gateway devices)"""
        # Need to register the child's async implementation
        child_async = child._async_impl if hasattr(child, '_async_impl') else child
        self._async_impl._register_child(child_async)

    # ---- Context Manager Support ----

    def __enter__(self):
        """Enter synchronous context manager"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit synchronous context manager"""
        self.close()

# Re-export commonly used items for backward compatibility  
# payload_dict can be accessed via: from tinytuya.core.XenonDeviceAsync import payload_dict

# Module-level constants and utilities remain the same
TCPPORT = 6668  # Default port
