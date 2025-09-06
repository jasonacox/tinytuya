#!/usr/bin/env python3
"""
Simple tests for CoverDevice wrapper implementation

Tests basic functionality of the CoverDevice sync wrapper.
"""

import unittest
from unittest.mock import patch

# Python 3.7 compatibility
from .test_compat import AsyncMock

from tinytuya import CoverDevice
from tinytuya.CoverDeviceAsync import CoverDeviceAsync


class TestCoverDevice(unittest.TestCase):
    """Test CoverDevice basic functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "test_cover_id"
        self.device_ip = "192.168.1.100"
        self.local_key = "test_key_123"
        self.version = 3.3
        
    def test_cover_device_initialization(self):
        """Test CoverDevice initialization."""
        cover = CoverDevice(
            self.device_id, 
            self.device_ip, 
            self.local_key, 
            version=self.version
        )
        
        # Test basic attributes
        self.assertEqual(cover.id, self.device_id)
        self.assertEqual(cover.address, self.device_ip)
        self.assertEqual(cover.version, self.version)
        
        # Test async implementation exists
        self.assertTrue(hasattr(cover, '_async_impl'))
        self.assertIsInstance(cover._async_impl, CoverDeviceAsync)
        
        # Test runner exists
        self.assertTrue(hasattr(cover, '_runner'))
    
    def test_cover_methods_exist(self):
        """Test that cover-specific methods exist."""
        cover = CoverDevice(
            self.device_id, 
            self.device_ip, 
            self.local_key, 
            version=self.version
        )
        
        # Test cover-specific methods
        self.assertTrue(hasattr(cover, 'open_cover'))
        self.assertTrue(hasattr(cover, 'close_cover'))
        self.assertTrue(hasattr(cover, 'stop_cover'))
        self.assertTrue(callable(cover.open_cover))
        self.assertTrue(callable(cover.close_cover))
        self.assertTrue(callable(cover.stop_cover))
    
    def test_inherited_methods_exist(self):
        """Test that inherited device methods exist."""
        cover = CoverDevice(
            self.device_id, 
            self.device_ip, 
            self.local_key, 
            version=self.version
        )
        
        # Test inherited methods via __getattr__
        inherited_methods = ['status', 'turn_on', 'turn_off', 'set_timer']
        for method_name in inherited_methods:
            self.assertTrue(hasattr(cover, method_name), 
                          f"Missing inherited method: {method_name}")
            self.assertTrue(callable(getattr(cover, method_name)),
                          f"Method {method_name} is not callable")
    
    def test_cover_method_delegation(self):
        """Test that cover methods properly delegate to async implementation."""
        cover = CoverDevice(
            self.device_id, 
            self.device_ip, 
            self.local_key, 
            version=self.version
        )
        
        # Mock the async implementation to prevent actual device calls
        with patch.object(cover._async_impl, 'open_cover', new_callable=AsyncMock) as mock_open, \
             patch.object(cover._async_impl, 'close_cover', new_callable=AsyncMock) as mock_close, \
             patch.object(cover._async_impl, 'stop_cover', new_callable=AsyncMock) as mock_stop:
            
            mock_open.return_value = {"success": True}
            mock_close.return_value = {"success": True}
            mock_stop.return_value = {"success": True}
            
            # Test each cover method
            result = cover.open_cover()
            self.assertEqual(result, {"success": True})
            mock_open.assert_called_once()
            
            result = cover.close_cover()
            self.assertEqual(result, {"success": True})
            mock_close.assert_called_once()
            
            result = cover.stop_cover()
            self.assertEqual(result, {"success": True})
            mock_stop.assert_called_once()
    
    def test_property_delegation(self):
        """Test property access delegation."""
        cover = CoverDevice(
            self.device_id, 
            self.device_ip, 
            self.local_key, 
            version=self.version
        )
        
        # Test property getters
        self.assertEqual(cover.id, cover._async_impl.id)
        self.assertEqual(cover.address, cover._async_impl.address)
        self.assertEqual(cover.version, cover._async_impl.version)
        
        # Test property setters
        cover.sendWait = 0.2
        self.assertEqual(cover._async_impl.sendWait, 0.2)


if __name__ == '__main__':
    unittest.main()
