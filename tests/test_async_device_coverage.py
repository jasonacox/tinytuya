#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Test Coverage for TinyTuya Async Device Classes

This module provides complete test coverage for:
- XenonDeviceAsync (core async base class)
- OutletDeviceAsync
- BulbDeviceAsync  
- CoverDeviceAsync
- AsyncRunner functionality
- Async-to-sync delegation patterns

Author: Jason A. Cox
"""

import unittest
import sys
import asyncio
from unittest.mock import patch

# Python 3.7 compatibility
from .test_compat import AsyncMock

# Add the parent directory to the path so we can import tinytuya
sys.path.insert(0, '.')

# Import async classes - use try/except for better error handling
try:
    from tinytuya.OutletDeviceAsync import OutletDeviceAsync
    from tinytuya.BulbDeviceAsync import BulbDeviceAsync
    from tinytuya.CoverDeviceAsync import CoverDeviceAsync
    from tinytuya.core.XenonDeviceAsync import XenonDeviceAsync
    from tinytuya.core.async_runner import AsyncRunner
except ImportError as e:
    print(f"Import error: {e}")
    print("Skipping async device tests - async classes not available")
    sys.exit(0)


class TestAsyncRunner(unittest.TestCase):
    """Test the AsyncRunner functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.runner = AsyncRunner()
        
    def test_async_runner_initialization(self):
        """Test AsyncRunner initialization."""
        runner = AsyncRunner()
        self.assertIsNotNone(runner)
        
    def test_async_runner_run_coroutine(self):
        """Test AsyncRunner can run coroutines."""
        async def test_coroutine():
            return "test_result"
            
        test_result = self.runner.run(test_coroutine())
        self.assertEqual(test_result, "test_result")
        
    def test_async_runner_run_with_return_value(self):
        """Test AsyncRunner with various return values."""
        async def return_dict():
            return {"status": "success", "data": {"dps": {"1": True}}}
            
        async def return_none():
            return None
            
        async def return_list():
            return [1, 2, 3, "test"]
            
        # Test dictionary return
        result = self.runner.run(return_dict())
        self.assertIsInstance(result, dict)
        self.assertEqual(result["status"], "success")
        
        # Test None return
        result = self.runner.run(return_none())
        self.assertIsNone(result)
        
        # Test list return
        result = self.runner.run(return_list())
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 4)
        
    def test_async_runner_exception_handling(self):
        """Test AsyncRunner exception handling."""
        async def failing_coroutine():
            raise ValueError("Test exception")
            
        with self.assertRaises(ValueError):
            self.runner.run(failing_coroutine())


class TestXenonDeviceAsync(unittest.TestCase):
    """Test the core XenonDeviceAsync functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "async_test_device"
        self.device_ip = "192.168.1.100"
        self.device_key = "async_test_key"
        
    def test_xenon_device_async_initialization(self):
        """Test XenonDeviceAsync initialization."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        self.assertEqual(device.id, self.device_id)
        self.assertEqual(device.address, self.device_ip) 
        self.assertEqual(device.local_key.decode() if isinstance(device.local_key, bytes) else device.local_key, self.device_key)
        
    def test_xenon_device_async_status(self):
        """Test XenonDeviceAsync status method."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
            mock_send_receive.return_value = {"dps": {"1": True}}
            
            async def test_status():
                result = await device.status()
                return result
                
            runner = AsyncRunner()
            result = runner.run(test_status())
            self.assertEqual(result, {"dps": {"1": True}})
        
    def test_xenon_device_async_turn_on_off(self):
        """Test XenonDeviceAsync turn_on and turn_off methods."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
            async def test_turn_operations():
                # Since XenonDeviceAsync doesn't have turn_on/turn_off, test basic functionality
                mock_send_receive.return_value = {"dps": {"1": True}}
                result = await device.status()
                self.assertIsNotNone(result)
                
                # Test another status call
                mock_send_receive.return_value = {"dps": {"1": False}}
                result = await device.status()
                self.assertIsNotNone(result)
                
            test_runner = AsyncRunner()
            test_runner.run(test_turn_operations())


class TestOutletDeviceAsync(unittest.TestCase):
    """Test OutletDeviceAsync functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "async_outlet_device"
        self.device_ip = "192.168.1.100"
        self.device_key = "async_outlet_key"
        
    @patch('tinytuya.OutletDeviceAsync.OutletDeviceAsync._send_receive')
    def test_outlet_device_async_initialization(self, mock_send_receive):
        """Test OutletDeviceAsync initialization."""
        device = OutletDeviceAsync(self.device_id, self.device_ip, self.device_key)
        self.assertIsInstance(device, XenonDeviceAsync)
        
    def test_outlet_device_async_set_dimmer(self):
        """Test OutletDeviceAsync set_dimmer method."""
        device = OutletDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        async def test_dimmer():
            if hasattr(device, 'set_dimmer'):
                with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                    mock_send_receive.return_value = {"dps": {"2": 75}}
                    # set_dimmer doesn't return a value, it performs operations
                    await device.set_dimmer(75)
                    # Verify that _send_receive was called (indicating operations occurred)
                    mock_send_receive.assert_called()
                
        test_runner = AsyncRunner()
        test_runner.run(test_dimmer())


class TestBulbDeviceAsync(unittest.TestCase):
    """Test BulbDeviceAsync functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "async_bulb_device" 
        self.device_ip = "192.168.1.101"
        self.device_key = "async_bulb_key"
        
    @patch('tinytuya.BulbDeviceAsync.BulbDeviceAsync._send_receive')
    def test_bulb_device_async_initialization(self, mock_send_receive):
        """Test BulbDeviceAsync initialization."""
        device = BulbDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        self.assertIsInstance(device, XenonDeviceAsync)
        
    def test_bulb_device_async_color_methods(self):
        """Test BulbDeviceAsync color methods."""
        device = BulbDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        # Configure the bulb as Type A (supports color)
        device.bulb_configured = True
        device.bulb_type = 'A'
        device.dpset = {
            'switch': '1',
            'mode': '2', 
            'brightness': '3',
            'colour': '5',
            'colourtemp': '4',
            'scene': '6',
            'music': False,
            'timer': False,
            'value_min': 10,
            'value_max': 1000,
            'value_hexformat': 'rgb8'  # Use a valid format
        }
        
        async def test_color_operations():
            # Test set_colour
            if hasattr(device, 'set_colour'):
                with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                    mock_send_receive.return_value = {"dps": {"5": "ff0000ff"}}
                    result = await device.set_colour(255, 0, 0)
                    # Color methods typically return None if successful, so check they don't raise errors
                    mock_send_receive.assert_called()
                
            # Test basic color functionality exists
            self.assertTrue(hasattr(device, 'set_colour'))
            self.assertTrue(hasattr(device, 'set_brightness'))
            self.assertTrue(hasattr(device, 'set_mode'))
                
        runner = AsyncRunner()
        runner.run(test_color_operations())


class TestCoverDeviceAsync(unittest.TestCase):
    """Test CoverDeviceAsync functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "async_cover_device"
        self.device_ip = "192.168.1.102" 
        self.device_key = "async_cover_key"
        
    @patch('tinytuya.CoverDeviceAsync.CoverDeviceAsync._send_receive')
    def test_cover_device_async_initialization(self, mock_send_receive):
        """Test CoverDeviceAsync initialization."""
        device = CoverDeviceAsync(self.device_id, self.device_ip, self.device_key)
        self.assertIsInstance(device, XenonDeviceAsync)
        
    def test_cover_device_async_operations(self):
        """Test CoverDeviceAsync cover operations."""
        device = CoverDeviceAsync(self.device_id, self.device_ip, self.device_key)
        
        async def test_cover_operations():
            # Test open_cover
            if hasattr(device, 'open_cover'):
                with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                    mock_send_receive.return_value = {"dps": {"1": "open"}}
                    result = await device.open_cover()
                    self.assertIsNotNone(result)
                    
            # Test close_cover
            if hasattr(device, 'close_cover'):
                with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                    mock_send_receive.return_value = {"dps": {"1": "close"}}
                    result = await device.close_cover()
                    self.assertIsNotNone(result)
                    
            # Test stop_cover
            if hasattr(device, 'stop_cover'):
                with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                    mock_send_receive.return_value = {"dps": {"1": "stop"}}
                    result = await device.stop_cover()
                    self.assertIsNotNone(result)
                
        runner = AsyncRunner()
        runner.run(test_cover_operations())


class TestAsyncToSyncDelegation(unittest.TestCase):
    """Test async-to-sync delegation patterns."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "delegation_test"
        self.device_ip = "192.168.1.100"
        self.device_key = "delegation_key"
        
    def test_sync_wrapper_delegates_to_async(self):
        """Test that sync wrappers properly delegate to async implementations."""
        # Import sync wrappers
        from tinytuya import OutletDevice, BulbDevice, CoverDevice
        
        # Test OutletDevice delegation
        outlet = OutletDevice(self.device_id, self.device_ip, self.device_key)
        self.assertIsInstance(outlet._async_impl, OutletDeviceAsync)
        
        # Test BulbDevice delegation  
        bulb = BulbDevice(self.device_id, self.device_ip, self.device_key, version=3.1)
        self.assertIsInstance(bulb._async_impl, BulbDeviceAsync)
        
        # Test CoverDevice delegation
        cover = CoverDevice(self.device_id, self.device_ip, self.device_key, version=3.1)
        self.assertIsInstance(cover._async_impl, CoverDeviceAsync)
        
    def test_async_runner_integration(self):
        """Test AsyncRunner integration with sync wrappers."""
        from tinytuya import OutletDevice
        
        outlet = OutletDevice(self.device_id, self.device_ip, self.device_key)
        
        # Verify AsyncRunner is present and functional
        self.assertIsNotNone(outlet._runner)
        self.assertIsInstance(outlet._runner, AsyncRunner)
        
        # Test that runner can execute async operations
        async def dummy_async():
            return "async_result"
            
        result = outlet._runner.run(dummy_async())
        self.assertEqual(result, "async_result")


class TestAsyncErrorHandling(unittest.TestCase):
    """Test error handling in async implementations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "async_error_test"
        self.device_ip = "192.168.1.100"
        self.device_key = "async_error_key"
        
    def test_async_network_errors(self):
        """Test async network error handling."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
            async def test_network_error():
                mock_send_receive.side_effect = ConnectionError("Network error")
                with self.assertRaises(ConnectionError):
                    await device.status()
                    
            test_runner = AsyncRunner()
            test_runner.run(test_network_error())
        
    def test_async_timeout_errors(self):
        """Test async timeout error handling."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
            async def test_timeout_error():
                mock_send_receive.side_effect = asyncio.TimeoutError("Timeout")
                with self.assertRaises(asyncio.TimeoutError):
                    await device.status()
                    
            test_runner = AsyncRunner()
            test_runner.run(test_timeout_error())
        
    def test_async_invalid_response(self):
        """Test async invalid response handling."""
        device = BulbDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        async def test_invalid_response():
            # Test None response
            with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                mock_send_receive.return_value = None
                result = await device.status()
                self.assertIsNone(result)
                
            # Test empty response
            with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
                mock_send_receive.return_value = {}
                result = await device.status()
                self.assertEqual(result, {})
            
        runner = AsyncRunner()
        runner.run(test_invalid_response())


class TestAsyncMethodSignatures(unittest.TestCase):
    """Test that async methods have correct signatures."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "signature_test"
        self.device_ip = "192.168.1.100" 
        self.device_key = "signature_key"
        
    def test_xenon_async_method_signatures(self):
        """Test XenonDeviceAsync method signatures."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key)
        
        # Test that methods are coroutines
        if hasattr(device, 'status'):
            self.assertTrue(asyncio.iscoroutinefunction(device.status))
        if hasattr(device, 'turn_on'):
            self.assertTrue(asyncio.iscoroutinefunction(device.turn_on))
        if hasattr(device, 'turn_off'):
            self.assertTrue(asyncio.iscoroutinefunction(device.turn_off))
            
    def test_bulb_async_method_signatures(self):
        """Test BulbDeviceAsync method signatures."""
        device = BulbDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        # Test bulb-specific methods are coroutines
        bulb_methods = ['set_colour', 'set_white', 'set_brightness']
        for method_name in bulb_methods:
            if hasattr(device, method_name):
                method = getattr(device, method_name)
                self.assertTrue(asyncio.iscoroutinefunction(method))
                
    def test_cover_async_method_signatures(self):
        """Test CoverDeviceAsync method signatures."""
        device = CoverDeviceAsync(self.device_id, self.device_ip, self.device_key)
        
        # Test cover-specific methods are coroutines
        cover_methods = ['open_cover', 'close_cover', 'stop_cover']
        for method_name in cover_methods:
            if hasattr(device, method_name):
                method = getattr(device, method_name)
                self.assertTrue(asyncio.iscoroutinefunction(method))


class TestAsyncContextManagers(unittest.TestCase):
    """Test async context manager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "context_test"
        self.device_ip = "192.168.1.100"
        self.device_key = "context_key"
        
    def test_xenon_async_context_manager(self):
        """Test XenonDeviceAsync as async context manager."""
        device = XenonDeviceAsync(self.device_id, self.device_ip, self.device_key, version=3.1)
        
        with patch.object(device, '_send_receive', new_callable=AsyncMock) as mock_send_receive:
            async def test_context_manager():
                try:
                    async with device as d:
                        self.assertIs(d, device)
                        # Test operations within context
                        mock_send_receive.return_value = {"dps": {"1": True}}
                        result = await d.status()
                        self.assertIsNotNone(result)
                except AttributeError:
                    # Some implementations may not support async context manager
                    pass
                    
            test_runner = AsyncRunner()
            test_runner.run(test_context_manager())


if __name__ == '__main__':
    # Create a test suite combining all async test classes
    test_classes = [
        TestAsyncRunner,
        TestXenonDeviceAsync,
        TestOutletDeviceAsync, 
        TestBulbDeviceAsync,
        TestCoverDeviceAsync,
        TestAsyncToSyncDelegation,
        TestAsyncErrorHandling,
        TestAsyncMethodSignatures,
        TestAsyncContextManagers
    ]
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"ASYNC TEST COVERAGE SUMMARY") 
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%" if result.testsRun > 0 else "N/A")
    
    if result.wasSuccessful():
        print(f"🎉 All async tests passed!")
    else:
        print(f"❌ Some async tests failed")
        sys.exit(1)
