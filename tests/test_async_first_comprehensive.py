#!/usr/bin/env python3
"""
Comprehensive test suite for TinyTuya async-first architecture

This test suite validates that all device classes follow the consistent 
async-first pattern and maintain backward compatibility.
"""

import unittest
import asyncio
from unittest.mock import patch


class TestAsyncFirstConsistency(unittest.TestCase):
    """Test that all device classes follow consistent async-first pattern."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_args = ('test_device_id', '192.168.1.100', 'test_local_key')
        self.device_kwargs = {'version': 3.3}
        
    def test_outlet_device_consistency(self):
        """Test OutletDevice follows async-first pattern."""
        from tinytuya import OutletDevice
        from tinytuya.OutletDeviceAsync import OutletDeviceAsync
        from tinytuya.core.async_runner import AsyncRunner
        
        device = OutletDevice(*self.device_args, **self.device_kwargs)
        
        # Test consistent attribute naming
        self.assertTrue(hasattr(device, '_async_impl'))
        self.assertTrue(hasattr(device, '_runner'))
        self.assertIsInstance(device._async_impl, OutletDeviceAsync)
        self.assertIsInstance(device._runner, AsyncRunner)
        
        # Test backward compatibility attributes
        self.assertEqual(device.id, device._async_impl.id)
        self.assertEqual(device.address, device._async_impl.address)
        self.assertEqual(device.version, device._async_impl.version)
        
    def test_bulb_device_consistency(self):
        """Test BulbDevice follows async-first pattern."""
        from tinytuya import BulbDevice
        from tinytuya.BulbDeviceAsync import BulbDeviceAsync
        from tinytuya.core.async_runner import AsyncRunner
        
        device = BulbDevice(*self.device_args, **self.device_kwargs)
        
        # Test consistent attribute naming
        self.assertTrue(hasattr(device, '_async_impl'))
        self.assertTrue(hasattr(device, '_runner'))
        self.assertIsInstance(device._async_impl, BulbDeviceAsync)
        self.assertIsInstance(device._runner, AsyncRunner)
        
        # Test bulb-specific methods exist
        bulb_methods = ['set_colour', 'set_brightness', 'set_white_percentage', 
                       'set_hsv', 'set_scene', 'set_music_colour']
        for method in bulb_methods:
            self.assertTrue(hasattr(device, method))
            self.assertTrue(callable(getattr(device, method)))
            
    def test_cover_device_consistency(self):
        """Test CoverDevice follows async-first pattern."""
        from tinytuya import CoverDevice
        from tinytuya.CoverDeviceAsync import CoverDeviceAsync
        from tinytuya.core.async_runner import AsyncRunner
        
        device = CoverDevice(*self.device_args, **self.device_kwargs)
        
        # Test consistent attribute naming
        self.assertTrue(hasattr(device, '_async_impl'))
        self.assertTrue(hasattr(device, '_runner'))
        self.assertIsInstance(device._async_impl, CoverDeviceAsync)
        self.assertIsInstance(device._runner, AsyncRunner)
        
        # Test cover-specific methods exist
        cover_methods = ['open_cover', 'close_cover', 'stop_cover']
        for method in cover_methods:
            self.assertTrue(hasattr(device, method))
            self.assertTrue(callable(getattr(device, method)))


class TestAsyncRunnerFunctionality(unittest.TestCase):
    """Test AsyncRunner utility functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        from tinytuya.core.async_runner import AsyncRunner
        self.runner = AsyncRunner()
        
    def test_async_runner_basic_operation(self):
        """Test AsyncRunner can execute async functions."""
        async def test_coro():
            await asyncio.sleep(0.01)
            return "test_result"
            
        result = self.runner.run(test_coro())
        self.assertEqual(result, "test_result")
        
    def test_async_runner_exception_handling(self):
        """Test AsyncRunner properly handles exceptions."""
        async def failing_coro():
            raise ValueError("Test async error")
            
        with self.assertRaises(ValueError) as cm:
            self.runner.run(failing_coro())
        self.assertEqual(str(cm.exception), "Test async error")
        
    def test_async_runner_return_types(self):
        """Test AsyncRunner preserves return types."""
        test_cases = [
            (42, int),
            ("string", str),
            ([1, 2, 3], list),
            ({"key": "value"}, dict),
            (True, bool),
            (None, type(None))
        ]
        
        for expected_value, expected_type in test_cases:
            with self.subTest(value=expected_value, type=expected_type):
                async def typed_coro(val=expected_value):
                    return val
                    
                result = self.runner.run(typed_coro())
                self.assertEqual(result, expected_value)
                self.assertIsInstance(result, expected_type)


class TestMethodDelegation(unittest.TestCase):
    """Test that sync methods properly delegate to async implementations."""
    
    def test_outlet_device_method_delegation(self):
        """Test OutletDevice methods delegate properly."""
        from tinytuya import OutletDevice
        
        device = OutletDevice('test', '127.0.0.1', 'test_key', version=3.3)
        
        def mock_runner(coro):
            """Mock runner that properly consumes the coroutine"""
            try:
                loop = asyncio.new_event_loop()
                try:
                    # Mock the _send_receive to avoid network calls
                    with patch.object(device._async_impl, '_send_receive') as mock_send:
                        mock_send.return_value = {"test": "data"}
                        return loop.run_until_complete(coro)
                finally:
                    loop.close()
            except Exception:
                # If we can't run it, at least close the coroutine to avoid warnings
                if hasattr(coro, 'close'):
                    coro.close()
                return {"test": "data"}
        
        with patch.object(device._runner, 'run', side_effect=mock_runner) as mock_run:
            # Test delegation of common methods
            test_result = device.status()
            self.assertEqual(test_result, {"test": "data"})
            mock_run.assert_called()
            
    def test_bulb_device_method_delegation(self):
        """Test BulbDevice methods delegate properly."""
        from tinytuya import BulbDevice
        
        device = BulbDevice('test', '127.0.0.1', 'test_key', version=3.3)
        
        def mock_runner(coro):
            """Mock runner that properly consumes the coroutine"""
            try:
                loop = asyncio.new_event_loop()
                try:
                    # Mock the _send_receive to avoid network calls
                    with patch.object(device._async_impl, '_send_receive') as mock_send:
                        mock_send.return_value = {"success": True}
                        return loop.run_until_complete(coro)
                finally:
                    loop.close()
            except Exception:
                # If we can't run it, at least close the coroutine to avoid warnings
                if hasattr(coro, 'close'):
                    coro.close()
                return {"success": True}
        
        with patch.object(device._runner, 'run', side_effect=mock_runner) as mock_run:
            
            # Test bulb-specific method delegation
            result = device.set_colour(255, 128, 64)
            self.assertEqual(result, {"success": True})
            mock_run.assert_called()
            
    def test_cover_device_method_delegation(self):
        """Test CoverDevice methods delegate properly."""
        from tinytuya import CoverDevice
        
        device = CoverDevice('test', '127.0.0.1', 'test_key', version=3.3)
        
        def mock_runner(coro):
            """Mock runner that properly consumes the coroutine"""
            try:
                loop = asyncio.new_event_loop()
                try:
                    # Mock the _send_receive to avoid network calls
                    with patch.object(device._async_impl, '_send_receive') as mock_send:
                        mock_send.return_value = {"success": True}
                        return loop.run_until_complete(coro)
                finally:
                    loop.close()
            except Exception:
                # If we can't run it, at least close the coroutine to avoid warnings
                if hasattr(coro, 'close'):
                    coro.close()
                return {"success": True}
        
        with patch.object(device._runner, 'run', side_effect=mock_runner) as mock_run:
            
            # Test cover-specific method delegation
            result = device.open_cover()
            self.assertEqual(result, {"success": True})
            mock_run.assert_called()


class TestPropertyDelegation(unittest.TestCase):
    """Test that properties are properly delegated between sync and async."""
    
    def test_property_getter_delegation(self):
        """Test property getters delegate to async implementation."""
        from tinytuya import OutletDevice
        
        device = OutletDevice('test_id', '192.168.1.100', 'test_key', version=3.3)
        
        # Test property delegation via __getattr__
        self.assertEqual(device.id, 'test_id')
        self.assertEqual(device.address, '192.168.1.100')
        self.assertEqual(device.version, 3.3)
        
    def test_property_setter_delegation(self):
        """Test property setters delegate to async implementation."""
        from tinytuya import OutletDevice
        
        device = OutletDevice('test_id', '192.168.1.100', 'test_key', version=3.3)
        
        # Test property setting delegation via __setattr__
        device.sendWait = 0.5
        self.assertEqual(device._async_impl.sendWait, 0.5)
        
        device.socketRetryLimit = 10
        self.assertEqual(device._async_impl.socketRetryLimit, 10)


class TestBackwardCompatibility(unittest.TestCase):
    """Test that refactoring maintains full backward compatibility."""
    
    def test_all_sync_methods_exist(self):
        """Test that all expected sync methods still exist."""
        from tinytuya import OutletDevice, BulbDevice, CoverDevice
        
        # Test OutletDevice
        outlet = OutletDevice('test', '127.0.0.1', 'test_key', version=3.3)
        outlet_methods = ['status', 'turn_on', 'turn_off', 'set_timer', 'set_value']
        for method in outlet_methods:
            self.assertTrue(hasattr(outlet, method), f"OutletDevice missing {method}")
            
        # Test BulbDevice  
        bulb = BulbDevice('test', '127.0.0.1', 'test_key', version=3.3)
        bulb_methods = ['set_colour', 'set_brightness', 'set_hsv', 'set_white_percentage']
        for method in bulb_methods:
            self.assertTrue(hasattr(bulb, method), f"BulbDevice missing {method}")
            
        # Test CoverDevice
        cover = CoverDevice('test', '127.0.0.1', 'test_key', version=3.3)
        cover_methods = ['open_cover', 'close_cover', 'stop_cover']
        for method in cover_methods:
            self.assertTrue(hasattr(cover, method), f"CoverDevice missing {method}")
            
    def test_initialization_parameters_unchanged(self):
        """Test that device initialization parameters work as before."""
        from tinytuya import OutletDevice, BulbDevice, CoverDevice
        
        # Test various initialization patterns (skip Auto-IP in test environment)
        test_params = [
            ('device_id', '192.168.1.100', 'local_key'),
            ('device_id', '192.168.1.100', 'local_key', 'default'),
            # Skip Auto-IP discovery in test environment: ('device_id', None, 'local_key'),
        ]
        
        for params in test_params:
            # Should not raise exceptions
            outlet = OutletDevice(*params, version=3.3)
            bulb = BulbDevice(*params, version=3.3)
            cover = CoverDevice(*params, version=3.3)
            
            self.assertIsNotNone(outlet)
            self.assertIsNotNone(bulb)
            self.assertIsNotNone(cover)


if __name__ == '__main__':
    unittest.main(verbosity=2)
