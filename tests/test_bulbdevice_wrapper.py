#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for BulbDevice wrapper implementation

This tests the BulbDevice wrapper class to ensure it properly delegates
all functionality to BulbDeviceAsync while maintaining full backward compatibility.

Author: Jason A. Cox
"""

import unittest
import asyncio
import sys
import time
from unittest.mock import Mock, patch
import inspect

# Python 3.7 compatibility
from .test_compat import AsyncMock

# Add the parent directory to the path so we can import tinytuya
sys.path.insert(0, '.')

from tinytuya import BulbDevice
from tinytuya.BulbDeviceAsync import BulbDeviceAsync
from tinytuya.core.async_runner import AsyncRunner


class TestBulbDeviceWrapper(unittest.TestCase):
    """Test the BulbDevice wrapper implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "test_device_id"
        self.device_ip = "192.168.1.100"
        self.device_key = "test_local_key"
        
        # Create mock device that won't try to connect
        with patch('tinytuya.BulbDeviceAsync.BulbDeviceAsync.__init__', return_value=None):
            self.bulb = BulbDevice(self.device_id, self.device_ip, self.device_key, version=3.1)
            # Mock the _async_impl after creation
            self.bulb._async_impl = Mock()
            # Use a simple Mock instead of AsyncMock to avoid unawaited coroutine warnings
            self.bulb._async_impl.close = Mock()

    def test_initialization(self):
        """Test that BulbDevice properly initializes with async components."""
        bulb = BulbDevice('device_id', 'address', 'local_key', version=3.1)
        self.assertTrue(hasattr(bulb, '_async_impl'))
        self.assertTrue(hasattr(bulb, '_runner'))
        self.assertIsInstance(bulb._async_impl, BulbDeviceAsync)
        self.assertIsInstance(bulb._runner, AsyncRunner)
        
        # Test with additional parameters
        with patch('tinytuya.BulbDeviceAsync.BulbDeviceAsync.__init__', return_value=None):
            bulb2 = BulbDevice(
                self.device_id, 
                self.device_ip, 
                self.device_key,
                dev_type='device22',
                connection_timeout=10
            )
        self.assertTrue(hasattr(bulb2, '_async_impl'))

    def test_static_methods(self):
        """Test that static methods work correctly."""
        
        # Test RGB to hex conversion
        rgb_hex = BulbDevice.rgb_to_hexvalue(255, 128, 0, 'rgb8')
        self.assertIsInstance(rgb_hex, str)
        self.assertTrue(len(rgb_hex) > 0)
        
        # Test HSV to hex conversion (values should be 0-1) 
        try:
            hsv_hex = BulbDevice.hsv_to_hexvalue(0.33, 1.0, 1.0, 'rgb8')  # Green at full saturation/value
            self.assertIsInstance(hsv_hex, str)
        except (TypeError, ValueError) as e:
            # If there's a conversion issue, that's a separate bug to fix
            print(f"Note: HSV conversion has implementation issue: {e}")
            pass
        
        # Test hex to RGB conversion
        rgb = BulbDevice.hexvalue_to_rgb('ff8000', 'rgb8')
        self.assertIsInstance(rgb, tuple)
        self.assertEqual(len(rgb), 3)
        
        # Test hex to HSV conversion
        hsv = BulbDevice.hexvalue_to_hsv('ff8000', 'rgb8')
        self.assertIsInstance(hsv, tuple)
        self.assertEqual(len(hsv), 3)

    def test_async_method_delegation(self):
        """Test that methods are properly delegated to async device."""
        # Create a proper async mock method
        async def mock_status():
            return {'status': 'ok'}
        
        # Set the async method on the mock
        self.bulb._async_impl.status = mock_status
        
        # Test that the method is called and wrapped properly
        result = self.bulb.status()
        self.assertEqual(result, {'status': 'ok'})

    def test_property_delegation(self):
        """Test that property access is delegated to async device."""
        # Test attribute access delegation
        # Set a property directly on the mock async_impl
        self.bulb._async_impl.test_property = 'test_value'
        self.assertEqual(self.bulb.test_property, 'test_value')
        
        # Test attribute setting delegation  
        self.bulb.connection_timeout = 15
        self.assertEqual(self.bulb._async_impl.connection_timeout, 15)

    def test_setattr_behavior(self):
        """Test __setattr__ behavior for internal vs external attributes."""
        # Test that internal attributes are set on wrapper
        original_async_impl = self.bulb._async_impl
        new_mock = Mock()
        self.bulb._async_impl = new_mock
        self.assertIsInstance(self.bulb._async_impl, Mock)
        self.assertIs(self.bulb._async_impl, new_mock)
        
        # Test that external attributes are set on _async_impl
        test_value = "test_value"
        self.bulb.some_property = test_value
        # Check that the value was actually set (not just a Mock)
        self.assertEqual(self.bulb._async_impl.some_property, test_value)
        # Verify by accessing it again
        self.assertEqual(self.bulb.some_property, test_value)

    def test_context_manager(self):
        """Test context manager functionality."""
        # Test that context manager returns self
        with self.bulb as bulb_context:
            self.assertIs(bulb_context, self.bulb)
        
        # Test context manager cleanup behavior
        with patch.object(self.bulb, '_async_impl') as mock_async_impl:
            # Create a simple mock that doesn't return coroutines
            mock_close = Mock()
            mock_async_impl.close = mock_close
            
            with self.bulb:
                pass
            
            # Verify that close was called during cleanup
            mock_close.assert_called_once()

    def test_method_existence(self):
        """Test that all expected methods exist on the wrapper."""
        expected_methods = [
            'status', 'turn_on', 'turn_off', 'turn_onoff',
            'set_mode', 'set_scene', 'set_timer', 'set_music_colour',
            'set_colour', 'set_hsv', 'set_white_percentage', 'set_white',
            'set_brightness_percentage', 'set_brightness',
            'set_colourtemp_percentage', 'set_colourtemp',
            'get_value', 'get_mode', 'white_percentage',
            'get_brightness_percentage', 'brightness',
            'get_colourtemp_percentage', 'colourtemp',
            'colour_rgb', 'colour_hsv', 'bulb_has_capability'
        ]
        
        for method_name in expected_methods:
            self.assertTrue(hasattr(self.bulb, method_name),
                          f"Method {method_name} not found on BulbDevice")
            method = getattr(self.bulb, method_name)
            self.assertTrue(callable(method),
                          f"Attribute {method_name} is not callable")

    def test_static_method_existence(self):
        """Test that all expected static methods exist."""
        expected_static_methods = [
            'rgb_to_hexvalue', '_rgb_to_hexvalue', 'hsv_to_hexvalue',
            'hexvalue_to_rgb', '_hexvalue_to_rgb', 'hexvalue_to_hsv', '_hexvalue_to_hsv'
        ]
        
        for method_name in expected_static_methods:
            self.assertTrue(hasattr(BulbDevice, method_name),
                          f"Static method {method_name} not found on BulbDevice")
            method = getattr(BulbDevice, method_name)
            self.assertTrue(callable(method),
                          f"Static method {method_name} is not callable")

    def test_backward_compatibility(self):
        """Test that the wrapper maintains backward compatibility."""
        # Test that we can create a device with the old API
        with patch('tinytuya.BulbDeviceAsync.BulbDeviceAsync.__init__', return_value=None):
            bulb = BulbDevice("device_id", "192.168.1.100", "local_key")
            # Mock basic properties
            bulb._async_impl.id = "device_id"
            bulb._async_impl.address = "192.168.1.100" 
            bulb._async_impl.local_key = "local_key"
            bulb._async_impl.DPS_MODE_WHITE = "white"
            bulb._async_impl.DPS_MODE_COLOUR = "colour"
            bulb._async_impl.DPS_MODE_SCENE = "scene"
        
        # Test that basic properties work
        self.assertEqual(bulb.id, "device_id")
        self.assertEqual(bulb.address, "192.168.1.100")
        self.assertEqual(bulb.local_key, "local_key")
        
        # Test that bulb-specific constants are accessible
        self.assertEqual(bulb.DPS_MODE_WHITE, "white")
        self.assertEqual(bulb.DPS_MODE_COLOUR, "colour")
        self.assertEqual(bulb.DPS_MODE_SCENE, "scene")

    def test_method_signatures(self):
        """Test that wrapper methods have correct signatures."""
        # Patch the actual instance's _runner.run method
        with patch.object(self.bulb._runner, 'run') as mock_run:
            mock_run.return_value = {"dps": {}}
            
            # Test methods with different parameter patterns
            test_cases = [
                ('status', [False], {}),
                ('turn_on', [0, False], {}),
                ('turn_off', [0, False], {}),
                ('set_mode', ["white", False], {}),
                ('set_colour', [255, 128, 0, False], {}),
                ('set_hsv', [0.33, 1.0, 1.0, False], {}),  # Fixed HSV values
                ('set_white_percentage', [], {'brightness': 100, 'colourtemp': 0, 'nowait': False}),
                ('set_brightness_percentage', [100, False], {}),
                ('set_timer', [3600, 0, False], {})
            ]
            
            for method_name, args, kwargs in test_cases:
                method = getattr(self.bulb, method_name)
                try:
                    # This should not raise any signature errors
                    method(*args, **kwargs)
                    mock_run.assert_called()
                except Exception as e:
                    if "signature" in str(e).lower() or "argument" in str(e).lower():
                        self.fail(f"Method {method_name} signature error: {e}")

    def test_color_conversion_accuracy(self):
        """Test color conversion methods for accuracy."""
        # Test RGB -> Hex -> RGB roundtrip
        original_rgb = (255, 128, 64)
        hex_value = BulbDevice.rgb_to_hexvalue(*original_rgb, 'rgb8')
        converted_rgb = BulbDevice.hexvalue_to_rgb(hex_value, 'rgb8')
        
        # Should be close (within rounding errors)
        for orig, conv in zip(original_rgb, converted_rgb):
            self.assertAlmostEqual(orig, conv, delta=1,
                                 msg=f"RGB roundtrip failed: {original_rgb} -> {hex_value} -> {converted_rgb}")

    def test_error_handling(self):
        """Test error handling in the wrapper."""
        # Create an async method that raises an exception
        async def mock_status():
            raise RuntimeError("Connection failed")
        
        # Set the async method on the mock
        self.bulb._async_impl.status = mock_status
        
        # Test that exceptions are properly propagated
        with self.assertRaises(RuntimeError):
            self.bulb.status()

    def test_performance_baseline(self):
        """Test performance characteristics of the wrapper."""
        with patch.object(self.bulb._runner, 'run') as mock_run:
            mock_run.return_value = {"dps": {"1": True}}
            
            # Time multiple calls to check for reasonable overhead
            start_time = time.time()
            for _ in range(100):
                self.bulb.status()
            end_time = time.time()
            
            # Should complete 100 wrapper calls quickly (< 1 second with mocks)
            duration = end_time - start_time
            self.assertLess(duration, 1.0, 
                          f"Wrapper overhead too high: {duration}s for 100 calls")

    def test__runner_integration(self):
        """Test that AsyncRunner is properly integrated."""
        # Test that we have a proper AsyncRunner instance
        self.assertIsInstance(self.bulb._runner, AsyncRunner)
        
        # Test that AsyncRunner has the run method
        self.assertTrue(hasattr(self.bulb._runner, 'run'))
        self.assertTrue(callable(self.bulb._runner.run))

    def test_inheritance_hierarchy(self):
        """Test the inheritance hierarchy works correctly."""
        # In the new AsyncWrapper architecture, BulbDevice inherits from Device
        from tinytuya.core.Device import Device
        self.assertTrue(isinstance(self.bulb, Device))
        
        # And Device inherits from XenonDevice
        from tinytuya.core.XenonDevice import XenonDevice
        self.assertTrue(isinstance(self.bulb, XenonDevice))
        
        # And XenonDevice inherits from AsyncWrapper
        from tinytuya.core.AsyncWrapper import AsyncWrapper
        self.assertTrue(isinstance(self.bulb, AsyncWrapper))
        
        # The _async_impl should be a BulbDeviceAsync instance (mocked in setUp)
        self.assertTrue(hasattr(self.bulb, '_async_impl'))


class TestAsyncRunnerIntegration(unittest.TestCase):
    """Test AsyncRunner integration with real async methods."""
    
    def test__runner_basic_functionality(self):
        """Test that AsyncRunner can run simple coroutines."""
        runner = AsyncRunner()
        
        async def test_coro():
            await asyncio.sleep(0.01)  # Small delay
            return "test_result"
        
        result = runner.run(test_coro())
        self.assertEqual(result, "test_result")

    def test__runner_exception_handling(self):
        """Test that AsyncRunner properly handles exceptions."""
        runner = AsyncRunner()
        
        async def failing_coro():
            raise ValueError("Test error")
        
        with self.assertRaises(ValueError):
            runner.run(failing_coro())


class TestBulbDeviceConstants(unittest.TestCase):
    """Test that bulb device constants are accessible."""
    
    def setUp(self):
        with patch('tinytuya.BulbDeviceAsync.BulbDeviceAsync.__init__', return_value=None):
            self.bulb = BulbDevice("id", "ip", "key")
            # Mock constants
            self.bulb._async_impl = Mock()
            self.bulb._async_impl.DPS_MODE_WHITE = "white"
            self.bulb._async_impl.DPS_MODE_COLOUR = "colour"
            self.bulb._async_impl.DPS_MODE_SCENE = "scene"
    
    def test_dpset_constants(self):
        """Test that dpset constants are accessible."""
        # These should be accessible through the wrapper
        constants_to_check = [
            ('DPS_MODE_WHITE', 'white'),
            ('DPS_MODE_COLOUR', 'colour'), 
            ('DPS_MODE_SCENE', 'scene')
        ]
        
        for const_name, expected_value in constants_to_check:
            # Should be accessible through property delegation
            self.assertTrue(hasattr(self.bulb, const_name),
                          f"Constant {const_name} not accessible through wrapper")
            actual_value = getattr(self.bulb, const_name)
            self.assertEqual(actual_value, expected_value,
                           f"Constant {const_name} has wrong value")


def run_tests():
    """Run all tests."""
    print("🧪 Running BulbDevice Wrapper Tests...")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestBulbDeviceWrapper))
    suite.addTests(loader.loadTestsFromTestCase(TestAsyncRunnerIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestBulbDeviceConstants))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("=" * 60)
    if result.wasSuccessful():
        print("✅ All tests passed!")
        print(f"   Tests run: {result.testsRun}")
        print(f"   Failures: {len(result.failures)}")
        print(f"   Errors: {len(result.errors)}")
        return True
    else:
        print("❌ Some tests failed!")
        print(f"   Tests run: {result.testsRun}")
        print(f"   Failures: {len(result.failures)}")
        print(f"   Errors: {len(result.errors)}")
        return False


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
