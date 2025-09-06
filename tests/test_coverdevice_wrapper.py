#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for CoverDevice wrapper implementation

This tests the CoverDevice wrapper class to ensure it properly delegates
all functionality to CoverDeviceAsync while maintaining full backward compatibility.

Author: Jason A. Cox
"""

import unittest
import asyncio
import sys
import time
from unittest.mock import Mock, patch, AsyncMock

# Add the parent directory to the path so we can import tinytuya
sys.path.insert(0, '.')

from tinytuya import CoverDevice
from tinytuya.CoverDeviceAsync import CoverDeviceAsync
from tinytuya.core import AsyncRunner


class TestCoverDeviceWrapper(unittest.TestCase):
    """Test the CoverDevice wrapper implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_id = "test_cover_id"
        self.device_ip = "192.168.1.100"
        self.device_key = "test_local_key"
        
        # Create mock device that won't try to connect
        with patch('tinytuya.CoverDeviceAsync.CoverDeviceAsync.__init__', return_value=None):
            self.cover = CoverDevice(self.device_id, self.device_ip, self.device_key, version=3.1)
            # Mock the _async_impl after creation
            self.cover._async_impl = Mock()
            self.cover._async_impl.close = AsyncMock()

    def test_initialization(self):
        """Test that CoverDevice properly initializes with async components."""
        cover = CoverDevice('device_id', 'address', 'local_key', version=3.1)
        self.assertTrue(hasattr(cover, '_async_impl'))
        self.assertTrue(hasattr(cover, '_runner'))
        self.assertIsInstance(cover._async_impl, CoverDeviceAsync)
        self.assertIsInstance(cover._runner, AsyncRunner)

    def test_cover_specific_methods(self):
        """Test cover-specific method delegation through AsyncRunner."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            mock_run.return_value = {"dps": {"1": "on"}}
            
            # Test open_cover method
            result = self.cover.open_cover()
            mock_run.assert_called()
            self.assertEqual(result, {"dps": {"1": "on"}})
            
            # Test close_cover method
            mock_run.return_value = {"dps": {"1": "off"}}
            result = self.cover.close_cover()
            mock_run.assert_called()
            self.assertEqual(result, {"dps": {"1": "off"}})
            
            # Test stop_cover method
            mock_run.return_value = {"dps": {"1": "stop"}}
            result = self.cover.stop_cover()
            mock_run.assert_called()
            self.assertEqual(result, {"dps": {"1": "stop"}})
            
            # Test methods with parameters
            result = self.cover.open_cover(switch=2, nowait=True)
            mock_run.assert_called()

    def test_inherited_method_delegation(self):
        """Test that inherited methods are properly delegated through AsyncRunner."""
        # Since CoverDevice uses __getattr__ forwarding, inherited methods
        # are directly accessed from the async device, not wrapped
        with patch.object(self.cover._async_impl, 'status', return_value={"dps": {"1": True, "2": "auto"}}) as mock_status:
            result = self.cover.status()
            mock_status.assert_called_once()
            self.assertEqual(result, {"dps": {"1": True, "2": "auto"}})
            
        with patch.object(self.cover._async_impl, 'turn_on', return_value={"dps": {"1": True}}) as mock_turn_on:
            result = self.cover.turn_on()
            mock_turn_on.assert_called_once()
            
        with patch.object(self.cover._async_impl, 'turn_off', return_value={"dps": {"1": False}}) as mock_turn_off:
            result = self.cover.turn_off()
            mock_turn_off.assert_called_once()

    def test_property_delegation(self):
        """Test that property access is delegated to async device."""
        # Test attribute access delegation
        with patch.object(self.cover._async_impl, 'id', 'test_cover_id'):
            self.assertEqual(self.cover.id, 'test_cover_id')
        
        # Test attribute setting delegation  
        self.cover.connection_timeout = 15
        self.assertEqual(self.cover._async_impl.connection_timeout, 15)

    def test_setattr_behavior(self):
        """Test __setattr__ behavior for internal vs external attributes."""
        # Test that internal attributes are set on wrapper
        self.cover._async_impl = Mock()
        self.assertIsInstance(self.cover._async_impl, Mock)
        
        # Test that external attributes are set on _async_impl
        test_value = "test_value"
        self.cover.some_property = test_value
        self.assertEqual(self.cover._async_impl.some_property, test_value)

    def test_context_manager(self):
        """Test context manager functionality."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            mock_run.return_value = None
            
            with self.cover as cover_context:
                self.assertIs(cover_context, self.cover)
            
            # Should call close() on exit
            mock_run.assert_called()

    def test_cover_method_existence(self):
        """Test that all expected cover methods exist on the wrapper."""
        expected_methods = [
            'open_cover', 'close_cover', 'stop_cover'
        ]
        
        for method_name in expected_methods:
            self.assertTrue(hasattr(self.cover, method_name),
                          f"Method {method_name} not found on CoverDevice")
            method = getattr(self.cover, method_name)
            self.assertTrue(callable(method),
                          f"Attribute {method_name} is not callable")

    def test_inherited_method_existence(self):
        """Test that inherited methods are accessible through the wrapper."""
        expected_inherited_methods = [
            'status', 'turn_on', 'turn_off', 'set_status', 'set_value',
            'heartbeat', 'set_timer', 'generate_payload'
        ]
        
        for method_name in expected_inherited_methods:
            self.assertTrue(hasattr(self.cover, method_name),
                          f"Inherited method {method_name} not found on CoverDevice")
            method = getattr(self.cover, method_name)
            self.assertTrue(callable(method),
                          f"Inherited method {method_name} is not callable")

    def test_backward_compatibility(self):
        """Test that the wrapper maintains backward compatibility."""
        # Test that we can create a device with the old API
        with patch('tinytuya.CoverDeviceAsync.CoverDeviceAsync.__init__', return_value=None):
            cover = CoverDevice("device_id", "192.168.1.100", "local_key")
            # Mock basic properties
            cover._async_impl.id = "device_id"
            cover._async_impl.address = "192.168.1.100" 
            cover._async_impl.local_key = "local_key"
        
        # Test that basic properties work
        self.assertEqual(cover.id, "device_id")
        self.assertEqual(cover.address, "192.168.1.100")
        self.assertEqual(cover.local_key, "local_key")

    def test_constants_access(self):
        """Test that CoverDevice constants are accessible."""
        # Mock the constants
        self.cover._async_impl.DPS_INDEX_MOVE = "1"
        self.cover._async_impl.DPS_INDEX_BL = "101"
        self.cover._async_impl.DPS_2_STATE = {
            "1": "movement",
            "101": "backlight",
        }
        
        # Test that constants are accessible through the wrapper
        self.assertEqual(self.cover.DPS_INDEX_MOVE, "1")
        self.assertEqual(self.cover.DPS_INDEX_BL, "101")
        self.assertIsInstance(self.cover.DPS_2_STATE, dict)
        self.assertEqual(self.cover.DPS_2_STATE["1"], "movement")

    def test_method_signatures(self):
        """Test that wrapper methods have correct signatures."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            mock_run.return_value = {"dps": {}}
            
            # Test cover methods with different parameter patterns
            test_cases = [
                ('open_cover', [], {}),
                ('open_cover', [2], {}),
                ('open_cover', [], {'switch': 2, 'nowait': False}),
                ('close_cover', [], {}),
                ('close_cover', [2, True], {}),
                ('stop_cover', [], {}),
                ('stop_cover', [], {'switch': 1, 'nowait': True})
            ]
            
            for method_name, args, kwargs in test_cases:
                method = getattr(self.cover, method_name)
                try:
                    # This should not raise any signature errors
                    method(*args, **kwargs)
                    mock_run.assert_called()
                except Exception as e:
                    if "signature" in str(e).lower() or "argument" in str(e).lower():
                        self.fail(f"Method {method_name} signature error: {e}")

    def test_error_handling(self):
        """Test error handling in the wrapper."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            # Test that exceptions are properly propagated
            mock_run.side_effect = RuntimeError("Connection failed")
            
            with self.assertRaises(RuntimeError):
                self.cover.open_cover()

    def test_performance_baseline(self):
        """Test performance characteristics of the wrapper."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            mock_run.return_value = {"dps": {"1": "on"}}
            
            # Time multiple calls to check for reasonable overhead
            start_time = time.time()
            for _ in range(100):
                self.cover.open_cover()
            end_time = time.time()
            
            # Should complete 100 wrapper calls quickly (< 1 second with mocks)
            duration = end_time - start_time
            self.assertLess(duration, 1.0, 
                          f"Wrapper overhead too high: {duration}s for 100 calls")

    def test__runner_integration(self):
        """Test that AsyncRunner is properly integrated."""
        # Test that we have a proper AsyncRunner instance
        self.assertIsInstance(self.cover._runner, AsyncRunner)
        
        # Test that AsyncRunner has the run method
        self.assertTrue(hasattr(self.cover._runner, 'run'))
        self.assertTrue(callable(self.cover._runner.run))

    def test_inheritance_hierarchy(self):
        """Test the inheritance hierarchy works correctly."""
        # CoverDevice should not inherit from Device (it's a wrapper)
        from tinytuya.core.Device import Device
        self.assertFalse(isinstance(self.cover, Device))
        
        # The _async_impl should be properly set up
        self.assertTrue(hasattr(self.cover, '_async_impl'))

    def test_cover_specific_use_cases(self):
        """Test cover-specific usage scenarios."""
        with patch.object(self.cover._runner, 'run') as mock_run:
            # Test opening cover
            mock_run.return_value = {"dps": {"1": "on"}}
            result = self.cover.open_cover()
            self.assertEqual(result["dps"]["1"], "on")
            
            # Test closing cover with specific switch
            mock_run.return_value = {"dps": {"2": "off"}}
            result = self.cover.close_cover(switch=2)
            self.assertEqual(result["dps"]["2"], "off")
            
            # Test stopping cover with nowait
            mock_run.return_value = {"dps": {"1": "stop"}}
            result = self.cover.stop_cover(nowait=True)
            self.assertEqual(result["dps"]["1"], "stop")

    def test_docstring_consistency(self):
        """Test that wrapper methods preserve docstrings."""
        # The wrapper should preserve method documentation
        self.assertTrue(hasattr(self.cover.open_cover, '__doc__'))
        if self.cover.open_cover.__doc__:
            self.assertIn("Open", self.cover.open_cover.__doc__)


class TestAsyncRunnerIntegrationForCover(unittest.TestCase):
    """Test AsyncRunner integration with real async methods for Cover."""
    
    def test__runner_basic_functionality(self):
        """Test that AsyncRunner can run simple coroutines."""
        runner = AsyncRunner()
        
        async def test_coro():
            await asyncio.sleep(0.01)  # Small delay
            return "cover_test_result"
        
        result = runner.run(test_coro())
        self.assertEqual(result, "cover_test_result")

    def test__runner_exception_handling(self):
        """Test that AsyncRunner properly handles exceptions."""
        runner = AsyncRunner()
        
        async def failing_coro():
            raise ValueError("Cover test error")
        
        with self.assertRaises(ValueError):
            runner.run(failing_coro())


class TestCoverDeviceConstants(unittest.TestCase):
    """Test that cover device constants are accessible."""
    
    def setUp(self):
        with patch('tinytuya.CoverDeviceAsync.CoverDeviceAsync.__init__', return_value=None):
            self.cover = CoverDevice("id", "ip", "key")
            # Mock constants
            self.cover._async_impl = Mock()
            self.cover._async_impl.DPS_INDEX_MOVE = "1"
            self.cover._async_impl.DPS_INDEX_BL = "101"
            self.cover._async_impl.DPS_2_STATE = {
                "1": "movement",
                "101": "backlight",
            }
    
    def test_dps_constants(self):
        """Test that DPS constants are accessible."""
        constants_to_check = [
            ('DPS_INDEX_MOVE', "1"),
            ('DPS_INDEX_BL', "101")
        ]
        
        for const_name, expected_value in constants_to_check:
            # Should be accessible through property delegation
            self.assertTrue(hasattr(self.cover, const_name),
                          f"Constant {const_name} not accessible through wrapper")
            actual_value = getattr(self.cover, const_name)
            self.assertEqual(actual_value, expected_value,
                           f"Constant {const_name} has wrong value")

    def test_dps_state_mapping(self):
        """Test that DPS state mapping is accessible."""
        self.assertTrue(hasattr(self.cover, 'DPS_2_STATE'),
                       "DPS_2_STATE not accessible through wrapper")
        dps_state = self.cover.DPS_2_STATE
        self.assertIsInstance(dps_state, dict)
        self.assertEqual(dps_state["1"], "movement")
        self.assertEqual(dps_state["101"], "backlight")


def run_tests():
    """Run all tests."""
    print("🧪 Running CoverDevice Wrapper Tests...")
    print("=" * 60)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestCoverDeviceWrapper))
    suite.addTests(loader.loadTestsFromTestCase(TestAsyncRunnerIntegrationForCover))
    suite.addTests(loader.loadTestsFromTestCase(TestCoverDeviceConstants))
    
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
        if result.failures:
            print("\nFailures:")
            for test, failure in result.failures:
                print(f"  - {test}: {failure}")
        if result.errors:
            print("\nErrors:")
            for test, error in result.errors:
                print(f"  - {test}: {error}")
        return False


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
