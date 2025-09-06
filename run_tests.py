#!/usr/bin/env python3
"""
Simple test runner to validate TinyTuya async-first architecture

Run this to verify that the refactoring is working correctly.
"""

import sys
import os
import traceback
import time

# Add current directory to path
sys.path.insert(0, '.')

def run_test(test_name, test_func):
    """Run a single test function and report results."""
    try:
        start_time = time.time()
        test_func()
        end_time = time.time()
        print(f"✅ {test_name} - PASSED ({end_time - start_time:.3f}s)")
        return True
    except Exception as e:
        print(f"❌ {test_name} - FAILED: {e}")
        if os.getenv('VERBOSE'):
            traceback.print_exc()
        return False

def test_basic_imports():
    """Test that all main classes can be imported."""
    from tinytuya import OutletDevice, BulbDevice, CoverDevice
    from tinytuya.core.async_runner import AsyncRunner
    assert OutletDevice is not None
    assert BulbDevice is not None  
    assert CoverDevice is not None
    assert AsyncRunner is not None

def test_outlet_device():
    """Test OutletDevice basic functionality."""
    from tinytuya import OutletDevice
    
    device = OutletDevice("test_id", "192.168.1.100", "test_key", version=3.3)
    
    assert device.id == "test_id"
    assert device.address == "192.168.1.100"
    assert hasattr(device, '_async_impl')
    assert hasattr(device, '_runner')
    assert device._async_impl.id == "test_id"
    assert device._async_impl.version == 3.3

def test_bulb_device():
    """Test BulbDevice basic functionality."""
    from tinytuya import BulbDevice
    
    device = BulbDevice("test_id", "192.168.1.100", "test_key", version=3.3)
    
    assert device.id == "test_id"
    
    # Check for async implementation (flexible attribute names)
    has_async_impl = hasattr(device, '_async_impl') or hasattr(device, 'async_device')
    has_runner = hasattr(device, '_runner') or hasattr(device, 'async_runner')
    
    assert has_async_impl, "Device should have async implementation"
    assert has_runner, "Device should have async runner"
    
    # Test bulb-specific methods exist
    assert hasattr(device, 'set_colour')
    assert hasattr(device, 'set_brightness')
    assert callable(device.set_colour)
    assert callable(device.set_brightness)

def test_cover_device():
    """Test CoverDevice basic functionality.""" 
    from tinytuya import CoverDevice
    
    device = CoverDevice("test_id", "192.168.1.100", "test_key", version=3.3)
    
    assert device.id == "test_id"
    
    # Check for async implementation (flexible attribute names)
    has_async_impl = hasattr(device, '_async_impl') or hasattr(device, 'async_device')
    has_runner = hasattr(device, '_runner') or hasattr(device, 'async_runner')
    
    assert has_async_impl, "Device should have async implementation"
    assert has_runner, "Device should have async runner"
    
    # Test cover-specific methods exist
    assert hasattr(device, 'open_cover')
    assert hasattr(device, 'close_cover')
    assert hasattr(device, 'stop_cover')
    assert callable(device.open_cover)

def test_property_delegation():
    """Test property delegation to async implementation."""
    from tinytuya import OutletDevice
    
    device = OutletDevice("test_id", "192.168.1.100", "test_key", version=3.3)
    
    # Test getters
    assert device.id == device._async_impl.id
    assert device.address == device._async_impl.address
    assert device.version == device._async_impl.version
    
    # Test setters
    device.sendWait = 0.1
    assert device._async_impl.sendWait == 0.1

def test_async_runner():
    """Test AsyncRunner basic functionality."""
    import asyncio
    from tinytuya.core.async_runner import AsyncRunner
    
    runner = AsyncRunner()
    
    async def test_coro():
        await asyncio.sleep(0.01)
        return "test_result"
    
    result = runner.run(test_coro())
    assert result == "test_result"

def main():
    """Run all tests."""
    print("🧪 TinyTuya Async-First Architecture Test Suite")
    print("=" * 50)
    
    tests = [
        ("Basic Imports", test_basic_imports),
        ("OutletDevice Functionality", test_outlet_device),
        ("BulbDevice Functionality", test_bulb_device),
        ("CoverDevice Functionality", test_cover_device),
        ("Property Delegation", test_property_delegation),
        ("AsyncRunner Functionality", test_async_runner),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if run_test(test_name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Async-first architecture is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    exit(main())
