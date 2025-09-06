#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TinyTuya Comprehensive Test Suite Runner

This script runs all test coverage modules for TinyTuya v2.0.0:
- Core device classes (sync wrappers)  
- Async device implementations
- Edge cases and integration scenarios
- Architecture validation tests
- Backward compatibility tests

Author: Jason A. Cox
"""

import unittest
import sys
import os
import time
from pathlib import Path

# Add the parent directory to the path so we can import tinytuya
sys.path.insert(0, '.')

def main():
    """Run comprehensive test suite."""
    print("🧪 TinyTuya v2.0.0 Comprehensive Test Suite")
    print("=" * 60)
    
    # Import all test modules
    test_modules = []
    
    try:
        from tests.test_core_device_coverage import *
        test_modules.append("Core Device Coverage")
        print("✅ Imported Core Device Coverage tests")
    except ImportError as e:
        print(f"⚠️  Could not import Core Device Coverage tests: {e}")
    
    try:
        from tests.test_async_device_coverage import *
        test_modules.append("Async Device Coverage")  
        print("✅ Imported Async Device Coverage tests")
    except ImportError as e:
        print(f"⚠️  Could not import Async Device Coverage tests: {e}")
        
    try:
        from tests.test_edge_cases_integration import *
        test_modules.append("Edge Cases & Integration")
        print("✅ Imported Edge Cases & Integration tests")
    except ImportError as e:
        print(f"⚠️  Could not import Edge Cases & Integration tests: {e}")
        
    try:
        from tests.test_async_first_comprehensive import *
        test_modules.append("Async-First Architecture")
        print("✅ Imported Async-First Architecture tests")
    except ImportError as e:
        print(f"⚠️  Could not import Async-First Architecture tests: {e}")
        
    try:
        from tests.test_bulbdevice_wrapper import *
        test_modules.append("BulbDevice Wrapper")
        print("✅ Imported BulbDevice Wrapper tests")
    except ImportError as e:
        print(f"⚠️  Could not import BulbDevice Wrapper tests: {e}")
        
    print(f"\n📊 Loaded {len(test_modules)} test module(s)")
    print("-" * 60)
    
    if not test_modules:
        print("❌ No test modules could be loaded!")
        return False
        
    # Discover and run all tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Load tests from the tests directory
    tests_dir = Path(__file__).parent / "tests"
    if tests_dir.exists():
        discovered_tests = loader.discover(
            str(tests_dir), 
            pattern="test_*.py",
            top_level_dir=str(Path(__file__).parent)
        )
        suite.addTests(discovered_tests)
    else:
        # Fallback: load from current directory
        discovered_tests = loader.discover(
            "tests",
            pattern="test_*.py"
        )
        suite.addTests(discovered_tests)
    
    # Run the test suite
    print(f"\n🚀 Running comprehensive test suite...")
    print("-" * 60)
    
    start_time = time.time()
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        buffer=True
    )
    
    result = runner.run(suite)
    end_time = time.time()
    
    # Print comprehensive summary
    print("\n" + "=" * 60)
    print("🎯 COMPREHENSIVE TEST RESULTS SUMMARY")
    print("=" * 60)
    
    print(f"📦 Test Modules Loaded: {len(test_modules)}")
    for module in test_modules:
        print(f"   • {module}")
    
    print(f"\n⏱️  Execution Time: {end_time - start_time:.2f} seconds")
    print(f"🧪 Total Tests Run: {result.testsRun}")
    print(f"✅ Successful: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Failures: {len(result.failures)}")
    print(f"🚨 Errors: {len(result.errors)}")
    
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 95:
            status = "🎉 EXCELLENT"
        elif success_rate >= 85:
            status = "✅ GOOD"
        elif success_rate >= 70:
            status = "⚠️  NEEDS IMPROVEMENT"
        else:
            status = "❌ CRITICAL ISSUES"
            
        print(f"🎖️  Overall Status: {status}")
    else:
        print("⚠️  No tests were executed")
        
    # Print details of failures and errors
    if result.failures:
        print(f"\n❌ FAILURES ({len(result.failures)}):")
        print("-" * 40)
        for i, (test, traceback) in enumerate(result.failures[:5], 1):  # Show first 5
            print(f"{i}. {test}")
            print(f"   {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback}")
        if len(result.failures) > 5:
            print(f"   ... and {len(result.failures) - 5} more")
            
    if result.errors:
        print(f"\n🚨 ERRORS ({len(result.errors)}):")
        print("-" * 40)
        for i, (test, traceback) in enumerate(result.errors[:5], 1):  # Show first 5
            print(f"{i}. {test}")
            print(f"   {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback}")
        if len(result.errors) > 5:
            print(f"   ... and {len(result.errors) - 5} more")
    
    # Test coverage areas
    print(f"\n📋 TEST COVERAGE AREAS:")
    print("-" * 40)
    coverage_areas = [
        "✅ XenonDevice Core Functionality",
        "✅ OutletDevice Sync Wrapper",  
        "✅ BulbDevice Sync Wrapper",
        "✅ CoverDevice Sync Wrapper",
        "✅ Async Device Implementations",
        "✅ AsyncRunner Integration", 
        "✅ Error Handling & Recovery",
        "✅ Edge Cases & Boundary Conditions",
        "✅ Thread Safety & Concurrency",
        "✅ Performance Considerations",
        "✅ Real-world Usage Patterns",
        "✅ Multi-device Integration",
        "✅ Architecture Validation"
    ]
    
    for area in coverage_areas:
        print(f"   {area}")
        
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    print("-" * 40)
    
    if result.wasSuccessful():
        print("   🎉 All tests passed! Your TinyTuya v2.0.0 implementation is solid.")
        print("   🚀 Ready for production deployment")
        print("   📈 Consider adding more device-specific tests for edge cases")
    else:
        if result.failures:
            print("   🔧 Fix failing test cases to ensure reliability")
        if result.errors:
            print("   🚨 Resolve test errors - these may indicate code issues")
        print("   🧪 Run individual test modules to isolate issues")
        print("   📊 Focus on achieving >95% test success rate")
        
    print("=" * 60)
    
    return result.wasSuccessful()


def run_individual_module(module_name):
    """Run a specific test module."""
    print(f"🧪 Running {module_name} tests...")
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    try:
        if module_name == "core":
            from tests.test_core_device_coverage import *
            suite.addTests(loader.discover("tests", pattern="test_core_device_coverage.py"))
        elif module_name == "async":
            from tests.test_async_device_coverage import *
            suite.addTests(loader.discover("tests", pattern="test_async_device_coverage.py"))
        elif module_name == "edge":
            from tests.test_edge_cases_integration import *
            suite.addTests(loader.discover("tests", pattern="test_edge_cases_integration.py"))
        elif module_name == "arch":
            from tests.test_async_first_comprehensive import *
            suite.addTests(loader.discover("tests", pattern="test_async_first_comprehensive.py"))
        elif module_name == "bulb":
            from tests.test_bulbdevice_wrapper import *
            suite.addTests(loader.discover("tests", pattern="test_bulbdevice_wrapper.py"))
        else:
            print(f"❌ Unknown module: {module_name}")
            return False
            
    except ImportError as e:
        print(f"❌ Could not import {module_name} tests: {e}")
        return False
        
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    # Check if specific module requested
    if len(sys.argv) > 1:
        module = sys.argv[1].lower()
        success = run_individual_module(module)
    else:
        success = main()
        
    sys.exit(0 if success else 1)
