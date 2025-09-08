#!/usr/bin/env python3
"""
TinyTuya Simple Async Test - Direct Device Testing

This is a simplified async test that demonstrates concurrent device communication
using the existing TinyTuya v2.0.0 architecture without complex imports.

The test creates multiple device instances and tests them concurrently using
asyncio to demonstrate the benefits of the async-first architecture.
"""

import sys
import json
import time
import asyncio
import argparse
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Import local development version of TinyTuya
try:
    from local_tinytuya import tinytuya
    print("📦 Using local TinyTuya development version")
    print(f"🔢 TinyTuya version: {tinytuya.__version__}")
except ImportError as e:
    print(f"❌ Failed to import local TinyTuya: {e}")
    print("💡 Make sure you're running from the regression/ directory")
    sys.exit(1)

# tinytuya.set_debug(True)

from extract_devices import extract_devices_from_snapshot

class SimpleAsyncTester:
    """Simple async test using thread pool for concurrent operations"""
    
    def __init__(self, devices: List[Dict[str, Any]], verbose: bool = False):
        self.devices = devices
        self.results = []
        self.verbose = verbose
        self.start_time = None
        
    def test_device_sync(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single device synchronously (to be called concurrently)"""
        test_start = time.time()
        
        if self.verbose:
            print(f"   🔍 Testing: {device_info['name']} ({device_info['ip']}) v{device_info.get('version', '3.3')}")
        
        result = {
            'name': device_info['name'],
            'id': device_info['id'],
            'ip': device_info['ip'],
            'version': device_info.get('version', '3.3'),
            'dev_type': device_info['dev_type'],
            'success': False,
            'response_time': 0.0,
            'status_data': None,
            'error': None,
            'error_category': None,
            'test_timestamp': test_start,
            'concurrent_test': True
        }
        
        try:
            # Create device instance using the standard TinyTuya sync API
            # but we'll run these concurrently to simulate async behavior
            device = tinytuya.OutletDevice(
                dev_id=device_info['id'],
                address=device_info['ip'],
                local_key=device_info['key'],
                version=float(device_info.get('version', '3.3'))
            )
            
            # Configure for better reliability with concurrent access
            device.set_socketTimeout(8.0)
            device.set_socketRetryLimit(2)
            device.set_retry(True)
            device.set_sendWait(0.3)
            
            # Perform status check
            status_start = time.time()
            status_response = device.status()
            status_end = time.time()
            
            result['response_time'] = status_end - status_start
            result['status_data'] = status_response
            
            # Analyze response for success
            if status_response and isinstance(status_response, dict):
                if 'dps' in status_response or 'devId' in status_response:
                    result['success'] = True
                    if not self.verbose:
                        dps_keys = list(status_response.get('dps', {}).keys()) if status_response.get('dps') else []
                        print(f"✅ {device_info['name']:<25} ({device_info['ip']:<15}) - {result['response_time']:.3f}s [Concurrent] - DPS: {dps_keys}")
                    else:
                        print(f"     ✅ SUCCESS ({result['response_time']:.3f}s)")
                elif 'Error' in status_response:
                    result['error'] = status_response['Error']
                    if not self.verbose:
                        print(f"⚠️  {device_info['name']:<25} ({device_info['ip']:<15}) - ERROR: {result['error']}")
                    else:
                        print(f"     ⚠️  ERROR: {result['error']}")
            else:
                result['error'] = 'No response or invalid response format'
                
        except Exception as e:
            result['error'] = str(e)
            result['error_category'] = 'CONNECTION_ERROR'
            if not self.verbose:
                print(f"❌ {device_info['name']:<25} ({device_info['ip']:<15}) - {str(e)}")
            else:
                print(f"     ❌ ERROR: {str(e)}")
        
        result['total_time'] = time.time() - test_start
        return result

    async def run_concurrent_tests(self, max_concurrent: int = 8) -> List[Dict[str, Any]]:
        """Run tests concurrently using ThreadPoolExecutor"""
        print(f"🚀 Running concurrent tests on {len(self.devices)} devices...")
        print(f"🔄 Max concurrent connections: {max_concurrent}")
        print("Device Name               IP Address      Result")
        print("-" * 65)
        
        self.start_time = time.time()
        
        # Use ThreadPoolExecutor to run sync functions concurrently
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all tasks
            futures = [
                loop.run_in_executor(executor, self.test_device_sync, device_info)
                for device_info in self.devices
            ]
            
            # Wait for all to complete
            results = await asyncio.gather(*futures, return_exceptions=True)
        
        # Handle any exceptions that occurred
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = {
                    'name': self.devices[i]['name'],
                    'id': self.devices[i]['id'],
                    'ip': self.devices[i]['ip'],
                    'success': False,
                    'error': f"Concurrent execution exception: {str(result)}",
                    'error_category': 'CONCURRENT_ERROR',
                    'concurrent_test': True
                }
                processed_results.append(error_result)
                print(f"💥 {self.devices[i]['name']:<25} ({self.devices[i]['ip']:<15}) - CONCURRENT EXCEPTION: {str(result)}")
            else:
                processed_results.append(result)
        
        return processed_results

    async def run_sequential_tests(self) -> List[Dict[str, Any]]:
        """Run tests sequentially for comparison"""
        print(f"🐌 Running sequential tests on {len(self.devices)} devices...")
        print("Device Name               IP Address      Result")
        print("-" * 65)
        
        self.start_time = time.time()
        results = []
        
        for device_info in self.devices:
            # Run each test with a small delay
            result = self.test_device_sync(device_info)
            results.append(result)
            time.sleep(0.1)  # Small delay between tests
        
        return results

    def generate_report(self, results: List[Dict[str, Any]], test_mode: str) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_time = time.time() - self.start_time if self.start_time else 0
        successful_tests = [r for r in results if r.get('success', False)]
        failed_tests = [r for r in results if not r.get('success', False)]
        
        # Performance metrics
        response_times = [r['response_time'] for r in results if r.get('response_time', 0) > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Error analysis
        error_categories = {}
        for result in failed_tests:
            category = result.get('error_category', 'UNKNOWN')
            error_categories[category] = error_categories.get(category, 0) + 1
        
        report = {
            'test_mode': test_mode,
            'timestamp': time.time(),
            'tinytuya_version': tinytuya.__version__,
            'total_devices_tested': len(results),
            'successful_tests': len(successful_tests),
            'failed_tests': len(failed_tests),
            'success_rate': (len(successful_tests) / len(results) * 100) if results else 0,
            'total_test_time': total_time,
            'average_response_time': avg_response_time,
            'fastest_response': min(response_times) if response_times else 0,
            'slowest_response': max(response_times) if response_times else 0,
            'error_categories': error_categories,
            'concurrent_capable': test_mode == 'concurrent',
            'results': results
        }
        
        return report

    def print_summary(self, report: Dict[str, Any]):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 CONCURRENT TEST SUMMARY")
        print("=" * 60)
        print(f"Test Mode:            {report['test_mode'].title()}")
        print(f"Total Devices Tested: {report['total_devices_tested']}")
        print(f"Successful Tests:     {report['successful_tests']} ({report['success_rate']:.1f}%)")
        print(f"Failed Tests:         {report['failed_tests']}")
        print(f"Total Test Time:      {report['total_test_time']:.2f}s")
        
        if report['successful_tests'] > 0:
            print("\n📈 PERFORMANCE METRICS")
            print(f"Average Response Time: {report['average_response_time']:.3f}s")
            print(f"Fastest Response:      {report['fastest_response']:.3f}s")
            print(f"Slowest Response:      {report['slowest_response']:.3f}s")
            
            if report['concurrent_capable']:
                devices_per_second = report['total_devices_tested'] / report['total_test_time']
                print(f"Concurrent Throughput: {devices_per_second:.1f} devices/second")
        
        if report['error_categories']:
            print("\n⚠️  ERROR ANALYSIS:")
            for category, count in report['error_categories'].items():
                print(f"   {category}: {count} devices")
        
        # Architecture validation
        if report['success_rate'] >= 80:
            print("\n🎉 CONCURRENT ARCHITECTURE TEST: PASSED")
            print("   TinyTuya v2.0.0 handles concurrent requests excellently!")
        elif report['success_rate'] >= 50:
            print("\n⚠️  CONCURRENT ARCHITECTURE TEST: PARTIAL")
            print("   Some concurrent issues detected, but core functionality works")
        else:
            print("\n❌ CONCURRENT ARCHITECTURE TEST: FAILED")
            print("   Significant concurrent architecture issues detected")

def main():
    parser = argparse.ArgumentParser(
        description="TinyTuya v2.0.0 Simple Concurrent Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python simple_async_test.py --concurrent         # Test all devices concurrently (fast)
  python simple_async_test.py --sequential        # Test all devices sequentially (safe)
  python simple_async_test.py --limit 10          # Test first 10 devices concurrently
  python simple_async_test.py --max-concurrent 5  # Limit concurrent connections to 5
  python simple_async_test.py --verbose           # Detailed output
        """
    )
    
    parser.add_argument('--concurrent', action='store_true', default=True,
                       help='Run tests concurrently (default)')
    parser.add_argument('--sequential', action='store_true',
                       help='Run tests sequentially instead of concurrently')
    parser.add_argument('--limit', type=int, metavar='N',
                       help='Test first N devices only')
    parser.add_argument('--max-concurrent', type=int, default=6, metavar='N',
                       help='Maximum concurrent connections (default: 6)')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output with detailed device info')
    parser.add_argument('--report', default='simple_concurrent_report.json',
                       help='Output report filename (default: simple_concurrent_report.json)')
    
    args = parser.parse_args()
    
    # Extract devices from snapshot
    print("🔍 Extracting devices from snapshot.json...")
    devices, snapshot_data = extract_devices_from_snapshot()
    
    if not devices:
        print("❌ No devices found in snapshot.json")
        sys.exit(1)
    
    # Apply limit if specified
    if args.limit:
        devices = devices[:args.limit]
        print(f"🎯 Limited test: testing first {len(devices)} devices")
    
    # Determine test mode
    test_mode = 'sequential' if args.sequential else 'concurrent'
    
    async def run_tests():
        # Create tester instance
        tester = SimpleAsyncTester(devices, verbose=args.verbose)
        
        # Run tests based on mode
        if test_mode == 'concurrent':
            results = await tester.run_concurrent_tests(max_concurrent=args.max_concurrent)
        else:
            results = await tester.run_sequential_tests()
        
        # Generate and save report
        report = tester.generate_report(results, test_mode)
        
        # Save report to file
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        tester.print_summary(report)
        print(f"💾 Detailed report saved to {args.report}")
        
        return report
    
    # Run the tests
    try:
        report = asyncio.run(run_tests())
        
        # Exit with appropriate code
        if report['success_rate'] >= 80:
            sys.exit(0)  # Success
        elif report['success_rate'] >= 50:
            sys.exit(1)  # Partial success
        else:
            sys.exit(2)  # Failure
            
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Concurrent test suite failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
