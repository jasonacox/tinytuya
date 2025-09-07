#!/usr/bin/env python3
"""
TinyTuya v2.0.0 Async Device Test

This script specifically tests the async classes by connecting to multiple devices
concurrently and reporting their status using pure async/await patterns.

Author: Jason A. Cox
For more information see https://github.com/jasonacox/tinytuya
"""

import sys
import os
import asyncio
import time
import json
from typing import List, Dict, Any, Tuple

# Add the local tinytuya path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import tinytuya
    from tinytuya.core.XenonDeviceAsync import XenonDeviceAsync
    from tinytuya.OutletDeviceAsync import OutletDeviceAsync
    from tinytuya.BulbDeviceAsync import BulbDeviceAsync
    from tinytuya.CoverDeviceAsync import CoverDeviceAsync
    print(f"📦 Using TinyTuya v{tinytuya.__version__}")
except ImportError as e:
    print(f"❌ Failed to import TinyTuya: {e}")
    sys.exit(1)

# Load devices from snapshot
from extract_devices import extract_devices_from_snapshot

class AsyncDeviceTester:
    """Test multiple devices using async classes"""
    
    def __init__(self, devices: List[Dict[str, Any]]):
        self.devices = devices
        self.results = []
        
    def create_async_device(self, device_info: Dict[str, Any]) -> XenonDeviceAsync:
        """Create an appropriate async device instance based on device type"""
        device_type = device_info.get('dev_type', 'default').lower()
        
        # Common parameters
        params = {
            'dev_id': device_info['id'],
            'address': device_info['ip'],
            'local_key': device_info['key'],
            'version': float(device_info['version']),
            'connection_timeout': 5,
            'persist': False  # Don't persist connections for testing
        }
        
        # Choose appropriate device class
        if 'bulb' in device_type or 'light' in device_type:
            return BulbDeviceAsync(**params)
        elif 'cover' in device_type or 'blind' in device_type or 'curtain' in device_type:
            return CoverDeviceAsync(**params)
        elif 'outlet' in device_type or 'switch' in device_type or device_type == 'default':
            return OutletDeviceAsync(**params)
        else:
            # Fallback to base XenonDeviceAsync
            return XenonDeviceAsync(**params)
    
    async def test_device_async(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single device asynchronously"""
        test_start = time.time()
        result = {
            'name': device_info['name'],
            'id': device_info['id'],
            'ip': device_info['ip'],
            'version': device_info['version'],
            'dev_type': device_info.get('dev_type', 'default'),
            'success': False,
            'error': None,
            'response_time': None,
            'status_data': None,
            'dps_count': 0
        }
        
        try:
            # Create async device
            device = self.create_async_device(device_info)
            
            print(f"   🔍 Testing: {device_info['name']} ({device_info['ip']}) v{device_info['version']}")
            
            # Initialize device
            await device.initialize()
            
            # Test status method
            status_start = time.time()
            status = await device.status()
            response_time = time.time() - status_start
            
            if status and not (isinstance(status, dict) and 'Error' in status):
                result['success'] = True
                result['response_time'] = response_time
                result['status_data'] = status
                
                # Count DPS entries if available
                if isinstance(status, dict) and 'dps' in status and isinstance(status['dps'], dict):
                    result['dps_count'] = len(status['dps'])
                    
                print(f"   ✅ Success! Response time: {response_time:.3f}s, DPS count: {result['dps_count']}")
            else:
                result['error'] = str(status) if status else "No response"
                print(f"   ❌ Failed: {result['error']}")
            
            # Clean up
            await device.close()
            
        except Exception as e:
            result['error'] = str(e)
            print(f"   ❌ Error: {e}")
        
        result['total_time'] = time.time() - test_start
        return result
    
    async def test_devices_concurrent(self, max_concurrent: int = 5) -> List[Dict[str, Any]]:
        """Test multiple devices concurrently with limited concurrency"""
        print(f"🚀 Testing {len(self.devices)} devices with max {max_concurrent} concurrent connections")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_with_semaphore(device_info):
            async with semaphore:
                return await self.test_device_async(device_info)
        
        # Create tasks for all devices
        tasks = [test_with_semaphore(device) for device in self.devices]
        
        # Run all tasks concurrently (but limited by semaphore)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'name': self.devices[i]['name'],
                    'id': self.devices[i]['id'],
                    'ip': self.devices[i]['ip'],
                    'version': self.devices[i]['version'],
                    'success': False,
                    'error': f"Task exception: {result}",
                    'response_time': None,
                    'total_time': None
                })
            else:
                processed_results.append(result)
        
        self.results = processed_results
        return processed_results
    
    def print_summary(self):
        """Print test summary"""
        if not self.results:
            print("❌ No test results available")
            return
        
        successful = [r for r in self.results if r['success']]
        failed = [r for r in self.results if not r['success']]
        
        print(f"\n📊 Test Summary:")
        print(f"   Total devices tested: {len(self.results)}")
        print(f"   ✅ Successful: {len(successful)}")
        print(f"   ❌ Failed: {len(failed)}")
        print(f"   📈 Success rate: {(len(successful)/len(self.results)*100):.1f}%")
        
        if successful:
            response_times = [r['response_time'] for r in successful if r['response_time']]
            if response_times:
                avg_response = sum(response_times) / len(response_times)
                print(f"   ⚡ Average response time: {avg_response:.3f}s")
                print(f"   🏃 Fastest response: {min(response_times):.3f}s")
                print(f"   🐌 Slowest response: {max(response_times):.3f}s")
        
        # Show version breakdown
        version_stats = {}
        for result in self.results:
            ver = result['version']
            if ver not in version_stats:
                version_stats[ver] = {'total': 0, 'success': 0}
            version_stats[ver]['total'] += 1
            if result['success']:
                version_stats[ver]['success'] += 1
        
        print(f"\n📋 Version Breakdown:")
        for ver in sorted(version_stats.keys()):
            stats = version_stats[ver]
            success_rate = (stats['success'] / stats['total']) * 100
            print(f"   Version {ver}: {stats['success']}/{stats['total']} ({success_rate:.1f}%)")
        
        # Show failed devices
        if failed:
            print(f"\n❌ Failed Devices:")
            for result in failed[:10]:  # Show first 10 failures
                print(f"   • {result['name']} ({result['ip']}): {result['error']}")
            if len(failed) > 10:
                print(f"   ... and {len(failed) - 10} more failures")

async def main():
    """Main async test function"""
    print("🧪 TinyTuya v2.0.0 Async Device Test")
    print("=" * 50)
    print("Testing multiple devices using pure async classes")
    print("=" * 50)
    
    # Extract devices from snapshot
    print("🔍 Loading devices from snapshot.json...")
    devices, _ = extract_devices_from_snapshot("../snapshot.json")
    
    if not devices:
        print("❌ No devices found for testing")
        return 1
    
    # Limit to first 10 devices for this test
    test_devices = devices[:10]
    print(f"📊 Selected {len(test_devices)} devices for async testing:")
    for i, device in enumerate(test_devices, 1):
        print(f"   {i}. {device['name']} ({device['ip']}) v{device['version']}")
    
    print(f"\n🚀 Starting async tests...")
    start_time = time.time()
    
    # Create tester and run tests
    tester = AsyncDeviceTester(test_devices)
    results = await tester.test_devices_concurrent(max_concurrent=3)
    
    total_time = time.time() - start_time
    print(f"\n⏱️  Total test time: {total_time:.3f}s")
    
    # Print summary
    tester.print_summary()
    
    # Save results
    report = {
        'test_info': {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tinytuya_version': tinytuya.__version__,
            'total_time': total_time,
            'devices_tested': len(test_devices)
        },
        'results': results
    }
    
    with open('async_test_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n📄 Detailed results saved to async_test_report.json")
    
    # Return exit code based on success rate
    successful = len([r for r in results if r['success']])
    success_rate = (successful / len(results)) * 100
    
    if success_rate >= 80:
        print("🎉 Async test completed successfully!")
        return 0
    elif success_rate >= 50:
        print("⚠️  Async test completed with some failures")
        return 1
    else:
        print("❌ Async test failed - too many device failures")
        return 2

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Test cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
