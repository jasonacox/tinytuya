#!/usr/bin/env python3
"""
TinyTuya v2.0.0 Simple Async Device Test

This script uses a very simple approach to gather status from multiple devices
concurrently using asyncio.gather() as shown in the README.

Author: Jason A. Cox
For more information see https://github.com/jasonacox/tinytuya
"""

import sys
import os
import asyncio
import time

# Add the local tinytuya path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import tinytuya
    print(f"📦 Using TinyTuya v{tinytuya.__version__}")
except ImportError as e:
    print(f"❌ Failed to import TinyTuya: {e}")
    sys.exit(1)

# Load devices from snapshot
from extract_devices import extract_devices_from_snapshot

async def handle_device(device_info):
    """Handle a single device - get its status"""
    try:
        # Create device using the sync wrapper (which will use async internally)
        if 'bulb' in device_info.get('dev_type', '').lower() or 'light' in device_info['name'].lower():
            device = tinytuya.BulbDevice(
                dev_id=device_info['id'],
                address=device_info['ip'],
                local_key=device_info['key'],
                version=float(device_info['version'])
            )
        elif 'cover' in device_info.get('dev_type', '').lower() or 'blind' in device_info['name'].lower():
            device = tinytuya.CoverDevice(
                dev_id=device_info['id'],
                address=device_info['ip'],
                local_key=device_info['key'],
                version=float(device_info['version'])
            )
        else:
            # Default to OutletDevice
            device = tinytuya.OutletDevice(
                dev_id=device_info['id'],
                address=device_info['ip'],
                local_key=device_info['key'],
                version=float(device_info['version'])
            )
        
        # Get status
        start_time = time.time()
        status = device.status()
        response_time = time.time() - start_time
        
        if status and not (isinstance(status, dict) and 'Error' in status):
            dps_count = 0
            if isinstance(status, dict) and 'dps' in status and isinstance(status['dps'], dict):
                dps_count = len(status['dps'])
            
            return {
                'name': device_info['name'],
                'success': True,
                'response_time': response_time,
                'dps_count': dps_count,
                'status': status
            }
        else:
            return {
                'name': device_info['name'],
                'success': False,
                'error': str(status) if status else "No response"
            }
            
    except Exception as e:
        return {
            'name': device_info['name'],
            'success': False,
            'error': str(e)
        }

async def main():
    """Main async function"""
    print("🧪 TinyTuya v2.0.0 Simple Async Test")
    print("=" * 50)
    print("Using asyncio.gather() for concurrent device status")
    print("=" * 50)
    
    # Load devices
    print("🔍 Loading devices from snapshot.json...")
    devices, _ = extract_devices_from_snapshot("../snapshot.json")
    
    if not devices:
        print("❌ No devices found for testing")
        return 1
    
    # Use first 10 devices
    device_list = devices[:99]
    print(f"📊 Testing {len(device_list)} devices concurrently:")
    for i, dev in enumerate(device_list, 1):
        print(f"   {i}. {dev['name']} ({dev['ip']}) v{dev['version']}")
    
    print("\n🚀 Starting concurrent status requests...")
    start_time = time.time()
    
    # Handle multiple devices concurrently (as shown in README)
    results = await asyncio.gather(*[handle_device(dev) for dev in device_list])
    
    total_time = time.time() - start_time
    print(f"⏱️  Total time: {total_time:.3f}s")
    print("\n📊 Results:")
    
    # Display results
    successful = 0
    for i, result in enumerate(results):
        if result['success']:
            successful += 1
            print(f'✅ Device {i+1} ({result["name"]}): Success in {result.get("response_time", 0):.3f}s - {result.get("dps_count", 0)} DPS entries')
        else:
            print(f'❌ Device {i+1} ({result["name"]}): Failed - {result.get("error", "Unknown error")}')
    
    # Summary
    success_rate = (successful / len(results)) * 100
    print("\n📈 Summary:")
    print(f"   Total devices: {len(results)}")
    print(f"   Successful: {successful}")
    print(f"   Failed: {len(results) - successful}")
    print(f"   Success rate: {success_rate:.1f}%")
    print(f"   Average time per device: {total_time/len(device_list):.3f}s")
    
    if successful > 0:
        response_times = [r['response_time'] for r in results if r['success'] and 'response_time' in r]
        if response_times:
            print(f"   Fastest response: {min(response_times):.3f}s")
            print(f"   Slowest response: {max(response_times):.3f}s")
    
    # Return appropriate exit code
    if success_rate >= 80:
        print("🎉 Test completed successfully!")
        return 0
    elif success_rate >= 50:
        print("⚠️  Test completed with some failures")
        return 1
    else:
        print("❌ Test failed - too many device failures")
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
