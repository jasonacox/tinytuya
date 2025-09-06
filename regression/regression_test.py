#!/usr/bin/env python3
"""
TinyTuya Regression Test Suite - Real Device Testing

This script performs practical tests against real devices listed in snapshot.json
to verify that the TinyTuya v2.0.0 async-first architecture works correctly
with actual hardware.

Tests performed:
- Device connectivity (status() method)  
- Response time measurement
- Error handling and reporting
- Architecture consistency validation
"""

import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple

# Import local development version of TinyTuya
try:
    from local_tinytuya import tinytuya
    print("📦 Using local TinyTuya development version")
    # Version
    print(f"🔢 TinyTuya version: {tinytuya.__version__}")
except ImportError as e:
    print(f"❌ Failed to import local TinyTuya: {e}")
    print("💡 Make sure you're running from the regression/ directory")
    sys.exit(1)

from extract_devices import extract_devices_from_snapshot

class RegressionTester:
    """Regression test suite for real TinyTuya devices"""
    
    def __init__(self, devices: List[Dict[str, Any]], verbose: bool = False):
        self.devices = devices
        self.results = []
        self.verbose = verbose
        self.start_time = None
        
    def test_single_device(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single device and return results"""
        test_start = time.time()
        
        if self.verbose:
            print(f"   🔍 Testing: {device_info['name']} ({device_info['ip']}) v{device_info.get('version', device_info.get('ver', '3.3'))}")
        
        result = {
            'name': device_info['name'],
            'id': device_info['id'],
            'ip': device_info['ip'],
            'version': device_info.get('version', device_info.get('ver', '3.3')),  # Support both field names
            'dev_type': device_info['dev_type'],
            'success': False,
            'response_time': 0.0,
            'status_data': None,
            'error': None,
            'error_category': None,
            'version_compatible': False,
            'test_timestamp': test_start
        }
        
        try:
            # Create device instance based on type
            device = self._create_device(device_info)
            
            # Set a reasonable timeout
            device.set_socketTimeout(5.0)
            
            # Perform status check
            status_start = time.time()
            status_response = device.status()
            status_end = time.time()
            
            result['response_time'] = status_end - status_start
            result['status_data'] = status_response
            
            # Analyze response for version compatibility
            version_analysis = self._analyze_version_compatibility(status_response, device_info.get('version', device_info.get('ver', '3.3')))
            result.update(version_analysis)
            
            if result['version_compatible']:
                if result['error_category'] in ['NETWORK_ERROR', 'CONNECTION_ERROR']:
                    # Version is compatible but device is unreachable
                    result['success'] = False  # Test failed due to infrastructure
                    if not self.verbose:
                        print(f"🔗 {device_info['name']:<25} ({device_info['ip']:<15}) - NETWORK ISSUE")
                        print(f"   Version compatible but device unreachable: {result['error']}")
                    else:
                        print(f"     🔗 NETWORK ISSUE: {result['error']}")
                else:
                    # True success - version compatible and device responded
                    result['success'] = True
                    if not self.verbose:
                        print(f"✅ {device_info['name']:<25} ({device_info['ip']:<15}) - {result['response_time']:.3f}s ")
                        if result['status_data']:
                            print(f"   Status: {result['status_data']}")
                        else:
                            print("   Status: Unknown")
                    else:
                        print(f"     ✅ SUCCESS ({result['response_time']:.3f}s)")
                        if result['status_data']:
                            dps_keys = list(result['status_data'].get('dps', {}).keys()) if result['status_data'].get('dps') else []
                            print(f"     📊 DPS keys: {dps_keys}")
            else:
                # Version compatibility issue - this is a library problem
                result['success'] = False
                if not self.verbose:
                    print(f"⚠️  {device_info['name']:<25} ({device_info['ip']:<15}) - VERSION ISSUE")
                    print(f"   Error: {result['error']}")
                    print(f"   Category: {result['error_category']}")
                else:
                    print(f"     ⚠️  VERSION ISSUE: {result['error']}")

        except Exception as e:
            result['error'] = str(e)
            result['error_category'] = 'CONNECTION_ERROR'
            if not self.verbose:
                print(f"❌ {device_info['name']:<25} ({device_info['ip']:<15}) - {str(e)}")
            else:
                print(f"     ❌ ERROR: {str(e)}")
        
        finally:
            result['total_time'] = time.time() - test_start
            
        return result
    
    def _create_device(self, device_info: Dict[str, Any]):
        """Create appropriate device instance based on device info"""
        # Extract parameters
        dev_id = device_info['id']
        address = device_info['ip']
        local_key = device_info['key']
        version = float(device_info.get('version', device_info.get('ver', '3.3')))
        dev_type = device_info.get('dev_type', 'default')
        
        # For regression testing, we'll primarily use OutletDevice
        # as it covers the core functionality we want to test
        device = tinytuya.OutletDevice(
            dev_id=dev_id,
            address=address,
            local_key=local_key,
            version=version,
            connection_timeout=5.0
        )
        
        return device

    def _analyze_version_compatibility(self, status_response: Dict[str, Any], device_version: str) -> Dict[str, Any]:
        """Analyze status response for version compatibility issues"""
        analysis = {
            'version_compatible': True,
            'error': None,
            'error_category': None
        }
        
        if not status_response:
            analysis['version_compatible'] = False
            analysis['error'] = 'No response from device'
            analysis['error_category'] = 'NO_RESPONSE'
            return analysis
        
        # Check for common error patterns that indicate version compatibility issues
        if isinstance(status_response, dict):
            if 'Error' in status_response:
                error_msg = status_response['Error']
                error_code = status_response.get('Err', '')
                
                # Categorize errors for version compatibility analysis
                if 'Unexpected Payload' in error_msg:
                    analysis['version_compatible'] = False
                    analysis['error'] = f"Protocol error: {error_msg} (Code: {error_code})"
                    analysis['error_category'] = 'PROTOCOL_VERSION_ERROR'
                elif 'Network Error' in error_msg:
                    analysis['version_compatible'] = True  # Network issue, not version issue
                    analysis['error'] = f"Network issue: {error_msg} (Code: {error_code})"
                    analysis['error_category'] = 'NETWORK_ERROR'
                elif 'Unable to Connect' in error_msg:
                    analysis['version_compatible'] = True  # Connection issue, not version issue
                    analysis['error'] = f"Connection issue: {error_msg} (Code: {error_code})"
                    analysis['error_category'] = 'CONNECTION_ERROR'
                elif error_code in ['904', '905', '906']:  # Protocol/payload related errors
                    analysis['version_compatible'] = False
                    analysis['error'] = f"Version incompatible: {error_msg} (Code: {error_code})"
                    analysis['error_category'] = 'PROTOCOL_VERSION_ERROR'
                else:
                    # Unknown error - assume it's version related to be safe
                    analysis['version_compatible'] = False
                    analysis['error'] = f"Unknown error: {error_msg} (Code: {error_code})"
                    analysis['error_category'] = 'UNKNOWN_VERSION_ERROR'
            elif 'dps' in status_response:
                # Successfully got DPS data - version is compatible
                analysis['version_compatible'] = True
            elif 'devId' in status_response:
                # Got device response with ID - version is compatible
                analysis['version_compatible'] = True
            else:
                # Unexpected response format
                analysis['version_compatible'] = False
                analysis['error'] = f"Unexpected response format for version {device_version}"
                analysis['error_category'] = 'RESPONSE_FORMAT_ERROR'
        else:
            # Non-dict response is unexpected
            analysis['version_compatible'] = False
            analysis['error'] = f"Invalid response type: {type(status_response)}"
            analysis['error_category'] = 'RESPONSE_TYPE_ERROR'
            
        return analysis
    
    @staticmethod
    def select_devices_by_version(devices: List[Dict[str, Any]], versions_wanted: List[str] = None) -> List[Dict[str, Any]]:
        """Select one representative device from each version for testing"""
        if versions_wanted is None:
            # Auto-detect all available versions
            versions_wanted = list(set(device.get('version', device.get('ver', '3.3')) for device in devices))
            versions_wanted.sort()
        
        version_devices = {}
        for device in devices:
            version = device.get('version', device.get('ver', '3.3'))
            if version in versions_wanted:
                if version not in version_devices:
                    version_devices[version] = []
                version_devices[version].append(device)
        
        # Select one device from each version (prefer devices with simpler names)
        selected_devices = []
        for version in sorted(version_devices.keys()):
            # Sort by name length to prefer simpler device names
            candidates = sorted(version_devices[version], key=lambda d: len(d['name']))
            selected_devices.append(candidates[0])
            
        return selected_devices
    
    @staticmethod
    def get_version_summary(devices: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Get a summary of devices grouped by version"""
        versions = {}
        for device in devices:
            ver = device.get('version', device.get('ver', '3.3'))
            if ver not in versions:
                versions[ver] = []
            versions[ver].append(device)
        return versions

    def run_parallel_tests(self, max_workers: int = 10) -> List[Dict[str, Any]]:
        """Run tests on all devices in parallel"""
        print(f"🚀 Starting regression tests on {len(self.devices)} devices...")
        print(f"⚙️  Using {max_workers} parallel workers")
        print(f"{'Device Name':<25} {'IP Address':<15} {'Result'}")
        print("-" * 65)
        
        self.start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all test jobs
            future_to_device = {
                executor.submit(self.test_single_device, device): device
                for device in self.devices
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_device):
                result = future.result()
                self.results.append(result)
        
        return self.results
    
    def run_sequential_tests(self) -> List[Dict[str, Any]]:
        """Run tests on all devices sequentially (safer for network)"""
        print(f"🐌 Starting sequential regression tests on {len(self.devices)} devices...")
        print(f"{'Device Name':<25} {'IP Address':<15} {'Result'}")
        print("-" * 65)
        
        self.start_time = time.time()
        
        for device in self.devices:
            result = self.test_single_device(device)
            self.results.append(result)
            
            # Small delay between tests to be network-friendly
            time.sleep(0.1)
        
        return self.results
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        if not self.results:
            return {'error': 'No test results available'}
        
        total_time = time.time() - self.start_time if self.start_time else 0
        successful_tests = [r for r in self.results if r['success']]
        failed_tests = [r for r in self.results if not r['success']]
        
        # Version compatibility analysis
        version_compatible = [r for r in self.results if r.get('version_compatible', True)]
        version_incompatible = [r for r in self.results if not r.get('version_compatible', True)]
        
        # Calculate statistics
        response_times = [r['response_time'] for r in successful_tests]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        
        report = {
            'test_summary': {
                'total_devices': len(self.results),
                'successful': len(successful_tests),
                'failed': len(failed_tests),
                'success_rate': len(successful_tests) / len(self.results) * 100,
                'total_test_time': total_time
            },
            'version_compatibility': {
                'compatible_devices': len(version_compatible),
                'incompatible_devices': len(version_incompatible),
                'compatibility_rate': len(version_compatible) / len(self.results) * 100 if self.results else 0,
                'incompatible_details': version_incompatible
            },
            'performance_metrics': {
                'avg_response_time': avg_response_time,
                'min_response_time': min_response_time,
                'max_response_time': max_response_time
            },
            'device_results': self.results,
            'failed_devices': failed_tests
        }
        
        return report
    
    def print_summary(self):
        """Print test summary to console"""
        report = self.generate_report()
        summary = report['test_summary']
        perf = report['performance_metrics']
        
        print("\n" + "="*60)
        print("📊 REGRESSION TEST SUMMARY")
        print("="*60)
        print(f"Total Devices Tested: {summary['total_devices']}")
        print(f"Successful Tests:     {summary['successful']} ({summary['success_rate']:.1f}%)")
        print(f"Failed Tests:         {summary['failed']}")
        print(f"Total Test Time:      {summary['total_test_time']:.2f}s")
        
        if summary['successful'] > 0:
            print(f"\n📈 PERFORMANCE METRICS")
            print(f"Average Response Time: {perf['avg_response_time']:.3f}s")
            print(f"Fastest Response:      {perf['min_response_time']:.3f}s")
            print(f"Slowest Response:      {perf['max_response_time']:.3f}s")
        
        # Version compatibility analysis
        version_compatible = [r for r in self.results if r.get('version_compatible', True)]
        version_incompatible = [r for r in self.results if not r.get('version_compatible', True)]
        
        # Network vs actual failures
        network_issues = [r for r in self.results if r.get('error_category') in ['NETWORK_ERROR', 'CONNECTION_ERROR', 'NO_RESPONSE']]
        version_issues = [r for r in self.results if r.get('error_category') in ['PROTOCOL_VERSION_ERROR', 'RESPONSE_FORMAT_ERROR', 'UNKNOWN_VERSION_ERROR']]
        true_successes = [r for r in self.results if r['success'] and not r.get('error')]
        
        if any('version_compatible' in r for r in self.results):
            # This was a version compatibility test
            print(f"\n🔢 VERSION COMPATIBILITY ANALYSIS")
            print(f"Compatible Versions:    {len(version_compatible)} devices")
            print(f"Incompatible Versions:  {len(version_incompatible)} devices")
            print(f"True Successes:         {len(true_successes)} devices")
            print(f"Network Issues:         {len(network_issues)} devices (version compatible but unreachable)")
            print(f"Version Issues:         {len(version_issues)} devices (library/protocol problems)")
            
            if version_incompatible:
                print(f"\n⚠️  VERSION COMPATIBILITY ISSUES:")
                for incompatible in version_incompatible:
                    error_cat = incompatible.get('error_category', 'UNKNOWN')
                    print(f"  • {incompatible['name']} (v{incompatible['version']}) - {error_cat}")
                    if incompatible.get('error'):
                        print(f"    {incompatible['error']}")
            
            if network_issues:
                print(f"\n🔗 NETWORK/INFRASTRUCTURE ISSUES:")
                for network in network_issues:
                    error_cat = network.get('error_category', 'UNKNOWN')
                    print(f"  • {network['name']} (v{network['version']}) - {error_cat}")
                    if network.get('error'):
                        print(f"    {network['error']}")
        
        if report['failed_devices']:
            other_failures = [f for f in report['failed_devices'] 
                            if f.get('error_category') not in ['NETWORK_ERROR', 'CONNECTION_ERROR', 'NO_RESPONSE', 
                                                             'PROTOCOL_VERSION_ERROR', 'RESPONSE_FORMAT_ERROR', 'UNKNOWN_VERSION_ERROR']]
            if other_failures:
                print(f"\n❌ OTHER FAILED DEVICES ({len(other_failures)}):")
                for failed in other_failures:
                    print(f"  • {failed['name']} ({failed['ip']}) - {failed['error']}")
        
        # Architecture validation
        if summary['success_rate'] > 80:
            print(f"\n🎉 ARCHITECTURE VALIDATION: PASSED")
            print(f"   TinyTuya v2.0.0 async-first architecture is working well!")
        elif summary['success_rate'] > 50:
            print(f"\n⚠️  ARCHITECTURE VALIDATION: PARTIAL")
            print(f"   Some issues detected, but core functionality works")
        else:
            print(f"\n❌ ARCHITECTURE VALIDATION: FAILED")
            print(f"   Significant issues with the async-first architecture")
    
    def save_report(self, filename: str = "regression_report.json"):
        """Save detailed report to JSON file"""
        report = self.generate_report()
        report['test_timestamp'] = time.time()
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"💾 Detailed report saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")

def main():
    """Main regression test execution"""
    print("🧪 TinyTuya v2.0.0 Regression Test Suite")
    print("="*50)
    
    # Extract devices from snapshot
    devices, _ = extract_devices_from_snapshot("../snapshot.json")
    
    if not devices:
        print("❌ No devices found for testing. Check snapshot.json")
        return 1
    
    # Limit devices for initial testing (can be removed later)
    if len(devices) > 20:
        print(f"⚠️  Testing subset of devices ({20}/{len(devices)}) for initial validation")
        devices = devices[:20]
    
    # Create tester instance
    tester = RegressionTester(devices)
    
    # Run tests (sequential is safer for network stability)
    tester.run_sequential_tests()
    
    # Generate and display results
    tester.print_summary()
    tester.save_report("regression_report.json")
    
    # Return appropriate exit code
    report = tester.generate_report()
    return 0 if report['test_summary']['success_rate'] > 50 else 1

if __name__ == "__main__":
    sys.exit(main())
