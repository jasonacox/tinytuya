#!/usr/bin/env python3
"""
TinyTuya Regression Test Suite Launcher

Simple launcher script for running regression tests with various options.
"""

import sys
import argparse
from local_tinytuya import tinytuya  # This loads and validates local TinyTuya
from extract_devices import extract_devices_from_snapshot
from regression_test import RegressionTester

def main():
    parser = argparse.ArgumentParser(
        description="TinyTuya v2.0.0 Regression Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test.py --quick             # Test first 5 devices
  python test.py --limit 10          # Test first 10 devices  
  python test.py --parallel          # Run tests in parallel
  python test.py --full              # Test all devices
  python test.py --versions          # Test one device from each version
  python test.py --compare-versions  # Compare local vs pip-installed TinyTuya
  python test.py --extract-only      # Just extract device list
        """
    )
    
    parser.add_argument('--quick', action='store_true',
                       help='Quick test with first 5 devices')
    parser.add_argument('--limit', type=int, metavar='N',
                       help='Test first N devices')
    parser.add_argument('--versions', action='store_true',
                       help='Test one device from each version (ensures version compatibility)')
    parser.add_argument('--compare-versions', action='store_true',
                       help='Compare local development version vs pip-installed version')
    parser.add_argument('--parallel', action='store_true',
                       help='Run tests in parallel (faster but harder on network)')
    parser.add_argument('--full', action='store_true',
                       help='Test all devices (may take a while)')
    parser.add_argument('--extract-only', action='store_true',
                       help='Only extract devices from snapshot, don\'t test')
    parser.add_argument('--report', default='regression_report.json',
                       help='Output report filename (default: regression_report.json)')
    
    args = parser.parse_args()
    
    # Extract devices from snapshot
    print("🔍 Extracting devices from snapshot.json...")
    devices, _ = extract_devices_from_snapshot("../snapshot.json")
    
    if not devices:
        print("❌ No devices found for testing. Check snapshot.json")
        return 1
    
    if args.extract_only:
        print(f"✅ Device extraction complete. Found {len(devices)} devices.")
        return 0
    
    # Determine how many devices to test
    if args.quick:
        test_limit = 5
        test_devices = devices[:test_limit]
        print(f"🏃 Quick test mode: testing first {test_limit} devices")
    elif args.limit:
        test_limit = args.limit
        test_devices = devices[:test_limit]
        print(f"🎯 Limited test: testing first {test_limit} devices")
    elif args.versions:
        # Select one device from each version
        test_devices = RegressionTester.select_devices_by_version(devices)
        version_summary = RegressionTester.get_version_summary(devices)
        
        print(f"🔢 Version compatibility test mode:")
        print(f"   Found {len(version_summary)} different versions:")
        for ver in sorted(version_summary.keys()):
            count = len(version_summary[ver])
            selected_device = next((d for d in test_devices if d.get('version', d.get('ver', '3.3')) == ver), None)
            if selected_device:
                print(f"   • Version {ver}: {count} devices → Testing '{selected_device['name']}'")
        print(f"   Total devices to test: {len(test_devices)}")
    elif '--compare-versions' in sys.argv:
        # Compare local development version with pip-installed version
        print("🔄 Starting version comparison tests...")
        
        from isolated_comparison import run_version_comparison_isolated
        from regression.regression_utils import get_devices_for_comparison
        
        # Use protocol version selection for comparison testing
        devices = get_devices_for_comparison()
        
        if not devices:
            print("❌ No devices available for comparison testing")
            sys.exit(1)
        
        print(f"🚀 Running comparison test with {len(devices)} devices across protocol versions...")
        result = run_version_comparison_isolated(devices)
        
        # Print results
        from isolated_comparison import print_comparison_summary
        print_comparison_summary(result)
        
        # Exit after comparison - don't continue to regular testing
        return 0
    elif args.full:
        test_devices = devices
        print(f"🌍 Full test mode: testing all {len(test_devices)} devices")
    else:
        # Default to a reasonable subset
        test_limit = min(10, len(devices))
        test_devices = devices[:test_limit]
        print(f"🔧 Default test: testing first {test_limit} devices")
        print("    (Use --full to test all devices or --versions for version compatibility)")
    
    # Create and run tester
    tester = RegressionTester(test_devices)
    
    if args.parallel:
        print("⚡ Running tests in parallel...")
        tester.run_parallel_tests(max_workers=min(5, len(test_devices)))
    else:
        print("🐌 Running tests sequentially (network-friendly)...")
        tester.run_sequential_tests()
    
    # Display results
    tester.print_summary()
    tester.save_report(args.report)
    
    # Return appropriate exit code
    report = tester.generate_report()
    success_rate = report['test_summary']['success_rate']
    
    if success_rate >= 80:
        return 0  # Success
    elif success_rate >= 50:
        return 1  # Partial success
    else:
        return 2  # Failure

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⚠️  Test cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
