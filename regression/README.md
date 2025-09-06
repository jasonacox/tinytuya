# TinyTuya Regression Testing Suite

This directory contains practical regression tests that validate TinyTuya v2.0.0's async-first architecture against real devices.

## Overview

The regression test suite performs real-world testing by:
- Extracting device information from `snapshot.json`
- Testing connectivity with actual devices on the network  
- Measuring response times and success rates
- Validating that the async-first architecture works with real hardware

## Regression Scripts

### `extract_devices.py`
Parses `../snapshot.json` and extracts device information needed for testing:
- Device name, ID, IP address, key, and version
- Filters out devices with missing critical information
- Saves extracted data to `test_devices.json`

### `regression_test.py` 
Main test suite that:
- Loads device information from snapshot
- Creates TinyTuya device instances
- Tests `status()` method on all devices
- Measures response times and success rates
- Generates comprehensive reports

### Generated Files

- `test_devices.json` - Extracted device information from snapshot
- `regression_report.json` - Detailed test results and metrics

## Test Modes

### Quick Testing (`--quick`)
Tests the first 5 devices from your snapshot. Perfect for:
- Initial validation after code changes
- Quick architecture health checks
- Development workflow testing

### Limited Testing (`--limit N`)
Tests the first N devices. Use when you want:
- More coverage than quick test but faster than full
- Specific number of devices for balanced testing

### Version Compatibility Testing (`--versions`)
Tests one device from each protocol version (3.1, 3.3, 3.4). Essential for:
- Ensuring compatibility across all Tuya protocol versions
- Release validation  
- Protocol-specific bug investigation
- **Distinguishes between network errors and version compatibility issues**
- Flags protocol errors (like "Unexpected Payload") as version compatibility problems
- Treats network/connection errors as infrastructure issues, not library problems

### Version Comparison Testing (`--compare-versions`)
Compares the local development version against the pip-installed stable version. Essential for:
- **Release validation** - ensuring new version performs as well as stable version
- **Performance regression detection** - identifying if changes impact response times
- **Compatibility assurance** - verifying new architecture maintains device compatibility  
- **Confidence building** - providing data-driven evidence that changes are safe
- Uses isolated subprocess testing to ensure true version separation

### Full Testing (`--full`)
Tests all devices in your snapshot. Use for:
- Comprehensive regression testing before releases
- Complete architecture validation
- Finding edge cases across your entire device fleet

### Parallel Testing (`--parallel`)
Runs tests in parallel for faster execution. Benefits:
- Significantly faster completion times
- Good for large device sets
- **Caution**: May overwhelm your network or router

### Extract Only (`--extract-only`)
Only processes the snapshot.json file without testing devices. Use for:
- Validating your device data
- Seeing what devices would be tested
- Troubleshooting snapshot parsing issues

## Usage

### Setup

You must first create the snapshot.json file of your devices. To do this run the
following from the project directory (parent of this one):

```bash
# Run wizard to get devices.json if you haven't already
python -m tinytuya wizard

# Run scan to get snapshot.json file
python -m tinytuya scan
```

### Extract Device Information
```bash
cd regression
python extract_devices.py
```

### Run Regression Tests

The test suite provides multiple testing modes through the `test.py` launcher:

```bash
cd regression

# Quick test (first 5 devices)
python test.py --quick

# Test specific number of devices
python test.py --limit 10

# Device version compatibility test (one device from each protocol version)
python test.py --versions

# Compare TinyTuya Versions - local development vs pip-installed
python test.py --compare-versions

# Full test (all devices - may take a while)
python test.py --full

# Parallel testing (faster but harder on network)
python test.py --parallel

# Extract devices only (no testing)
python test.py --extract-only

# Custom report filename
python test.py --quick --report my_test_results.json

# Default test (first 10 devices)
python test.py
```

You can also run the core regression module directly:
```bash
python regression_test.py
```

### Getting Help
```bash
# See all available options and examples
python test.py --help
```

### Custom Testing
```python
from regression_test import RegressionTester
from extract_devices import extract_devices_from_snapshot

# Load devices
devices, _ = extract_devices_from_snapshot("../snapshot.json")

# Create tester
tester = RegressionTester(devices)

# Run tests
tester.run_sequential_tests()  # or run_parallel_tests()

# Get results
tester.print_summary()
tester.save_report("my_test_report.json")
```

## Test Metrics

The regression suite tracks:
- **Success Rate**: Percentage of devices that respond successfully
- **Response Times**: Min/max/average response times  
- **Error Analysis**: Categorized failure reasons
- **Version Compatibility**: Protocol-specific compatibility analysis
- **Architecture Validation**: Overall health assessment

### Error Categorization

The test suite categorizes errors to distinguish between different types of issues:

**Version Compatibility Issues** (Library/Protocol Problems):
- `PROTOCOL_VERSION_ERROR`: "Unexpected Payload" or similar protocol errors
- `RESPONSE_FORMAT_ERROR`: Unexpected response structure for the version
- `UNKNOWN_VERSION_ERROR`: Unrecognized errors that may indicate version issues

**Infrastructure Issues** (Not Library Problems):
- `NETWORK_ERROR`: Network connectivity problems
- `CONNECTION_ERROR`: Device unreachable or offline  
- `NO_RESPONSE`: Device not responding (likely offline)

This categorization helps identify whether failures are due to TinyTuya compatibility issues or external factors like network problems or device availability.

### Success Thresholds
- **> 80%**: Architecture validation PASSED 🎉
- **50-80%**: Architecture validation PARTIAL ⚠️
- **< 50%**: Architecture validation FAILED ❌

## Architecture Validation

This test suite validates that TinyTuya v2.0.0's key architectural improvements work correctly:

1. **Async-First Design**: Sync wrappers properly delegate to async implementations
2. **Inheritance Model**: All device classes inherit from `XenonDevice`
3. **API Completeness**: Core methods like `status()`, `send()`, `receive()` work consistently
4. **Error Handling**: Graceful handling of network issues and device problems
5. **Performance**: Response times are reasonable for real-world usage

## Network Considerations

- Tests run sequentially by default to avoid overwhelming the network
- Parallel testing available but use with caution on large device sets
- Configurable timeouts (default: 5 seconds)
- Built-in delays between tests for network stability

## Troubleshooting

### No Devices Found
- Ensure `../snapshot.json` exists and contains device data
- Check that devices have required fields: `id`, `ip`, `key`

### High Failure Rate  
- Verify devices are powered on and connected to network
- Check network connectivity from test machine
- Some devices may be temporarily offline - this is expected

### Import Errors
- Run tests from within the `regression/` directory
- Ensure parent TinyTuya directory is accessible

## Future Enhancements

Potential additions to the regression suite:
- Device-specific testing (bulb color changes, outlet switching, etc.)
- Async-specific test patterns  
- Performance benchmarking over time
- Network topology analysis
- Automated daily/weekly regression runs
