#!/usr/bin/env python3
"""
Isolated version comparison using subprocess to ensure complete module isolation
"""

import json
import subprocess
import sys
import time
from typing import List, Dict, Any

def run_version_comparison_isolated(devices: List[Dict[str, Any]], parallel: bool = False) -> Dict[str, Any]:
    """
    Run comparison tests using subprocess for complete isolation
    """
    print("=" * 80)
    print("🔄 TINYTUYA VERSION COMPARISON (ISOLATED)")
    print("=" * 80)
    
    # Save devices to temp file for subprocess
    with open('temp_devices.json', 'w') as f:
        json.dump(devices, f)
    
    try:
        # Test local version
        print("🧪 Testing LOCAL development version...")
        local_results = run_isolated_test('local', parallel)
        
        # Test pip version  
        print("\n🧪 Testing PIP-INSTALLED version...")
        pip_results = run_isolated_test('pip', parallel)
        
        # Generate comparison
        comparison = generate_comparison_report(local_results, pip_results)
        
        # Print results
        print_comparison_summary(comparison)
        
        return comparison
        
    finally:
        # Cleanup temp file
        import os
        if os.path.exists('temp_devices.json'):
            os.remove('temp_devices.json')

def run_isolated_test(version_type: str, parallel: bool) -> Dict[str, Any]:
    """Run test in isolated subprocess"""
    
    # Create a simple test script
    test_script = f'''
import json
import sys
import os

# Load devices
with open('temp_devices.json', 'r') as f:
    devices = json.load(f)

if "{version_type}" == "local":
    # Use local version
    from local_tinytuya import tinytuya
    version_info = f"Local TinyTuya v{{tinytuya.__version__}}"
else:
    # Use pip version - don't import local_tinytuya at all
    try:
        import tinytuya  
        version_info = f"Pip TinyTuya v{{tinytuya.__version__}}"
    except ImportError:
        print(json.dumps({{"error": "TinyTuya not installed via pip", "success": False}}))
        sys.exit(1)

print(f"   📦 {{version_info}}")

# Import regression tester AFTER setting up tinytuya
from regression_test import RegressionTester

tester = RegressionTester(devices, verbose=True)  # Enable verbose mode for comparison
{"tester.run_parallel_tests(max_workers=3)" if parallel else "tester.run_sequential_tests()"}

report = tester.generate_report()

result = {{
    'version': "{version_type}",
    'version_info': version_info,
    'results': tester.results,
    'report': report,
    'success': True
}}

print("COMPARISON_RESULT_START")
print(json.dumps(result, default=str))
print("COMPARISON_RESULT_END")
'''
    
    # Write test script
    with open(f'temp_test_{version_type}.py', 'w') as f:
        f.write(test_script)
    
    try:
        # Run subprocess with real-time output
        import subprocess
        
        # Start the process
        process = subprocess.Popen([
            sys.executable, f'temp_test_{version_type}.py'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        # Read output line by line and display it
        stdout_lines = []
        stderr_lines = []
        
        # Read stdout in real-time
        for line in process.stdout:
            print(line.rstrip())  # Display immediately
            stdout_lines.append(line)
        
        # Wait for process to complete and get stderr
        _, stderr = process.communicate()
        if stderr:
            stderr_lines = stderr.splitlines()
            for line in stderr_lines:
                print(f"ERROR: {line}")
        
        # Combine output for parsing
        full_output = ''.join(stdout_lines)
        full_stderr = stderr if stderr else ''
        
        if process.returncode != 0:
            return {
                'version': version_type,
                'error': f'Test failed: {full_stderr}',
                'success': False
            }
        
        # Extract JSON result
        output = full_output
        start_marker = "COMPARISON_RESULT_START"
        end_marker = "COMPARISON_RESULT_END"
        
        start_idx = output.find(start_marker)
        end_idx = output.find(end_marker)
        
        if start_idx == -1 or end_idx == -1:
            return {
                'version': version_type,
                'error': 'Could not parse test output',
                'success': False,
                'raw_output': output
            }
        
        json_str = output[start_idx + len(start_marker):end_idx].strip()
        return json.loads(json_str)
        
    except subprocess.TimeoutExpired:
        return {
            'version': version_type,
            'error': 'Test timed out',
            'success': False
        }
    except Exception as e:
        return {
            'version': version_type,
            'error': f'Test error: {str(e)}',
            'success': False
        }
    finally:
        # Cleanup
        import os
        if os.path.exists(f'temp_test_{version_type}.py'):
            os.remove(f'temp_test_{version_type}.py')

def generate_comparison_report(local_results: Dict[str, Any], pip_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive comparison report including behavioral analysis"""
    
    if not local_results.get('success') or not pip_results.get('success'):
        return {
            'comparison_valid': False,
            'local_results': local_results,
            'pip_results': pip_results,
            'exit_code': 2
        }
    
    local_report = local_results['report']
    pip_report = pip_results['report']
    
    # Performance comparison
    local_perf = local_report['performance_metrics']
    pip_perf = pip_report['performance_metrics']
    
    perf_comparison = {
        'avg_response_time': {
            'local': local_perf['avg_response_time'],
            'pip': pip_perf['avg_response_time'],
            'improvement': local_perf['avg_response_time'] - pip_perf['avg_response_time'],  # local - pip (negative = local slower)
            'improvement_pct': ((local_perf['avg_response_time'] - pip_perf['avg_response_time']) / pip_perf['avg_response_time']) * 100 if pip_perf['avg_response_time'] > 0 else 0
        }
    }
    
    # Success rate comparison
    local_summary = local_report['test_summary']
    pip_summary = pip_report['test_summary']
    
    success_comparison = {
        'local_success_rate': local_summary['success_rate'],
        'pip_success_rate': pip_summary['success_rate'],
        'success_rate_diff': local_summary['success_rate'] - pip_summary['success_rate']
    }
    
    # NEW: Behavioral consistency analysis
    behavioral_analysis = analyze_behavioral_consistency(local_results['results'], pip_results['results'])
    
    # Overall assessment (now includes behavioral consistency)
    overall_better = (
        success_comparison['success_rate_diff'] >= -5 and  # Allow 5% tolerance
        perf_comparison['avg_response_time']['improvement'] >= -0.2 and  # Allow 0.2s slower (negative)
        behavioral_analysis['consistency_rate'] >= 95  # Require 95% behavioral consistency
    )
    
    return {
        'comparison_valid': True,
        'local_results': local_results,
        'pip_results': pip_results,
        'performance_comparison': perf_comparison,
        'success_comparison': success_comparison,
        'behavioral_analysis': behavioral_analysis,
        'overall_assessment': {
            'local_better_or_equal': overall_better,
            'recommendation': 'LOCAL version ready for release' if overall_better else 'LOCAL version needs improvement'
        },
        'timestamp': time.time(),
        'exit_code': 0 if overall_better else 1
    }

def analyze_behavioral_consistency(local_results: List[Dict[str, Any]], pip_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze behavioral consistency between versions by comparing actual device responses
    """
    
    # Create mapping of device IP to results for easy comparison
    local_by_ip = {r['ip']: r for r in local_results}
    pip_by_ip = {r['ip']: r for r in pip_results}
    
    total_devices = len(local_results)
    consistent_devices = 0
    behavioral_issues = []
    response_differences = []
    version_consistency = {}  # Track consistency by protocol version
    
    for ip in local_by_ip:
        if ip not in pip_by_ip:
            behavioral_issues.append({
                'device_ip': ip,
                'device_name': local_by_ip[ip]['name'],
                'protocol_version': local_by_ip[ip].get('version', 'unknown'),
                'issue': 'Device only tested in local version'
            })
            continue
        
        local_result = local_by_ip[ip]
        pip_result = pip_by_ip[ip]
        protocol_version = local_result.get('version', 'unknown')
        
        # Initialize version tracking
        if protocol_version not in version_consistency:
            version_consistency[protocol_version] = {'total': 0, 'consistent': 0}
        version_consistency[protocol_version]['total'] += 1
        
        # Compare success status
        if local_result['success'] != pip_result['success']:
            behavioral_issues.append({
                'device_ip': ip,
                'device_name': local_result['name'],
                'protocol_version': protocol_version,
                'issue': f"Success mismatch: local={local_result['success']}, pip={pip_result['success']}"
            })
            continue
        
        # If both failed, check if they failed the same way
        if not local_result['success'] and not pip_result['success']:
            local_error = local_result.get('error', '')
            pip_error = pip_result.get('error', '')
            if normalize_error(local_error) == normalize_error(pip_error):
                consistent_devices += 1  # Same failure = consistent behavior
                version_consistency[protocol_version]['consistent'] += 1
            else:
                behavioral_issues.append({
                    'device_ip': ip,
                    'device_name': local_result['name'],
                    'protocol_version': protocol_version,
                    'issue': f"Different failure types: local='{local_error}', pip='{pip_error}'"
                })
            continue
        
        # If both succeeded, compare the actual response data
        if local_result['success'] and pip_result['success']:
            consistency_check = compare_device_responses(
                local_result, pip_result, ip
            )
            
            if consistency_check['consistent']:
                consistent_devices += 1
                version_consistency[protocol_version]['consistent'] += 1
            else:
                # Add protocol version to issues
                for issue in consistency_check['issues']:
                    issue['protocol_version'] = protocol_version
                behavioral_issues.extend(consistency_check['issues'])
                response_differences.append(consistency_check['differences'])
    
    consistency_rate = (consistent_devices / total_devices * 100) if total_devices > 0 else 0
    
    return {
        'total_devices': total_devices,
        'consistent_devices': consistent_devices,
        'inconsistent_devices': total_devices - consistent_devices,
        'consistency_rate': consistency_rate,
        'behavioral_issues': behavioral_issues,
        'response_differences': response_differences,
        'version_consistency': version_consistency,
        'analysis_summary': generate_behavioral_summary(consistency_rate, behavioral_issues)
    }

def compare_device_responses(local_result: Dict[str, Any], pip_result: Dict[str, Any], device_ip: str) -> Dict[str, Any]:
    """
    Compare actual device responses between versions for behavioral consistency
    """
    
    local_data = local_result.get('status_data')
    pip_data = pip_result.get('status_data')
    device_name = local_result['name']
    
    issues = []
    differences = {}
    
    # Handle None responses
    if local_data is None and pip_data is None:
        return {'consistent': True, 'issues': [], 'differences': {}}
    
    if local_data is None or pip_data is None:
        issues.append({
            'device_ip': device_ip,
            'device_name': device_name,
            'issue': f"Response data mismatch: one version returned None"
        })
        return {'consistent': False, 'issues': issues, 'differences': {'one_none': True}}
    
    # Compare response structures
    if type(local_data) != type(pip_data):
        issues.append({
            'device_ip': device_ip,
            'device_name': device_name,
            'issue': f"Response type mismatch: local={type(local_data)}, pip={type(pip_data)}"
        })
        return {'consistent': False, 'issues': issues, 'differences': {'type_mismatch': True}}
    
    # For dict responses (most common), compare key-by-key
    if isinstance(local_data, dict) and isinstance(pip_data, dict):
        return compare_dict_responses(local_data, pip_data, device_ip, device_name)
    
    # For other types, direct comparison
    if local_data == pip_data:
        return {'consistent': True, 'issues': [], 'differences': {}}
    else:
        issues.append({
            'device_ip': device_ip,
            'device_name': device_name,
            'issue': f"Response value mismatch: local='{local_data}', pip='{pip_data}'"
        })
        return {'consistent': False, 'issues': issues, 'differences': {'value_mismatch': True}}

def compare_dict_responses(local_data: dict, pip_data: dict, device_ip: str, device_name: str) -> Dict[str, Any]:
    """
    Compare dictionary responses for behavioral consistency
    """
    
    issues = []
    differences = {}
    
    # Check for error responses first
    local_error = local_data.get('Error')
    pip_error = pip_data.get('Error')
    
    if local_error or pip_error:
        if normalize_error(local_error or '') == normalize_error(pip_error or ''):
            return {'consistent': True, 'issues': [], 'differences': {}}
        else:
            issues.append({
                'device_ip': device_ip,
                'device_name': device_name,
                'issue': f"Error response mismatch: local='{local_error}', pip='{pip_error}'"
            })
            return {'consistent': False, 'issues': issues, 'differences': {'error_mismatch': True}}
    
    # Compare successful responses
    # Check for DPS data (most important)
    local_dps = local_data.get('dps', {})
    pip_dps = pip_data.get('dps', {})
    
    # Only flag structural differences (missing keys), not value differences
    local_keys = set(local_dps.keys()) if local_dps else set()
    pip_keys = set(pip_dps.keys()) if pip_dps else set()
    
    if local_keys != pip_keys:
        # Only structural differences are real issues
        dps_diff = analyze_dps_differences(local_dps, pip_dps)
        issues.append({
            'device_ip': device_ip,
            'device_name': device_name,
            'issue': f"DPS structure mismatch: {dps_diff}"
        })
        differences['dps_differences'] = dps_diff
    # Note: Same keys but different values is OK - values change over time
    
    # Check device ID consistency
    local_dev_id = local_data.get('devId')
    pip_dev_id = pip_data.get('devId')
    
    if local_dev_id != pip_dev_id and local_dev_id is not None and pip_dev_id is not None:
        issues.append({
            'device_ip': device_ip,
            'device_name': device_name,
            'issue': f"Device ID mismatch: local='{local_dev_id}', pip='{pip_dev_id}'"
        })
        differences['dev_id_mismatch'] = True
    
    # If we found issues, it's inconsistent
    if issues:
        return {'consistent': False, 'issues': issues, 'differences': differences}
    
    return {'consistent': True, 'issues': [], 'differences': {}}

def analyze_dps_differences(local_dps: dict, pip_dps: dict) -> str:
    """
    Analyze structural differences in DPS (Data Point) responses
    Focus on keys/structure, not values (which can vary over time)
    """
    
    if not local_dps and not pip_dps:
        return "Both empty"
    
    if not local_dps:
        return f"Local empty, Pip has {len(pip_dps)} DPS points"
    
    if not pip_dps:
        return f"Pip empty, Local has {len(local_dps)} DPS points"
    
    local_keys = set(local_dps.keys())
    pip_keys = set(pip_dps.keys())
    
    missing_in_pip = local_keys - pip_keys
    missing_in_local = pip_keys - local_keys
    
    differences = []
    
    if missing_in_pip:
        differences.append(f"Missing in pip: {sorted(missing_in_pip)}")
    
    if missing_in_local:
        differences.append(f"Missing in local: {sorted(missing_in_local)}")
    
    # NOTE: We intentionally don't compare values since they can vary over time
    # (voltage, current, temperature, etc.) - we only care about structural consistency
    
    if differences:
        return "; ".join(differences)
    else:
        # Same keys = structurally consistent (values may differ and that's OK)
        return "Structurally consistent"

def normalize_error(error_msg: str) -> str:
    """
    Normalize error messages for comparison (remove timing/network specifics)
    """
    if not error_msg:
        return ""
    
    # Normalize common variations
    error_msg = error_msg.lower()
    error_msg = error_msg.replace("network error", "network_error")
    error_msg = error_msg.replace("unable to connect", "connection_failed")
    error_msg = error_msg.replace("timeout", "timeout_error")
    
    return error_msg

def generate_behavioral_summary(consistency_rate: float, behavioral_issues: List[Dict[str, Any]]) -> str:
    """
    Generate human-readable summary of behavioral analysis
    """
    
    if consistency_rate >= 95:
        return f"Excellent behavioral consistency ({consistency_rate:.1f}%)"
    elif consistency_rate >= 80:
        return f"Good behavioral consistency ({consistency_rate:.1f}%) with minor differences"
    elif consistency_rate >= 60:
        return f"Moderate behavioral consistency ({consistency_rate:.1f}) - review differences"
    else:
        return f"Poor behavioral consistency ({consistency_rate:.1f}%) - significant issues detected"

def print_comparison_summary(comparison: Dict[str, Any]):
    """Print comprehensive comparison summary including behavioral analysis"""
    
    if not comparison['comparison_valid']:
        print("❌ Comparison could not be completed:")
        if not comparison['local_results'].get('success'):
            print(f"   Local version error: {comparison['local_results'].get('error', 'Unknown')}")
        if not comparison['pip_results'].get('success'):
            print(f"   Pip version error: {comparison['pip_results'].get('error', 'Unknown')}")
        return
    
    print("\n" + "=" * 80)
    print("📊 VERSION COMPARISON RESULTS")
    print("=" * 80)
    
    # Version info
    local_info = comparison['local_results']['version_info']
    pip_info = comparison['pip_results']['version_info']
    print(f"🏠 Local Version:     {local_info}")
    print(f"📦 Pip Version:       {pip_info}")
    
    # Success rates
    success = comparison['success_comparison']
    print("\n🎯 SUCCESS RATE COMPARISON:")
    print(f"   Local Success Rate:  {success['local_success_rate']:.1f}%")
    print(f"   Pip Success Rate:    {success['pip_success_rate']:.1f}%")
    diff_symbol = "📈" if success['success_rate_diff'] > 0 else "📉" if success['success_rate_diff'] < 0 else "➡️"
    print(f"   Difference:          {diff_symbol} {success['success_rate_diff']:+.1f}%")
    
    # Performance comparison
    perf = comparison['performance_comparison']['avg_response_time']
    print("\n⚡ PERFORMANCE COMPARISON:")
    print(f"   Local Avg Response:  {perf['local']:.3f}s")
    print(f"   Pip Avg Response:    {perf['pip']:.3f}s")
    
    if perf['improvement'] < 0:
        # Negative improvement means local is slower than pip (bad)
        print(f"   Performance:         � {abs(perf['improvement']):.3f}s SLOWER ({abs(perf['improvement_pct']):.1f}% regression)")
    elif perf['improvement'] > 0:
        # Positive improvement means local is faster than pip (good)
        print(f"   Performance:         � {perf['improvement']:.3f}s FASTER ({perf['improvement_pct']:.1f}% improvement)")
    else:
        print("   Performance:         ➡️  Same performance")
    
    # NEW: Behavioral consistency analysis
    behavioral = comparison['behavioral_analysis']
    print(f"\n🔍 BEHAVIORAL CONSISTENCY ANALYSIS:")
    print(f"   Total Devices Tested:     {behavioral['total_devices']}")
    print(f"   Behaviorally Consistent:  {behavioral['consistent_devices']} ({behavioral['consistency_rate']:.1f}%)")
    print(f"   Behaviorally Different:   {behavioral['inconsistent_devices']}")
    print(f"   Analysis: {behavioral['analysis_summary']}")
    
    # Show consistency by protocol version
    version_consistency = behavioral.get('version_consistency', {})
    if version_consistency:
        print(f"\n📈 CONSISTENCY BY PROTOCOL VERSION:")
        for version in sorted(version_consistency.keys()):
            vc = version_consistency[version]
            version_rate = (vc['consistent'] / vc['total'] * 100) if vc['total'] > 0 else 0
            print(f"   Protocol v{version}: {version_rate:.1f}% ({vc['consistent']}/{vc['total']} devices)")
    
    # Show behavioral issues if any
    if behavioral['behavioral_issues']:
        print(f"\n⚠️  BEHAVIORAL DIFFERENCES DETECTED:")
        # Group issues by protocol version
        grouped_by_version = {}
        for issue in behavioral['behavioral_issues']:
            version = issue.get('protocol_version', 'unknown')
            if version not in grouped_by_version:
                grouped_by_version[version] = []
            grouped_by_version[version].append(issue)
        
        shown_count = 0
        for version in sorted(grouped_by_version.keys()):
            issues = grouped_by_version[version]
            if shown_count < 5:  # Show details for first 5 issues total
                print(f"   Protocol v{version}:")
                for issue in issues:
                    if shown_count >= 5:
                        break
                    print(f"     • {issue['device_name']} ({issue['device_ip']})")
                    print(f"       {issue['issue']}")
                    shown_count += 1
            else:
                print(f"   Protocol v{version}: {len(issues)} issues")
        
        if len(behavioral['behavioral_issues']) > 5:
            print(f"   ... and {len(behavioral['behavioral_issues']) - 5} more issues total")
    
    # Show response differences if any
    if behavioral['response_differences']:
        print(f"\n📊 RESPONSE DATA DIFFERENCES:")
        for diff in behavioral['response_differences'][:3]:  # Show first 3
            print(f"   • {diff}")
        
        if len(behavioral['response_differences']) > 3:
            print(f"   ... and {len(behavioral['response_differences']) - 3} more differences")
    
    # Overall assessment
    assessment = comparison['overall_assessment']
    behavioral_ok = behavioral['consistency_rate'] >= 95
    
    if assessment['local_better_or_equal'] and behavioral_ok:
        print("\n🎉 OVERALL ASSESSMENT: LOCAL VERSION READY")
        print(f"   {assessment['recommendation']}")
        print("   ✅ Success rate maintained or improved")
        print("   ✅ Performance acceptable") 
        print("   ✅ Behavioral consistency maintained")
    elif assessment['local_better_or_equal'] and not behavioral_ok:
        print("\n⚠️  OVERALL ASSESSMENT: BEHAVIORAL ISSUES DETECTED")
        print("   LOCAL version has performance/success issues resolved")
        print("   ❌ Behavioral differences detected - investigate before release")
        print(f"   Behavioral consistency: {behavioral['consistency_rate']:.1f}% (need 95%+)")
    else:
        print("\n⚠️  OVERALL ASSESSMENT: LOCAL VERSION NEEDS WORK")
        print(f"   {assessment['recommendation']}")
        if not behavioral_ok:
            print(f"   ❌ Behavioral consistency issues: {behavioral['consistency_rate']:.1f}%")

if __name__ == "__main__":
    print("This module should be used via test.py --compare-versions")
