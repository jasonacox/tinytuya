#!/usr/bin/env python3
"""
Utility functions for regression testing
"""

from typing import Dict, List, Any
from extract_devices import extract_devices_from_snapshot


def select_devices_by_version(device_list: List[Dict[str, Any]], versions_desired: List[str] = None, devices_per_version: int = 1) -> List[Dict[str, Any]]:
    """
    Select devices ensuring representation across different protocol versions
    
    Args:
        device_list: List of device dictionaries
        versions_desired: List of version strings to include (e.g., ['3.1', '3.3', '3.4'])
        devices_per_version: Number of devices per version to select
        
    Returns:
        List of selected devices with version diversity
    """
    
    if versions_desired is None:
        versions_desired = ['3.1', '3.3', '3.4']
    
    # Group devices by version
    devices_by_version = {}
    for device in device_list:
        version = str(device.get('version', '3.3'))  # Default to 3.3 if not specified
        if version not in devices_by_version:
            devices_by_version[version] = []
        devices_by_version[version].append(device)
    
    selected_devices = []
    version_counts = {}
    
    # First, try to get at least one device from each desired version
    for version in versions_desired:
        if version in devices_by_version and devices_by_version[version]:
            selected_devices.extend(devices_by_version[version][:devices_per_version])
            version_counts[version] = min(devices_per_version, len(devices_by_version[version]))
    
    # Report selection
    print("\n📋 DEVICE SELECTION BY PROTOCOL VERSION:")
    for version in sorted(version_counts.keys()):
        available = len(devices_by_version.get(version, []))
        selected = version_counts[version]
        print(f"   Protocol v{version}: Selected {selected}/{available} devices")
    
    total_selected = len(selected_devices)
    total_available = len(device_list)
    print(f"   Total: {total_selected}/{total_available} devices selected")
    
    return selected_devices


def get_devices_for_comparison() -> List[Dict[str, Any]]:
    """
    Get devices optimized for version comparison testing - one from each protocol version
    """
    print("📦 Loading devices from snapshot...")
    all_devices, _ = extract_devices_from_snapshot()
    
    if not all_devices:
        print("❌ No devices found in snapshot")
        return []
    
    # Select one device from each version for comparison, fallback to more devices if needed
    selected = select_devices_by_version(all_devices, versions_desired=['3.1', '3.3', '3.4'], devices_per_version=1)
    
    # If we didn't get devices from all versions, add more from available versions
    if len(selected) < 3:  # We want at least 3 devices for good testing
        # Group devices by version to see what's available
        devices_by_version = {}
        for device in all_devices:
            version = str(device.get('version', '3.3'))
            if version not in devices_by_version:
                devices_by_version[version] = []
            devices_by_version[version].append(device)
        
        print(f"⚠️  Only found {len(selected)} devices across different protocol versions.")
        print("📈 Adding more devices for comprehensive testing...")
        
        # Add more devices from the most common version (v3.3)
        if '3.3' in devices_by_version and len(selected) < 5:
            additional_needed = min(3, len(devices_by_version['3.3']) - 1)  # -1 because we already have one
            for device in devices_by_version['3.3'][1:additional_needed+1]:  # Skip first one we already have
                if device not in selected:
                    selected.append(device)
        
        print(f"📊 Final selection: {len(selected)} devices")
    
    return selected


if __name__ == "__main__":
    # Test the selection logic
    devices = get_devices_for_comparison()
    if devices:
        print(f"\n✅ Selected {len(devices)} devices for comparison testing:")
        for device in devices:
            print(f"   • {device['name']} (v{device.get('version', 'unknown')}) - {device['ip']}")
    else:
        print("❌ No devices selected")
