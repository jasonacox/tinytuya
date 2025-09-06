#!/usr/bin/env python3
"""
Extract device information from snapshot.json for regression testing

This script parses the snapshot.json file and extracts the essential
device parameters needed for practical testing: name, id, ip, key, and version.
"""

import json
import sys
import os

def extract_devices_from_snapshot(snapshot_path="../snapshot.json"):
    """Extract device information from snapshot.json"""
    
    if not os.path.exists(snapshot_path):
        print(f"❌ Snapshot file not found: {snapshot_path}")
        return [], None
    
    try:
        with open(snapshot_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing snapshot.json: {e}")
        return [], None
    except Exception as e:
        print(f"❌ Error reading snapshot.json: {e}")
        return [], None
    
    device_list = []
    snapshot_devices = data.get('devices', [])
    
    print(f"📄 Found {len(snapshot_devices)} devices in snapshot.json")
    
    for device in snapshot_devices:
        # Extract essential fields
        device_info = {
            'name': device.get('name', 'Unknown Device'),
            'id': device.get('id', ''),
            'ip': device.get('ip', ''),
            'key': device.get('key', ''),
            'version': device.get('ver', '3.3'),  # Default to 3.3 if not specified
            'active': device.get('active', 0),
            'dev_type': device.get('dev_type', 'default'),
            'encrypt': device.get('encrypt', True)
        }
        
        # Skip devices with missing critical information
        if not all([device_info['id'], device_info['ip'], device_info['key']]):
            print(f"⚠️  Skipping device '{device_info['name']}' - missing required fields")
            continue
            
        device_list.append(device_info)
    
    print(f"✅ Extracted {len(device_list)} valid devices for testing")
    return device_list, data

def save_devices_list(device_list, snapshot_data, output_path="test_devices.json"):
    """Save extracted devices to a JSON file"""
    try:
        with open(output_path, 'w') as f:
            json.dump({
                'extracted_timestamp': snapshot_data.get('timestamp', 0) if snapshot_data else 0,
                'device_count': len(device_list),
                'devices': device_list
            }, f, indent=2)
        print(f"💾 Saved device list to {output_path}")
        return True
    except Exception as e:
        print(f"❌ Error saving device list: {e}")
        return False

def print_device_summary(device_list):
    """Print a summary of extracted devices"""
    print("\n📊 Device Summary:")
    print(f"{'Name':<25} {'ID':<25} {'IP':<15} {'Version':<8} {'Type'}")
    print("-" * 80)
    
    for device in device_list:
        print(f"{device['name']:<25} {device['id']:<25} {device['ip']:<15} {device['version']:<8} {device['dev_type']}")

if __name__ == "__main__":
    print("🔍 TinyTuya Device Extractor")
    print("=" * 40)
    
    # Extract devices from snapshot
    devices, snapshot_data = extract_devices_from_snapshot()
    
    if devices:
        # Save to JSON file
        save_devices_list(devices, snapshot_data)
        
        # Print summary
        print_device_summary(devices)
        
        print(f"\n🎯 Ready for regression testing with {len(devices)} devices!")
    else:
        print("❌ No devices extracted. Check your snapshot.json file.")
        sys.exit(1)
