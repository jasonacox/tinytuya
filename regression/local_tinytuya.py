#!/usr/bin/env python3
"""
TinyTuya Development Import Helper

This module ensures we import the local development version of TinyTuya
instead of any installed version, for regression testing purposes.
"""

import sys
import os
import importlib.util

def setup_local_tinytuya():
    """Setup imports to use the local development version of TinyTuya"""
    
    # Get the parent directory (main TinyTuya project root)
    regression_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(regression_dir)
    tinytuya_package_path = os.path.join(project_root, 'tinytuya')
    
    # Verify the local tinytuya package exists
    if not os.path.exists(tinytuya_package_path):
        raise ImportError(f"Local TinyTuya package not found at: {tinytuya_package_path}")
    
    # Remove any existing tinytuya from sys.modules to avoid conflicts
    modules_to_remove = [mod for mod in sys.modules.keys() if mod.startswith('tinytuya')]
    for mod in modules_to_remove:
        del sys.modules[mod]
    
    # Insert the project root at the beginning of sys.path
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Import the local version
    try:
        import tinytuya
        
        # Verify we're using the local version
        tinytuya_file = tinytuya.__file__
        if project_root not in tinytuya_file:
            raise ImportError(f"Still importing installed TinyTuya from: {tinytuya_file}")
        
        print(f"✅ Local TinyTuya loaded from: {tinytuya_file}")
        return tinytuya
        
    except ImportError as e:
        raise ImportError(f"Failed to import local TinyTuya: {e}")

# Auto-setup when this module is imported
tinytuya = setup_local_tinytuya()

# Re-export commonly used classes for convenience
OutletDevice = tinytuya.OutletDevice
BulbDevice = tinytuya.BulbDevice
CoverDevice = tinytuya.CoverDevice

# Try to import XenonDevice, but don't fail if it's not available in the expected location
try:
    from tinytuya.core.XenonDevice import XenonDevice
except ImportError:
    try:
        XenonDevice = tinytuya.XenonDevice
    except AttributeError:
        XenonDevice = None
        print("⚠️  XenonDevice not found - using basic device classes")
