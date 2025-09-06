#!/usr/bin/env python3
"""Single test for CoverDevice"""

import sys
import unittest
sys.path.insert(0, '.')

from tinytuya import CoverDevice
from tinytuya.core import AsyncRunner
from unittest.mock import patch

class SingleCoverTest(unittest.TestCase):
    def test_cover_initialization(self):
        """Test cover device initialization and basic attributes."""
        cover = CoverDevice("test_id", "192.168.1.100", "test_key", version=3.1)
        self.assertIsNotNone(cover._async_impl)
        self.assertIsNotNone(cover._runner)
        self.assertIsInstance(cover._runner, AsyncRunner)
        print("✅ Initialization test passed")

    def test_cover_methods(self):
        """Test cover-specific methods exist"""
        cover = CoverDevice("dev1", "192.168.1.100", "key123", version="3.3")
        
        # Test method existence
        self.assertTrue(hasattr(cover, 'open_cover'))
        self.assertTrue(hasattr(cover, 'close_cover'))
        self.assertTrue(hasattr(cover, 'stop_cover'))
        print("✅ Cover methods test passed")

    def test_cover_method_calls(self):
        """Test cover method delegation"""
        cover = CoverDevice("dev1", "192.168.1.100", "key123", version="3.3")
        
        with patch.object(cover._runner, 'run', return_value=True) as mock_run:
            result = cover.open_cover()
            mock_run.assert_called_once()
            self.assertTrue(result)
        print("✅ Cover method call test passed")

if __name__ == '__main__':
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(SingleCoverTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed!")
    else:
        print(f"\n❌ {len(result.failures)} failures, {len(result.errors)} errors")
