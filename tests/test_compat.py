"""
Compatibility utilities for testing across Python versions.
"""

from unittest.mock import Mock

# Python 3.7 compatibility for AsyncMock
try:
    from unittest.mock import AsyncMock
except ImportError:
    # Fallback for Python < 3.8
    class AsyncMock(Mock):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            
        async def __call__(self, *args, **kwargs):
            return super().__call__(*args, **kwargs)

__all__ = ['AsyncMock']
