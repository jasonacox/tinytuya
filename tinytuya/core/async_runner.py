# TinyTuya Async Runner Utility
# -*- coding: utf-8 -*-
"""
Utility for running async code from sync contexts across Python versions.
This is the key component that enables sync wrappers to call async implementations.
"""

import asyncio
import sys
import threading
import logging
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

class AsyncRunner:
    """
    Handles running async code from sync context across Python versions.
    
    This class manages the complexity of:
    - Running async code when no event loop exists
    - Running async code when already inside an event loop
    - Python version compatibility (3.5+)
    - Thread safety for multiple sync callers
    """
    
    _thread_pool = None
    _thread_pool_lock = threading.Lock()
    
    @classmethod
    def get_thread_pool(cls):
        """Get or create a thread pool for running async code"""
        if cls._thread_pool is None:
            with cls._thread_pool_lock:
                if cls._thread_pool is None:
                    cls._thread_pool = ThreadPoolExecutor(
                        max_workers=10, 
                        thread_name_prefix="tinytuya-async"
                    )
        return cls._thread_pool
    
    @classmethod
    def cleanup(cls):
        """Clean up the thread pool"""
        if cls._thread_pool is not None:
            with cls._thread_pool_lock:
                if cls._thread_pool is not None:
                    cls._thread_pool.shutdown(wait=True)
                    cls._thread_pool = None
    
    @staticmethod
    def run(coro):
        """
        Run async coroutine from sync context.
        
        Args:
            coro: The async coroutine to run
            
        Returns:
            The result of the coroutine
            
        Raises:
            Any exception raised by the coroutine
        """
        # First, try to detect if we're in a running event loop
        try:
            # Use get_running_loop() if available (Python 3.7+)
            # For Python 3.6 and below, fallback to get_event_loop() + is_running() check
            if hasattr(asyncio, 'get_running_loop'):
                loop = asyncio.get_running_loop()
            else:
                # Python 3.6 and below fallback
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    raise RuntimeError("no running event loop")
                    
            # If we reach here, we're in an async context and need to run in a thread
            log.debug("Already in event loop, running async code in thread pool")
            executor = AsyncRunner.get_thread_pool()
            
            # Create a new event loop in the thread and run the coroutine
            def run_in_thread():
                if sys.version_info >= (3, 7):
                    return asyncio.run(coro)
                else:
                    # Python 3.6 and below fallback
                    new_loop = asyncio.new_event_loop()
                    try:
                        return new_loop.run_until_complete(coro)
                    finally:
                        new_loop.close()
            
            future = executor.submit(run_in_thread)
            return future.result()
            
        except RuntimeError as e:
            # No running loop or other asyncio error
            error_msg = str(e).lower()
            if ("no running event loop" in error_msg or 
                "no current event loop" in error_msg or
                "tinytuya detected async context" in error_msg):
                log.debug("No event loop running, creating new one")
                # We can run directly since there's no event loop
                if sys.version_info >= (3, 7):
                    return asyncio.run(coro)
                else:
                    # Python 3.6 and below fallback
                    loop = asyncio.new_event_loop()
                    try:
                        return loop.run_until_complete(coro)
                    finally:
                        loop.close()
            else:
                # Some other asyncio error, re-raise with better context
                raise RuntimeError(f"TinyTuya AsyncRunner encountered an unexpected error: {e}") from e

# Cleanup thread pool on module exit
import atexit
atexit.register(AsyncRunner.cleanup)
