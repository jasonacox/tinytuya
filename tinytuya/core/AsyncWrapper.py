"""
AsyncWrapper - Base class for creating sync wrappers of async device classes.

This module provides the foundation for TinyTuya's sync wrapper architecture,
allowing async device classes to be used synchronously with minimal overhead.
"""

import asyncio
import inspect
import warnings
from typing import Any, Callable, TypeVar, Type
from .async_runner import AsyncRunner

T = TypeVar('T')


class AsyncWrapper:
    """
    Base class for creating synchronous wrappers of async device classes.
    
    This class automatically wraps async methods to make them synchronous,
    delegates attribute access to the wrapped async implementation, and
    handles proper cleanup of async resources.
    
    Usage:
        class MyDevice(AsyncWrapper):
            def __init__(self, *args, **kwargs):
                super().__init__(MyDeviceAsync, *args, **kwargs)
    """
    
    def __init__(self, async_class: Type[T], *args, **kwargs):
        """
        Initialize the sync wrapper with an async implementation.
        
        Args:
            async_class: The async class to wrap
            *args: Arguments to pass to the async class constructor
            **kwargs: Keyword arguments to pass to the async class constructor
        """
        self._async_impl = async_class(*args, **kwargs)
        self._runner = AsyncRunner()
        self._async_class = async_class
        
        # Cache commonly accessed attributes to avoid repeated __getattr__ calls
        self._cached_attrs = {}
    
    def __getattr__(self, name: str) -> Any:
        """
        Delegate attribute access to the async implementation.
        
        Automatically wraps async methods to make them synchronous.
        Caches wrapped methods to avoid repeated introspection.
        
        Args:
            name: The attribute name to access
            
        Returns:
            The attribute value, with async methods wrapped for sync use
        """
        # Check cache first
        if name in self._cached_attrs:
            return self._cached_attrs[name]
        
        # Get the attribute from the async implementation
        try:
            attr = getattr(self._async_impl, name)
        except AttributeError:
            # If attribute doesn't exist on async impl, raise AttributeError
            # with the wrapper class name for clearer error messages
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
        
        # If it's a callable, check if it's async and wrap it
        if callable(attr):
            if self._is_async_method(attr):
                wrapped_method = self._wrap_async_method(attr, name)
                self._cached_attrs[name] = wrapped_method
                return wrapped_method
            else:
                # Regular method, cache and return as-is
                self._cached_attrs[name] = attr
                return attr
        
        # For non-callable attributes, return as-is (don't cache as they might change)
        return attr
    
    def __setattr__(self, name: str, value: Any) -> None:
        """
        Delegate attribute setting to the async implementation.
        
        Internal attributes (starting with _) are set on the wrapper,
        while external attributes are set on the async implementation.
        
        Args:
            name: The attribute name to set
            value: The value to set
        """
        # Internal attributes (starting with _) stay on the wrapper
        if name.startswith('_'):
            super().__setattr__(name, value)
        else:
            # External attributes are delegated to the async implementation
            if hasattr(self, '_async_impl'):
                setattr(self._async_impl, name, value)
            else:
                # During initialization, _async_impl might not exist yet
                super().__setattr__(name, value)
    
    def _is_async_method(self, method: Callable) -> bool:
        """
        Check if a method is async (coroutine function).
        
        Args:
            method: The method to check
            
        Returns:
            True if the method is async, False otherwise
        """
        return asyncio.iscoroutinefunction(method)
    
    def _wrap_async_method(self, async_method: Callable, method_name: str) -> Callable:
        """
        Wrap an async method to make it synchronous.
        
        Args:
            async_method: The async method to wrap
            method_name: Name of the method (for debugging)
            
        Returns:
            A synchronous wrapper function
        """
        def sync_wrapper(*args, **kwargs):
            """Synchronous wrapper for async method"""
            try:
                # Suppress false positive "coroutine was never awaited" warnings
                # The coroutine IS awaited immediately by the runner
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", 
                                          message="coroutine .* was never awaited",
                                          category=RuntimeWarning)
                    coro = async_method(*args, **kwargs)
                return self._runner.run(coro)
            except Exception as e:
                # Re-raise with context about which method failed
                raise type(e)(f"Error in {self.__class__.__name__}.{method_name}: {str(e)}") from e
        
        # Preserve the original method's signature and docstring
        sync_wrapper.__name__ = method_name
        sync_wrapper.__doc__ = getattr(async_method, '__doc__', None)
        
        # Copy the signature if available (for better IDE support)
        try:
            sync_wrapper.__signature__ = inspect.signature(async_method)
        except (ValueError, TypeError):
            # Some methods might not have inspectable signatures
            pass
        
        return sync_wrapper
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit with proper async cleanup.
        
        Attempts to close the async implementation if it has a close method.
        """
        if hasattr(self._async_impl, 'close'):
            try:
                close_method = getattr(self._async_impl, 'close')
                if self._is_async_method(close_method):
                    self._runner.run(close_method())
                else:
                    close_method()
            except Exception:
                # Don't raise exceptions during cleanup, just log them
                import logging
                logging.getLogger(__name__).warning(
                    "Error during cleanup of %s", 
                    self.__class__.__name__,
                    exc_info=True
                )
    
    def __repr__(self) -> str:
        """String representation showing both wrapper and async impl"""
        return f"{self.__class__.__name__}(wrapping {self._async_impl!r})"
    
    def __str__(self) -> str:
        """String representation delegated to async implementation"""
        return str(self._async_impl)
    
    @property
    def async_impl(self):
        """
        Access to the underlying async implementation.
        
        Use this for advanced cases where direct async access is needed.
        """
        return self._async_impl
