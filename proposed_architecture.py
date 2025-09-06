# Example of the proposed simple wrapper pattern

from .core.async_runner import AsyncRunner

class AsyncWrapper:
    """Base class for all sync wrappers of async devices"""
    
    def __init__(self, async_class, *args, **kwargs):
        """Initialize wrapper with any async implementation"""
        self._async_impl = async_class(*args, **kwargs)
        self._runner = AsyncRunner()
        
    def __getattr__(self, name):
        """Delegate all attribute access to async implementation"""
        attr = getattr(self._async_impl, name)
        # If it's a coroutine method, wrap it with the runner
        if callable(attr) and hasattr(attr, '__code__'):
            if 'async' in str(attr.__code__.co_flags):
                def sync_wrapper(*args, **kwargs):
                    return self._runner.run(attr(*args, **kwargs))
                return sync_wrapper
        return attr
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self._async_impl, 'close'):
            self._runner.run(self._async_impl.close())

# Then each sync class becomes trivial:

class XenonDevice(AsyncWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(XenonDeviceAsync, *args, **kwargs)

class Device(AsyncWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(DeviceAsync, *args, **kwargs)

class BulbDevice(AsyncWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(BulbDeviceAsync, *args, **kwargs)
        
class OutletDevice(AsyncWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(OutletDeviceAsync, *args, **kwargs)

class CoverDevice(AsyncWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(CoverDeviceAsync, *args, **kwargs)
