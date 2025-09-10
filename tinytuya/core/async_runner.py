import asyncio
import threading
from concurrent.futures import Future

class AsyncRunner:
    """A class to run an asyncio event loop in a separate, dedicated thread.

    This allows you to safely submit coroutines to the event loop from
    other threads, making it useful for integrating asyncio with
    synchronous codebases or libraries.
    """
    def __init__(self):
        """Initializes the AsyncRunner, creating and starting the event loop thread."""
        self._loop = None
        self._loop_ready_event = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._loop_ready_event.wait()

    def _run_loop(self):
        """Internal method to create and run the asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop_ready_event.set()
        self._loop.run_forever()

    def run(self, coro, nowait=False):
        """
        Run async coroutine from sync context.

        Args:
            coro: The async coroutine to run

        Returns:
            The result of the coroutine

        Raises:
            Any exception raised by the coroutine
        """
        if nowait:
            asyncio.run_coroutine_threadsafe(coro, self._loop)
            return
        else:
            future: Future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            return future.result()

    def shutdown(self):
        """Stops the event loop and joins the thread.

        Note: The shutdown is safe because `XenonDeviceAsync.close` is always called
        before this method, which ensures the event loop is properly and
        gracefully shut down.
        """
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()
