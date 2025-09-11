# TinyTuya Async Runner Utility
# -*- coding: utf-8 -*-
"""
Utility for running async code from sync contexts across Python versions.
This is the key component that enables sync wrappers to call async implementations.
"""

import asyncio
import logging
import threading
from concurrent.futures import Future

tinytuya_event = {
    'loop': None,
    'thread': None,
    'ready': threading.Event(),
    'lock': threading.Lock(),
}

log = logging.getLogger(__name__)

def create_eventloop():
    """Creating and starting the event loop thread."""
    global tinytuya_event
    tinytuya_event['thread'] = threading.Thread(target=run_eventloop, daemon=True)
    tinytuya_event['thread'].start()
    tinytuya_event['ready'].wait()

def run_eventloop():
    """Global method to create and run the asyncio event loop."""
    global tinytuya_event
    tinytuya_event['loop'] = asyncio.new_event_loop()
    asyncio.set_event_loop(tinytuya_event['loop'])
    tinytuya_event['ready'].set()
    tinytuya_event['loop'].run_forever()

class AsyncRunner:
    """A class to run an asyncio event loop in a separate, dedicated thread.

    This allows you to safely submit coroutines to the event loop from
    other threads, making it useful for integrating asyncio with
    synchronous codebases or libraries.
    """
    def __init__(self):
        """Initializes the AsyncRunner, creating and starting the event loop thread."""
        global tinytuya_event
        with tinytuya_event['lock']:
            if not tinytuya_event['ready'].is_set():
                log.debug("No event loop running, creating new one")
                create_eventloop()
            self._loop = tinytuya_event['loop']

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
