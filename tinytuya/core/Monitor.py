# TinyTuya Module
# -*- coding: utf-8 -*-
"""
Monitor — Single-thread, multi-device status monitoring via selectors.

Design based on the Monitor (TBD) proposal by @3735943886.

A single ``Monitor`` watches any number of Tuya devices on one OS thread
using ``selectors`` (``select``/``poll``/``epoll``).  Updates are delivered
through callbacks.  No ``asyncio``, no per-device threads, no new
dependencies.

This class is experimental. It currently duplicates some framing logic from
``XenonDevice._receive()`` to keep the feature self-contained and limit the
blast radius for this release. Longer term, that shared parsing path should
be refactored into a common helper. Please report issues so the API and
internals can be hardened before this graduates from experimental status.

Usage::

    import tinytuya

    def on_status(device, result):
        print(device.id, result.get('dps'))

    mon = tinytuya.Monitor(on_status=on_status)
    handles = []
    for cfg in my_devices:
        d = tinytuya.OutletDevice(cfg['id'], cfg['ip'], cfg['key'],
                                  version=3.3, persist=True)
        handle = mon.add(d)     # blocking connect happens here, once
        handles.append(handle)

    mon.start()                  # reactor runs on one daemon thread

    # Send commands via the proxy handle (thread-safe)
    handles[0].set_value(1, True)

    # Or use .command() directly:
    # mon.command(d, 'set_value', 1, True)

    mon.stop()

With automatic reconnect::

    mon = tinytuya.Monitor(
        on_status=on_status,
        on_disconnect=lambda dev, err: print(f'{dev.id} disconnected: {err}'),
        auto_reconnect=True,           # enables background connector thread
        reconnect_backoff=5.0,         # seconds between retry attempts
    )

Or drive it from a caller's own loop::

    while True:
        mon.poll(timeout=1.0)

Author: Sam (jasonacox-sam)
"""

import inspect
import logging
import os
import selectors
import socket
import threading
import time

from . import header as H
from .const import MAX_PAYLOAD_LENGTH
from .message_helper import (
    parse_header,
    unpack_message,
)

log = logging.getLogger(__name__)


def _accepts_nowait(method):
    """Return True if ``method`` accepts a ``nowait`` keyword argument.

    Used so the command proxy only injects ``nowait=True`` for methods that
    actually take it; methods without it (e.g. ``set_socketPersistent``) would
    otherwise raise ``TypeError`` when dispatched.
    """
    try:
        params = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return True  # cannot introspect — preserve historical behavior
    if 'nowait' in params:
        return True
    return any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())


# ── Callback types ──────────────────────────────────────────────────
# on_status(device, result)        — decoded status payload
# on_connect(device, error)        — error is None on success
# on_disconnect(device, error)     — connection lost


class _DeviceState:
    """Per-device bookkeeping kept by Monitor."""

    __slots__ = (
        'device', 'fileno', 'recv_buffer', 'heartbeat_interval',
        'last_heartbeat', 'on_status', 'on_connect', 'on_disconnect',
        'saved_retry_limit',
    )

    def __init__(self, device, heartbeat_interval=12,
                 on_status=None, on_connect=None, on_disconnect=None):
        self.device = device
        self.fileno = None          # set when registered with selector
        self.recv_buffer = b''
        self.heartbeat_interval = heartbeat_interval
        self.last_heartbeat = time.monotonic()
        self.on_status = on_status
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        # The device's own retry limit, restored for blocking (re)connects and
        # on removal.  While the device is watched by the reactor its limit is
        # forced to 0 so a failed send fails fast instead of blocking the reactor
        # thread or silently opening a new socket behind the selector's back.
        self.saved_retry_limit = getattr(device, 'socketRetryLimit', 5)


class _DeviceProxy:
    """
    Proxy handle returned by ``Monitor.add()``.

    Provides a clean UX for sending commands through the Monitor's
    thread-safe command queue.  Any attribute access on the proxy
    returns a callable that queues the method call for execution
    on the reactor thread (always with ``nowait=True``).

    Usage::

        handle = mon.add(device)
        handle.set_value(1, True)       # equivalent to mon.command(device, 'set_value', 1, True)
        handle.set_status(False, 1)     # equivalent to mon.command(device, 'set_status', False, 1)
    """

    def __init__(self, monitor, device):
        # Store without __dict__ pollution via object.__setattr__
        object.__setattr__(self, '_monitor', monitor)
        object.__setattr__(self, '_device', device)

    def __getattr__(self, name):
        """Return a callable that enqueues the method call via Monitor.command()."""
        def enqueue(*args, **kwargs):
            self._monitor.command(self._device, name, *args, **kwargs)
        return enqueue

    def __repr__(self):
        return f'_DeviceProxy({self._device.id})'


class Monitor:
    """
    Single-thread, multi-device status monitor using ``selectors``.

    Experimental: this class intentionally keeps some logic self-contained,
    including duplicated framing behavior that should be refactored into a
    shared helper in a future release once the design settles.

    The reactor loop calls ``select()``, reads from ready sockets,
    reassembles complete frames, decodes them, and fires callbacks.
    All socket I/O for monitored devices happens on the reactor thread.

    Args:
        on_status:      Global callback ``f(device, result)`` for decoded data.
        on_connect:     Global callback ``f(device, error)`` when a device connects.
        on_disconnect:  Global callback ``f(device, error)`` when a device disconnects.
        heartbeat_interval: Default seconds between heartbeats per device (default 12).
        auto_reconnect: When True, a background connector thread automatically
                        attempts to reconnect disconnected devices (default False).
        reconnect_backoff: Seconds between reconnect attempts (default 5.0).
    """

    def __init__(self, on_status=None, on_connect=None, on_disconnect=None,
                 heartbeat_interval=12, auto_reconnect=False,
                 reconnect_backoff=5.0):
        self._on_status = on_status
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._heartbeat_interval = heartbeat_interval
        self._auto_reconnect = auto_reconnect
        self._reconnect_backoff = reconnect_backoff

        self._sel = selectors.DefaultSelector()
        self._devices = {}          # fileno -> _DeviceState
        self._id_to_state = {}      # device.id -> _DeviceState

        # Self-pipe: allows wake() to interrupt a blocking select().
        # Uses socket.socketpair() instead of os.pipe() for Windows
        # compatibility — SelectSelector on Windows only supports sockets.
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._sel.register(self._wake_r, selectors.EVENT_READ, data='_wake')

        # Thread-safe command queue
        self._queue = []
        self._queue_lock = threading.Lock()

        # Reactor thread state
        self._thread = None
        self._running = False

        # Auto-reconnect infrastructure
        self._reconnect_queue = []      # device_ids waiting for reconnect
        self._reconnect_lock = threading.Lock()
        self._register_queue = []       # device_ids ready for re-registration
        self._register_lock = threading.Lock()
        self._connector_thread = None
        self._devices_in_reconnect = set()  # device_ids currently being processed
        # Set on stop() so the connector thread's backoff wait is interruptible
        # (a plain time.sleep would delay shutdown and could let a second
        # connector thread start before the first one exits its sleep).
        self._stop_event = threading.Event()

    # ── Public API ──────────────────────────────────────────────────

    def add(self, device, heartbeat_interval=None,
            on_status=None, on_connect=None, on_disconnect=None):
        """
        Register a device with the Monitor.

        Opens a persistent connection to the device (blocking) and
        registers its socket with the selector.

        Args:
            device: A tinytuya Device (must have ``persist=True`` or
                    will be set automatically).
            heartbeat_interval: Override default heartbeat interval for this device.
            on_status: Per-device callback override.
            on_connect: Per-device callback override.
            on_disconnect: Per-device callback override.

        Returns:
            A ``_DeviceProxy`` handle on success, or an error string on failure.
            The proxy allows thread-safe command dispatch::

                handle = mon.add(device)
                handle.set_value(1, True)
        """
        if device.id in self._id_to_state:
            log.warning('Device %s already registered with Monitor', device.id)
            return _DeviceProxy(self, device)

        # Ensure persistent connection mode
        if not device.socketPersistent:
            device.socketPersistent = True

        # Connect (blocking — includes v3.4/3.5 session-key handshake)
        result = device._get_socket(False)
        if result is not True:
            return result

        sock = device.socket
        if sock is None:
            return 'Unable to open socket'

        # Note: selectors does NOT require non-blocking sockets as long as
        # we only recv() after select() indicates readability.  Keeping the
        # socket in blocking mode avoids issues with TinyTuya's send path
        # (sendall, retry logic) which was not designed for non-blocking I/O.

        hb = heartbeat_interval if heartbeat_interval is not None else self._heartbeat_interval
        state = _DeviceState(
            device, hb,
            on_status=on_status,
            on_connect=on_connect,
            on_disconnect=on_disconnect,
        )

        # Monitor now owns this device's connection lifecycle.  Force the device
        # to fail fast on send errors (retry limit 0) so a broken connection can
        # never (a) block the reactor thread inside the device's own retry loop,
        # or (b) silently open a replacement socket the selector isn't watching.
        # The saved limit is restored for blocking (re)connects and on removal.
        state.saved_retry_limit = device.socketRetryLimit
        device.socketRetryLimit = 0

        fd = sock.fileno()
        state.fileno = fd

        self._devices[fd] = state
        self._id_to_state[device.id] = state

        self._sel.register(sock, selectors.EVENT_READ, data=state)

        # Fire connect callback
        self._fire_connect(state, None)

        return _DeviceProxy(self, device)

    def remove(self, device):
        """
        Unregister a device from the Monitor and close its socket.

        Note: like ``add()``, this mutates the selector directly and is intended
        to be called from the same thread that drives the reactor (or before
        ``start()``).  Marshalling add/remove onto the reactor thread is a
        planned follow-up (see #713).
        """
        state = self._id_to_state.pop(device.id, None)
        if state is None:
            return
        # Unregister by the stored fd rather than device.socket: the socket may
        # already be closed (and its fileno() invalid) if the device dropped.
        fd = state.fileno
        if fd is not None:
            try:
                self._sel.unregister(fd)
            except (KeyError, ValueError, OSError):
                pass
            self._devices.pop(fd, None)
        state.fileno = None

        if device.socket is not None:
            try:
                device.socket.close()
            except Exception:
                pass
            device.socket = None

        # Hand the device back to the caller as we found it.
        device.socketRetryLimit = state.saved_retry_limit

    def command(self, device, method_name, *args, **kwargs):
        """
        Thread-safe: queue a command to be executed on the reactor thread.

        Args:
            device: The target device.
            method_name: Name of a device method (e.g. ``'set_value'``).
            *args, **kwargs: Arguments forwarded to the method.

        The method is always called with ``nowait=True``.  Passing
        ``nowait=False`` will raise ``ValueError`` to prevent blocking
        the reactor loop.
        """
        if kwargs.get('nowait', True) is False:
            raise ValueError(
                'Monitor.command() does not support nowait=False — '
                'blocking calls would stall the reactor loop.'
            )
        # Only force nowait=True for methods that accept it, so proxying a method
        # without a nowait parameter (e.g. set_socketPersistent) doesn't raise.
        method = getattr(device, method_name, None)
        if 'nowait' not in kwargs and method is not None and _accepts_nowait(method):
            kwargs['nowait'] = True
        with self._queue_lock:
            self._queue.append((device.id, method_name, args, kwargs))
        self._wake()

    # Backward-compatible alias
    send = command

    def __getitem__(self, device):
        """
        Return a ``_DeviceProxy`` for the given device.

        Allows dict-style access for a clean UX::

            mon[device].set_value(1, True)
        """
        if device.id not in self._id_to_state:
            raise KeyError(f'Device {device.id} is not registered with this Monitor')
        return _DeviceProxy(self, device)

    def start(self):
        """
        Start the reactor on a daemon thread.

        If ``auto_reconnect`` is enabled, also starts a background
        connector thread that handles automatic reconnection of
        disconnected devices.
        """
        if self._thread is not None and self._thread.is_alive():
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='TinyTuyaMonitor')
        self._thread.start()

        if self._auto_reconnect and self._connector_thread is None:
            self._connector_thread = threading.Thread(
                target=self._run_connector, daemon=True,
                name='TinyTuyaReconnect')
            self._connector_thread.start()

    def stop(self):
        """
        Stop the reactor and close all device sockets.
        """
        self._running = False
        self._stop_event.set()
        self._wake()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._connector_thread is not None:
            self._connector_thread.join(timeout=5)
            self._connector_thread = None
        # Close all device sockets and hand each device back with its own
        # retry limit restored.
        for state in list(self._devices.values()):
            device = state.device
            fd = state.fileno
            if fd is not None:
                try:
                    self._sel.unregister(fd)
                except (KeyError, ValueError, OSError):
                    pass
            state.fileno = None
            try:
                if device.socket is not None:
                    device.socket.close()
            except Exception:
                pass
            device.socket = None
            device.socketRetryLimit = state.saved_retry_limit
        self._devices.clear()
        # Restore the retry limit for devices that disconnected mid-flight and
        # remained in _id_to_state awaiting auto-reconnect (not in _devices).
        # Devices that were still active had their limit restored above already
        # — setting it again to saved_retry_limit is idempotent.
        for state in list(self._id_to_state.values()):
            state.device.socketRetryLimit = state.saved_retry_limit
        self._id_to_state.clear()
        with self._reconnect_lock:
            self._reconnect_queue.clear()
            self._devices_in_reconnect.clear()
        with self._register_lock:
            self._register_queue.clear()

    def poll(self, timeout=1.0):
        """
        Run one iteration of the reactor loop (non-threaded mode).

        Call this from your own loop instead of ``start()``.
        """
        self._drain_queue()
        self._process_register_queue()
        self._send_heartbeats()

        events = self._sel.select(timeout=timeout)
        for key, mask in events:
            if key.data == '_wake':
                # Drain the wake socket
                try:
                    self._wake_r.recv(1024)
                except Exception:
                    pass
                continue
            self._handle_readable(key.data)

    # ── Internal reactor ────────────────────────────────────────────

    def _run(self):
        """Reactor loop (runs on daemon thread)."""
        while self._running:
            try:
                self._drain_queue()
                self._process_register_queue()
                self._send_heartbeats()

                events = self._sel.select(timeout=1.0)
                for key, mask in events:
                    if not self._running:
                        break
                    if key.data == '_wake':
                        try:
                            self._wake_r.recv(1024)
                        except Exception:
                            pass
                        continue
                    self._handle_readable(key.data)
            except Exception:
                log.error('Monitor reactor error', exc_info=True)
                time.sleep(0.1)

    def _handle_readable(self, state):
        """Handle a socket-read event for one device."""
        device = state.device
        sock = device.socket
        if sock is None:
            return

        try:
            data = sock.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError, OSError) as exc:
            log.debug('Monitor: recv error for %s: %s', device.id, exc)
            self._handle_disconnect(state, exc)
            return

        if not data:
            # Connection closed by remote
            self._handle_disconnect(state, 'Connection closed')
            return

        state.recv_buffer += data
        self._process_buffer(state)

    def _process_buffer(self, state):
        """
        Extract and dispatch complete frames from a device's receive buffer.

        The framing logic mirrors ``XenonDevice._receive()``: search for
        the prefix, parse the header to get total_length, and accumulate
        until the full frame is available.
        """
        device = state.device

        while True:
            buf = state.recv_buffer
            if len(buf) < 4:
                return  # not enough data for even a prefix

            # Find the prefix
            offset_55aa = buf.find(H.PREFIX_55AA_BIN)
            offset_6699 = buf.find(H.PREFIX_6699_BIN)

            # Determine which prefix comes first
            if offset_55aa < 0 and offset_6699 < 0:
                # No prefix found — discard everything except last 3 bytes
                state.recv_buffer = buf[-3:]
                return

            if offset_55aa < 0:
                offset = offset_6699
            elif offset_6699 < 0:
                offset = offset_55aa
            else:
                offset = min(offset_55aa, offset_6699)

            # Discard leading garbage before the prefix
            if offset > 0:
                buf = buf[offset:]
                state.recv_buffer = buf

            # Try to parse the header
            try:
                header = parse_header(buf)
            except Exception:
                # Normally this means the header is incomplete, so wait for more
                # data.  But if the buffer is already larger than any legal frame,
                # "not enough data" cannot be the real cause — the stream is
                # desynced/corrupt.  Resync by discarding up to the next prefix.
                if len(buf) > MAX_PAYLOAD_LENGTH:
                    next_55aa = buf.find(H.PREFIX_55AA_BIN, 1)
                    next_6699 = buf.find(H.PREFIX_6699_BIN, 1)
                    candidates = [o for o in (next_55aa, next_6699) if o >= 1]
                    if candidates:
                        next_offset = min(candidates)
                        log.debug("Corrupt/oversized header, resyncing buffer to next prefix at offset %d", next_offset)
                        state.recv_buffer = buf[next_offset:]
                        continue
                    log.debug("Corrupt/oversized header and no further prefix found, dropping buffer")
                    state.recv_buffer = buf[-3:]
                    return
                # Incomplete header — wait for more data
                return

            remaining = header.total_length - len(buf)
            if remaining > 0:
                # Incomplete frame — wait for more data
                return

            # We have a complete frame
            frame = buf[:header.total_length:]
            state.recv_buffer = buf[header.total_length:]

            # Decode the frame
            self._decode_and_dispatch(state, frame, header)

    def _decode_and_dispatch(self, state, frame_data, header):
        """Decrypt and dispatch a single complete frame."""
        device = state.device

        try:
            hmac_key = device.local_key if device.version >= 3.4 else None
            no_retcode = False
            msg = unpack_message(frame_data, hmac_key=hmac_key, header=header,
                                 no_retcode=no_retcode)
        except Exception:
            log.debug('Monitor: error unpacking frame for %s', device.id, exc_info=True)
            return

        if msg is None:
            return

        # For 6699/GCM frames a failed authentication tag means the payload is
        # undecryptable ciphertext; drop the frame instead of decoding garbage.
        if msg.prefix == H.PREFIX_6699_VALUE and not msg.crc_good:
            log.debug('Monitor: GCM authentication failed for %s - frame dropped', device.id)
            return

        # Null payload — heartbeat ack, etc.
        if not msg.payload or len(msg.payload) == 0:
            log.debug('Monitor: null payload from %s (cmd=%s)', device.id, msg.cmd)
            return

        # Decode the payload using the device's own decoder
        try:
            result = device._decode_payload(msg.payload)
        except Exception:
            log.debug('Monitor: error decoding payload for %s', device.id, exc_info=True)
            return

        if result is None:
            return

        # Handle CID routing for gateway sub-devices
        target_state = state
        if device.children:
            found_cid = None
            if isinstance(result, dict):
                found_cid = result.get('cid')
                if not found_cid and isinstance(result.get('data'), dict):
                    found_cid = result['data'].get('cid')
            if found_cid:
                for child in device.children.values():
                    if child.cid == found_cid:
                        # Route to the child device: cache + process on it,
                        # and dispatch the callback using the child's state
                        child._cache_response(result)
                        result = child._process_response(result)
                        # Look up the child's own state if registered, or
                        # fall back to the gateway's state with child device object
                        child_state = self._id_to_state.get(child.id)
                        if child_state is not None:
                            target_state = child_state
                        else:
                            # Child not separately registered — update state to
                            # reference the child device so callbacks use it
                            target_state = _DeviceState.__new__(_DeviceState)
                            for attr in _DeviceState.__slots__:
                                setattr(target_state, attr, getattr(state, attr))
                            target_state.device = child
                        break

        # Cache on the main device (if not already handled via CID routing)
        if target_state is state:
            device._cache_response(result)
            result = device._process_response(result)

        # Fire status callback
        self._fire_status(target_state, result)

    # ── Heartbeats ──────────────────────────────────────────────────

    def _send_heartbeats(self):
        """Send heartbeats to any device that needs one."""
        now = time.monotonic()
        for state in list(self._devices.values()):
            if now - state.last_heartbeat >= state.heartbeat_interval:
                self._do_heartbeat(state)
                state.last_heartbeat = now

    def _do_heartbeat(self, state):
        """Send a heartbeat to one device using the existing Device API."""
        device = state.device
        if device.socket is None:
            return
        try:
            device.heartbeat(nowait=True)
        except Exception:
            log.debug('Monitor: heartbeat send failed for %s', device.id, exc_info=True)
            self._handle_disconnect(state, 'Heartbeat send failed')
            return
        # With the retry limit forced to 0, a failed send closes the socket and
        # returns an error dict instead of raising.  A vanished socket is the
        # disconnect signal — route it through reconnect rather than letting the
        # device get stuck with no socket and no pending reconnect.
        if device.socket is None:
            self._handle_disconnect(state, 'Heartbeat send failed')
        else:
            log.debug('Monitor: sent heartbeat to %s', device.id)

    # ── Disconnect handling ─────────────────────────────────────────

    def _handle_disconnect(self, state, error):
        """Handle a disconnection event (reactor thread only)."""
        # Guard against a double teardown — e.g. a recv error and a heartbeat
        # failure for the same device within one reactor tick.  Once fileno is
        # cleared the device is already unregistered.
        if state.fileno is None:
            return
        device = state.device
        log.debug('Monitor: device %s disconnected: %s', device.id, error)

        # Unregister by the stored fd: the device may already have closed its
        # socket (fail-fast send), leaving device.socket == None and its old
        # fileno() invalid, so the selector entry can only be found by fd.
        fd = state.fileno
        try:
            self._sel.unregister(fd)
        except (KeyError, ValueError, OSError):
            pass
        self._devices.pop(fd, None)
        state.fileno = None
        state.recv_buffer = b''

        if device.socket is not None:
            try:
                device.socket.close()
            except Exception:
                pass
            device.socket = None

        # Fire disconnect callback
        self._fire_disconnect(state, str(error))

        # Enqueue for auto-reconnect if enabled
        if self._auto_reconnect and device.id in self._id_to_state:
            with self._reconnect_lock:
                if device.id not in self._devices_in_reconnect:
                    self._reconnect_queue.append(device.id)
                    self._devices_in_reconnect.add(device.id)
                    log.debug('Monitor: enqueued %s for auto-reconnect', device.id)

    # ── Auto-reconnect connector thread ─────────────────────────

    def _run_connector(self):
        """Background thread that handles blocking reconnects."""
        while self._running:
            # Pop a device that needs reconnect
            device_id = None
            with self._reconnect_lock:
                if self._reconnect_queue:
                    device_id = self._reconnect_queue.pop(0)

            if device_id is None:
                # Interruptible idle wait so stop() returns promptly
                if self._stop_event.wait(0.5):
                    break
                continue

            state = self._id_to_state.get(device_id)
            if state is None:
                # Device was removed entirely
                with self._reconnect_lock:
                    self._devices_in_reconnect.discard(device_id)
                continue

            device = state.device
            log.debug('Monitor: attempting reconnect for %s', device_id)

            # Interruptible backoff before attempting — a plain sleep would delay
            # shutdown and could let a second connector thread spawn on restart.
            if self._stop_event.wait(self._reconnect_backoff):
                break

            if not self._running:
                break

            # Blocking connect (this is why we're on a separate thread).  Restore
            # the device's real retry limit for the connect, then put it back to
            # the reactor-safe fail-fast value before handing the socket back.
            device.socketRetryLimit = state.saved_retry_limit
            try:
                result = device._get_socket(False)
            except Exception as exc:
                result = str(exc)
            finally:
                device.socketRetryLimit = 0

            if result is True and device.socket is not None:
                # Success — hand off to reactor for selector registration
                with self._register_lock:
                    self._register_queue.append(device_id)
                self._wake()
                log.debug('Monitor: reconnect successful for %s, queued for registration', device_id)
            else:
                # Failure — re-enqueue for another cycle
                log.debug('Monitor: reconnect failed for %s: %s, will retry', device_id, result)
                with self._reconnect_lock:
                    if device_id in self._id_to_state:  # still registered?
                        self._reconnect_queue.append(device_id)
                    else:
                        self._devices_in_reconnect.discard(device_id)

    def _process_register_queue(self):
        """Register reconnected sockets with the selector (reactor thread only)."""
        with self._register_lock:
            items = self._register_queue[:]
            self._register_queue.clear()

        for device_id in items:
            state = self._id_to_state.get(device_id)
            if state is None:
                with self._reconnect_lock:
                    self._devices_in_reconnect.discard(device_id)
                continue

            device = state.device
            sock = device.socket
            if sock is None:
                # Socket was closed between reconnect and registration
                with self._reconnect_lock:
                    self._devices_in_reconnect.discard(device_id)
                continue

            try:
                fd = sock.fileno()
                state.fileno = fd
                state.recv_buffer = b''
                state.last_heartbeat = time.monotonic()
                self._devices[fd] = state
                self._sel.register(sock, selectors.EVENT_READ, data=state)
            except (KeyError, ValueError, OSError) as exc:
                log.error('Monitor: failed to re-register %s: %s', device_id, exc)
                # Try again next cycle
                with self._reconnect_lock:
                    self._reconnect_queue.append(device_id)
                continue

            with self._reconnect_lock:
                self._devices_in_reconnect.discard(device_id)

            # Fire connect callback
            self._fire_connect(state, None)
            log.debug('Monitor: device %s re-registered with selector', device_id)

    # ── Command queue ───────────────────────────────────────────────

    def _drain_queue(self):
        """Execute all queued commands on the reactor thread."""
        with self._queue_lock:
            items = self._queue[:]
            self._queue.clear()

        for device_id, method_name, args, kwargs in items:
            state = self._id_to_state.get(device_id)
            if state is None:
                log.warning('Monitor: queued command for unknown device %s', device_id)
                continue
            device = state.device
            # Only dispatch to a fully-registered, active device.  Gating on
            # state.fileno (set only after selector registration) — rather than
            # device.socket — avoids sending on a socket the connector thread is
            # still mid-handshake on during a reconnect.
            if state.fileno is None or device.socket is None:
                log.warning('Monitor: device %s not active, dropping command %r', device_id, method_name)
                continue
            method = getattr(device, method_name, None)
            if method is None:
                log.warning('Monitor: device has no method %r', method_name)
                continue
            try:
                method(*args, **kwargs)
            except Exception:
                log.error('Monitor: error executing %s on %s', method_name, device_id,
                          exc_info=True)
                self._handle_disconnect(state, 'Command send failed')
                continue
            # Fail-fast send closed the socket instead of raising — reconnect.
            if device.socket is None:
                self._handle_disconnect(state, 'Command send failed')

    # ── Wake mechanism ──────────────────────────────────────────────

    def _wake(self):
        """Interrupt a blocking select() by writing to the self-pipe socket."""
        try:
            self._wake_w.send(b'\x00')
        except OSError:
            pass

    # ── Callback helpers ────────────────────────────────────────────

    def _fire_status(self, state, result):
        cb = state.on_status or self._on_status
        if cb:
            try:
                cb(state.device, result)
            except Exception:
                log.error('Monitor: error in on_status callback', exc_info=True)

    def _fire_connect(self, state, error):
        cb = state.on_connect or self._on_connect
        if cb:
            try:
                cb(state.device, error)
            except Exception:
                log.error('Monitor: error in on_connect callback', exc_info=True)

    def _fire_disconnect(self, state, error):
        cb = state.on_disconnect or self._on_disconnect
        if cb:
            try:
                cb(state.device, error)
            except Exception:
                log.error('Monitor: error in on_disconnect callback', exc_info=True)

    # ── Cleanup ─────────────────────────────────────────────────────

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass
        try:
            self._sel.close()
        except Exception:
            pass
        try:
            self._wake_r.close()
        except Exception:
            pass
        try:
            self._wake_w.close()
        except Exception:
            pass
