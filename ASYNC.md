# TinyTuya Async Roadmap (v2.x)

## Vision
Provide a first-class asyncio-native API for local Tuya LAN control that:
* Preserves rock-solid backward compatibility with the existing synchronous API (1.x style) for the large installed base.
* Enables high-concurrency, low-latency operations (parallel status polling, batched control, streaming updates) across mixed protocol versions (3.1–3.5) without blocking threads.
* Establishes a sustainable architecture so future protocol changes (e.g. 3.6+, new discovery flows) can be integrated once at the async layer and selectively backported.

## Goals
1. Async Core: Non-blocking socket connect, handshake, encrypt/decrypt, send/receive framed messages for all protocol versions.
2. High Throughput: Support dozens/hundreds of devices concurrently with graceful backpressure and timeout handling.
3. Pluggable Crypto & Parsing: Reuse existing message framing logic but allow async pipeline (reader / writer tasks) with cancellation.
4. Structured API: Mirror familiar synchronous class names with `Async` suffix (e.g. `XenonDeviceAsync`, `OutletDeviceAsync`).
5. Observability: Built-in debug / trace hooks and metrics counters (messages sent, retries, handshake duration) pluggable via callbacks.
6. Incremental Adoption: No forced migration—sync and async coexist; shared utility modules (e.g. encoding, DPS merge) remain single-source.

## Out of Scope
* Replacing synchronous classes or removing sync code paths.
* Full async Cloud API (could follow later).

## Architectural Overview (Planned)
```
+------------------------------+            +---------------------------+
| XenonDeviceAsync (base)      |            | MessageHelper (shared)    |
|  - state machine             |<--calls--> |  pack/unpack (sync funcs) |
|  - connection supervisor     |            |  crypto helpers           |
|  - protocol v3.1..v3.5       |            +---------------------------+
|  - send queue (asyncio.Queue)|
|  - recv task (reader loop)   |            +---------------------------+
|  - handshake coroutine       |<--uses---->| Crypto (AESCipher)        |
+--------------+---------------+            +---------------------------+
               | derives
    +----------+-----------+
    | Async Device Mixins  |
    | (Outlet/Bulb/etc.)   |
    +----------------------+
```

## Milestones
| Milestone | Description | Deliverables | Target Version |
|-----------|-------------|--------------|----------------|
| M0 | Planning & Version Bump | v2.0.0, `ASYNC.md`, release notes | 2.0.0 |
| M1 | Async Core Skeleton | `xasync/connection.py`, `XenonDeviceAsync` minimal connect + status (3.1/3.3) | 2.1.0 |
| M2 | Protocol Coverage | Support 3.4/3.5 handshake & GCM in async path | 2.2.0 |
| M3 | Device Classes | `OutletDeviceAsync`, `BulbDeviceAsync`, `CoverDeviceAsync` parity subset | 2.3.0 |
| M4 | High-Perf Scanner | Async scanner refactor (parallel probes, cancellation) | 2.4.0 |
| M5 | Test & Metrics | 85%+ coverage for async modules; metrics hooks | 2.5.0 |
| M6 | Examples & Docs | Async examples, README + PROTOCOL cross-links | 2.6.0 |
| M7 | Optimization | Connection pooling, adaptive retry, rate limiting | 2.7.0 |

## Detailed Task Breakdown
### M1 – Async Core Skeleton
- [ ] Create package folder `tinytuya/asyncio/` (or `tinytuya/async_`) to avoid name collision.
- [ ] Implement `XenonDeviceAsync` with:
  * `__init__(..., loop=None)` store config
  * `_ensure_connection()` coroutine: open TCP, negotiate session key if needed
  * `_reader_task()` coroutine: read frames, push to internal queue
  * `_send_frame()` coroutine: pack + write
  * `status()` -> `await get_status()` that sends DP_QUERY / CONTROL_NEW per version
  * Graceful close / cancellation
- [ ] Reuse existing `pack_message` / `unpack_message` in a thread-safe way (they are CPU-bound but fast; optionally offload heavy crypto to default loop executor only if needed later).

### M2 – Protocol v3.4 / v3.5 Handshake
- [ ] Async handshake coroutine with timeout + auto-retry
- [ ] Session key caching per open connection
- [ ] Automatic renegotiation on GCM tag failure

### M3 – Device Class Parity
- [ ] Async mixins or subclasses replicating key sync API (`set_value`, `set_multiple_values`, `turn_on/off`)
- [ ] If return values differ (e.g. coroutines), document mapping in README
- [ ] Shared DPS merge logic factored into pure functions usable by both sync/async

### M4 – Async Scanner
- [ ] Coroutine to probe IP ranges concurrently (configurable concurrency)
- [ ] Cancel outstanding probes on shutdown
- [ ] Integrate UDP discovery (v3.1–v3.5) with async sockets
- [ ] Provide `await scan_network(subnet, timeout)` returning structured device list

### M5 – Tests & QA
- [ ] Pytest-asyncio test suite for: framing, handshake, reconnection, DPS updates
- [ ] Fake device server (async) to simulate v3.1, 3.3, 3.4, 3.5 behaviors
- [ ] Performance smoke test (N devices concurrently) gating PR merges

### M6 – Documentation & Examples
- [ ] `examples/async/` directory with: basic status, bulk control, scanner usage, bulb effects
- [ ] README section: “Using the Async API” with migration notes
- [ ] Cross-link PROTOCOL.md for handshake & framing details

### M7 – Optimization & Enhancements
- [ ] Connection pooling for multiple logical child devices (gateways) sharing transport
- [ ] Adaptive retry and exponential backoff for transient network errors
- [ ] Optional structured logging adapter (JSON events)
- [ ] Metrics hook interface (`on_event(event_name, **data)`) for integrations

## Testing Strategy
| Layer | Strategy |
|-------|----------|
| Unit | Pure functions (framing, header parse) deterministic tests |
| Integration | Async fake device endpoints per protocol version |
| Performance | Timed concurrent status for N synthetic devices (assert throughput baseline) |
| Regression | Mirror critical sync tests with async equivalents |
| Fuzz (future) | Random DP payload mutation on fake server to harden parsing |

## API Sketch (Draft)
```python
import asyncio
import tinytuya
from tinytuya.asyncio import XenonDeviceAsync

async def main():
    dev = XenonDeviceAsync(dev_id, address=ip, local_key=key, version=3.5, persist=True)
    status = await dev.status()  # coroutine
    print(status)
    await dev.set_value(1, True)
    await dev.close()

asyncio.run(main())
```
Methods returning coroutines (awaitables): `status`, `set_value`, `set_multiple_values`, `heartbeat`, `updatedps`, `close`.

## Backward Compatibility Plan
* Sync code paths untouched; existing imports remain default.
* Async lives under `tinytuya.asyncio` (explicit opt-in) to avoid polluting top-level namespace initially.
* When async reaches parity, consider promoting selected classes to top-level import in a minor release (opt-in alias only).

## Open Questions / To Refine
- Should we introduce an event callback API for spontaneous DP updates vs polling? (Likely yes in M3/M4.)
- Provide context manager (`async with XenonDeviceAsync(...)`) for auto-connect/close? (Planned.)
- Rate limiting: global vs per-device? (Investigate after baseline performance metrics.)

## Contribution Guidelines (Async Track)
* Prefer small, reviewable PRs per milestone task.
* Include tests & docs for every new public coroutine.
* Avoid breaking sync APIs—additive only.
* Mark experimental APIs with a leading `_` or mention in docstring.

## Next Step
Implement Milestone M1 skeleton: create async package, base class, minimal status() for 3.1 & 3.3 devices.

---
Maintained with the goal of long-term stability for existing users while enabling modern async performance.
