# TinyTuya Design

This document describes the architecture of TinyTuya for contributors and coding agents. It explains how the pieces fit together, the design decisions behind them, and the known architectural debt. For contribution conventions (tests, style, release process), see [AGENTS.md](AGENTS.md). For the wire protocol itself, see [PROTOCOL.md](PROTOCOL.md).

## Overview

TinyTuya controls Tuya-based WiFi smart devices over the local network (LAN) and optionally via the Tuya Cloud API. The library speaks five generations of the Tuya LAN protocol (3.1 through 3.5) using synchronous TCP sockets — no asyncio, no per-device threads (the experimental `Monitor` class multiplexes many devices on one thread using `selectors`).

```
        User code
           │
   OutletDevice / BulbDevice / CoverDevice / Contrib.*      Cloud (REST)
           │                                                    │
        Device            ← user command API                requests
           │
       XenonDevice        ← sockets, framing, crypto, session keys,
           │                payload templates, gateway routing
     message_helper / crypto_helper / header / command_types
           │
        TCP 6668  +  UDP 6666/6667/7000 (discovery via scanner)
```

## Package Layout

```
tinytuya/
├── __init__.py          Public API surface — wildcard re-exports from core,
│                        plus OutletDevice, BulbDevice, CoverDevice, Cloud
├── core/
│   ├── core.py          Version (version_tuple), set_debug(), module-level
│   │                    helpers (deviceScan, assign_dp_mappings, ...)
│   ├── XenonDevice.py   Base device class (see below)
│   ├── Device.py        User command API: set_status, set_value,
│   │                    set_multiple_values, heartbeat, set_timer, ...
│   ├── Monitor.py       EXPERIMENTAL single-thread multi-device monitor (#713)
│   ├── message_helper.py  pack_message()/unpack_message() — 55AA + 6699 framing,
│   │                    CRC32 / HMAC-SHA256 / AES-GCM integrity
│   ├── crypto_helper.py AESCipher — backend-neutral AES (ECB + GCM)
│   ├── header.py        Frame constants, TuyaMessage/MessagePayload namedtuples,
│   │                    NO_PROTOCOL_HEADER_CMDS skip list
│   ├── command_types.py Tuya LAN command IDs (DP_QUERY, CONTROL, ...)
│   ├── const.py         Ports (6666/6667/6668/7000), timeouts, MAX_PAYLOAD_LENGTH
│   ├── error_helper.py  Error codes 900–914 and error_json() builder
│   ├── exceptions.py    DecodeError (framing/parse failures)
│   └── udp_helper.py    Discovery broadcast decryption (static UDP key)
├── OutletDevice.py      Thin Device subclass (set_dimmer)
├── BulbDevice.py        Bulb type A/B/C detection, RGB/HSV ↔ Tuya hex conversion
├── CoverDevice.py       8 command vocabularies with status-based autodetection
├── Cloud.py             Tuya Cloud REST client — HMAC-SHA256 request signing,
│                        token lifecycle, device list / DP mappings / logs
├── scanner.py           Network discovery — select() event loop over UDP
│                        listeners + optional TCP force-scan state machines
├── wizard.py            Interactive setup: Cloud creds → devices.json keys →
│                        scanner IP matching
├── cli.py               Device control commands for the CLI (list/on/off/set/get/monitor)
├── __main__.py          argparse dispatcher for `python -m tinytuya`
└── Contrib/             Community-contributed device classes (see Contrib/README.md)
```

## Core Class Hierarchy

`XenonDevice` (core/XenonDevice.py) is the base of every local device object. It owns:

- **Socket lifecycle** — connect/retry policy (`connection_retry_limit`, `socketRetryDelay`), persistent vs per-call sockets (`set_socketPersistent`), auto-IP discovery via scanner when `address` is `None` or `'Auto'`.
- **Payload templating** — a layered merge of the module-level `payload_dict` (default → gateway → zigbee → version → dev_type overlays), cached per instance as `self.payload_dict`. `generate_payload()` fills in device IDs, timestamps, and DPS values.
- **Encryption orchestration** — `_encode_message()` / `_decode_payload()` apply the version-specific crypto described below.
- **Session key negotiation** — the 3-message nonce exchange required by protocols 3.4/3.5 (`_negotiate_session_key*`). On success `self.local_key` becomes the session key; `self.real_local_key` keeps the device key.
- **Gateway/sub-device routing** — children (`cid`/`node_id`) delegate send/receive and sequence numbers to their parent; responses are routed by `cid`, with out-of-order responses parked in `received_wrong_cid_queue`.
- **device22 detection** — some devices (22-char IDs, and everything speaking 3.2) reject plain DP_QUERY with `"data unvalid"`; the library switches `dev_type` to `device22`, rewrites DP_QUERY → CONTROL_NEW with an explicit DPS list, and can brute-force available DPS (`detect_available_dps`).

`Device` (core/Device.py) layers the user-facing command API on top. `OutletDevice`, `BulbDevice`, `CoverDevice`, and all `Contrib` classes subclass `Device` and add device-category helpers only — no protocol logic belongs in subclasses.

## Message Flow

**Send:** `generate_payload()` builds the JSON command → `MessagePayload(cmd, payload)` → `_encode_message()` encrypts/prefixes per protocol version → `pack_message()` frames it (prefix, seqno, cmd, length, CRC32/HMAC/GCM-tag, suffix) → `sendall()`.

**Receive:** `_receive()` reads via `_recv_all()`, scans for the `55AA`/`6699` prefix to resync a desynced stream, `parse_header()` yields total length (bounded by `MAX_PAYLOAD_LENGTH`), `unpack_message()` verifies integrity and (for 6699) GCM-decrypts → `_decode_payload()` strips version headers, ECB-decrypts, JSON-parses → `_process_message()` handles device22 detection, child routing, and status caching → `_process_response()` is the subclass hook.

## Protocol Versions

| Version | Frame  | Integrity        | Payload crypto                                   | Session key |
|---------|--------|------------------|--------------------------------------------------|-------------|
| 3.1     | 55AA   | CRC32            | AES-ECB + base64, CONTROL only, MD5-fragment sig  | no          |
| 3.2     | 55AA   | CRC32            | AES-ECB (binary); treated as device22             | no          |
| 3.3     | 55AA   | CRC32            | AES-ECB (binary) + clear 15-byte version header   | no          |
| 3.4     | 55AA   | HMAC-SHA256      | AES-ECB over the whole payload (incl. header)     | yes         |
| 3.5     | 6699   | AES-GCM tag      | AES-GCM, 12-byte IV, retcode inside ciphertext    | yes         |

Commands in `NO_PROTOCOL_HEADER_CMDS` (header.py) — DP_QUERY, DP_QUERY_NEW, UPDATEDPS, HEART_BEAT, the session-negotiation commands, LAN_EXT_STREAM — skip the `3.x` version header but not encryption. See PROTOCOL.md for byte-level detail.

## Key Design Decisions

- **Synchronous, dependency-light core.** The device stack uses only the standard library plus one AES backend. `requests` and `colorama` are needed only by Cloud/wizard/CLI paths. New hard dependencies require strong justification.
- **Pluggable crypto backend.** `crypto_helper.py` selects pyca/cryptography → PyCryptodome(x) → PyCrypto → pyaes at import time and wraps whichever it finds in a single `AESCipher` class. Nothing else in the library may import a crypto library directly. pyaes has no GCM, so protocol 3.5 support is gated on `CRYPTOLIB_HAS_GCM`.
- **Error dicts, not exceptions.** Runtime device failures return `error_json()` dicts (`{"Error", "Err", "Payload"}`, codes 900–914 in error_helper.py) so long-running callers don't need try/except around every poll. Exceptions are reserved for programmer errors and framing (`DecodeError`).
- **Lazy scanner import.** `XenonDevice.find_device()` imports `..scanner` inside the function to avoid a circular import (scanner builds device objects; devices use the scanner for auto-IP).
- **Version/behavior quirks live in data, not branches, where possible.** Per-version and per-dev_type command overrides are expressed in the `payload_dict` template structure rather than scattered conditionals.
- **Monitor is a separate reactor, not a rewrite.** `Monitor` (experimental, #713) watches many persistent sockets with `selectors` on one thread, marshalling user commands via a locked queue + socketpair wake, with an optional connector thread for blocking reconnects. It currently duplicates `_receive()`'s framing logic for non-blocking buffered reads — a known refactoring target (extracting a shared frame codec).

## Discovery

Devices broadcast on UDP 6666 (3.1, plaintext) and 6667 (3.2+, AES-ECB under the well-known key `MD5("yGAdlopoPVldABfn")`); newer 3.5 devices stay silent until solicited via an app-style broadcast on UDP 7000 (6699/GCM frames, same key). `scanner.devices()` runs a single-threaded `select()` loop that listens on all three ports and can optionally "force scan" TCP 6668 across address ranges, brute-forcing version/key from `devices.json`. `udp_helper.decrypt_udp()` transparently handles raw-ECB, 55AA-framed, and 6699-GCM broadcast formats.

## Cloud

`Cloud` is a self-contained REST client for the Tuya IoT Platform: HMAC-SHA256 request signing (key + token + timestamp, alphabetically sorted query params), automatic token fetch/refresh, and helpers for device lists, DP mappings, logs, and commands. The wizard composes `Cloud` (to fetch local keys) with `scanner` (to find IPs) and writes `tinytuya.json` (credentials), `devices.json` (keys), and `tuya-raw.json` (raw API dump).

## Known Architectural Debt

Recorded here so future work moves toward the target state rather than adding to the pile:

1. **`XenonDevice` is a god class** (~1350 lines): discovery, sockets, retry policy, three crypto generations, session negotiation, templating, gateway routing, and caching in one class. Target: extract a frame codec (shared with Monitor) and a transport object.
2. **Four error-signaling conventions coexist** — error dicts (`_send_receive`), int-or-True (`_get_socket`), `None`/`True`/`False`/message (`_send_receive_quick`), and raised `RuntimeError` (auto-IP failure in `__init__`). New code should use `error_json()` dicts at API boundaries.
3. **Network I/O inside constructors** — auto-IP scans the LAN in `__init__`; `set_version(3.2)` can trigger a multi-round-trip DPS scan. Prefer lazy/first-use I/O for new features.
4. **`scanner.devices()` is a ~450-line function** driven by module-level globals that `__main__.py` mutates (`DEVICEFILE`, `SNAPSHOTFILE`), which makes the scanner awkward as a library. New scanner features should go into the `DeviceDetect` state-machine classes, not the main loop.
5. **Wildcard re-exports without `__all__`** leak internals (`tinytuya.socket`, `tinytuya.json`, ...) into the public namespace, so renaming module-level names is riskier than it looks.
6. **Monitor/`_receive()` framing duplication** — two independent implementations of prefix scanning and header parsing must be kept in sync until a shared codec exists.
7. **Python 2 remnants** — `IS_PY2` branches and shims are dead (Monitor.py's f-strings make py2 imports fail anyway) and should be removed rather than extended.
