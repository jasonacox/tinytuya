#!/usr/bin/env python3
"""
Regression Test - DeviceAsync

Async example: Fetch status for all devices listed in devices.json using DeviceAsync.

Features:
- Loads devices.json in current working directory (same format produced by wizard)
- Creates DeviceAsync instances (auto-discovers IP if blank)
- Runs status() concurrently with optional concurrency limit
 - Optional --rediscover flag ignores stored IPs and forces broadcast discovery per device
- Prints per-device summary line and optional JSON output
- Gracefully closes each connection

Usage:
  python test-devices.py                 # human-readable summary
  python test-devices.py --json          # JSON array output
  python test-devices.py --include-sub   # include sub (child) devices
  python test-devices.py --limit 5       # max concurrent connections
  python test-devices.py --rediscover    # force IP rediscovery for all devices

Exit code is 0 if all succeeded, 1 if any device failed.
"""
from __future__ import annotations
import asyncio, json, argparse, sys, time, os, socket
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
    HAVE_COLORAMA = True
except ImportError:  # fallback
    HAVE_COLORAMA = False
    class _Dummy:
        RESET_ALL = ''
    class _ForeDummy:
        RED = GREEN = ''
    class _StyleDummy:
        BRIGHT = NORMAL = RESET_ALL = ''
    Fore = _ForeDummy()
    Style = _StyleDummy()
import tinytuya
try:
    from tinytuya.async_scanner import shared_discover  # native async UDP discovery
except Exception:  # fallback if module path changes
    shared_discover = None  # type: ignore

DEFAULT_DEVICES_FILE = 'devices.json'

# -------------------- Data Loading --------------------

def load_devices(path: str, include_sub: bool) -> list[dict]:
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: devices file not found: {path}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"ERROR: unable to parse {path}: {e}", file=sys.stderr)
        return []

    devices = []
    for item in data:
        if (not include_sub) and item.get('sub'):
            continue
        dev_id = item.get('id') or item.get('uuid')
        if not dev_id:
            continue
        version_raw = (item.get('version') or '').strip()
        try:
            version = float(version_raw) if version_raw else 3.3
        except Exception:
            version = 3.3
        devices.append({
            'id': dev_id,
            'name': item.get('name') or dev_id,
            'ip': item.get('ip') or None,
            'key': item.get('key',''),
            'version': version,
            'sub': item.get('sub', False),
            'dev_type': 'default'
        })
    return devices

# -------------------- Async Fetch --------------------

COLOR_OK = Fore.GREEN
COLOR_FAIL = Fore.RED
COLOR_DIM = Style.DIM if hasattr(Style, 'DIM') else ''
COLOR_RESET = Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''

def _supports_color(args) -> bool:
    if getattr(args, 'no_color', False):
        return False
    if getattr(args, 'color', False):
        return True
    return sys.stdout.isatty() and HAVE_COLORAMA

def _short_error(msg: str, limit: int = 60) -> str:
    if not msg:
        return ''
    msg = msg.replace('\n', ' ').replace('\r', ' ')
    return (msg[:limit] + '…') if len(msg) > limit else msg

async def fetch_status(meta: dict, sem: asyncio.Semaphore, timeout: float = 8.0) -> dict:
    start = time.time()
    async with sem:
        try:
            async with tinytuya.DeviceAsync(
                meta['id'],
                address=meta['ip'],
                local_key=meta['key'],
                version=meta['version'],
                dev_type=meta['dev_type'],
                persist=False
            ) as dev:
                # Directly call status(); DeviceAsync handles any lazy setup internally.
                result = await asyncio.wait_for(dev.status(), timeout=timeout)
                duration = time.time() - start
            if not result:
                raise RuntimeError('No response')
            if isinstance(result, dict) and 'dps' in result:
                dps = result['dps'] if isinstance(result['dps'], dict) else result['dps']
            else:
                dps = result
            return {
                'id': meta['id'],
                'name': meta['name'],
                'ip': dev.address,
                'version': meta['version'],
                'ok': True,
                'dps': dps,
                'elapsed': round(duration, 3),
                'category': 'ok'
            }
        except Exception as e:  # gather error info
            duration = time.time() - start
            emsg = f"{e.__class__.__name__}: {e}" if isinstance(e, Exception) else str(e)
            low = emsg.lower()
            if isinstance(e, asyncio.TimeoutError) or 'timeout' in low:
                cat = 'timeout'
            elif isinstance(e, (ConnectionError, OSError, socket.timeout)) or 'network' in low or 'connect' in low:
                cat = 'network'
            elif 'key' in low:
                cat = 'key'
            elif 'payload' in low or 'decode' in low or 'protocol' in low:
                cat = 'protocol'
            else:
                cat = 'other'
            return {
                'id': meta['id'],
                'name': meta['name'],
                'ip': meta['ip'],
                'version': meta['version'],
                'ok': False,
                'error': emsg,
                'elapsed': round(duration, 3),
                'category': cat
            }

# -------------------- Main --------------------

async def run(args) -> int:
    # Early exit if devices file missing per requirement
    if not os.path.exists(args.file):
        # Dynamic message with actual filename; still a successful (0) exit
        print(f"No {os.path.basename(args.file)} found", flush=True)
        return 0

    meta_list = load_devices(args.file, args.include_sub)
    if not meta_list:
        print('No devices to query.')
        return 1

    if getattr(args, 'rediscover', False):
        for m in meta_list:
            m['ip'] = None  # force AUTO discovery
        print('Forcing IP discovery for all devices (ignoring stored IPs)...')

    # Shared discovery pre-pass (quick win) if any device missing IP or rediscover forced
    need_discovery = any(m['ip'] is None for m in meta_list)
    if need_discovery and shared_discover:
        try:
            print(f"Performing shared discovery ({args.discover_seconds:.1f}s)...", flush=True)
            discovered = await shared_discover(listen_seconds=args.discover_seconds, include_app=True, verbose=False)
            # discovered is dict: id -> info
            hits = 0
            for m in meta_list:
                info = discovered.get(m['id'])
                if info and info.get('ip'):
                    m['ip'] = info.get('ip')
                    # update version if available
                    ver = info.get('version')
                    try:
                        if ver:
                            m['version'] = float(ver)
                    except Exception:
                        pass
                    hits += 1
            print(f"Discovery matched {hits} / {total} device IDs.")
        except Exception as e:
            print(f"Shared discovery failed: {e}")

    total = len(meta_list)
    name_width = max(len(m['name']) for m in meta_list)
    id_width = max(len(m['id']) for m in meta_list)
    # Ensure space for full IPv4 (15 chars) or placeholder '---'
    ip_width = max(15, max(len(m.get('ip') or '---') for m in meta_list))
    sem = asyncio.Semaphore(args.limit)

    tasks = [asyncio.create_task(fetch_status(meta, sem, timeout=args.timeout)) for meta in meta_list]
    results = []

    if args.json:
        # Still stream-complete internally, just collect for JSON dump
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
        print(json.dumps(results, indent=2))
    else:
        print(f"Querying {total} device(s)...")
        RES_PLAIN_WIDTH = 5   # visible width for result column (OK / FAIL)
        TIME_WIDTH = 7        # width for time like '99.99s'
        prefix_sample = f"[{total:>3}/{total}] "  # sample to measure prefix width (includes trailing space)
        prefix_width = len(prefix_sample)
        header = (f"{'':<{prefix_width}}"
                  f"{'Name':<{name_width}}  {'ID':<{id_width}}  {'IP':<{ip_width}}  "
                  f"{'Ver':<3}  {'Res':<{RES_PLAIN_WIDTH}} {'Time':>{TIME_WIDTH}}  DPS")
        print(header)
        completed = 0
        use_color = _supports_color(args)
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            completed += 1
            raw_time = f"{r['elapsed']:.2f}s"
            time_str = raw_time.rjust(TIME_WIDTH)
            if r['ok']:
                plain = 'OK'
                if use_color:
                    colored = f"{COLOR_OK}{plain}{COLOR_RESET}"
                else:
                    colored = plain
                pad = ' ' * (RES_PLAIN_WIDTH - len(plain))
                res_col = colored + pad
                ip_disp = r['ip'] or '---'
                line = (f"[{completed:>3}/{total}] {r['name']:<{name_width}}  {r['id']:<{id_width}}  {ip_disp:<{ip_width}}  "
                        f"v{r['version']:<3} {res_col}{time_str}  dps={len(r.get('dps',{}))}")
            else:
                plain = 'FAIL'
                if use_color:
                    colored = f"{COLOR_FAIL}{plain}{COLOR_RESET}"
                else:
                    colored = plain
                pad = ' ' * (RES_PLAIN_WIDTH - len(plain))
                res_col = colored + pad
                err = _short_error(r.get('error',''))
                ip_disp = r['ip'] or '---'
                line = (f"[{completed:>3}/{total}] {r['name']:<{name_width}}  {r['id']:<{id_width}}  {ip_disp:<{ip_width}}  "
                        f"v{r['version']:<3} {res_col}{time_str}  {err}")
            print(line, flush=True)

        ok = sum(1 for r in results if r['ok'])
        if use_color:
            summary = (f"Done: {COLOR_OK}{ok}{COLOR_RESET}/{total} succeeded; "
                       f"{COLOR_FAIL}{total-ok}{COLOR_RESET} failed.")
        else:
            summary = f"Done: {ok}/{total} succeeded; {total-ok} failed."
        print(summary)

        # Error category counters
        categories = {}
        for r in results:
            cat = r.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        if any(not r['ok'] for r in results):
            parts = [f"{k}={v}" for k, v in sorted(categories.items())]
            print("Categories: " + ", ".join(parts))

    return 0 if all(r['ok'] for r in results) else 1

# -------------------- CLI --------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description='Async status fetch for devices in devices.json')
    p.add_argument('-f','--file', default=DEFAULT_DEVICES_FILE, help='Path to devices.json (default: devices.json)')
    p.add_argument('--include-sub', action='store_true', help='Include sub / child devices')
    p.add_argument('--rediscover', action='store_true', help='Ignore stored IPs and force broadcast discovery for every device')
    p.add_argument('-l','--limit', type=int, default=10, help='Max concurrent connections (default: 10)')
    p.add_argument('-t','--timeout', type=float, default=8.0, help='Per-device connect+status timeout seconds (default: 8)')
    p.add_argument('--discover-seconds', type=float, default=3.0, help='Seconds for shared discovery pre-pass (default: 3.0)')
    p.add_argument('--json', action='store_true', help='Output JSON array instead of text summary')
    return p.parse_args(argv)

if __name__ == '__main__':
    args = parse_args()
    try:
        code = asyncio.run(run(args))
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)
