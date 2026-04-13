#!/usr/bin/env python
# -*- coding: utf-8 -*-
# TinyTuya Module
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya

 Run TinyTuya Setup Wizard:
    python -m tinytuya wizard
 This network scan will run if calling this module via command line:
    python -m tinytuya <max_time>

"""

# Modules
import getpass
import json
import os
import sys
import time

from . import scanner, DEVICEFILE
from .core import Device
from .core.XenonDevice import load_devicefile


def _run_list_command(args):
    """Handle the list command."""
    device_file = getattr(args, 'device_file', DEVICEFILE)
    tuyadevices = load_devicefile(device_file)
    if not tuyadevices:
        if not os.path.exists(device_file):
            print('Error: device file "%s" not found.' % device_file)
        else:
            print('Error: device file "%s" contains no valid devices (check JSON syntax and format).' % device_file)
        sys.exit(1)

    FIELDS = ('name', 'id', 'key', 'ip', 'version')

    # Normalise rows — prefer last_ip over ip
    rows = []
    for dev in tuyadevices:
        if not isinstance(dev, dict):
            continue
        rows.append({
            'name':    dev.get('name', ''),
            'id':      dev.get('id', ''),
            'key':     dev.get('key', ''),
            'ip':      dev.get('last_ip') or dev.get('ip', ''),
            'version': str(dev.get('version', '')),
        })

    if args.json:
        print(json.dumps(rows, indent=2))
        return

    # Table output
    col_w = {f: len(f) for f in FIELDS}
    for row in rows:
        for f in FIELDS:
            col_w[f] = max(col_w[f], len(str(row[f])))

    sep = '+' + '+'.join('-' * (col_w[f] + 2) for f in FIELDS) + '+'
    header = '|' + '|'.join(' %-*s ' % (col_w[f], f.upper()) for f in FIELDS) + '|'
    print(sep)
    print(header)
    print(sep)
    for row in rows:
        line = '|' + '|'.join(' %-*s ' % (col_w[f], row[f]) for f in FIELDS) + '|'
        print(line)
    print(sep)


def _build_device(args):
    """Build a Device() object from args, using device file if needed."""
    dev_id      = args.id
    dev_key     = args.key
    dev_ip      = args.ip
    dev_version = args.dev_version
    device_file = getattr(args, 'device_file', DEVICEFILE)
    dev_name    = getattr(args, 'name', None)

    # Load devices.json once (best-effort; missing file is fine)
    tuyadevices = load_devicefile(device_file)

    # Resolve --name to an ID
    if dev_name and not dev_id:
        match = next(
            (dev for dev in tuyadevices
             if isinstance(dev, dict) and dev.get('name', '').lower() == dev_name.lower()),
            None
        )
        if not match:
            print('Error: no device named "%s" found in %s.' % (dev_name, device_file))
            sys.exit(1)
        dev_id = match.get('id')

    # Look up remaining fields by ID
    devinfo = None
    if dev_id:
        devinfo = next(
            (dev for dev in tuyadevices
             if isinstance(dev, dict) and dev.get('id') == dev_id),
            None
        )

    if devinfo:
        if not dev_key:
            dev_key = devinfo.get('key') or ''
        if not dev_ip:
            # devices.json may carry last_ip from a previous scan
            dev_ip = devinfo.get('last_ip') or devinfo.get('ip') or None
        if dev_version is None:
            raw_ver = devinfo.get('version')
            if raw_ver:
                try:
                    dev_version = float(raw_ver)
                except (TypeError, ValueError):
                    print(
                        'Warning: invalid "version" value (%r) for device %s in %s; '
                        'using default protocol version.' % (
                            raw_ver,
                            devinfo.get('id') or devinfo.get('name') or '<unknown>',
                            device_file,
                        )
                    )
                    dev_version = None
            else:
                dev_version = None

    # Validate
    if not dev_id:
        print('Error: --id or --name is required.')
        sys.exit(1)
    # Strip any accidental whitespace (e.g. trailing newline from copy-paste)
    # from every key source before validation.
    if dev_key:
        dev_key = dev_key.strip()

    if not dev_key:
        # Interactive prompt as last resort — avoids shell-escaping issues
        # entirely for keys that contain $, #, =, :, etc.
        # Only prompt when attached to a real terminal; in piped/CI contexts
        # there is no user to answer, so exit with a clear error instead.
        if not sys.stdin.isatty():
            print(
                'Error: device local key not found. Provide --key or add the device '
                'to %s.' % device_file
            )
            sys.exit(1)
        try:
            # Use getpass so the key is not echoed to the terminal or logs.
            dev_key = getpass.getpass('Enter device local key (16 chars, input hidden): ').strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)
        if not dev_key:
            print(
                'Error: device local key not found. Provide --key, add the device to %s, '
                'or enter it when prompted.' % device_file
            )
            sys.exit(1)

    # Validate key length — Tuya local keys are always exactly 16 characters.
    # A wrong length is the most common cause of error 914 and is usually a
    # shell-escaping problem (e.g. $, #, = being interpreted by the shell).
    if len(dev_key) != 16:
        print(
            'Error: device key must be exactly 16 characters (got %d).' % len(dev_key)
        )
        print('  This is often a shell-escaping issue when the key contains')
        print("  special characters such as $, #, =, :, ', or !.")
        print('  Tips:')
        print("    Linux/Mac - wrap the key in single quotes:  --key '$y123c5...'")
        print('    Windows CMD - wrap in double quotes and escape ^ before each')
        print('                  special char, e.g.  --key "$y123^=c5..."')
        print('    Any platform - omit --key entirely and enter it at the prompt')
        print('                   (safest option for tricky keys).')
        sys.exit(1)

    if (not dev_ip) or (dev_ip.lower().strip() == 'auto') or (not dev_version):
        # Call the scanner here so we can pass args to it
        all_results = scanner.devices(
            verbose=bool(args.debug or args.debug2), scantime=args.max_time, color=(not args.nocolor), poll=False,
            forcescan=args.force, byID=True, discover=(not args.no_broadcasts), wantids=(dev_id,), assume_yes=args.yes,
            tuyadevices=tuyadevices)
        if all_results and dev_id in all_results:
            dev_ip = all_results[dev_id]['ip']
            dev_version = all_results[dev_id]['version']

    if not dev_version:
        # Uh oh, scan did not find it!
        dev_version = 3.3

    # Create device handle
    try:
        d = Device(dev_id, address=dev_ip, local_key=dev_key, version=dev_version)
    except RuntimeError as e:
        print('Error: %s' % e)
        sys.exit(1)
    except Exception as e:
        print('Error creating device: %s' % e)
        sys.exit(1)

    return d

def _run_device_command(args):
    """Handle on / off / set / get device control commands."""
    d = _build_device(args)

    # Execute command
    if args.command == 'on':
        result = d.turn_on(switch=args.dps)
    elif args.command == 'off':
        result = d.turn_off(switch=args.dps)
    elif args.command == 'set':
        # Attempt to parse the value as JSON so that "true", "123", etc.
        # are sent with the correct type; fall back to a plain string.
        try:
            typed_value = json.loads(args.value)
        except (ValueError, TypeError):
            typed_value = args.value
        result = d.set_value(args.dps, typed_value)
    elif args.command == 'get':
        result = d.status()
        if result and 'Err' not in result:
            if args.dps is None:
                # No --dps given: print full status
                print(json.dumps(result))
                return
            dps_str = str(args.dps)
            if 'dps' in result and dps_str in result['dps']:
                # --dps given: print the plain value only
                print(json.dumps(result['dps'][dps_str]))
                return
            else:
                available = list(result.get('dps', {}).keys())
                print('Error: DPS %d not found in device response.' % args.dps)
                print('Available DPS keys:', available)
                sys.exit(1)
        # fall through to error check below
    else:
        result = None

    # Shared error check for on/off/set (and get error path)
    if result and 'Err' in result:
        print('Error %s: %s' % (result['Err'], result['Error']))
        sys.exit(1)

    if result:
        print(json.dumps(result))
    else:
        print('OK')


def _monitor_device(args):
    """Connect to device, get status, and monitor for async updates."""
    d = _build_device(args)
    d.set_socketPersistent(True)

    # check to see if debug is in args
    debug = bool(args.debug or args.debug2)
    STATUS_TIMER = 30
    KEEPALIVE_TIMER = 12

    print(" > Send Request for Status < ")
    print('Initial Status: %r' % d.status())

    print(" > Beginning Monitor Loop, <CTRL>-c To Exit <")
    heartbeat_time = time.time() + KEEPALIVE_TIMER
    status_time = time.time() + STATUS_TIMER

    try:
        while True:
            if status_time and time.time() >= status_time:
                # some devices require a UPDATEDPS command to force measurements of power
                if debug:
                    print(" > Send Request for Status < ")
                data = d.status()
                status_time = time.time() + STATUS_TIMER
                heartbeat_time = time.time() + KEEPALIVE_TIMER
            elif time.time() >= heartbeat_time:
                # send a keep-alive
                data = d.heartbeat(nowait=False)
                heartbeat_time = time.time() + KEEPALIVE_TIMER
            else:
                # no need to send anything, just listen for an asynchronous update
                data = d.receive()

            if data or debug:
                print('Received Payload: %r' % data)

            if data and 'Err' in data:
                print("Received error!  Sleeping for 5 seconds...")
                # rate limit retries so we don't hammer the device
                time.sleep(5)
    except KeyboardInterrupt:
        print("\n > Keyboard Interrupt, Exiting! < ")
