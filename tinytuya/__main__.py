#!/usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK
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
import json
import sys
import argparse
try:
    import argcomplete
    HAVE_ARGCOMPLETE = True
except:
    HAVE_ARGCOMPLETE = False

from . import wizard, scanner, version, SCANTIME, DEVICEFILE, SNAPSHOTFILE, CONFIGFILE, RAWFILE, set_debug
from .core import Device

prog = 'python3 -m tinytuya' if sys.argv[0][-11:] == '__main__.py' else None
description = 'TinyTuya [%s]' % (version,)
parser = argparse.ArgumentParser( prog=prog, description=description )

# Options for all functions.
# Add both here and in subparsers (with alternate `dest=`) if you want to allow it to be positioned anywhere
parser.add_argument( '-debug', '-d', help='Enable debug messages', action='store_true' )
parser.add_argument( '-v', '--version', help='Display version information', action='store_true' )

subparser = parser.add_subparsers( dest='command', title='commands (run <command> -h to see usage information)' )
subparsers = {}
cmd_list = {
    'wizard': 'Launch Setup Wizard to get Device Local Keys',
    'scan': 'Scan local network for Tuya devices',
    'devices': 'Scan all devices listed in device-file',
    'snapshot': 'Scan devices listed in snapshot-file',
    'json': 'Scan devices listed in snapshot-file and display the result as JSON'
}
for sp in cmd_list:
    subparsers[sp] = subparser.add_parser(sp, help=cmd_list[sp])
    subparsers[sp].add_argument( '-debug', '-d', help='Enable debug messages', action='store_true', dest='debug2' )

    if sp != 'json':
        if sp != 'snapshot':
            subparsers[sp].add_argument( 'max_time', help='Maximum time to find Tuya devices [Default: %s]' % SCANTIME, nargs='?', type=int )
            subparsers[sp].add_argument( '-force', '-f', metavar='0.0.0.0/24', help='Force network scan of device IP addresses. Auto-detects net/mask if none provided', action='append', nargs='*' )
            subparsers[sp].add_argument( '-no-broadcasts', help='Ignore broadcast packets when force scanning', action='store_true' )

        subparsers[sp].add_argument( '-nocolor', help='Disable color text output', action='store_true' )
        subparsers[sp].add_argument( '-yes', '-y', help='Answer "yes" to all questions', action='store_true' )
        if sp != 'scan':
            subparsers[sp].add_argument( '-no-poll', '-no', help='Answer "no" to "Poll?" (overrides -yes)', action='store_true' )

    if sp == 'wizard':
        help = 'JSON file to load/save devices from/to [Default: %s]' % DEVICEFILE
        subparsers[sp].add_argument( '-device-file', help=help, default=DEVICEFILE, metavar='FILE' )
        subparsers[sp].add_argument( '-raw-response-file', help='JSON file to save the raw server response to [Default: %s]' % RAWFILE, default=RAWFILE, metavar='FILE' )
    else:
        help = 'JSON file to load devices from [Default: %s]' % DEVICEFILE
        subparsers[sp].add_argument( '-device-file', help=help, default=DEVICEFILE, metavar='FILE' )

    if sp == 'json':
        # Throw error if file does not exist
        subparsers[sp].add_argument( '-snapshot-file', help='JSON file to load snapshot from [Default: %s]' % SNAPSHOTFILE, default=SNAPSHOTFILE, metavar='FILE', type=argparse.FileType('r') )
    else:
        # May not exist yet, will be created
        subparsers[sp].add_argument( '-snapshot-file', help='JSON file to load/save snapshot from/to [Default: %s]' % SNAPSHOTFILE, default=SNAPSHOTFILE, metavar='FILE' )

# Looks neater in a group
cred_group = subparsers['wizard'].add_argument_group( 'Cloud API Credentials', 'If no option is set then the Wizard will prompt')
cred_group.add_argument( '-credentials-file', help='JSON file to load/save Cloud credentials from/to [Default: %s]' % CONFIGFILE, metavar='FILE' )
cred_group.add_argument( '-key', help='Cloud API Key to use' )
cred_group.add_argument( '-secret', help='Cloud API Secret to use' )
cred_group.add_argument( '-region', help='Cloud API Region to use', choices=('cn', 'eu', 'eu-w', 'in', 'us', 'us-e') )
cred_group.add_argument( '-device', help='One or more Device ID(s) to use', action='append', nargs='+' )

subparsers['wizard'].add_argument( '-dry-run', help='Do not actually connect to the Cloud', action='store_true' )

# list command
subparsers['list'] = subparser.add_parser('list', help='List devices from device-file')
subparsers['list'].add_argument('-debug', '-d', help='Enable debug messages', action='store_true', dest='debug2')
subparsers['list'].add_argument('-device-file', help='JSON file to load devices from [Default: %s]' % DEVICEFILE, default=DEVICEFILE, metavar='FILE')
subparsers['list'].add_argument('--json', help='Display as JSON instead of a table', action='store_true')

# Device control commands: on, off, set, get
control_cmds = {
    'on':  'Turn on a device switch',
    'off': 'Turn off a device switch',
    'set': 'Set a DPS value on a device',
    'get': 'Read a DPS value from a device',
}

for sp in control_cmds:
    subparsers[sp] = subparser.add_parser(sp, help=control_cmds[sp])
    subparsers[sp].add_argument('-debug', '-d', help='Enable debug messages', action='store_true', dest='debug2')
    subparsers[sp].add_argument('-device-file', help='JSON file to load devices from [Default: %s]' % DEVICEFILE, default=DEVICEFILE, metavar='FILE')

    dev_group = subparsers[sp].add_argument_group('Device', '--id (or --name) and --key are required if the --device-file lookup fails')
    dev_group.add_argument('--id',      help='Device ID', metavar='ID')
    dev_group.add_argument('--name',    help='Device name (looked up in device-file)', metavar='NAME')
    dev_group.add_argument('--key',     help='Device local encryption key', metavar='KEY')
    dev_group.add_argument('--ip',      help='Device IP address (auto-discovered if omitted)', metavar='IP')
    dev_group.add_argument('--version', help='Tuya protocol version [Default: 3.3]', default=None, type=float, metavar='VER', dest='dev_version')

    if sp in ('on', 'off'):
        subparsers[sp].add_argument('--dps', help='Switch number [Default: 1]', default=1, type=int, metavar='N')
    elif sp == 'get':
        subparsers[sp].add_argument('--dps', help='DPS index to read (omit to return full status)', default=None, type=int, metavar='N')
    else:
        subparsers[sp].add_argument('--dps', help='DPS index', required=True, type=int, metavar='N')

    if sp == 'set':
        subparsers[sp].add_argument('--value', help='Value to set. Parsed as JSON if possible (e.g. true, 123, "text"), otherwise sent as a plain string.', required=True, metavar='VALUE')

if HAVE_ARGCOMPLETE:
    argcomplete.autocomplete( parser )

args = parser.parse_args()

if args.version:
    print('TinyTuya version:', version)
    sys.exit(0)

if args.debug:
    print('Parsed args:', args)
    set_debug(True)


def _run_list_command(args):
    """Handle the list command."""
    device_file = getattr(args, 'device_file', DEVICEFILE)
    try:
        with open(device_file, 'r') as f:
            tuyadevices = json.load(f)
    except FileNotFoundError:
        print('Error: device file "%s" not found.' % device_file)
        sys.exit(1)
    except Exception as e:
        print('Error reading device file: %s' % e)
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


def _run_device_command(args):
    """Handle on / off / set / get device control commands."""
    dev_id      = args.id
    dev_key     = args.key
    dev_ip      = args.ip
    dev_version = args.dev_version
    device_file = getattr(args, 'device_file', DEVICEFILE)
    dev_name    = getattr(args, 'name', None)

    # Load devices.json once (best-effort; missing file is fine)
    tuyadevices = []
    try:
        with open(device_file, 'r') as f:
            tuyadevices = json.load(f)
    except Exception:
        pass

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
    if not dev_key:
        print(
            'Error: device local key not found. Provide --key or ensure '
            'the device entry in %s has a "key" field.' % device_file
        )
        sys.exit(1)
    if dev_version is None:
        dev_version = 3.3
    if not dev_ip:
        dev_ip = 'Auto'

    # Create device handle
    try:
        d = Device(dev_id, address=dev_ip, local_key=dev_key, version=dev_version)
    except RuntimeError as e:
        print('Error: %s' % e)
        sys.exit(1)
    except Exception as e:
        print('Error creating device: %s' % e)
        sys.exit(1)

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


if args.command:
    if args.debug2 and not args.debug:
        print('Parsed args:', args)
        set_debug(True)

    # Scanner / wizard file setup – skip for device control commands and list
    if args.command not in control_cmds and args.command != 'list':
        if args.command == 'wizard' and args.raw_response_file:
            wizard.RAWFILE = args.raw_response_file

        if args.device_file:
            if type(args.device_file) == str:
                scanner.DEVICEFILE = args.device_file
                wizard.DEVICEFILE = args.device_file
            else:
                fname = args.device_file.name
                args.device_file.close()
                args.device_file = fname
                scanner.DEVICEFILE = fname
                wizard.DEVICEFILE = fname

        if args.snapshot_file:
            if args.command == 'json':
                scanner.SNAPSHOTFILE = args.snapshot_file.name
                args.snapshot_file.close()
                args.snapshot_file = scanner.SNAPSHOTFILE
            else:
                scanner.SNAPSHOTFILE = args.snapshot_file
                wizard.SNAPSHOTFILE = args.snapshot_file

if args.command == 'scan':
    scanner.scan( scantime=args.max_time, color=(not args.nocolor), forcescan=args.force, discover=(not args.no_broadcasts), assume_yes=args.yes )
elif args.command == 'snapshot':
    scanner.snapshot( color=(not args.nocolor), assume_yes=args.yes, skip_poll=args.no_poll )
elif args.command == 'devices':
    scanner.alldevices( scantime=args.max_time, color=(not args.nocolor), forcescan=args.force, discover=(not args.no_broadcasts), assume_yes=args.yes, skip_poll=args.no_poll )
elif args.command == 'json':
    scanner.snapshotjson()
elif args.command == 'wizard':
    if args.credentials_file:
        wizard.CONFIGFILE = args.credentials_file
    creds = { 'file': args.credentials_file, 'apiKey': args.key, 'apiSecret': args.secret, 'apiRegion': args.region, 'apiDeviceID': None }
    if args.device:
        creds['apiDeviceID'] = ','.join(sum(args.device, []))
    wizard.wizard( color=(not args.nocolor), retries=args.max_time, forcescan=args.force, nocloud=args.dry_run, assume_yes=args.yes, discover=(not args.no_broadcasts), skip_poll=args.no_poll, credentials=creds )
elif args.command == 'list':
    _run_list_command(args)
elif args.command in control_cmds:
    _run_device_command(args)
else:
    # No command selected - show help
    parser.print_help()

# Entry_points/console_scripts endpoints require a function to be called
def dummy():
    pass

# End
