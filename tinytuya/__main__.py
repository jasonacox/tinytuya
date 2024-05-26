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
import sys
import argparse
try:
    import argcomplete
    HAVE_ARGCOMPLETE = True
except:
    HAVE_ARGCOMPLETE = False

from . import wizard, scanner, version, SCANTIME, DEVICEFILE, SNAPSHOTFILE, CONFIGFILE, RAWFILE, set_debug

prog = 'python3 -m tinytuya' if sys.argv[0][-11:] == '__main__.py' else None
description = 'TinyTuya [%s]' % (version,)
parser = argparse.ArgumentParser( prog=prog, description=description )

# Options for all functions.
# Add both here and in subparsers (with alternate `dest=`) if you want to allow it to be positioned anywhere
parser.add_argument( '-debug', '-d', help='Enable debug messages', action='store_true' )

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

if HAVE_ARGCOMPLETE:
    argcomplete.autocomplete( parser )

args = parser.parse_args()

if args.debug:
    print('Parsed args:', args)
    set_debug(True)

if args.command:
    if args.debug2 and not args.debug:
        print('Parsed args:', args)
        set_debug(True)

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
else:
    # No command selected - show help
    parser.print_help()

# Entry_points/console_scripts endpoints require a function to be called
def dummy():
    pass

# End
