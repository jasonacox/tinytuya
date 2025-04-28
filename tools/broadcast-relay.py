#!/usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

"""
 A program that listens for broadcast packets from Tuya devices and sends them via unicast to App clients.
  Useful to make the app work on broadcast-blocking WiFi networks.

 Written by uzlonewolf (https://github.com/uzlonewolf) for the TinyTuya project https://github.com/jasonacox/tinytuya

 Call with "-h" for options.
"""

BROADCASTTIME = 6                   # How often to broadcast to port 7000 to get v3.5 devices to send us their info

import json
import logging
import socket
import select
import time
import traceback
import argparse

from tinytuya import decrypt_udp, UDPPORT, UDPPORTS, UDPPORTAPP
from tinytuya.scanner import send_discovery_request

try:
    import argcomplete
    HAVE_ARGCOMPLETE = True
except:
    HAVE_ARGCOMPLETE = False

if __name__ == '__main__':
    log = logging.getLogger( 'broadcast-relay' )
else:
    log = logging.getLogger(__name__)

def relay( args ):
    log.info( 'Starting Relay' )

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #send_sock.bind(("", 0))

    # Enable UDP listening broadcasting mode on UDP port 6666 - 3.1 Devices
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        # SO_REUSEPORT not available
        pass
    client.bind(("", UDPPORT))

    # Enable UDP listening broadcasting mode on encrypted UDP port 6667 - 3.2-3.5 Devices
    clients = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clients.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        clients.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        # SO_REUSEPORT not available
        pass
    clients.bind(("", UDPPORTS))

    # Enable UDP listening broadcasting mode on encrypted UDP port 7000 - App
    clientapp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    clientapp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        clientapp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        # SO_REUSEPORT not available
        pass
    clientapp.bind(("", UDPPORTAPP))

    broadcasted_apps = {}
    our_broadcasts = {}
    read_socks = []
    write_socks = []
    broadcast_query_timer = 0

    while True:
        read_socks = [client, clients, clientapp]
        write_socks = []

        try:
            rd, wr, _ = select.select( read_socks, write_socks, [] )
        except KeyboardInterrupt as err:
            log.warning("**User Break**")
            break

        for sock in rd:
            data, addr = sock.recvfrom(4048)
            ip = addr[0]
            result = b''

            if sock is clientapp:
                tgt_port = UDPPORTAPP
                result = None

                if ip in our_broadcasts:
                    log.debug( 'Ignoring our own broadcast: %r', ip )
                    continue

                try:
                    result = decrypt_udp( data )
                    result = json.loads(result)
                except:
                    log.warning( '*  Invalid UDP Packet from %r port %r: %r (%r)', ip, tgt_port, result, data, exc_info=True )
                    continue

                if 'from' in result and result['from'] == 'app':
                    client_ip = result['ip'] if 'ip' in result else ip

                    if client_ip not in broadcasted_apps:
                        log.info( 'New Broadcast from App at %r (%r) - %r', client_ip, ip, result )
                    else:
                        log.debug( 'Updated Broadcast from App at %r (%r) - %r', client_ip, ip, result )

                    broadcasted_apps[client_ip] = time.time() + (2 * BROADCASTTIME)

                    if broadcast_query_timer < time.time():
                        broadcast_query_timer = time.time() + BROADCASTTIME
                        our_broadcasts = send_broadcast()
                    continue
                elif 'gwId' in result:
                    # queried v3.5 device response, let it fall through
                    pass
                else:
                    log.warning( 'New Broadcast from App does not contain app data! src:%r - %r', ip, result )
                    continue

            elif sock is client:
                tgt_port = UDPPORT
            elif sock is clients:
                tgt_port = UDPPORTS
            else:
                tgt_port = '???'
                log.warning( 'Sock not known??' )

            #log.debug("UDP Packet from %r port %r", ip, tgt_port)

            #if 'gwId' not in result:
            #    print("*  Payload missing required 'gwId' - from %r to port %r: %r (%r)\n" % (ip, tgt_port, result, data))
            #    log.debug("UDP Packet payload missing required 'gwId' - from %r port %r - %r", ip, tgt_port, data)
            #    continue

            need_delete = []
            for client_ip in broadcasted_apps:
                if broadcasted_apps[client_ip] < time.time():
                    need_delete.append( client_ip )
                    continue

                dst = (client_ip, tgt_port)
                #log.debug( 'Sending to: %r', dst )
                send_sock.sendto( data, dst )

            for client_ip in need_delete:
                log.info( 'Client App aged out: %r', client_ip )
                del broadcasted_apps[client_ip]

    client.close()
    clients.close()
    clientapp.close()

    return

def send_broadcast():
    """
    Send broadcasts to query for newer v3.5 devices
    """
    our_broadcasts = send_discovery_request()
    if not our_broadcasts:
        our_broadcasts = {}
    return our_broadcasts

if __name__ == '__main__':
    disc = 'Listens for broadcast packets from Tuya devices and sends them via unicast to App clients.  Useful to make the app work on broadcast-blocking WiFi networks.'
    epi = None #'The "-s" option is designed to make the output display packets in the correct order when sorted, i.e. with `python3 pcap_parse.py ... | sort`'
    arg_parser = argparse.ArgumentParser( description=disc, epilog=epi )
    arg_parser.add_argument( '-debug', '-d', help='Enable debug messages', action='store_true' )

    if HAVE_ARGCOMPLETE:
        argcomplete.autocomplete( arg_parser )

    args = arg_parser.parse_args()

    logging.basicConfig( level=logging.DEBUG + (0 if args.debug else 1) )

    relay( args )
