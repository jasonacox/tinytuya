
try:
    import dpkt
    from dpkt.utils import mac_to_str, inet_to_str
except:
    print( "Required module 'dpkt' not found" )
    print( "Try: pip install dpkt" )
    print( "" )
    raise

import json
import argparse
import traceback
import struct
from hashlib import md5,sha256
import hmac

import tinytuya

devices = {}

def decrypt( data, key, has_ret=True ):
    p = tinytuya.unpack_message( data, None, has_ret )
    #print(p)

    payload = p.payload
    k2 = key.encode('utf8')
    print('plen:',len(data),len(payload),payload)
    cipher = tinytuya.AESCipher( k2 )

    if payload.startswith(tinytuya.PROTOCOL_VERSION_BYTES_31):
        payload = payload[len(tinytuya.PROTOCOL_VERSION_BYTES_31) :]
        payload = cipher.decrypt(payload[16:])
    else:
        if payload.startswith(
                tinytuya.PROTOCOL_VERSION_BYTES_33
        ):
            payload = payload[len(tinytuya.PROTOCOL_33_HEADER) :]
            #print("removing 3.3=%r" % payload)
            #print('plen:',len(payload), len(tinytuya.PROTOCOL_33_HEADER))

        if len(payload) == 0:
            #print('pay len 0 ???')
            return None

        mod = len(payload) % 16

        if mod > 0:
            print(' !!!! Paload not multiple of 16 !!!!', len(payload), mod)
            #print( '%r' % payload )
            #payload = payload + (b'\x00' * (16-mod))
            #payload = payload[mod:]
            payload = payload[:-mod]

        if len(payload) == 0:
            return None

        payload = cipher.decrypt(payload, False)
        if mod > 0:
            print("decrypted 3.3 payload=%r" % payload)
        #print("payload type = %s", type(payload))
        #if not isinstance(payload, str):
        #    payload = payload.decode()

        #if not payload.startswith("{"):
        #    print("Unexpected payload=%r", payload)
        #    return

        #print("decoded results=%r", payload)
        return payload

def pop_packet( data, from_dev ):
    min_len_55AA = struct.calcsize(tinytuya.MESSAGE_HEADER_FMT_55AA) + 4 + 4 + len(tinytuya.SUFFIX_BIN)
    min_len_6699 = struct.calcsize(tinytuya.MESSAGE_HEADER_FMT_6699) + 12 + 4 + 16 + len(tinytuya.SUFFIX_BIN)
    min_len = min_len_55AA if min_len_55AA < min_len_6699 else min_len_6699
    prefix_len = len( tinytuya.PREFIX_55AA_BIN )

    # search for the prefix.  if not found, delete everything except
    # the last (prefix_len - 1) bytes and recv more to replace it
    prefix_offset_55AA = data.find( tinytuya.PREFIX_55AA_BIN )
    prefix_offset_6699 = data.find( tinytuya.PREFIX_6699_BIN )

    if prefix_offset_55AA != 0 and prefix_offset_6699 != 0:
        print('Message prefix not at the beginning of the received data!')
        print('Offset 55AA: %d, 6699: %d, Received data: %r', prefix_offset_55AA, prefix_offset_6699, data)
        if prefix_offset_55AA < 0 and prefix_offset_6699 < 0:
            return None, None, None, None

        if prefix_offset_55AA < 0:
            prefix_offset = prefix_offset_6699 # if prefix_offset_55AA < 0 else prefix_offset_55AA
            prefix = tinytuya.PREFIX_6699_BIN
        else:
            prefix_offset = prefix_offset_55AA
            prefix = tinytuya.PREFIX_55AA_BIN

        data = data[prefix_offset:]
    elif prefix_offset_55AA == 0:
        prefix = tinytuya.PREFIX_55AA_BIN
    else:
        prefix = tinytuya.PREFIX_6699_BIN

    header = tinytuya.parse_header(data)
    remaining = header.total_length - len(data)
    if remaining > 0:
        return None, None, prefix, data

    return header, data[:header.total_length], prefix, data[header.total_length:]

def process_data( data, from_dev, devinfo, flow, args ):
    #print( 'di', devinfo )
    #print( 'fl', flow )
    if( ('key' not in devinfo) or (not devinfo['key']) ):
        print( 'Missing device key, skipping packet' )
        return

    if 'packet_idx' not in flow:
        flow['packet_idx'] = 0

    while data:
        header, pdata, prefix, data = pop_packet( data, from_dev )

        if 'ver' not in flow:
            if 'version' in devinfo:
                flow['ver'] = float( devinfo['version'] )
            elif 'ver' in devinfo:
                flow['ver'] = devinfo['ver']
            elif( prefix == tinytuya.PREFIX_6699_BIN ):
                flow['ver'] = 3.5
            else:
                flow['ver'] = 0

        src_str = ('from' if from_dev else 'to') + (' %r' % devinfo['id'])
        cmd_str = 'cmd:% 3d (%02X) v%.1f' % (header.cmd, header.cmd, flow['ver'])
        flow['packet_idx'] += 1

        if args.sortable:
            src_str = ('from' if from_dev else 'to  ')
            output_prefix = '%s %04d %04d ' % ( devinfo['id'], flow['idx'], flow['packet_idx'] )
        else:
            src_str = '%-29s' % (('from' if from_dev else 'to') + (' %r' % devinfo['id']))
            output_prefix = ''

        if not flow['ver']:
            # try <=3.3
            packet = tinytuya.unpack_message(pdata, header=header, hmac_key=None, no_retcode=(not from_dev))
            if( not packet.crc_good ):
                # next try v3.4
                try2 = tinytuya.unpack_message(pdata, header=header, hmac_key=devinfo['key'], no_retcode=True)
                if try2.crc_good:
                    print( '%s %-11s %s' % (src_str, '', '<Auto-detected v3.4 device>') )
                    flow['ver'] = 3.4
                    packet = try2
        if flow['ver'] <= 3.3:
            packet = tinytuya.unpack_message(pdata, header=header, hmac_key=None, no_retcode=(not from_dev))
            payload = packet.payload

            if not flow['ver']:
                if payload.startswith( b'3.' ):
                    v = payload[2]
                    if type(v) == str: v = int(str)
                    if v > 0 and v < 4:
                        flow['ver'] = float(payload[:3])

            if len(payload) == 0:
                pass
            elif not flow['ver']:
                pass
            elif( flow['ver'] == 3.1 ):
                pass
            else: # 3.2 or 3.3
                if( payload.startswith( str(flow['ver']).encode('utf8') ) ):
                    headlen = len(tinytuya.PROTOCOL_3x_HEADER)+3
                    head = payload[:headlen]
                    enc = payload[headlen:]
                else:
                    head = b''
                    enc = payload

                payload = head + tinytuya.AESCipher( devinfo['key'] ).decrypt(enc, False).encode('utf8')
        else:
            if 'session_key' not in flow:
                flow['session_key'] = b''

            if( (header.cmd >= tinytuya.SESS_KEY_NEG_START) and (header.cmd <= tinytuya.SESS_KEY_NEG_FINISH) ):
                hmac_key = devinfo['key']
            elif not flow['session_key']:
                print( '%s %-15s %s' % (src_str, cmd_str, '<Error: No Session Key for stream!  The 3-way handshake needs to be captured to decrypt v3.4+ device streams!') )
                continue
            else:
                hmac_key = flow['session_key']

            packet = tinytuya.unpack_message(pdata, header=header, hmac_key=hmac_key, no_retcode=(not from_dev))
            if( (not packet.crc_good) and (hmac_key != devinfo['key']) ):
                try2 = tinytuya.unpack_message(pdata, header=header, hmac_key=devinfo['key'], no_retcode=True)
                if try2.crc_good:
                    packet = try2
                    flow['session_key'] = b''

            payload = packet.payload
            if packet.crc_good:
                payload = packet.payload
                if flow['ver'] == 3.4 and len(payload):
                    try:
                        payload = tinytuya.AESCipher( hmac_key ).decrypt(payload, False, decode_text=False)
                    except:
                        print("v3.4 decrypt payload failed, payload=%r (len:%d)" % (payload, len(payload)))
                        payload = b''

                if( packet.cmd == tinytuya.SESS_KEY_NEG_START ):
                    payload_str = '<Negotiate Session Key Step 1>'
                    flow['session_key'] = b''
                    flow['device_nonce'] = b''
                    flow['client_nonce'] = payload
                elif( packet.cmd == tinytuya.SESS_KEY_NEG_RESP ):
                    payload_str = '<Negotiate Session Key Step 2>'
                    flow['session_key'] = b''
                    flow['device_nonce'] = payload[:16]
                    dev_hmac = payload[16:]
                    hmac_check = hmac.new( devinfo['key'], flow['client_nonce'], sha256).digest()
                    if( dev_hmac != hmac_check ):
                        payload_str += ' session key step 2 HMAC verify fail!'
                    else:
                        payload_str += ' session key step 2 HMAC verify OK!'
                elif( packet.cmd == tinytuya.SESS_KEY_NEG_FINISH ):
                    payload_str = '<Negotiate Session Key Step 3>'
                    hmac_check = hmac.new( devinfo['key'], flow['device_nonce'], sha256).digest()
                    if( payload != hmac_check ):
                        payload_str += ' session key step 3 HMAC verify fail!'
                    else:
                        payload_str += ' session key step 3 HMAC verify OK!'

                    try:
                        flow['session_key'] = bytes( [ a^b for (a,b) in zip(flow['client_nonce'], flow['device_nonce']) ] )
                    except:
                        k = [ chr(ord(a)^ord(b)) for (a,b) in zip(flow['client_nonce'], flow['device_nonce']) ]
                        flow['session_key'] = ''.join(k)

                    if flow['ver'] == 3.4:
                        flow['session_key'] = tinytuya.AESCipher( devinfo['key'] ).encrypt( flow['session_key'], False, pad=False )
                    else:
                        iv = flow['client_nonce'][:12]
                        print("Session IV:", iv)
                        flow['session_key'] = tinytuya.AESCipher( devinfo['key'] ).encrypt( flow['session_key'], use_base64=False, pad=False, iv=iv )[12:28]

        if( len(packet.payload) == 0 and args.hide_zero_len ):
            continue
        elif not packet.crc_good:
            print( output_prefix, packet )
        else:
            cmd_str += ' len(%d)' % len(packet.payload)
            if( flow['ver'] < 3.4 or (packet.cmd < tinytuya.SESS_KEY_NEG_START) or (packet.cmd > tinytuya.SESS_KEY_NEG_FINISH) ):
                if all((char <= 0x7E and char >= 0x20) for char in payload):
                    payload_str = payload.decode('utf8')
                else:
                    payload_str = '%r' % payload

            print( output_prefix, '%s %-22s %s' % (src_str, cmd_str, payload_str) )

    return True

def get_key( dev=None, mac=None, ip=None ):
    global devices

    ver = 0

    if dev:
        for dev in devices:
            if 'id' in dev and 'key' in dev and dev['key']:
                if dev == dev['id']:
                    return dev['id'], dev['key'], ver

    if mac:
        mac = mac.lower()
        for dev in devices:
            if 'mac' in dev and 'key' in dev and dev['key']:
                if mac == dev['mac'].lower():
                    return dev['id'], dev['key'], ver
    if ip:
        for dev in devices:
            if 'ip' in dev and 'key' in dev and dev['key']:
                if ip == dev['ip']:
                    return dev['id'], dev['key'], ver

    return None, '', ver

def process_pcap( pcap_file, args ):
    flows = {}
    ignore_flows = {}
    flow_count = 0
    ip_devs = {}

    for ts, buf in dpkt.pcap.Reader(pcap_file):
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            #print( 'Non IP Packet type not supported: %s\n' % eth.data.__class__.__name__ )
            continue

        if( isinstance(eth.ip.data, dpkt.udp.UDP) ):
            if( eth.ip.udp.dport == 6667 and eth.ip.src not in ip_devs ):
                try:
                    data = eth.ip.udp.data
                    devmac = mac_to_str( eth.src )
                    devip = inet_to_str( eth.ip.src )
                    payload = json.loads( tinytuya.decrypt_udp( data ) )
                    did, dkey, dver = get_key( dev=payload['gwId'], mac=devmac )
                    payload['id'] = did
                    payload['key'] = dkey.encode('utf8')
                    ip_devs[devip] = payload
                except:
                    traceback.print_exc()

    pcap_file.seek(0)
    for ts, buf in dpkt.pcap.Reader(pcap_file):
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            #print( 'Non IP Packet type not supported: %s\n' % eth.data.__class__.__name__ )
            continue

        if( isinstance(eth.ip.data, dpkt.tcp.TCP) ):
            data = None
            if( eth.ip.tcp.dport == 6668 ):
                #TcpFrom( eth )
                data = eth.ip.tcp.data
                devmac = mac_to_str( eth.dst )
                devip = inet_to_str( eth.ip.dst )
                dev_str = '%s:%d' % (devip, eth.ip.tcp.dport)
                client_str = '%s:%d' % (inet_to_str( eth.ip.src ), eth.ip.tcp.sport)
                from_dev = False
            elif( eth.ip.tcp.sport == 6668 ):
                #TcpTo( eth )
                data = eth.ip.tcp.data
                devmac = mac_to_str( eth.src )
                devip = inet_to_str( eth.ip.src )
                dev_str = '%s:%d' % (devip, eth.ip.tcp.sport)
                client_str = '%s:%d' % (inet_to_str( eth.ip.dst ), eth.ip.tcp.dport)
                from_dev = True

            if data:
                flow_key = '%s_%s' % (dev_str, client_str)

                if flow_key in ignore_flows:
                    continue

                if( devip not in ip_devs ):
                    print( 'Flow but no broadcast??  Attempting lookup by MAC address' )
                    did, dkey, dver = get_key( mac=devmac, ip=devip )
                    ip_devs[devip] = {'id': did, 'key': dkey.encode('utf8')}
                    print( 'Lookup result:', ip_devs[devip])

                if( flow_key not in flows ):
                    flow_count += 1
                    flows[flow_key] = { 'id': flow_key, 'idx': flow_count }
                    print( '%s %04d %04d %s' % ( ip_devs[devip]['id'], flow_count, 0, flow_key ) )


                if not ip_devs[devip]['key']:
                    print( 'Missing device key for %s [MAC %s] [Flow %s], skipping' % (devip, devmac, flow_key) )
                    ignore_flows[flow_key] = True
                    continue

                process_data( data, from_dev, ip_devs[devip], flows[flow_key], args )

        else:
            #print( 'Non TCP/UDP Packet type not supported: %s\n' % eth.ip.data.__class__.__name__ )
            continue

if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Reads PCAP files created by tcpdump and prints the traffic to/from Tuya devices.  Local keys are loaded from devices.json.')
    arg_parser.add_argument('files', metavar='INFILE.pcap', nargs='+', help='Input file(s) to parse', type=argparse.FileType('rb'))
    arg_parser.add_argument('-d', '--devices', help='devices.json file to read local keys from', default='devices.json', metavar='devices.json', type=argparse.FileType('rb'))
    arg_parser.add_argument('-z', '--hide-zero-len', help='Hide 0-length packets', action='store_true')
    arg_parser.add_argument('-s', '--sortable', help='Output data in a way which is sortable', action='store_true')

    args = arg_parser.parse_args()
    devices = json.load( args.devices )

    for pf in args.files:
        process_pcap( pf, args )

    
