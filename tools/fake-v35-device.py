
import ttcorefunc as tinytuya
import socket
import select
import time
import json
from hashlib import md5, sha256
import hmac

bind_host = ''
bind_port = 6668

# can also be set to the address of a hub/gateway device or phone running  SmartLife
bcast_to = '127.0.0.1'

bcast_data = b'{"ip":"127.0.0.1","gwId":"eb0123456789abcdefghij","active":2,"ablilty":0,"encrypt":true,"productKey":"keydeadbeef12345","version":"3.5","token":true,"wf_cfg":true}'
real_key = b'thisisarealkey00'
local_nonce = str(time.time() * 1000000)[:16].encode('utf8') #b'0123456789abcdef'

msg = tinytuya.TuyaMessage(1, tinytuya.UDP_NEW, 0, bcast_data, 0, True, tinytuya.PREFIX_6699_VALUE, True)
bcast_data = tinytuya.pack_message(msg,hmac_key=tinytuya.udpkey)
print("broadcast encrypted=%r" % bcast_data.hex() )


srv = socket.socket( socket.AF_INET6, socket.SOCK_STREAM )
srv.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
srv.bind( (bind_host, bind_port) )
srv.listen( 1 )

bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
bsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

client = None

bcast_time = 0

while True:
    r = [srv]
    if client: r.append( client )
    w = []
    x = []

    r, w, x = select.select( r, w, x, 1 )
    #print('select')

    if( bcast_time < time.time() ):
        bcast_time = time.time() + 8
        #print( 'bcast' )
        bsock.sendto( bcast_data, (bcast_to, 6667) )

    for sock in r:
        if sock is srv:
            if client:
                client.close()
                client = None
            client, addr = sock.accept()
            client.setblocking( False )
            tmp_key = real_key
            seqno = 1
            print( 'new client connected:', addr )
            continue

        if sock is not client:
            print('not:', sock)
            continue

        data = sock.recv( 4096 )
        #print( 'client data: %r' % data )
        if not data:
            client.close()
            client = None
            continue

        print('')
        print('client sent:', data)
        #print(data.hex())
        m = tinytuya.unpack_message(data,hmac_key=tmp_key, no_retcode=True)
        #print('payload len:', len(m.payload), 'tuya message:', m)
        print('decoded message:', m)

        if m.cmd == tinytuya.SESS_KEY_NEG_START:
            tmp_key = real_key
            payload = m.payload
            remote_nonce = payload
            miv = remote_nonce[:12]
            hmac_check = hmac.new(real_key, remote_nonce, sha256).digest()
            msg = tinytuya.TuyaMessage(seqno, tinytuya.SESS_KEY_NEG_RESP, 0, local_nonce+hmac_check, 0, True, tinytuya.PREFIX_6699_VALUE, True)
            seqno += 1
            data = tinytuya.pack_message(msg, hmac_key=tmp_key)
            print( 'session neg start:', msg )
            client.sendall( data )
        elif m.cmd == tinytuya.SESS_KEY_NEG_FINISH:
            rkey_hmac = hmac.new(real_key, local_nonce, sha256).digest()
            print('neg fin. success:', rkey_hmac == m.payload)
            print('want hmac:', rkey_hmac.hex())
            print('got hmac: ', m.payload.hex())
            tmp_key = bytes( [ a^b for (a,b) in zip(remote_nonce,local_nonce) ] )
            print( 'sess nonce:', tmp_key.hex() )
            cipher = tinytuya.AESCipher( real_key )
            print( 'sess iv:', m.iv.hex() )
            tmp_key = cipher.encrypt( tmp_key, use_base64=False, pad=False, iv=miv )[12:28]
            print( 'sess key:', tmp_key.hex(), tmp_key)
        elif m.cmd == tinytuya.DP_QUERY_NEW:
            print('got status request')
            resp = {'protocol': 4, 't': int(time.time()), 'data': {'dps': {'20': True, '21': 'white', '22': 946, '23': 3, '24': '014a03e803a9', '25': '04464602007803e803e800000000464602007803e8000a00000000', '26': 0, '34': False}} }
            msg = tinytuya.TuyaMessage(seqno, 16, 0, json.dumps(resp).encode('ascii'), 0, True, tinytuya.PREFIX_6699_VALUE, True)
            seqno += 1
            data = tinytuya.pack_message(msg, hmac_key=tmp_key)
            client.sendall( data )
        else:
            print('unhandled command', m.cmd)
            msg = tinytuya.TuyaMessage(seqno, 16, 0, b'json obj data unvalid', 0, True, tinytuya.PREFIX_6699_VALUE, True)
            seqno += 1
            data = tinytuya.pack_message(msg, hmac_key=tmp_key)
            client.sendall( data )


