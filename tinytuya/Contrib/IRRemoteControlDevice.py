# TinyTuya Contrib IRRemoteControlDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart universal remote control simulators

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Module Author: Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)

 Local Control Classes
    IRRemoteControlDevice(..., version=3.3)
        This class uses a default version of 3.3
        See OutletDevice() for the other constructor arguments

    Functions:
        ir = IRRemoteControlDevice(...)

        ir.receive_button( timeout )
            -> call this method and press button on real remote control to read its code in Base64 format
               timeout - maximum time to wait for button press

        ir.send_button( base64_code )
            -> simulate button press

        IRRemoteControlDevice.base64_to_pulses ( code_base_64 )
            -> convert Base64-encoded button code to sequence of pulses and gaps length

        IRRemoteControlDevice.pulses_to_base64 ( pulses )
            -> convert sequence of pulses and gaps length to Base64-encoded button code

        IRRemoteControlDevice.head_key_to_pulses ( head='...', key='...' )
            -> convert head/key pair to sequence of pulses and gaps
               'head' can be omitted if key starts with '1'
               'key' must begin with '000' through '1FF'

        IRRemoteControlDevice.pulses_to_head_key ( pulses )
            -> attempt to pack a sequence of pulses and gaps into a head/key pair

        IRRemoteControlDevice.hex_to_pulses ( code_hex )
            -> convert HEX-encoded button code to sequence of pulses and gaps length
               HEX-encoded codes are used in the Cloud API

        IRRemoteControlDevice.pulses_to_hex ( pulses )
            -> convert sequence of pulses and gaps length to HEX-encoded button code
               HEX-encoded codes are used in the Cloud API

        IRRemoteControlDevice.nec_to_pulses ( address, data=None )
            -> convert a 32-bit NEC button code (when data=None) or a 8/16-bit address and 8-bit data to sequence of pulses and gaps length
               address - a 32-bit NEC button code (when data=None), or a 8-bit or 16-bit address
               data - 8-bit data when address is 8-bit or 16-bit

        IRRemoteControlDevice.pulses_to_nec ( pulses )
            -> convert sequence of pulses and gaps length to a NEC button code
               returns an array of dicts containing 'type'="nec", 'address' and 'data' (if valid), 'uint32' raw data, and 'hex' hex-encoded data

        IRRemoteControlDevice.samsung_to_pulses ( address, data=None )
            -> similar to nec_to_pulses() but for the Samsung format (start pulse 4.5ms instead of 9ms)

        IRRemoteControlDevice.pulses_to_samsung ( pulses )
            -> similar to pulses_to_nec() but for the Samsung format
               returns same array of dict as pulses_to_nec() but with 'type'="samsung"

        IRRemoteControlDevice.pronto_to_pulses ( pronto )
            -> convert a Pronto code string to sequence of pulses and gaps length

        IRRemoteControlDevice.pulses_to_pronto ( pulses )
            -> convert sequence of pulses and gaps length to a Pronto code string

        IRRemoteControlDevice.width_encoded_to_pulses ( uint32, start_mark=9000, start_space=4500, pulse_one=563, pulse_zero=563,
          space_one=1688, space_zero=563, trailing_pulse=563, trailing_space=30000 )
            -> flexible uint32 to sequence of pulses encoder
               default values are for NEC format, set start_mark=4500 for Samsung format

        IRRemoteControlDevice.pulses_to_width_encoded ( pulses, start_mark=None, start_space=None, pulse_threshold=None, space_threshold=None )
            -> flexible space-width or pulse-width to uint32 decoder
               converts sequence of pulses to a 32-bit unsigned integer
               recommended *_threshold is `(length_of_zero + length_of_one) / 2`

"""

import base64
import json
import logging
import struct
from math import ceil, floor

from ..core import Device, log, CONTROL

class IRRemoteControlDevice(Device):
    DP_SEND_IR = "201"             # ir_send, send and report (read-write)
    DP_LEARNED_ID = "202"          # ir_study_code, report only (read-only)
    NSDP_CONTROL = "control"       # The control commands
    NSDP_STUDY_CODE = "study_code" # Report learned IR codes
    NSDP_IR_CODE = "ir_code"       # IR signal decoding2
    NSDP_KEY_CODE = "key_code"     # Remote key code
    NSDP_KEY_CODE2 = "key_code2"   # Remote key code 2
    NSDP_KEY_CODE3 = "key_code3"   # Remote key code 3
    NSDP_KEY_CODE4 = "key_code4"   # Remote key code 4
    NSDP_KEY_STUDY = "key_study"   # Send the learning code 1
    NSDP_KEY_STUDY2 = "key_study2" # Send the learning code 2
    NSDP_KEY_STUDY3 = "key_study3" # Send the learning code 3
    NSDP_KEY_STUDY4 = "key_study4" # Send the learning code 4
    NSDP_DELAY_TIME = "delay_time" # IR code transmission delay
    NSDP_TYPE = "type"             # The identifier of an IR library
    NSDP_DELAY = "delay"           # Actually used but not documented
    NSDP_HEAD = "head"             # Actually used but not documented
    NSDP_KEY1 = "key1"             # Actually used but not documented
    KEY1_SYMBOL_LIST = "@#$%^&*()" # Timing symbols used in key1

    def __init__(self, *args, **kwargs):
        # set the default version to 3.3 as there are no 3.1 devices
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.3
        super(IRRemoteControlDevice, self).__init__(*args, **kwargs)

    def receive_button( self, timeout ):
        log.debug("Receiving button")
        # Exit study mode in case it's enabled
        command = {
            IRRemoteControlDevice.NSDP_CONTROL: "study_exit",
        }
        payload = self.generate_payload(CONTROL, {IRRemoteControlDevice.DP_SEND_IR: json.dumps(command)})
        self.send(payload)
                # Enable study mode
        command = {
            IRRemoteControlDevice.NSDP_CONTROL: "study",
        }
        payload = self.generate_payload(CONTROL, {IRRemoteControlDevice.DP_SEND_IR: json.dumps(command)})        
        self.send(payload)

        # Receiving button code
        button = None
        # Remember old timeout and set new timeout
        old_timeout = self.connection_timeout
        self.set_socketTimeout(timeout)
        try:
            log.debug("Waiting for button...")
            button = self._send_receive(None)
            if button == None:
                # Nothing received
                log.debug("Timeout")
                base64_code = None
            elif type(button) != dict or "dps" not in button or IRRemoteControlDevice.DP_LEARNED_ID not in button["dps"]:
                # Some unexpected result
                log.debug(f"Unexpected response: {button}")
                base64_code = button # Some error message? Pass it.
            else:
                # Button code received, extracting it as Base64 string
                base64_code = button["dps"][IRRemoteControlDevice.DP_LEARNED_ID]
                # Some debug info
                if log.getEffectiveLevel() <= logging.DEBUG:
                    pulses = self.base64_to_pulses(base64_code)
                    log.debug("Pulses and gaps (microseconds): " + 
                        ' '.join([f'{"p" if i % 2 == 0 else "g"}{pulses[i]}' for i in range(len(pulses))]))
        finally:
            # Revert timeout
            self.set_socketTimeout(old_timeout)

        # Exit study mode
        command = {
            IRRemoteControlDevice.NSDP_CONTROL: "study_exit",
        }
        payload = self.generate_payload(CONTROL, {IRRemoteControlDevice.DP_SEND_IR: json.dumps(command)})
        self.send(payload)        

        return base64_code

    def send_button( self, base64_code ):
        if len(base64_code) % 4 == 0: base64_code = '1' + base64_code; # code need to be padded with "1" (wtf?)
        log.debug("Sending IR Button: " + base64_code)
        # Some debug info
        if log.getEffectiveLevel() <= logging.DEBUG:
            pulses = self.base64_to_pulses(base64_code)
            log.debug("Pulses and gaps (microseconds): " + 
                ' '.join([f'{"p" if i % 2 == 0 else "g"}{pulses[i]}' for i in range(len(pulses))]))
        command = {
            IRRemoteControlDevice.NSDP_CONTROL: "send_ir",
            IRRemoteControlDevice.NSDP_KEY1: base64_code,
            IRRemoteControlDevice.NSDP_TYPE: 0,
        }
        payload = self.generate_payload(CONTROL, {IRRemoteControlDevice.DP_SEND_IR: json.dumps(command)})
        return self.send(payload)

    @staticmethod
    def base64_to_pulses( code_base_64 ):
        if len(code_base_64) % 4 == 1 and code_base_64.startswith("1"):
            # code can be padded with "1" (wtf?)
            code_base_64 = code_base_64[1:]
        raw_bytes = base64.b64decode(code_base_64)
        return [int.from_bytes(raw_bytes[i:i+2], byteorder="little") for i in range(0, len(raw_bytes), 2)]

    @staticmethod
    def pulses_to_base64( pulses ):
        raw_bytes = [x.to_bytes(2, byteorder="little") for x in pulses]
        raw_bytes = [x for xs in raw_bytes for x in xs] # flatten
        return base64.b64encode(bytes(raw_bytes)).decode("ascii")

    @staticmethod
    def head_key_to_pulses( head, key ):
        if len(key) < 4:
            raise ValueError( '"key" must be at least 4 characters' )

        keytype = int(key[0], 16)
        if keytype < 0 or keytype > 1:
            raise ValueError( 'First digit of "key" must be "0" or "1" (got: %r)' % keytype )
        elif keytype == 1:
            return IRRemoteControlDevice.base64_to_pulses( key )

        if len(head) < 18:
            raise ValueError( '"head" must be at least 18 characters' )

        head = bytearray.fromhex( head )
        headtype, timescale, unused1, unused2, num_timings = struct.unpack( '>BHHHH', head[:9] )
        headlen = num_timings * 2 # times are 16-bit
        timebase = 100000.0 / timescale
        symbols = '@#$%^&*()'[:num_timings]
        try:
            repeat = int( key[1:3], 16 )
        except:
            raise ValueError( 'First digit of "key" must be "0" or "1" and the next 2 digits must be a hexidecimal byte' )
        key = key[3:]

        # 'head' type 1 uses '@' for 0 and '#' for 1
        # 'head' type 2 uses '#' for 0 and '$' for 1

        if headtype == 1:
            bit_timimgs = ( '@@', '@#' )
        elif headtype == 2:
            bit_timimgs = ( '@#', '@$' )
        else:
            raise ValueError( 'Unhandled "head" type: %d' % headtype )

        if len(head) != (headlen+9):
            raise ValueError( '"head" must be %d characters' % ((headlen+9)*2) )

        # unpack the timing values, however many there are
        fmt = '>%dH' % num_timings
        timings = struct.unpack( fmt, head[9:] )
        symbol_timings = {}

        for i in range(num_timings):
            symbol_timings[symbols[i]] = round(timebase * timings[i])

        if False:
            print( 'Head:' )
            print( 'Frequency: %r kHz, Time Base: %r' % (timescale / 100.0, timebase) )
            print( 'Bit Symbols: 0 = %s, 1 = %s' % bit_timimgs)
            print( 'Symbol Timings:' )
            for i in range(num_timings):
                print( '  %s = %r microseconds' % (symbols[i], symbol_timings[symbols[i]]) )
            print( '' )
            print( 'Key:' )
            print( 'Send count:', repeat )
            print( 'Code:', key )

        # although it's not as effiecient, it's easier to see what's going on if
        #  you first unpack the packed bits into their symbol pairs, and then
        #  expand those symbols to their timing times

        expanded = ''
        while key:
            cnt = 0
            # first, copy symbols as-is
            for c in key:
                if c not in symbols:
                    break

                expanded += c
                cnt += 1

            key = key[cnt:]
            if not key:
                # all finished
                break

            # next, expand packed bits
            #print( 'Unpacking:', key[:4] )
            byts, bits = struct.unpack( '>BB', bytearray.fromhex( key[:4] ) )
            key = key[4:]
            if byts != 0:
                # if the first byte is not 0, read in and transmit bytes until a symbol is encountered
                cnt = 0
                bits = 0
                data = ''
                for c in key:
                    c2 = ord(c.upper())
                    if c2 < 0x30 or c2 > 0x46 or (c2 > 0x39 and c2 < 0x41):
                        # it's a symbol, we're done
                        break
                    data += c
                    cnt += 1
                    bits += 4
                if (len(data) % 2):
                    data += '0'
            else:
                # if the first byte is 0, the next byte is how many bits to transmit
                byts = ceil( bits / 8 )
                cnt = byts * 2
                data = key[:cnt]

            key = key[cnt:]
            byts = bytearray.fromhex( data )
            # unpack the bits into symbol pairs
            while bits:
                d = byts[0]
                byts = byts[1:]
                for i in range(8):
                    if not bits:
                        break
                    # devices transmit MSB first
                    if (d & 0x80) == 0x80:
                        expanded += bit_timimgs[1]
                    else:
                        expanded += bit_timimgs[0]
                    d <<= 1
                    bits -= 1

        if False:
            print( 'Expanded Code:', expanded )
            print( '' )
            print( 'Pulse train:' )

            # expand the symbols into their pulses
            for c in expanded:
                print( symbol_timings[c], end=' ' )
            print( '' )

        return [symbol_timings[c] for c in expanded]


    @staticmethod
    def pulses_to_head_key( pulses, fudge=0.1 ):
        # see if it will decode with NEC/Samsung
        res = None #IRRemoteControlDevice.pulses_to_space_encoded_head_key( pulses )
        print( 'res:', res )
        #return
        #if not res:
        #    # next try SIRC
        #    res = IRRemoteControlDevice.pulses_to_pulse_encoded_head_key( pulses )

        ps_count = { }
        for p_in in pulses:
            if p_in not in ps_count:
                ps_count[p_in] = 1
            else:
                ps_count[p_in] += 1

        ps_map = IRRemoteControlDevice._merge_similar_pulse_times( ps_count, fudge )

        p_count = { }
        s_count = { }
        is_pulse = False
        for p_in in pulses:
            is_pulse = not is_pulse

            if p_in in ps_map:
                p_in = ps_map[p_in]

            if is_pulse:
                if p_in not in p_count:
                    p_count[p_in] = 1
                else:
                    p_count[p_in] += 1
            else:
                if p_in not in s_count:
                    s_count[p_in] = 1
                else:
                    s_count[p_in] += 1

        print( 'p_count:', p_count, 's_count:', s_count )
        #p_map = IRRemoteControlDevice._merge_similar_pulse_times( p_count, fudge )
        #s_map = IRRemoteControlDevice._merge_similar_pulse_times( s_count, fudge )
        p_map = s_map = ps_map

        symbol_pattern = ''
        symbol_list = { }
        p_key_map = { }
        s_key_map = { }
        is_pulse = False
        for p_in in pulses:
            is_pulse = not is_pulse
            if is_pulse:
                k = p_map[p_in] if p_in in p_map else p_in
                if k not in p_key_map:
                    mk = chr(len(p_key_map) + 0x41) # A-z
                    #print('adding pulse', k, mk)
                    p_key_map[k] = { 'count': 1, 'char': mk }
                    if mk not in symbol_list:
                        symbol_list[mk] = [k, False]
                else:
                    p_key_map[k]['count'] += 1
                symbol_pattern += p_key_map[k]['char']
            else:
                k = s_map[p_in] if p_in in s_map else p_in
                if k not in s_key_map:
                    mk = chr(len(s_key_map) + 0x61) # a-z
                    #print('adding SPACE', k, mk)
                    s_key_map[k] = { 'count': 1, 'char': mk }
                    if mk not in symbol_list:
                        symbol_list[mk] = [k, False]
                else:
                    s_key_map[k]['count'] += 1
                symbol_pattern += s_key_map[k]['char']

        print( 'symbol_pattern:', symbol_pattern )
        print( 'symbol_list:', symbol_list )

        pmax = { 'count': 0, 'time': 0 }
        smax = { 'count': 0, 'time': 0 }
        for k in p_key_map:
            if p_key_map[k]['count'] > pmax['count']:
                pmax['count'] = p_key_map[k]['count']
                pmax['time'] = k
        for k in s_key_map:
            if s_key_map[k]['count'] > smax['count']:
                smax['count'] = s_key_map[k]['count']
                smax['time'] = k
        print( 'smax, pmax:', smax, pmax )

        #if False and smax['count'] > pmax['count']:
        #    # probably pulse-width encoded
        #    k = smax['time']
        #    pat = s_key_map[k]['char']
        #else:
        #    # probably space-width encoded
        #    k = pmax['time']
        #    pat = p_key_map[k]['char']
        #del pmax
        #del smax
        #print( 'pat:', pat )
        k = smax['time']
        s_pat = s_key_map[k]['char']

        k = pmax['time']
        p_pat = p_key_map[k]['char']

        print( 'p_pat s_pat:', p_pat, s_pat )

        offset_0_shortest = offset_1_shortest = None
        for offset in range( 2 ):
            print( 'Trying offset', offset )

            pat = p_pat if offset == 0 else s_pat
            pat_counts = {}
            for i in range( offset, len(symbol_pattern), 2 ):
                if symbol_pattern[i] == pat:
                    k = symbol_pattern[i:i+2]
                    if len(k) == 2:
                        if k not in pat_counts:
                            pat_counts[k] = 1
                        else:
                            pat_counts[k] += 1

            print( 'pat_counts:', pat_counts )

            # find the most-common pattern pair, and the next-most-common pattern pair
            pat_max = [0, '']
            pat_next_max = [0, '']
            for k in pat_counts:
                if pat_counts[k] > pat_max[0]:
                    pat_max[0] = pat_counts[k]
                    pat_max[1] = k
            for k in pat_counts:
                if k != pat_max[1] and pat_counts[k] > pat_next_max[0]:
                    pat_next_max[0] = pat_counts[k]
                    pat_next_max[1] = k

            print( 'pat_max', pat_max, 'pat_next_max', pat_next_max)

            # reset from the previous 'offset' loop
            for k in symbol_list:
                symbol_list[k][1] = False

            try_bitfield = True
            new_symbol_pattern = ''
            full_symbol_pattern = symbol_pattern

            a = pat_max[1][0]
            b = pat_next_max[1][0]
            if symbol_list[a][0] == symbol_list[b][0]:
                # pulses are the same, it might be space-width encoded
                symbol_list[a][1] = symbol_list[b][1] = '@'
                a = pat_max[1][1]
                b = pat_next_max[1][1]
                if symbol_list[a][0] < symbol_list[b][0]:
                    symbol_list[a][1] = '#'
                    symbol_list[b][1] = '$'
                    zero_symbol = pat_max[1]
                    one_symbol = pat_next_max[1]
                else:
                    symbol_list[a][1] = '$'
                    symbol_list[b][1] = '#'
                    zero_symbol = pat_next_max[1]
                    one_symbol = pat_max[1]
            else:
                # pulses are not the same
                if symbol_list[a][0] < symbol_list[b][0]:
                    symbol_list[a][1] = '#'
                    symbol_list[b][1] = '$'
                    zero_symbol = pat_max[1]
                    one_symbol = pat_next_max[1]
                else:
                    symbol_list[a][1] = '$'
                    symbol_list[b][1] = '#'
                    zero_symbol = pat_next_max[1]
                    one_symbol = pat_max[1]

                a = pat_max[1][1]
                b = pat_next_max[1][1]
                if symbol_list[a][0] == symbol_list[b][0]:
                    # but all spaces are the same, probably pulse-width encoded
                    symbol_list[a][1] = symbol_list[b][1] = '@'
                    new_symbol_pattern = symbol_pattern[0]
                    full_symbol_pattern = symbol_pattern[1:]
                else:
                    symbol_list[a][1] = '@'
                    try_bitfield = False

            time_symbols = { }
            for k in symbol_list:
                if symbol_list[k][1]:
                    c = symbol_list[k][0]
                    time_symbols[c] = symbol_list[k][1]

            symbol_set = '%^&*()'
            symbols_available = []
            need_abort = False
            for c in symbol_set:
                symbols_available.append(c)
            print('sls1:', symbol_list )
            for k in symbol_list:
                if not symbol_list[k][1]:
                    t = symbol_list[k][0]
                    if t in time_symbols:
                        symbol_list[k][1] = time_symbols[t]
                        continue
                    if not symbols_available:
                        #raise ValueError( 'Cannot convert pulses to head/key, too many unique pulse/space values' )
                        print( 'Cannot convert pulses to head/key, too many unique pulse/space values' )
                        #return None
                        need_abort = True
                        break
                    s = symbols_available.pop( 0 )
                    symbol_list[k][1] = s
                    time_symbols[t] = s
            print('sls2:', symbol_list )
            if need_abort:
                continue

            print( 'zero:', zero_symbol, 'one:', one_symbol )

            raw_symbol_pattern = ''
            for c in symbol_pattern:
                raw_symbol_pattern += symbol_list[c][1]

            if try_bitfield:
                if offset:
                    c = full_symbol_pattern[0]
                    new_symbol_pattern += symbol_list[c][1]

                bits = data = 0
                byts = []
                for i in range( offset, len(full_symbol_pattern), 2 ):
                    k = full_symbol_pattern[i:i+2]
                    if k == zero_symbol:
                        bits += 1
                        if bits == 8:
                            byts.append( data )
                            bits = data = 0
                    elif k == one_symbol:
                        bits +=	1
                        data |= 1 << (8 - bits)
                        if bits == 8:
                            byts.append( data )
                            bits = data = 0
                    else:
                        if bits or byts:
                            new_symbol_pattern += IRRemoteControlDevice._build_key_bitfield( bits, data, byts )
                        bits = data = 0
                        byts = []

                        for c in k:
                            new_symbol_pattern += symbol_list[c][1]
            else:
                print( 'Not attempting bitfield' )
                new_symbol_pattern = raw_symbol_pattern

            if len(new_symbol_pattern) > len(raw_symbol_pattern):
                print( 'Bitfield pattern is longer than pulse/space symbol lists, using shorter symbol list' )
                new_symbol_pattern = raw_symbol_pattern

            if offset:
                offset_1_shortest = new_symbol_pattern

                offset_1_symbol_list = { }
                for k in symbol_list:
                    j = symbol_list[k][1]
                    offset_1_symbol_list[j] = symbol_list[k][0]
            else:
                offset_0_shortest = new_symbol_pattern
                offset_0_symbol_list = { }
                for k in symbol_list:
                    j =	symbol_list[k][1]
                    offset_0_symbol_list[j] = symbol_list[k][0]

        if not offset_0_shortest:
            new_symbol_pattern = offset_1_shortest
            new_symbol_list = offset_1_symbol_list
        elif not offset_1_shortest:
            new_symbol_pattern = offset_0_shortest
            new_symbol_list = offset_0_symbol_list
        elif len(offset_0_shortest) < len(offset_1_shortest):
            new_symbol_pattern = offset_0_shortest
            new_symbol_list = offset_0_symbol_list
        else:
            new_symbol_pattern = offset_1_shortest
            new_symbol_list = offset_1_symbol_list

        header = IRRemoteControlDevice._build_head_field( 2, 3800, new_symbol_list )

        print( 'pattern options:', offset_0_shortest, offset_1_shortest )
        print( 'symbol list options:', offset_0_symbol_list, offset_1_symbol_list )
        print( 'new pattern:', header, new_symbol_pattern )
        print( p_key_map )
        print( s_key_map )
        #print( symbol_pattern )
        return header, '001' + new_symbol_pattern

    @staticmethod
    def	_merge_similar_pulse_times( p_count, fudge ):
        p_map = { }
        mod = True
        while mod:
            mod = False
            merge = None
            for p_in in p_count:
                pfudge = p_in * fudge
                pmin = p_in - pfudge
                pmax = p_in + pfudge
                for p_check in p_count:
                    if p_in == p_check:
                        continue
                    if p_check >= pmin and p_check <= pmax:
                        merge = (p_in, p_check)
                        print( 'merging', merge )
                        break
                if merge:
                    break
            if merge:
                mod = True
                a = merge[0]
                b = merge[1]
                new_count = p_count[a] + p_count[b]
                #new_p = round(((p_count[a] * a) + (p_count[b] * b)) / new_count)
                new_p = round((a + b) / 2)
                del p_count[a]
                del p_count[b]
                p_count[new_p] = new_count
                p_map[a] = new_p
                p_map[b] = new_p

        print('final map', p_map)
        return p_map

    @staticmethod
    def pulses_to_space_encoded_head_key( pulses ):
        results = []
        bits = 0
        data = 0
        byts = []
        start_pulse = 0
        start_space = 0
        last_space = 0

        is_pulse = False
        fail_if_again = False
        for p_in in pulses:
            if fail_if_again:
                return None
            is_pulse = not is_pulse
            if is_pulse:
                print( 'p', p_in )
                if p_in >= 7900 and p_in <= 10100:
                    # NEC protocol start pulse
                    if start_pulse > 0:
                        if not start_space:
                            return None
                        bits2 = (len(byts) * 8) + bits
                        if bits2 == 0 and start_space == 2250:
                            # repeat code
                            pass
                        elif bits2 < 8 or bits2 > 100:
                            return None
                        results.append( (start_pulse, start_space, byts, bits, data, last_space) )
                    start_pulse = 9000
                    bits = data = start_space = last_space = 0
                    byts = []
                elif p_in >= 3400 and p_in <= 5600:
                    # Samsung procol start pulse
                    if start_pulse > 0:
                        if not start_space:
                            return None
                        bits2 = (len(byts) * 8) + bits
                        if bits2 == 0 and start_space == 2250:
                            # repeat code
                            pass
                        elif bits2 < 8 or bits2 > 100:
                            return None
                        results.append( (start_pulse, start_space, byts, bits, data, last_space) )
                    start_pulse = 4500
                    bits = data = start_space = last_space = 0
                    byts = []
                elif p_in > 665 or p_in < 400:
                    # not NEC/Samsung
                    return None
                elif start_space == 0:
                    # not NEC/Samsung
                    return None
            else: # not is_pulse
                print( 's', p_in )
                if start_space == 0:
                    if p_in >= 3400 and p_in <= 5600:
                        # normal start space
                        start_space = 4500
                    elif p_in >= 1150 and p_in <= 3350:
                        # repeat code
                        start_space = 2250
                    else:
                        # not NEC/Samsung
                        return None
                else:
                    if p_in > 3350:
                        # gap between transmissions
                        if start_pulse > 0:
                            if not start_space:
                                return None
                            bits2 = (len(byts) * 8) + bits
                            #if bits2 < 8 or bits2 > 100:
                            #    return None
                            results.append( (start_pulse, start_space, byts, bits, data, last_space) )
                            start_pulse = 9000
                            bits = data = start_space = last_space = 0
                            byts = []
                    elif p_in >= 400 and p_in <= 665:
                        # zero
                        bits += 1
                        if bits == 8:
                            byts.append(data)
                            bits = data = 0
                    elif p_in >= 1400 and p_in <= 1800:
                        # one
                        bits += 1
                        data |= (1 << (8 - bits))
                        if bits == 8:
                            byts.append(data)
                            bits = data = 0
                    else:
                        fail_if_again = True
        if start_pulse > 0:
            if not start_space:
                return None
            bits2 = (len(byts) * 8) + bits
            if bits2 == 0 and start_space == 2250:
                # repeat code
                pass
            elif bits2 < 8 or bits2 > 100:
                return None
            results.append( (start_pulse, start_space, byts, bits, data, last_space) )

        if not results:
            return None

        count = -1
        for r in results:
            count += 1
            if count == 0:
                continue
            # make sure start pulse is the same
            if r[0] != results[0][0]:
                return None

        result_string = ''
        symbols = { results[0][0]: '%', 4500: '^', 2250: '&', results[0][5]: '*' }
        for r in results:
            if r[0] not in symbols or r[1] not	in symbols:
                return None
            result_string += symbols[r[0]] + symbols[r[1]]
            result_string += IRRemoteControlDevice._build_key_bitfield( r[3], r[4], r[2] )
            result_string += '@*'

        return result_string

    @staticmethod
    def _build_key_bitfield( bits, bitdata, byts ):
        numbits = bits + (len(byts) * 8)
        result_string = '%02X%02X' % (0, numbits)
        for b in byts:
            result_string += '%02X' % b
        if bits:
            result_string += '%02X' % bitdata
        print('bitfield:', result_string)
        return result_string

    @staticmethod
    def _build_head_field( typ, freq, symbol_list ):
        max_symbol = 0
        for c in symbol_list:
            i = IRRemoteControlDevice.KEY1_SYMBOL_LIST.index( c )
            if i >= max_symbol:
                max_symbol = i + 1

        time_base = (100000 / freq)
        print(time_base)

        # 02 0ed8 0000 0000 0007 00100014001500380026009a013c
        header = '%02x%04x%04x%04x%04x' % (typ, freq, 0, 0, max_symbol)
        for i in range( max_symbol ):
            k = IRRemoteControlDevice.KEY1_SYMBOL_LIST[i]
            print( k, symbol_list[k], time_base, round(symbol_list[k] / time_base))
            header += '%04x' % round(symbol_list[k] / time_base)

        return header

    @staticmethod
    def hex_to_pulses( code_hex ):
        raw_bytes = bytes.fromhex(code_hex)
        return [int.from_bytes(raw_bytes[x:x+2], byteorder="little") for x in range(0, len(raw_bytes), 2)]

    @staticmethod
    def pulses_to_hex( pulses ):
        return "".join([f"{((x >> 8) | (x << 8)) & 0xFFFF:04x}" for x in pulses])

    @staticmethod
    def width_encoded_to_pulses( uint32, start_mark=9000, start_space=4500, pulse_one=563, pulse_zero=563, space_one=1688, space_zero=563, trailing_pulse=563, trailing_space=30000 ):
        pulses = [ start_mark, start_space ]
        one = [ pulse_one, space_one ]
        zero =  [ pulse_zero, space_zero ]
        for i in range(31, -1, -1):
            pulses += one if uint32 & (1 << i) else zero
        pulses.append( trailing_pulse )
        pulses.append( trailing_space )
        return pulses

    @staticmethod
    def pulses_to_width_encoded( pulses, start_mark=None, start_space=None, pulse_threshold=None, space_threshold=None ):
        ret = [ ]
        if len(pulses) < 68:
            log.debug('Length of pulses must be a multiple of 68! (2 start + 64 data + 2 trailing)')
            return ret
        if (pulse_threshold is None) and (space_threshold is None):
            log.debug('"pulse_threshold" and/or "space_threshold" must be supplied!')
            return ret

        if start_mark is not None:
            while( len(pulses) >= 68 and (pulses[0] < (start_mark * 0.75) or pulses[0] > (start_mark * 1.25)) ):
                pulses = pulses[1:]

        while( len(pulses) >= 68 ):
            if start_mark is not None:
                if pulses[0] < (start_mark * 0.75) or pulses[0] > (start_mark * 1.25):
                    log.debug('The start mark is not the correct length')
                    return ret
            if start_space is not None:
                if pulses[1] < (start_space * 0.75) or pulses[1] > (start_space * 1.25):
                    log.debug('The start space is not the correct length')
                    return ret

            pulses = pulses[2:]
            uint32 = 0

            for i in range(31, -1, -1):
                pulse_match = space_match = None
                if pulse_threshold is not None:
                    if pulses[0] >= pulse_threshold:
                        pulse_match = 1
                    else:
                        pulse_match = 0

                if space_threshold is not None:
                    if pulses[1] >= space_threshold:
                        space_match = 1
                    else:
                        space_match = 0

                if (pulse_match is not None) and (space_match is not None):
                    if pulse_match != space_match:
                        log.debug('Both "pulse_threshold" and "space_threshold" are supplied and bit %d conflicts with both!' % i)
                        return ret
                    res = space_match
                elif pulse_match is None:
                    res = space_match
                else:
                    res = pulse_match

                uint32 |= res << i
                pulses = pulses[2:]

            pulses = pulses[2:]

            if ret is None:
                ret = [ uint32 ]
            elif uint32 not in ret:
                ret.append( uint32 )

        return ret

    @staticmethod
    def _mirror_bits( data, bits=8 ):
        shift = bits - 1
        out = 0
        for i in range(bits):
            if data & (1 << i):
                out |= 1 << shift
            shift -= 1
        return out

    @staticmethod
    def nec_to_pulses( address, data=None ):
        # address can be 8-bit or 16-bit
        # if 8, it is repeated after complementing (just like the data)
        if data is None:
            uint32 = address
        else:
            if address < 256:
                address = IRRemoteControlDevice._mirror_bits(address)
                address = (address << 8) | (address ^ 0xFF)
            else:
                address = (IRRemoteControlDevice._mirror_bits( (address >> 8) & 0xFF) << 8) | IRRemoteControlDevice._mirror_bits(address & 0xFF)
            data = IRRemoteControlDevice._mirror_bits(data)
            data = (data << 8) | (data ^ 0xFF)
            uint32 = (address << 16) | data
        return IRRemoteControlDevice.width_encoded_to_pulses( uint32 )

    @staticmethod
    def pulses_to_nec( pulses ):
        ret = [ ]
        res = IRRemoteControlDevice.pulses_to_width_encoded( pulses, start_mark=9000, space_threshold=1125 )
        for code in res:
            addr = IRRemoteControlDevice._mirror_bits((code >> 24) & 0xFF)
            addr_not = IRRemoteControlDevice._mirror_bits((code >> 16) & 0xFF)
            data = IRRemoteControlDevice._mirror_bits((code >> 8) & 0xFF)
            data_not = IRRemoteControlDevice._mirror_bits(code & 0xFF)
            # if the address is 8-bit, it is repeated after complementing (just like the data)
            if addr != (addr_not ^ 0xFF):
                addr = (addr << 8) | addr_not
            d = { 'type': 'nec', 'uint32': code, 'address': None, 'data': None, 'hex': '%08X' % code }
            if data == (data_not ^ 0xFF):
                d['address'] = addr
                d['data'] = data
            ret.append(d)
        return ret

    @staticmethod
    def samsung_to_pulses( address, data=None ):
        if data is None:
            uint32 = address
        else:
            address = IRRemoteControlDevice._mirror_bits(address)
            data = IRRemoteControlDevice._mirror_bits(data)
            uint32 = (address << 24) + (address << 16) + (data << 8) + (data ^ 0xFF)
        return IRRemoteControlDevice.width_encoded_to_pulses( uint32, start_mark=4500 )

    @staticmethod
    def pulses_to_samsung( pulses ):
        ret = [ ]
        res = IRRemoteControlDevice.pulses_to_width_encoded( pulses, start_mark=4500, space_threshold=1125 )
        for code in res:
            addr = (code >> 24) & 0xFF
            addr_not = (code >> 16) & 0xFF
            data = (code >> 8) & 0xFF
            data_not = code & 0xFF
            d = { 'type': 'samsung', 'uint32': code, 'address': None, 'data': None, 'hex': '%08X' % code }
            # samsung repeats the 8-bit address but complements the 8-bit data
            if addr == addr_not and data == (data_not ^ 0xFF):
                d['address'] = IRRemoteControlDevice._mirror_bits(addr)
                d['data'] = IRRemoteControlDevice._mirror_bits(data)
            ret.append(d)
        return ret

    @staticmethod
    def pronto_to_pulses( pronto ):
        ret = [ ]
        pronto = [int(x, 16) for x in pronto.split(' ')]
        ptype = pronto[0]
        timebase = pronto[1]
        pair1_len = pronto[2]
        pair2_len = pronto[3]
        if ptype != 0:
            # only raw (learned) codes are handled
            return ret
        if timebase < 90 or timebase > 139:
            # only 38 kHz is supported?
            return ret
        pronto = pronto[4:]
        timebase *= 0.241246
        for i in range(0, pair1_len*2, 2):
            ret += [round(pronto[i] * timebase), round(pronto[i+1] * timebase)]
        pronto = pronto[pair1_len*2:]
        for i in range(0, pair2_len*2, 2):
            ret += [round(pronto[i] * timebase), round(pronto[i+1] * timebase)]
        return ret

    @staticmethod
    def pulses_to_pronto( pulses ):
        # only 38 kHz is supported?
        freq = 38000.0
        scale = (1 / freq) * 1000000.0
        ret = '%04X %04X %04X %04X' % (0, round(scale/0.241246), 0, len(pulses) >> 1)
        for i in pulses:
            ret += ' %04X' % round(i/scale)
        return ret
