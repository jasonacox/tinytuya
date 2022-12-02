# TinyTuya Contrib IRRemoteControlDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart universal remote control simulators

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Module Author: Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)
 Rewritten by uzlonewolf (https://github.com/uzlonewolf) for new devices and IR format conversion

 Local Control Classes
    IRRemoteControlDevice(..., version=3.3)
        This class uses a default version of 3.3
        See OutletDevice() for the other constructor arguments

    Functions:
        ir = IRRemoteControlDevice(..., control_type=None)
            -> will immediately connect to the device to try and detect the control type if control_type is not provided
               control_type=1 for older devices using DPS 201/202
               control_type=2 for newer devices using DPS 1-13

        ir.detect_control_type()
            -> polls device status to try and detect the control type

        ir.send_command( mode, data={} )
            -> sends a command to the device
               when mode is 'send', data is parsed for the data to send
                   data = { "base64_code": "..." } or
                   data = { "head": "...", "key": "..." }
               all other commands are sent though as-is without data

        ir.study_start()
        ir.study_end()
            -> start or end a study session

        ir.receive_button( timeout )
            -> call this method and press button on real remote control to read its code in Base64 format
               timeout - maximum time to wait for button press

        ir.send_button( base64_code )
            -> simulate a learned (raw base64-encoded) button press

        ir.send_key( head, key )
            -> send a head/key pair

        ir.build_head( freq=38, bit_time=0, zero_time=0, one_time=0, bit_time_type=1, timings=[], convert_time=True )
            -> build a 'head' section
               'freq' is in kHz
               if bit_time, zero_time, or one_time evaluate to False, timings are taken from timings[] as needed
               if convert_time is True, timings are in microseconds and converted as needed.
                   when False, timings are sent as-is

        IRRemoteControlDevice.print_pulses ( pulses )
            -> pretty-print a sequence of pulses and gaps length

        IRRemoteControlDevice.base64_to_pulses ( code_base_64 )
            -> convert Base64-encoded button code to sequence of pulses and gaps length

        IRRemoteControlDevice.pulses_to_base64 ( pulses )
            -> convert sequence of pulses and gaps length to Base64-encoded button code

        IRRemoteControlDevice.head_key_to_pulses ( head='...', key='...' )
            -> convert head/key pair to sequence of pulses and gaps
               'head' can be None when the key is raw bytes in base64
               'key' must begin with '00' through 'FF' when it is not raw bytes in base64

        IRRemoteControlDevice.pulses_to_head_key ( pulses, fudge=0.1, freq=38 )
            -> attempts to pack a sequence of pulses and gaps into a head/key pair
               pulses/gaps within 10% (fudge=0.1) are assumed to be the same and are merged together

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
import time
from math import ceil, floor

from ..core import Device, log, CONTROL

class IRRemoteControlDevice(Device):
    CMD_SEND_KEY_CODE =	"send_ir"  # Command to start sending a key
    DP_SEND_IR        = "201"       # ir_send, send and report (read-write)
    DP_LEARNED_ID     = "202"       # ir_study_code, report only (read-only)
    DP_MODE           =   "1"
    DP_LEARNED_REPORT =   "2"
    DP_HEAD           =   "3"
    DP_KEY_CODE       =   "4"
    DP_KEY_CODE2      =   "5"
    DP_KEY_CODE3      =   "6"
    DP_KEY_CODE4      =  "11"
    DP_KEY_STUDY      =   "7"
    DP_KEY_STUDY2     =   "8"
    DP_KEY_STUDY3     =   "9"
    DP_KEY_STUDY4     =  "12"
    DP_SEND_DELAY     =  "10"
    DP_CODE_TYPE      =  "13"
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
    KEY1_SYMBOL_LIST = "@#$%^&*()QWRLTXKVNM{}[]JUP<>|=HS~" # Timing symbols used in key1

    def __init__(self, *args, **kwargs):
        # set the default version to 3.3 as there are no 3.1 devices
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.3

        control_type = 0
        if 'control_type' in kwargs:
            control_type = kwargs['control_type']
            del kwargs['control_type']

        super(IRRemoteControlDevice, self).__init__(*args, **kwargs)

        self.disabledetect = True
        self.control_type = control_type
        if not self.control_type:
            self.detect_control_type()

    def detect_control_type( self ):
        # This is more difficult than it seems.  Neither device responds to status() after
        #   a reboot until after a command is sent.  201 devices do not respond to study_end
        #   if they are already in that mode.
        old_timeout = self.connection_timeout
        old_persist = self.socketPersistent
        self.set_socketTimeout( 1 )
        self.set_socketPersistent( True )
        self.control_type = 1
        self.study_end()
        self.control_type = 2
        self.study_end()
        self.control_type = 0
        status = self.status()
        while status:
            if status and 'dps' in status:
                # original devices using DPS 201/202
                if self.DP_SEND_IR in status['dps']:
                    log.debug( 'Detected control type 1' )
                    self.control_type = 1
                    break
                # newer devices using DPS 1-13
                elif self.DP_MODE in status['dps']:
                    log.debug( 'Detected control type 2' )
                    self.control_type = 2
                    break
            status = self._send_receive(None)
        if not self.control_type:
            log.warning( 'Detect control type failed! control_type= must be set manually' )
        elif status:
            # try and make sure no data is waiting to be read
            status = self._send_receive(None)
        self.set_socketTimeout( old_timeout )
        self.set_socketPersistent( old_persist )

    def send_command( self, mode, data={} ):
        if mode == 'send':
            if self.control_type == 1:
                command = {
                    IRRemoteControlDevice.NSDP_CONTROL: "send_ir",
                    IRRemoteControlDevice.NSDP_TYPE: 0,
                }

                if 'base64_code' in data:
                    command[IRRemoteControlDevice.NSDP_HEAD] = ''
                    command[IRRemoteControlDevice.NSDP_KEY1] = '1' + data['base64_code']
                elif 'head' in data and 'key' in data:
                    command[IRRemoteControlDevice.NSDP_HEAD] = data['head']
                    command[IRRemoteControlDevice.NSDP_KEY1] = '0' + data['key']
                self.set_value( IRRemoteControlDevice.DP_SEND_IR, json.dumps(command), nowait=True )
            elif self.control_type == 2:
                mode = 'study_key' if 'base64_code' in data else 'send_ir'
                command = {
                    IRRemoteControlDevice.DP_MODE: mode,
                    IRRemoteControlDevice.DP_CODE_TYPE: 0,
                }
                if 'base64_code' in data:
                    command[IRRemoteControlDevice.DP_KEY_STUDY] = data['base64_code']
                elif 'head' in data and 'key' in data:
                    command[IRRemoteControlDevice.DP_HEAD] = data['head']
                    command[IRRemoteControlDevice.DP_KEY_CODE] = data['key']
                self.set_multiple_values( command, nowait=True )
        elif self.control_type == 1:
            command = { IRRemoteControlDevice.NSDP_CONTROL: mode }
            self.set_value( IRRemoteControlDevice.DP_SEND_IR, json.dumps(command), nowait=True )
        elif self.control_type == 2:
            self.set_value( IRRemoteControlDevice.DP_MODE, mode, nowait=True )

    def study_start( self ):
        self.send_command( 'study' )

    def	study_end( self ):
        self.send_command( 'study_exit' )

    def receive_button( self, timeout=30 ):
        log.debug("Receiving button")
        # Exit study mode in case it's enabled
        self.study_end()
        # Enable study mode
        self.study_start()

        # Receiving button code
        response = None
        response_code = None
        found = False
        # Remember old timeout and set new timeout
        old_timeout = self.connection_timeout
        end_at_time = time.time() + timeout
        try:
            while end_at_time > time.time():
                timeo = round(time.time() - end_at_time)
                if timeo < 1: timeo = 1
                self.set_socketTimeout(timeo)

                log.debug("Waiting for button...")
                response = self._send_receive(None)
                if response == None:
                    # Nothing received
                    log.debug("Timeout")
                elif type(response) != dict or "dps" not in response:
                    # Some unexpected result
                    log.debug("Unexpected response: %r", response)
                    response_code = response # Some error message? Pass it.
                    break
                elif self.DP_LEARNED_ID in response["dps"]:
                    # Button code received, extracting it as Base64 string
                    response_code = response["dps"][self.DP_LEARNED_ID]
                    found = True
                    break
                elif self.DP_LEARNED_REPORT in response["dps"]:
                    response_code = response["dps"][self.DP_LEARNED_REPORT]
                    found = True
                    break
                else:
                    # Unknown DPS
                    log.debug("Unknown DPS in response: %r", response)
                    response_code = response # Pass it if we do not get a response we like
                    # try again
        finally:
            # Revert timeout
            self.set_socketTimeout(old_timeout)

        if found:
            self.print_pulses( response_code )

        # Exit study mode
        self.study_end()

        return response_code

    def send_button( self, base64_code ):
        log.debug( 'Sending Learned Button: ' + base64_code)
        self.print_pulses( base64_code )
        return self.send_command( 'send', {'base64_code': base64_code} )

    def send_key( self, head, key ):
        log.debug( 'Sending Key: %r / %r', head, key )
        return self.send_command( 'send', { 'head': head, 'key': key } )

    @staticmethod
    def build_head( freq=38, bit_time=0, zero_time=0, one_time=0, bit_time_type=1, timings=[], convert_time=True ):
        timings = list(timings)
        freq =	round( freq * 100)
        if not bit_time and len(timings) > 0:
            bit_time = timings[0]
            timings = timings[1:]
        if not zero_time and len(timings) > 0:
            zero_time = timings[0]
            timings = timings[1:]
        if not one_time and len(timings) > 0:
            one_time = timings[0]
            timings = timings[1:]

        if convert_time:
            time_base = 100000.0 / freq
            bit_time = round( bit_time / time_base )
            zero_time = round( zero_time / time_base )
            one_time = round( one_time / time_base )
            for i in range(len(timings)):
                timings[i] = round( timings[i] / time_base )

        head = '%02X%04X0000000000' % (bit_time_type, freq)
        head += '%02X%04X%04X%04X' % (len(timings) + 3, bit_time, zero_time, one_time)
        for i in timings:
            head += '%04X' % i

        return head

    @staticmethod
    def print_pulses( base64_code, use_log=None ):
        if not use_log: use_log = log
        if type(base64_code) == list:
            pulses = base64_code
        else:
            pulses = IRRemoteControlDevice.base64_to_pulses(base64_code)
        message = "Pulses and gaps (microseconds): " + ' '.join([f'{"p" if i % 2 == 0 else "g"}{pulses[i]}' for i in range(len(pulses))])
        if log.getEffectiveLevel() <= logging.DEBUG:
            log.debug( message )
        return message

    @staticmethod
    def base64_to_pulses( code_base_64 ):
        if len(code_base_64) % 4 == 1 and code_base_64.startswith("1"):
            # code can be padded with "1"
            code_base_64 = code_base_64[1:]
        raw_bytes = base64.b64decode(code_base_64)
        fmt = '<%dH' % (len(raw_bytes) >> 1)
        return list(struct.unpack(fmt, raw_bytes))

    @staticmethod
    def pulses_to_base64( pulses ):
        fmt = '<' + str(len(pulses)) + 'H'
        return base64.b64encode( struct.pack(fmt, *pulses) ).decode("ascii")

    @staticmethod
    def head_key_to_pulses( head, key ):
        if len(key) < 4:
            raise ValueError( '"key" must be at least 4 characters' )

        if not head:
            return IRRemoteControlDevice.base64_to_pulses( key )

        if len(head) < 18:
            raise ValueError( '"head" must be at least 18 characters' )

        head = bytearray.fromhex( head )
        headtype, timescale, unused1, unused2, num_timings = struct.unpack( '>BHHHH', head[:9] )
        headlen = num_timings * 2 # times are 16-bit
        timebase = 100000.0 / timescale
        symbols = IRRemoteControlDevice.KEY1_SYMBOL_LIST[:num_timings]
        try:
            repeat = int( key[:2], 16 )
        except:
            raise ValueError( 'First 2 digit of "key" must be a hexidecimal byte' )
        key = key[2:]

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
    def pulses_to_head_key( pulses, fudge=0.1, freq=38 ):
        mylog = log.getChild( 'pulses_to_head_key' )

        if len(pulses) < 2:
            return None

        if len(pulses) % 2 == 1:
            pulses = list(pulses)
            pulses.append(pulses[0])

        ps_count = { }
        for current_ps_time in pulses:
            if current_ps_time not in ps_count:
                ps_count[current_ps_time] = 1
            else:
                ps_count[current_ps_time] += 1
        ps_map = IRRemoteControlDevice._merge_similar_pulse_times( ps_count, fudge )

        # should we process the pulses and spaces separately?
        # combining them seems to give good results
        if False:
            p_count = { }
            s_count = { }
            is_pulse = False
            for current_ps_time in pulses:
                is_pulse = not is_pulse

                if current_ps_time in ps_map:
                    current_ps_time = ps_map[current_ps_time]

                if is_pulse:
                    if current_ps_time not in p_count:
                        p_count[current_ps_time] = 1
                    else:
                        p_count[current_ps_time] += 1
                else:
                    if current_ps_time not in s_count:
                        s_count[current_ps_time] = 1
                    else:
                        s_count[current_ps_time] += 1

            mylog.debug( 'p_count: %r, s_count: %r', p_count, s_count )
            p_map = IRRemoteControlDevice._merge_similar_pulse_times( p_count, fudge )
            s_map = IRRemoteControlDevice._merge_similar_pulse_times( s_count, fudge )
            mylog.debug('merged pulse map: %r', p_map)
            mylog.debug('merged space map: %r', s_map)
        else:
            p_map = s_map = ps_map
            mylog.debug('merged pulse+space map: %r', ps_map)

        # convert the list of pulse and space lengths into a string to
        #  make it easier to group and count unique sequences.
        # the first unique pulse will get the symbol 'A' while
        #  the first space becomes 'a'.  The next is 'B' and 'b'.
        # all pulses/spaces of the same length get the same letter
        # I.e. [ 4523 4523 552 1683 552 1683 552 552 552 552 ] becomes
        #        A    a    B   b    B   b    B   c   B   c   -> AaBbBbBcBc
        # we can then substring count 'Bb' and 'Bc'
        symbol_pattern = ''
        symbol_list = { }
        p_key_map = { }
        s_key_map = { }
        is_pulse = False
        for current_ps_time in pulses:
            is_pulse = not is_pulse
            if is_pulse:
                #if this length was combined, use the new (averaged) value
                k = p_map[current_ps_time] if current_ps_time in p_map else current_ps_time

                # if this length has not been seen yet, assign it a letter
                if k not in p_key_map:
                    next_letter = chr(len(p_key_map) + 0x41) # A-Z
                    #mylog.debug('adding pulse %r %r', k, next_letter)
                    p_key_map[k] = { 'count': 1, 'char': next_letter }
                    if next_letter not in symbol_list:
                        symbol_list[next_letter] = [k, False]
                else:
                    p_key_map[k]['count'] += 1
                symbol_pattern += p_key_map[k]['char']
            else:
                #if this length was combined, use the new (averaged) value
                k = s_map[current_ps_time] if current_ps_time in s_map else current_ps_time

                # if this length has not been seen yet, assign it a letter
                if k not in s_key_map:
                    next_letter = chr(len(s_key_map) + 0x61) # a-z
                    #mylog.debug('adding SPACE %r %r', k, next_letter)
                    s_key_map[k] = { 'count': 1, 'char': next_letter }
                    if next_letter not in symbol_list:
                        symbol_list[next_letter] = [k, False]
                else:
                    s_key_map[k]['count'] += 1
                symbol_pattern += s_key_map[k]['char']

        mylog.debug( 'symbol pattern: %r', symbol_pattern )
        mylog.debug( 'symbol list: %r', symbol_list )

        # find the most-commonly-ocurring pulse and space lengths
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

        k = smax['time']
        space_letter = s_key_map[k]['char']

        k = pmax['time']
        pulse_letter = p_key_map[k]['char']

        mylog.debug( 'most common space: %r %r', space_letter, smax )
        mylog.debug( 'most common pulse: %r %r', pulse_letter, pmax )

        encoding_type_shortest = [None, None]
        encoding_type_symbol_list = [{}, {}]
        bit_time_types = [0, 0]
        # calculate the head and key for both space-width and pulse-width encoding
        # we will use the shorter of the 2 as the final head/key
        for encoding_type in range( 2 ):
            mylog.debug( '' )
            current_letter = pulse_letter if encoding_type == 0 else space_letter
            encoding_type_name = 'pulse' if not encoding_type else 'space'
            mylog.debug( 'Trying encoding_type %r - character %r', encoding_type_name, current_letter )
            pat_counts = {}
            for i in range( encoding_type, len(symbol_pattern), 2 ):
                if symbol_pattern[i] == current_letter:
                    k = symbol_pattern[i:i+2]
                    if len(k) == 2:
                        if k not in pat_counts:
                            pat_counts[k] = 1
                        else:
                            pat_counts[k] += 1

            mylog.debug( 'pat_counts: %r', pat_counts )

            # find the most-common and next-most-common pattern pair
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

            mylog.debug( 'pat_max: %r, pat_next_max: %r', pat_max, pat_next_max)

            # reset from the previous 'encoding_type' loop
            for k in symbol_list:
                symbol_list[k][1] = False

            try_bitfield = True
            bit_symbol_pattern = ''
            full_symbol_pattern = symbol_pattern

            if pat_max[0] and not pat_next_max[0]:
                a = pat_max[1][0]
                symbol_list[a][1] = '@'
                a2 = pat_max[1][1]
                symbol_list[a2][1] = '#'
                zero_symbol = pat_max[1]
                one_symbol = 'DEADBEEF'
            # assign timing symbols to the most-common and next-most-common lengths
            elif pat_max[0] and pat_next_max[0]:
                a = pat_max[1][0]
                b = pat_next_max[1][0]
                if symbol_list[a][0] == symbol_list[b][0]:
                    # pulses are the same, it might be space-width encoded
                    symbol_list[a][1] = symbol_list[b][1] = '@'
                    a2 = pat_max[1][1]
                    b2 = pat_next_max[1][1]
                    if symbol_list[a2][0] < symbol_list[b2][0]:
                        symbol_list[a2][1] = '#'
                        symbol_list[b2][1] = '$'
                        zero_symbol = pat_max[1]
                        one_symbol = pat_next_max[1]
                    else:
                        symbol_list[a2][1] = '$'
                        symbol_list[b2][1] = '#'
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
                        bit_symbol_pattern = symbol_pattern[0]
                        full_symbol_pattern = symbol_pattern[1:]
                    else:
                        symbol_list[a][1] = '@'
                        try_bitfield = False

            mylog.debug('initial symbol list: %r', symbol_list)

            # if the common length and the zero length are the same, combine them as 'head type 1'
            # first find the symbols for '@' and '#'
            bit_start_symbol = bit_zero_symbol = None
            for k in symbol_list:
                if symbol_list[k][1] == '@':
                    bit_start_symbol = k
                elif symbol_list[k][1] == '#':
                    bit_zero_symbol = k

            # they are the same, combine them into 'head type 1'
            if bit_start_symbol and bit_zero_symbol and symbol_list[bit_start_symbol][0] == symbol_list[bit_zero_symbol][0]:
                bit_time_types[encoding_type] = 1
                symbols_available = list(IRRemoteControlDevice.KEY1_SYMBOL_LIST[2:])
                symbol_list[bit_zero_symbol][1] = '@'
                for k in symbol_list:
                    if symbol_list[k][1] == '$':
                        symbol_list[k][1] = '#'
            # they are different, use 'head type 2'
            else:
                bit_time_types[encoding_type] = 2
                symbols_available = list(IRRemoteControlDevice.KEY1_SYMBOL_LIST[2:])

            # start assigning times to symbols
            # the common/0/1 symbols were already set above
            time_symbols = { }
            for k in symbol_list:
                if symbol_list[k][1]:
                    c = symbol_list[k][0]
                    time_symbols[c] = symbol_list[k][1]

            # assign symbols to the remaining pulse/space times
            need_abort = False
            mylog.debug('symbol list before assignment: %r', symbol_list )
            for k in symbol_list:
                if not symbol_list[k][1]:
                    t = symbol_list[k][0]
                    if t in time_symbols:
                        symbol_list[k][1] = time_symbols[t]
                        continue
                    if not symbols_available:
                        #raise ValueError( 'Cannot convert pulses to head/key, too many unique pulse/space values' )
                        mylog.debug( 'Cannot convert pulses to head/key, too many unique pulse/space values!' )
                        #return None
                        need_abort = True
                        break
                    s = symbols_available.pop( 0 )
                    symbol_list[k][1] = s
                    time_symbols[t] = s
            mylog.debug('symbol list after assignment:  %r', symbol_list )
            mylog.debug('unique time symbols: %r', time_symbols)
            if need_abort:
                mylog.debug('!! need_abort !!')
                continue

            mylog.debug( 'zero sequence: %r, one sequence: %r', zero_symbol, one_symbol )

            raw_symbol_pattern = ''
            for c in symbol_pattern:
                raw_symbol_pattern += symbol_list[c][1]
            mylog.debug( 'raw symbol pattern: %r', raw_symbol_pattern )

            # see if we can condense bitfields into len+data
            if try_bitfield:
                if encoding_type:
                    c = full_symbol_pattern[0]
                    bit_symbol_pattern += symbol_list[c][1]

                bits = data = 0
                byts = []
                removed = ''
                # the len+2 is to make sure we catch any trailing bits
                for i in range( encoding_type, len(full_symbol_pattern)+2, 2 ):
                    k = full_symbol_pattern[i:i+2]
                    k_symbol_pattern = ''
                    for c in k:
                        k_symbol_pattern += symbol_list[c][1]
                    if k == zero_symbol:
                        removed += k_symbol_pattern
                        bits += 1
                        if bits == 8:
                            byts.append( data )
                            bits = data = 0
                    elif k == one_symbol:
                        removed += k_symbol_pattern
                        bits +=	1
                        data |= 1 << (8 - bits)
                        if bits == 8:
                            byts.append( data )
                            bits = data = 0
                    else:
                        if bits or byts:
                            new_bitfield = IRRemoteControlDevice._build_key_bitfield( bits, data, byts )
                            # if the new bitfield is longer than the original timing symbols, don't use it
                            if len(new_bitfield) < len(removed):
                                bit_symbol_pattern += new_bitfield
                            else:
                                bit_symbol_pattern += removed
                        bits = data = 0
                        byts = []
                        removed = ''
                        bit_symbol_pattern += k_symbol_pattern
                mylog.debug( 'bit symbol pattern: %r', bit_symbol_pattern )

                # this should not be needed due to the check in the loop above, but make sure anyway
                if len(bit_symbol_pattern) > len(raw_symbol_pattern):
                    mylog.debug( 'Bitfield pattern is longer than pulse/space symbol lists, using shorter symbol list' )
                    bit_symbol_pattern = raw_symbol_pattern
            else:
                mylog.debug( 'Not attempting bitfield' )
                bit_symbol_pattern = raw_symbol_pattern

            # save the results to see which one is better
            encoding_type_shortest[encoding_type] = bit_symbol_pattern
            encoding_type_symbol_list[encoding_type] = { }
            for k in symbol_list:
                j = symbol_list[k][1]
                encoding_type_symbol_list[encoding_type][j] = symbol_list[k][0]

        mylog.debug( '' )

        if not encoding_type_shortest[0]:
            key1 = encoding_type_shortest[1]
            new_symbol_list = encoding_type_symbol_list[1]
            bit_time_type = bit_time_types[1]
        elif not encoding_type_shortest[1]:
            key1 = encoding_type_shortest[0]
            new_symbol_list = encoding_type_symbol_list[0]
            bit_time_type = bit_time_types[0]
        elif len(encoding_type_shortest[0]) <= len(encoding_type_shortest[1]):
            key1 = encoding_type_shortest[0]
            new_symbol_list = encoding_type_symbol_list[0]
            bit_time_type = bit_time_types[0]
        else:
            key1 = encoding_type_shortest[1]
            new_symbol_list = encoding_type_symbol_list[1]
            bit_time_type = bit_time_types[1]
        #mylog.debug(new_symbol_list)

        # copy over the symbol times, making sure they're in the correct order
        time_symbols = []
        for c in IRRemoteControlDevice.KEY1_SYMBOL_LIST:
            if c in new_symbol_list:
                time_symbols.append( new_symbol_list[c] )
            elif len(time_symbols) < 3:
                time_symbols.append( 100 )
            else:
                break

        header = IRRemoteControlDevice.build_head( freq=freq, bit_time_type=bit_time_type, timings=time_symbols )

        mylog.debug( 'Space-Width Encoded: %r Timings: %r', encoding_type_shortest[0], encoding_type_symbol_list[0] )
        mylog.debug( 'Pulse-Width Encoded: %r Timings: %r', encoding_type_shortest[1], encoding_type_symbol_list[1] )
        mylog.debug( 'new pattern: %r / %r', header, key1 )
        mylog.debug( p_key_map )
        mylog.debug( s_key_map )
        #mylog.debug( symbol_pattern )
        return header, '01' + key1

    @staticmethod
    def	_merge_similar_pulse_times( p_count, fudge ):
        p_map = { }
        mod = True
        while mod:
            mod = False
            merge = None
            for current_ps_time in p_count:
                pfudge = current_ps_time * fudge
                pmin = current_ps_time - pfudge
                pmax = current_ps_time + pfudge
                for p_check in p_count:
                    if current_ps_time == p_check:
                        continue
                    if p_check >= pmin and p_check <= pmax:
                        merge = (current_ps_time, p_check)
                        #print( 'merging', merge )
                        break
                    #else:
                    #    print('not merging, pmin < p_check < pmax', pmin, p_check, pmax)
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
                for i in p_map:
                    if p_map[i] == a or p_map[i] == b:
                        p_map[i] = new_p

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
        for current_ps_time in pulses:
            if fail_if_again:
                return None
            is_pulse = not is_pulse
            if is_pulse:
                print( 'p', current_ps_time )
                if current_ps_time >= 7900 and current_ps_time <= 10100:
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
                elif current_ps_time >= 3400 and current_ps_time <= 5600:
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
                elif current_ps_time > 665 or current_ps_time < 400:
                    # not NEC/Samsung
                    return None
                elif start_space == 0:
                    # not NEC/Samsung
                    return None
            else: # not is_pulse
                print( 's', current_ps_time )
                if start_space == 0:
                    if current_ps_time >= 3400 and current_ps_time <= 5600:
                        # normal start space
                        start_space = 4500
                    elif current_ps_time >= 1150 and current_ps_time <= 3350:
                        # repeat code
                        start_space = 2250
                    else:
                        # not NEC/Samsung
                        return None
                else:
                    if current_ps_time > 3350:
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
                    elif current_ps_time >= 400 and current_ps_time <= 665:
                        # zero
                        bits += 1
                        if bits == 8:
                            byts.append(data)
                            bits = data = 0
                    elif current_ps_time >= 1400 and current_ps_time <= 1800:
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
        #print('bitfield:', result_string)
        return result_string

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

    @staticmethod
    def pronto_to_head_key( pronto ):
        ret = [ ]
        pronto = [int(x, 16) for x in pronto.split(' ')]
        ptype = pronto[0]
        timebase = pronto[1]
        pair1_len = pronto[2]
        pair2_len = pronto[3]
        if ptype != 0:
            # only raw (learned) codes are handled
            return None

        # 4,145,152 is 32,768 * 506 / 4
        freq = round(4145152.0 / timebase / 100) / 10

        pronto = pronto[4:]
        timebase *= 0.241246
        for i in range(0, pair1_len*2, 2):
            ret += [round(pronto[i] * timebase), round(pronto[i+1] * timebase)]
        pronto = pronto[pair1_len*2:]
        for i in range(0, pair2_len*2, 2):
            ret += [round(pronto[i] * timebase), round(pronto[i+1] * timebase)]

        return IRRemoteControlDevice.pulses_to_head_key( ret, freq=freq )
