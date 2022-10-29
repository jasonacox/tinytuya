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
