# TinyTuya Contrib IRRemoteControlDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart universal remote control simulators

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Module Author: Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)

 Local Control Classes
    IRRemoteControlDevice(dev_id, address, local_key=None, dev_type='default', persist=True)
        This class automatically sets the version to 3.3

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

    def __init__(self, dev_id, address, local_key="", dev_type="default", persist=True):
        super(IRRemoteControlDevice, self).__init__(dev_id, address, local_key, dev_type)
        self.set_version(3.3)

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
