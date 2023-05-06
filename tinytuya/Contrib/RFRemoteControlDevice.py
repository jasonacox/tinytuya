# TinyTuya Contrib RFRemoteControlDevice Module
# -*- coding: utf-8 -*-
"""
 A community-contributed Python module to add support for Tuya WiFi smart universal RF remote controller

 This module attempts to provide everything needed so there is no need to import the base tinytuya module

 Module Author: uzlonewolf (https://github.com/uzlonewolf)
 Based on IRRemoteControlDevice by Alexey 'Cluster' Avdyukhin (https://github.com/clusterm)

 Local Control Classes
    RFRemoteControlDevice(..., version=3.3)
        This class uses a default version of 3.3
        See OutletDevice() for the other constructor arguments

    Functions:
        rf = RFRemoteControlDevice(..., control_type=None)
            -> will immediately connect to the device to try and detect the control type if control_type is not provided
               control_type=1 for older devices using DPS 201/202
               control_type=2 for newer devices using DPS 1-13

        rf.send_command( mode, data={} )
            -> sends a command to the device
               IRRemoteControlDevice.send_command() is used when mode is not 'rf_study', 'rfstudy_exit', 'rfstudy_send',
                   'rf_shortstudy', 'rfshortstudy_exit', or 'send_cmd'

        rf.rf_study_start( freq=0, short=False )
        rf.rf_study_end( freq=0, short=False )
            -> start or end a study session
               freq=0 auto-detects the frequency, or it can be specified as i.e. freq="433.92" or freq="315"
               when sort=True, 'rf_shortstudy' is used instead of 'rf_study'

        rf.rf_receive_button( freq=0, timeout )
            -> call this method and press button on real remote control to read its code in Base64 format
               freq - 0 to auto-detect
               timeout - maximum time to wait for button press

        rf.rf_send_button( base64_code, times=6, delay=0, intervals=0 )
            -> send a learned (raw base64-encoded) button press

        rf.rf_send_key( keys, cmt_bank, system_bank, frequency_bank, datarate_bank, baseband_bank, tx_bank, mode=8, freq=0, rate=0 )
            -> send pre-defined key(s)
               The *_bank values are directly copied from CMOSTEK's RFPDK software (select chip "CMT2300A")
              'keys' can be:
                  a dict containing 'code', 'delay', 'intervals', and  'times'
                  a single hex string
                  a list or tuple containing dicts or hex strings

        RFRemoteControlDevice.rf_print_button( base64_code )
            -> prints and returns the JSON dict as a string from a base64-encoded learned button
                the base64 string is base64 decoded but not JSON parsed

        RFRemoteControlDevice.rf_decode_button( base64_code )
            -> returns the JSON dict as a dict from a base64-encoded learned button
                the base64 string is base64 decoded and then JSON parsed

"""

import base64
import json
import logging
import struct
import time

from ..core import log, CONTROL
from .IRRemoteControlDevice import IRRemoteControlDevice

# extends IRRemoteControlDevice
class RFRemoteControlDevice(IRRemoteControlDevice):
    def send_command( self, mode, data={} ):
        if( mode in ('rf_study', 'rfstudy_exit', 'rfstudy_send', 'rf_shortstudy', 'rfshortstudy_exit') ):
            if 'rf_type' not in data or not data['rf_type']:
                data['rf_type'] = 'sub_2g'
            if 'freq' not in data or not data['freq']:
                data['freq'] = '0'
            if 'ver' not in data or not data['ver']:
                data['ver'] = '2'
            command = { RFRemoteControlDevice.NSDP_CONTROL: mode, 'rf_type': data['rf_type'], 'study_feq': data['freq'], 'ver': data['ver'] }
            if mode == 'rfstudy_send':
                for i in range( 1, 10 ):
                    k = 'key%d' % i
                    if k in data:
                        command[k] = data[k]
            self.set_value( RFRemoteControlDevice.DP_SEND_IR, json.dumps(command), nowait=True )
        elif mode == 'send_cmd':
            data[RFRemoteControlDevice.NSDP_CONTROL] = mode
            self.set_value( RFRemoteControlDevice.DP_SEND_IR, json.dumps(data), nowait=True )
        else:
            super(RFRemoteControlDevice, self).send_command( mode, data )

    def rf_study_start( self, freq=0, short=False ):
        # {"dps":{"201":"{\"rf_type\":\"sub_2g\",\"control\":\"rf_study\",\"study_feq\":\"433\",\"ver\":\"2\"}"}
        data = { 'freq': str(freq) }
        cmd = 'rf_shortstudy' if short else 'rf_study'
        self.send_command( cmd, data )

    def rf_study_end( self, freq=0, short=False ):
        # {"dps":{"201":"{\"rf_type\":\"sub_2g\",\"control\":\"rfstudy_exit\",\"study_feq\":\"433\",\"ver\":\"2\"}"}
        data = { 'freq': str(freq) }
        cmd = 'rfshortstudy_exit' if short else 'rfstudy_exit'
        self.send_command( cmd, data )

    def rf_receive_button( self, freq=0, timeout=30 ):
        log.debug("Receiving button")
        # Exit study mode in case it's enabled
        self.rf_study_end()
        # Enable study mode
        self.rf_study_start( freq=freq )

        # Receiving button code
        response = None
        response_code = None
        found = False
        # Remember old timeout and set new timeout
        old_timeout = self.connection_timeout
        end_at_time = time.time() + timeout
        old_persist = self.socketPersistent
        self.set_socketPersistent( True )
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
                    log.info( 'Response (type 1): %r', response )
                    response_code = response["dps"][self.DP_LEARNED_ID]
                    found = True
                    break
                elif self.DP_LEARNED_REPORT in response["dps"]:
                    log.info( 'Response (type 2): %r', response )
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
            self.rf_print_button( response_code )

        # Exit study mode
        self.rf_study_end( freq=freq )

        if not old_persist:
            self.set_socketPersistent( False )

        return response_code

    def rf_send_button( self, base64_code, times=6, delay=0, intervals=0 ):
        # key1\":{\"code\":\"eyJud..iI==\",\"times\":6,\"delay\":0,\"intervals\":0}}"}}'
        log.debug( 'Sending Learned RF Button: ' + base64_code)
        self.rf_print_button( base64_code )

        bdata = self.rf_decode_button( base64_code )
        key1 = { 'code': base64_code, 'times': times, 'delay': delay, 'intervals': intervals }
        data = { 'key1': key1 }
        if bdata:
            if 'study_feq' in bdata: data['freq'] = bdata['study_feq']
            if 'ver' in bdata: data['ver'] = bdata['ver']
        return self.send_command( 'rfstudy_send', data )

    def rf_send_key( self, keys, cmt_bank, system_bank, frequency_bank, datarate_bank, baseband_bank, tx_bank, mode=8, freq=0, rate=0 ):
        """
        'keys' can be:
          a dict containing 'code', 'delay', 'intervals', and  'times'
          a single hex string
          a list or tuple containing dicts or hex strings

        The *_bank values are directly copied from CMOSTEK's RFPDK software (select chip "CMT2300A")
        Example:
          Baseband "b":  [2,0,0,0,0,0,0,0,0,0,0,0,0,0,19,0,0,0,0,0,0,0,0,96,255,0,0,31,16]
          CMT "c":       [0,102,236,28,240,128,20,8,145,2,2,208]
          System "s":    [174,224,53,0,0,244,16,226,66,32,0,129]
          Data Rate "d": [63,30,128,204,0,0,0,0,0,0,0,41,192,218,33,75,5,0,80,45,0,1,5,5]
          TX "t":        [81,154,12,0,12,176,0,31,4,63,127]
          Frequency "f": [66,113,206,28,66,91,28,28]
        """
        if len(cmt_bank) != 12 or type(cmt_bank) not in (list, tuple):
            raise ValueError( 'CMT Bank list/tuple size must be 12' )
        if len(system_bank) != 12 or type(system_bank) not in (list, tuple):
            raise ValueError( 'System Bank list/tuple size must be 12' )
        if len(frequency_bank) != 8 or type(frequency_bank) not in (list, tuple):
            raise ValueError( 'Frequency Bank list/tuple size must be 8' )
        if len(datarate_bank) != 24 or type(datarate_bank) not in (list, tuple):
            raise ValueError( 'Data Rate Bank list/tuple size must be 24' )
        if len(baseband_bank) != 29 or type(baseband_bank) not in (list, tuple):
            raise ValueError( 'Baseband Bank list/tuple size must be 29' )
        if len(tx_bank) != 11 or type(tx_bank) not in (list, tuple):
            raise ValueError( 'TX Bank list/tuple size must be 11' )

        # {"dps":{"201":"{\"rf_type\":\"sub_2g\",\"mode\":8,\"key1\":{\"code\":\"ffffc01fa4934924924924934d34924da4926db0\",\"delay\":0,\"intervals\":0,\"times\":5},\"feq\":0,\"rate\":0,\"cfg\":{\"b\":[2,0,0,0,0,0,0,0,0,0,0,0,0,0,19,0,0,0,0,0,0,0,0,96,255,0,0,31,16],\"c\":[0,102,236,28,240,128,20,8,145,2,2,208],\"s\":[174,224,53,0,0,244,16,226,66,32,0,129],\"d\":[63,30,128,204,0,0,0,0,0,0,0,41,192,218,33,75,5,0,80,45,0,1,5,5],\"t\":[81,154,12,0,12,176,0,31,4,63,127],\"f\":[66,113,206,28,66,91,28,28]},\"control\":\"send_cmd\"}"}

        if type(keys) == dict:
            data = { 'key1': keys }
        elif type(keys) == str:
            data = { 'key1': { 'code': keys, 'delay': 0, 'intervals': 0, 'times': 5 } }
        elif type(keys) in (list, tuple):
            i = 1
            data = {}
            for k in keys:
                kkey = 'key%d' % i
                if type(k) == dict:
                    data[kkey] = k
                elif type(k) == str:
                    data[kkey] = { 'code': k, 'delay': 0, 'intervals': 0, 'times': 5 }
                else:
                    raise ValueError( 'rf_send_key(): Unknown data type for key: %r' % k )
        else:
            raise ValueError( 'rf_send_key(): Unknown data type for keys: %r' % keys )

        default = { 'delay': 0, 'intervals': 0, 'times': 5 }
        for k in data:
            for d in default:
                if d not in data[k] or type(data[k][d]) != int:
                    data[k][d] = default[d]

        data['rf_type'] = 'sub_2g'
        data['mode'] = mode
        data['feq'] = freq
        data['rate'] = rate
        data['cfg'] = { 'c': cmt_bank, 's': system_bank, 'f': frequency_bank, 'd': datarate_bank, 'b': baseband_bank, 't': tx_bank }

        log.info( 'Sending Keys: %r', data )
        return self.send_command( 'send_cmd', data )

    @staticmethod
    def rf_print_button( base64_code, use_log=None ):
        if not use_log: use_log = log
        try:
            jstr = base64.b64decode( base64_code )
            #jdata = json.loads( jstr )
            use_log.debug( 'Learned button: %s', jstr )
            return jstr
        except:
            use_log.debug( 'Failed to decode learned button: %r', base64_code )
            return None

    @staticmethod
    def rf_decode_button( base64_code ):
        try:
            jstr = base64.b64decode
            jdata = json.loads( jstr )
            return jdata
        except:
            return None
