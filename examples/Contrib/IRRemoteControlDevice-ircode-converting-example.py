# TinyTuya IRRemoteControlDevice Example
# -*- coding: utf-8 -*-
"""
 Example script using the community-contributed Python module for Tuya WiFi smart universal remote control simulators

 Author: uzlonewolf (https://github.com/uzlonewolf)
 For more information see https://github.com/jasonacox/tinytuya

"""
import sys
import tinytuya
from tinytuya.Contrib import IRRemoteControlDevice
from time import sleep

#tinytuya.set_debug(toggle=True, color=True)




# parsing and converting between data formats


# discrete on/off codes for Samsung in Pronto format
pronto_samsung_on = '0000 006D 0000 0022 00AC 00AC 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0689'
pronto_samsung_off = '0000 006D 0000 0022 00AC 00AC 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0040 0015 0040 0015 0015 0015 0015 0015 0040 0015 0040 0015 0015 0015 0689'

# convert the Pronto format into pulses
pulses_samsung_on = IRRemoteControlDevice.pronto_to_pulses( pronto_samsung_on )
pulses_samsung_off = IRRemoteControlDevice.pronto_to_pulses( pronto_samsung_off )

# decode the pulses as Samsung format (similar to NEC but with a half-width start burst)
# there may be more than one code in the data stream, so this returns a list of codes
samsung_on_code = IRRemoteControlDevice.pulses_to_samsung( pulses_samsung_on )
samsung_off_code = IRRemoteControlDevice.pulses_to_samsung( pulses_samsung_off )

# print only the first code
print( 'Samsung on code:', samsung_on_code[0] )
# Samsung on code: {'type': 'samsung', 'uint32': 3772815718, 'address': 7, 'data': 153, 'hex': 'E0E09966'}

print( 'Samsung off code:', samsung_off_code[0] )
# Samsung off code: {'type': 'samsung', 'uint32': 3772783078, 'address': 7, 'data': 152, 'hex': 'E0E019E6'}






# discrete on/off codes for LG
hex_lg_on = 0x20DF23DC
hex_lg_off = 0x20DFA35C

# convert the 32-bit integers into a stream of pulses
pulses_lg_on = IRRemoteControlDevice.nec_to_pulses( hex_lg_on )
pulses_lg_off = IRRemoteControlDevice.nec_to_pulses( hex_lg_off )

# decode the pulses to verify and print them like the above Samsung
lg_on_code = IRRemoteControlDevice.pulses_to_nec( pulses_lg_on )
print( 'LG on code:', lg_on_code[0] )
# LG on code: {'type': 'nec', 'uint32': 551494620, 'address': 4, 'data': 196, 'hex': '20DF23DC'}

lg_off_code = IRRemoteControlDevice.pulses_to_nec( pulses_lg_off )
print( 'LG off code:', lg_off_code[0] )
# LG off code: {'type': 'nec', 'uint32': 551527260, 'address': 4, 'data': 197, 'hex': '20DFA35C'}





# both Pronto codes and pulses can also be turned into head/key format
# Pronto will have the correct frequency in the data
headkey = IRRemoteControlDevice.pronto_to_head_key( pronto_samsung_on )
if headkey:
    head, key = headkey
# but the pulses frequency needs to be specified manually if it is not 38 kHz
headkey = IRRemoteControlDevice.pulses_to_head_key( pulses_samsung_on, freq=38 )
if headkey:
    head, key = headkey




# learned codes can also be converted
pulses = IRRemoteControlDevice.base64_to_pulses('IyOvEToCZQI5AkoCOgJNAjYCTwI4AlACNQJMAjkCTQI2ApsGSwKZBkkClwZMAp8GLALLBhgC0wYRAtMGEwLRBhMCbgIdAmkCGwLKBhsCagIaAsoGGgJzAhACbwIWAnICFAJvAh0CxgYdAmoCFwLMBhoCcAIUAtAGFALRBhQC0QYUAtAGFQKXnBgjCAkXAiDL')
# default frequency is 38 kHz
headkey = IRRemoteControlDevice.pulses_to_head_key( pulses )
if headkey:
    head, key = headkey




# now onto talking to the device!


# Create the device.
# This will automatically call detect_control_type() which connects
#   to the device to try and determine which DPS to use.  As such
#   the version must be set here and not later via set_version()
ir = IRRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc', version=3.3, persist=True )


print( 'Turning the Samsung tv on with pulses' )
ir.send_button( ir.pulses_to_base64( pulses_samsung_on ) )
sleep(0.5)
print( 'Turning the LG tv on with pulses' )
ir.send_button( ir.pulses_to_base64( pulses_lg_on ) )
sleep(0.5)


print( 'Turning the Samsung tv off with head/key' )
head, key = IRRemoteControlDevice.pronto_to_head_key( pronto_samsung_off )
ir.send_key( head, key )
sleep(0.5)
print( 'Turning the LG tv off with head/key' )
head, key = IRRemoteControlDevice.pulses_to_head_key( pulses_lg_off )
ir.send_key( head, key )
sleep(0.5)

