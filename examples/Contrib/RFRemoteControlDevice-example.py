#import tinytuya
#tinytuya.set_debug()

from tinytuya.Contrib import RFRemoteControlDevice

d = RFRemoteControlDevice.RFRemoteControlDevice( 'abcdefghijklmnop123456', '172.28.321.475', '1234567890123abc', persist=True )

print( 'Please hold remote close to device and press and hold a button' )
print( 'Waiting for button press...' )

button = d.rf_receive_button()

if not button:
    print( 'No button received!' )
else:
    print( 'Learned button:', button )
    print( 'Decoded:', d.rf_print_button( button ) )
    print( 'Transmitting learned button...' )
    d.rf_send_button( button )
    print( 'Done!' )
