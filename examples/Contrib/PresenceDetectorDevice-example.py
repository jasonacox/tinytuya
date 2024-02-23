from tinytuya.Contrib import PresenceDetectorDevice
#from tinytuya import core
import time
import logging
import requests

log = logging.getLogger(__name__)
device_id = 'XXXX'                                                                  
device_ip = 'YYYY'                                                                           
local_key = 'ZZZZ'
iftt_url = "https://maker.ifttt.com/trigger/{webhook_name_here}/json/with/key/{key_here}"

def main():
   setup()
   run()

def setup():
    global device
    device = PresenceDetectorDevice.PresenceDetectorDevice(device_id, address=device_ip, local_key=local_key, version=3.3)

def run():
    log.info(" >>>> Begin Monitor Loop <<<< ")
    while(True):
        presence = device.get_presence_state()
        if (presence == 'presence'):
            log.info('ALERT! Presence detected!')
            presence_detected_steps()
        else:
            log.debug('no presence, sleep...') 
        time.sleep(20)

def presence_detected_steps():
    requests.post(iftt_url, json={})

if __name__ == "__main__":
    main()
