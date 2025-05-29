#!/usr/bin/env python3

import logging

import unittest
try:
    from unittest.mock import MagicMock  # Python 3
except ImportError:
    from mock import MagicMock  # py2 use https://pypi.python.org/pypi/mock
import json
import struct

# Enable info logging to see version information
log = logging.getLogger('tinytuya')
logging.basicConfig()  # TODO include function name/line numbers in log
log.setLevel(level=logging.INFO)
log.setLevel(level=logging.DEBUG)  # Debug hack!

import tinytuya

LOCAL_KEY = '0123456789abcdef'

mock_byte_encoding = 'utf-8'


def get_results_from_mock(d):
    result_message_payload = d._send_receive.call_args[0][0]
    result_cmd = result_message_payload.cmd
    result_payload = json.loads(result_message_payload.payload.decode(mock_byte_encoding))
    result_payload["t"] = "" # clear "t"

    return result_cmd, result_payload

def build_mock_bulb(bulb):
    d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
    if bulb == 'A':
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"1": False, "2":"none", "3": -1, "4": -1, "5":"00000000000000"}} # tell it which commands to support and which DPs need updating
    elif bulb == 'B':
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"20": False, "21":"none", "22": -1, "23": -1, "24":"000000000000"}} # tell it which commands to support and DPs need updating
    elif bulb == 'C':
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"1": False, "2": -1}} # tell it which commands to support and which DPs need updating
    else:
        raise ValueError("Unknown bulb type %r" % bulb)

    #d.set_bulb_type(bulb) # tell it which commands to support
    d.detect_bulb(d.status()) # tell it which commands to support

    d.set_version(3.1)
    d._send_receive = MagicMock(return_value={})
    return d

class TestXenonDevice(unittest.TestCase):
    def test_set_timer(self):
        # arrange
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.set_version(3.1)
        mock_response = {"devId":"DEVICE_ID","dps":{"1":False,"2":0}}
        d._send_receive = MagicMock(return_value=mock_response)

        # act
        d.set_timer(6666)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        expected_payload = {"uid":"DEVICE_ID_HERE","devId":"DEVICE_ID_HERE","t":"","dps":{"2":6666}}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_status(self):
        # arrange
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={"devId":"DEVICE_ID","dps":{"1":False,"2":0}})

        # act
        d.set_status(True, 1)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        expected_payload = {"dps":{"1":True},"uid":"DEVICE_ID_HERE","t":"","devId":"DEVICE_ID_HERE"}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_status(self):
        # arrange
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={"devId":"DEVICE_ID","dps":{"1":False,"2":0}})

        # act
        d.status()

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.DP_QUERY
        expected_payload = {"devId": "DEVICE_ID_HERE", "gwId": "DEVICE_ID_HERE", "uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_colour_A(self):
        # arrange
        d = build_mock_bulb('A')

        # act
        d.set_colour(255,127,63)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        print(result_cmd, result_payload)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"colour", "5":"ffffff000000ff"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{"1": True, "2":"colour", "5":"ff7f3f0014c0ff"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_colour_B(self):
        # arrange
        d = build_mock_bulb('B')

        # act
        d.set_colour(255,127,63)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        print(result_cmd, result_payload)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"colour", "5":"ffffff000000ff"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{"20": True, "21":"colour", "24":"001402f003e8"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_white_A(self):
        # arrange
        d = build_mock_bulb('A')

        # act
        d.set_white_percentage(100,100)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        print(result_cmd, result_payload)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"colour", "5":"ffffff000000ff"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{'1': True, '2': 'white', '3': 255, '4': 255}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_white_B(self):
        # arrange
        d = build_mock_bulb('B')

        # act
        d.set_white_percentage(100,100)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"white", "3": 255, "4": 255}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{'20': True, "21":"white", "22": 1000, "23": 1000}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_brightness_C(self):
        # arrange
        d = build_mock_bulb('C')

        # act
        d.set_brightness_percentage(100)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"white", "3": 255, "4": 255}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{'1': True, "2": 255}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_bulb_type(self):
        d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"1": False, "2": 90}} # tell it which commands to support and which DPs need updating
        d.set_bulb_type('C') # tell it which commands to support
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={})

        # act
        d.turn_on()

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        expected_payload = {"dps":{'1': True}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_not_a_bulb(self):
        d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"1": False}} # tell it which commands to support and which DPs need updating
        #d.set_bulb_type('C') # tell it which commands to support
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={})

        # act
        d.turn_on()

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        expected_payload = {"dps":{'1': True}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)


if __name__ == '__main__':
    unittest.main()
