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

    def test_set_colour(self):
        # arrange
        d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.status = MagicMock(return_value={}) # set_version calls this to figure out which commands it supports
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={"devId":"DEVICE_ID","dps":{"2":"colour", "5":"ffffff000000ff"}})

        # act
        d.set_colour(255,255,255)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"colour", "5":"ffffff000000ff"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{"21":"colour", "24":"0000000003e8"}, "devId":"DEVICE_ID_HERE","uid":"DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)

    def test_set_white(self):
        # arrange
        d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.status = MagicMock(return_value={}) # set_version calls this to figure out which commands it supports
        d.set_version(3.1)
        d._send_receive = MagicMock(return_value={"devId":"DEVICE_ID","dps":{"1":False,"2":0}})

        # act
        d.set_white(255, 255)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # expectations
        expected_cmd = tinytuya.CONTROL
        # expected_payload = {"dps":{"2":"white", "3": 255, "4": 255}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}
        expected_payload = {"dps":{"21":"white", "22": 255, "23": 255}, "devId": "DEVICE_ID_HERE","uid": "DEVICE_ID_HERE", "t": ""}

        # assert
        self.assertEqual(result_cmd, expected_cmd)
        self.assertDictEqual(result_payload, expected_payload)


if __name__ == '__main__':
    unittest.main()
