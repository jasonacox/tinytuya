#!/usr/bin/env python3

import logging

import unittest
try:
    from unittest.mock import MagicMock, patch  # Python 3
except ImportError:
    from mock import MagicMock, patch  # py2 use https://pypi.python.org/pypi/mock
import json
import struct

# Enable info logging to see version information
log = logging.getLogger('tinytuya')
logging.basicConfig()  # TODO include function name/line numbers in log
log.setLevel(level=logging.INFO)
log.setLevel(level=logging.DEBUG)  # Debug hack!

import base64

import tinytuya
from tinytuya.Contrib.RFRemoteControlDevice import RFRemoteControlDevice
from tinytuya.core import message_helper as mh
from tinytuya.core.exceptions import DecodeError

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

    def test_set_timer_picks_numeric_max_dp(self):
        # regression: DP keys must be selected numerically, not lexicographically
        # ("9" > "102" as strings, but 102 > 9 as ints)
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.set_version(3.1)
        # status() supplies the DPS the timer selection scans
        d.status = lambda nowait=False: {"devId":"DEVICE_ID","dps":{"1":False,"9":0,"102":0}}
        d._send_receive = MagicMock(return_value={"devId":"DEVICE_ID","dps":{"1":False,"9":0,"102":0}})

        # act
        d.set_timer(6666)

        # gather results
        result_cmd, result_payload = get_results_from_mock(d)

        # assert the timer targeted DP "102", not "9"
        self.assertEqual(result_cmd, tinytuya.CONTROL)
        self.assertDictEqual(result_payload, {"uid":"DEVICE_ID_HERE","devId":"DEVICE_ID_HERE","t":"","dps":{"102":6666}})

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

    def test_generate_payload_does_not_mutate_template(self):
        # v3.4+/zigbee templates contain a nested "data" dict; a shallow copy let
        # the DPs of one command leak into the cached template and later payloads
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY, version=3.4)
        d.generate_payload(tinytuya.CONTROL, {'1': True})
        self.assertEqual(d.payload_dict[tinytuya.CONTROL]['command']['data'], {})
        msg = d.generate_payload(tinytuya.CONTROL)
        self.assertNotIn('dps', json.loads(msg.payload.decode('utf-8'))['data'])

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

    def test_percentage_raises_when_unconfigured(self):
        # Regression test: calling *_percentage() before bulb detection,
        # with nowait=True and no cached status, should raise RuntimeError
        # instead of silently computing with value_max=-1.
        d = tinytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d.set_version(3.3)
        # No detect_bulb() called, no cached status available
        d.cached_status = MagicMock(return_value=None)

        with self.assertRaises(RuntimeError):
            d.set_brightness_percentage(50, nowait=True)
        with self.assertRaises(RuntimeError):
            d.set_white_percentage(50, 50, nowait=True)
        with self.assertRaises(RuntimeError):
            d.set_colourtemp_percentage(50, nowait=True)


def build_mock_rf():
    d = RFRemoteControlDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY, control_type=1)
    d.set_version(3.3)
    d.set_value = MagicMock()
    return d


class TestRFRemoteControlDevice(unittest.TestCase):
    def test_rf_decode_button_returns_dict(self):
        # Bug 1: rf_decode_button was missing the () call on base64.b64decode,
        # causing it to always return None instead of the decoded JSON dict.
        sample = {"study_feq": "433", "ver": "2"}
        encoded = base64.b64encode(json.dumps(sample).encode()).decode()

        result = RFRemoteControlDevice.rf_decode_button(encoded)

        self.assertIsNotNone(result, "rf_decode_button returned None — function was not called")
        self.assertDictEqual(result, sample)

    def test_rf_send_button_payload_structure(self):
        # Bug 2: send_command('rfstudy_send', ...) was building the wrong payload:
        #   - used 'study_feq' (string) instead of 'feq' (int)
        #   - omitted 'mode' and 'rate' fields
        #   - omitted 'ver' inside each key dict
        # Bug 3: rf_send_button was forwarding study_feq from the decoded button into
        #   feq, but feq must always be 0 so the device uses the frequency embedded in
        #   the code. Passing the actual frequency value selects a different chip path.
        d = build_mock_rf()

        # Use a button that has study_feq set to a non-zero value to confirm it is
        # NOT forwarded into the payload's feq field.
        button_data = {"study_feq": "433", "ver": "2"}
        base64_code = base64.b64encode(json.dumps(button_data).encode()).decode()

        d.rf_send_button(base64_code)

        call_args = d.set_value.call_args
        dp = call_args[0][0]
        payload = json.loads(call_args[0][1])

        self.assertEqual(dp, RFRemoteControlDevice.DP_SEND_IR)
        self.assertEqual(payload['control'], 'rfstudy_send')

        self.assertIn('feq', payload, "payload missing 'feq' (was 'study_feq')")
        self.assertNotIn('study_feq', payload, "payload must not contain 'study_feq' for rfstudy_send")
        self.assertIsInstance(payload['feq'], int, "'feq' must be int, not string")
        self.assertEqual(payload['feq'], 0, "feq must be 0 so the device uses the frequency embedded in the code")
        self.assertIn('mode', payload, "payload missing 'mode'")
        self.assertIn('rate', payload, "payload missing 'rate'")

        self.assertIn('key1', payload)
        self.assertIn('ver', payload['key1'], "key1 missing 'ver'")


class TestGatewayWrongCidQueue(unittest.TestCase):
    """Updates queued for a different child are stored as (child, result) tuples;
    receive() must hand back only the result dict."""

    def _build(self):
        gw = tinytuya.Device('GATEWAY_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY, version=3.3, persist=True)
        child1 = tinytuya.Device('CHILD1_ID_HERE', cid='cid1', parent=gw)
        child2 = tinytuya.Device('CHILD2_ID_HERE', cid='cid2', parent=gw)
        gw._get_socket = MagicMock(return_value=True)
        return gw, child1, child2

    def test_parent_receive_returns_dict(self):
        gw, child1, _ = self._build()
        result = {'dps': {'1': True}, 'device': child1}
        gw.received_wrong_cid_queue.append((child1, result))
        self.assertIs(gw.receive(), result)
        self.assertEqual(gw.received_wrong_cid_queue, [])

    def test_child_receive_returns_its_own_queued_dict(self):
        gw, child1, child2 = self._build()
        r1 = {'dps': {'1': True}, 'device': child1}
        r2 = {'dps': {'1': False}, 'device': child2}
        gw.received_wrong_cid_queue.extend([(child1, r1), (child2, r2)])
        self.assertIs(child2.receive(), r2)
        self.assertEqual(gw.received_wrong_cid_queue, [(child1, r1)])


class _FakeResponse:
    def __init__(self, body):
        self.text = json.dumps(body)
        self.content = self.text.encode()
        self.status_code = 200


class TestCloudTokenRetry(unittest.TestCase):
    """After a token refresh, _tuyaplatform() retries the request; the retry
    must sign the same un-encoded query string as the first attempt."""

    def test_retry_signs_unencoded_dict_query(self):
        import sys, hashlib, hmac
        from unittest.mock import patch
        cloudmod = sys.modules['tinytuya.Cloud']
        key, secret = 'abcdefghijklmnop123456', '0123456789abcdef0123456789abcdef'
        c = tinytuya.Cloud(apiRegion='us', apiKey=key, apiSecret=secret, initial_token='expired_token')
        responses = [
            _FakeResponse({'success': False, 'msg': 'token invalid'}),
            _FakeResponse({'success': True, 'result': {'access_token': 'new_token'}}),
            _FakeResponse({'success': True, 'result': {'logs': []}}),
        ]
        with patch.object(cloudmod.requests, 'get', side_effect=responses) as mock_get, \
             patch.object(cloudmod.time, 'time', return_value=1700000000.0):
            result = c.cloudrequest('/v1.0/devices/0123456789abcdef/logs', query={'type': '1,7', 'size': 100})

        self.assertEqual(result, {'success': True, 'result': {'logs': []}})
        self.assertEqual(c.token, 'new_token')
        # Tuya signs the sorted query *before* URL-encoding (the comma stays a comma)
        string_to_sign = (key + 'new_token' + '1700000000000' + 'GET\n' +
                          hashlib.sha256(b'').hexdigest() + '\n\n' +
                          '/v1.0/devices/0123456789abcdef/logs?size=100&type=1,7')
        expected = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest().upper()
        retry_headers = mock_get.call_args_list[2][1]['headers']
        self.assertEqual(retry_headers['access_token'], 'new_token')
        self.assertEqual(retry_headers['sign'], expected)


class TestCloudDeviceLog(unittest.TestCase):
    def _cloud(self, pages):
        c = tinytuya.Cloud(apiRegion='us', apiKey='abcdefghijklmnop123456', apiSecret='0123456789abcdef0123456789abcdef', initial_token='token')
        calls = []

        def fake_request(url, action=None, post=None, query=None):
            calls.append(dict(query))
            n = len(calls)
            return {'success': True, 'result': {
                'logs': [{'event_id': 7, 'value': '%d-%d' % (n, i)} for i in range(100)],
                'has_next': n < pages, 'next_row_key': 'row%d' % n}}

        c.cloudrequest = fake_request
        return c, calls

    def test_size_over_100_fetches_multiple_pages(self):
        # the server caps a page at 100 rows; size=250 must keep paging until 250 are collected
        c, calls = self._cloud(pages=10)
        result = c.getdevicelog('0123456789abcdef', size=250)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(result['result']['logs']), 300)
        self.assertEqual(calls[0]['size'], 100)

    def test_size_under_100_single_page(self):
        c, calls = self._cloud(pages=10)
        c.getdevicelog('0123456789abcdef', size=50)
        self.assertEqual(len(calls), 1)


class TestLoadDeviceFile(unittest.TestCase):
    """Tests for the load_devicefile() helper."""

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def _write_json(self, data, fname='devices.json'):
        import os
        path = os.path.join(self.tmpdir, fname)
        with open(path, 'w') as f:
            json.dump(data, f)
        return path

    def test_flat_list(self):
        """Flat list format should be returned as-is."""
        devices = [{'id': 'dev1', 'key': 'abc'}]
        path = self._write_json(devices)
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, devices)

    def test_wrapped_dict(self):
        """Wrapped {"devices": [...]} format should return the inner list."""
        devices = [{'id': 'dev2', 'key': 'xyz'}]
        path = self._write_json({'devices': devices})
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, devices)

    def test_missing_file(self):
        """Missing file should return empty list, not raise."""
        result = tinytuya.load_devicefile('/nonexistent_path/devices.json')
        self.assertEqual(result, [])

    def test_empty_list(self):
        """Empty list should return empty list."""
        path = self._write_json([])
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, [])

    def test_invalid_json(self):
        """Invalid JSON should return empty list, not raise."""
        import os
        path = os.path.join(self.tmpdir, 'bad.json')
        with open(path, 'w') as f:
            f.write('{not valid json')
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, [])

    def test_non_list_non_dict(self):
        """A JSON file containing a scalar should return empty list."""
        path = self._write_json("just a string")
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, [])

    def test_dict_without_devices_key(self):
        """A dict without a 'devices' key should return empty list."""
        path = self._write_json({'other_key': [{'id': 'x'}]})
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result, [])

    def test_special_chars_in_key(self):
        """Keys with special characters should be preserved."""
        devices = [{'id': 'dev3', 'key': ":|S'vf<MT6xhr{1~"}]
        path = self._write_json(devices)
        result = tinytuya.load_devicefile(path)
        self.assertEqual(result[0]['key'], ":|S'vf<MT6xhr{1~")


class TestParseHeader(unittest.TestCase):
    """parse_header must accept large IR/AC learn frames (>1000 bytes) while
    still rejecting absurd sizes from a corrupt or desynced stream."""

    def _header_6699(self, payload_len):
        return struct.pack(
            mh.H.MESSAGE_HEADER_FMT_6699,
            mh.H.PREFIX_6699_VALUE, 0, 1, 8, payload_len,
        )

    def test_large_ir_payload_accepted(self):
        # a 1038-byte frame is a real air-conditioner learn report; it must parse
        header = mh.parse_header(self._header_6699(1038) + b'\x00' * 40)
        self.assertEqual(header.length, 1038)

    def test_oversized_payload_rejected(self):
        oversized = self._header_6699(mh.MAX_PAYLOAD_LENGTH + 1)
        with self.assertRaises(DecodeError):
            mh.parse_header(oversized + b'\x00' * 40)


class TestErrorJson(unittest.TestCase):
    """error_json must return the expected dict shape and never raise, even
    for an unknown error code."""

    def test_known_code_shape(self):
        from tinytuya.core.error_helper import error_json, ERR_TIMEOUT
        result = error_json(ERR_TIMEOUT)
        self.assertEqual(result["Error"], "Timeout Waiting for Device")
        self.assertEqual(result["Err"], "902")
        self.assertIsNone(result["Payload"])
        self.assertEqual(set(result.keys()), {"Error", "Err", "Payload"})

    def test_payload_preserved(self):
        from tinytuya.core.error_helper import error_json, ERR_CLOUD
        result = error_json(ERR_CLOUD, "some detail")
        self.assertEqual(result["Payload"], "some detail")
        self.assertEqual(result["Err"], "913")

    def test_unknown_code_does_not_raise(self):
        from tinytuya.core.error_helper import error_json
        result = error_json(99999)
        self.assertEqual(result["Error"], "Unknown Error")
        self.assertEqual(result["Err"], "99999")

    def test_default_none_code(self):
        from tinytuya.core.error_helper import error_json
        result = error_json()
        self.assertEqual(result["Error"], "Unknown Error")
        self.assertEqual(result["Err"], "None")
        self.assertIsNone(result["Payload"])


class TestHexvalueRoundTrip(unittest.TestCase):
    """hexvalue_to_hsv must decode the hue written by rgb_to_hexvalue at the
    correct offset (regression for the [7:10] vs [6:10] off-by-one)."""

    def test_rgb8_round_trip(self):
        import colorsys
        for rgb in ((255, 128, 0), (0, 255, 64), (30, 60, 200)):
            hexvalue = tinytuya.BulbDevice.rgb_to_hexvalue(*rgb, 'rgb8')
            self.assertEqual(len(hexvalue), 14)
            h, s, v = tinytuya.BulbDevice.hexvalue_to_hsv(hexvalue, 'rgb8')
            eh, es, ev = colorsys.rgb_to_hsv(rgb[0] / 255.0, rgb[1] / 255.0, rgb[2] / 255.0)
            # allow small quantization error from the 8-bit hex encoding
            self.assertAlmostEqual(h, eh, delta=0.01)
            self.assertAlmostEqual(s, es, delta=0.01)
            self.assertAlmostEqual(v, ev, delta=0.01)

    def test_rgb8_accepts_float_rgb(self):
        # set_colour() documents r/g/b as floats 0.0-255.0; %x used to raise TypeError
        self.assertEqual(tinytuya.BulbDevice.rgb_to_hexvalue(255.0, 0.0, 127.6, 'rgb8')[:6], 'ff0080')

    def test_hsv_to_hexvalue_rgb8(self):
        # hsv_to_hexvalue() feeds float RGB into rgb_to_hexvalue(), so set_hsv() on rgb8 bulbs always crashed
        hexvalue = tinytuya.BulbDevice.hsv_to_hexvalue(0.0, 1.0, 1.0, 'rgb8')
        self.assertEqual(hexvalue, 'ff00000000ffff')
        self.assertEqual(tinytuya.BulbDevice.hexvalue_to_rgb(hexvalue, 'rgb8'), (255, 0, 0))

    def test_set_hsv_A(self):
        d = build_mock_bulb('A')
        d.set_hsv(0.5, 0.5, 0.5)
        result_cmd, result_payload = get_results_from_mock(d)
        self.assertEqual(result_cmd, tinytuya.CONTROL)
        self.assertEqual(result_payload['dps']['5'], '40808000b47f7f')
        self.assertEqual(result_payload['dps']['2'], 'colour')


class TestSessionCrypto(unittest.TestCase):
    """Session-key negotiation and GCM nonces must use fresh randomness so the
    same nonce/IV is never reused across messages or sessions."""

    def test_client_nonce_is_random_and_16_bytes(self):
        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY, version=3.5)
        d._negotiate_session_key_generate_step_1()
        first = d.local_nonce
        d._negotiate_session_key_generate_step_1()
        second = d.local_nonce
        self.assertEqual(len(first), 16)
        self.assertEqual(len(second), 16)
        self.assertNotEqual(first, second, "client nonce must differ between negotiations")

    def _set_crypto_log_level(self, level):
        # tests.py enables DEBUG for all of tinytuya, which switches on the fixed
        # debug IV; pin the crypto_helper logger so each mode is tested explicitly
        clog = logging.getLogger('tinytuya.core.crypto_helper')
        self.addCleanup(clog.setLevel, clog.level)
        clog.setLevel(level)

    def test_gcm_iv_is_random_and_12_bytes(self):
        cipher = mh.AESCipher(LOCAL_KEY.encode('latin1'))
        if not cipher.CRYPTOLIB_HAS_GCM:
            self.skipTest("crypto backend has no GCM support")
        self._set_crypto_log_level(logging.INFO)
        iv1 = cipher.get_encryption_iv(True)
        iv2 = cipher.get_encryption_iv(True)
        self.assertEqual(len(iv1), 12)
        self.assertEqual(len(iv2), 12)
        self.assertNotEqual(iv1, iv2, "GCM IV must be random per message")

    def test_gcm_iv_is_fixed_in_debug_mode(self):
        # deliberate troubleshooting aid (see AGENTS.md safety rails)
        cipher = mh.AESCipher(LOCAL_KEY.encode('latin1'))
        if not cipher.CRYPTOLIB_HAS_GCM:
            self.skipTest("crypto backend has no GCM support")
        self._set_crypto_log_level(logging.DEBUG)
        self.assertEqual(cipher.get_encryption_iv(True), b'0123456789ab')

    def test_receive_rejects_gcm_auth_failure(self):
        key = LOCAL_KEY.encode('latin1')
        cipher = mh.AESCipher(key)
        if not cipher.CRYPTOLIB_HAS_GCM:
            self.skipTest("crypto backend has no GCM support")

        # Build a valid 6699/GCM frame, then flip 1 bit in the tag.
        payload = b'{"x":1}'
        good = mh.pack_message(
            mh.TuyaMessage(1, 16, None, payload, 0, True, mh.H.PREFIX_6699_VALUE, b'\x00' * 12),
            hmac_key=key,
        )
        bad = good[:-5] + bytes([good[-5] ^ 1]) + good[-4:]

        d = tinytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY, version=3.5)
        d._recv_all = lambda n: bad
        d.local_key = key
        with self.assertRaises(DecodeError):
            d._receive()


import socket as _socket_mod
from tinytuya.core.Monitor import Monitor, _accepts_nowait


class _FakeDevice:
    """Minimal stand-in for a tinytuya Device that Monitor can drive without a
    real network — _get_socket() hands back one end of a socketpair."""

    def __init__(self, dev_id, retry_limit=5):
        self.id = dev_id
        self.socket = None
        self.socketPersistent = False
        self.socketRetryLimit = retry_limit
        self.children = {}
        self.version = 3.3
        self._peer = None
        self.heartbeat_should_fail = False
        self.heartbeat_calls = 0
        self.method_calls = []

    def _get_socket(self, renew):
        s, peer = _socket_mod.socketpair()
        self.socket = s
        self._peer = peer
        return True

    def __del__(self):
        if self._peer is not None:
            try:
                self._peer.close()
            except Exception:
                pass

    def heartbeat(self, nowait=True):
        self.heartbeat_calls += 1
        if self.heartbeat_should_fail:
            # emulate fail-fast: socket closed + cleared, error dict returned
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            return {"Error": "fail"}
        return None

    def set_value(self, index, value, nowait=False):
        self.method_calls.append(('set_value', index, value, nowait))

    def set_socketPersistent(self, persist):   # note: no nowait param
        self.method_calls.append(('set_socketPersistent', persist))


class TestMonitorReliability(unittest.TestCase):
    """Monitor must own reconnection: monitored devices fail fast instead of
    blocking the reactor or silently opening an unwatched socket."""

    def _make(self, **kw):
        mon = Monitor(**kw)
        self.addCleanup(mon.stop)
        return mon

    def test_add_forces_fail_fast_and_remove_restores(self):
        mon = self._make()
        dev = _FakeDevice('devA', retry_limit=5)
        proxy = mon.add(dev)
        self.assertFalse(isinstance(proxy, str), 'add() should succeed')
        # While monitored, the device must not run its own retry/reconnect loop.
        self.assertEqual(dev.socketRetryLimit, 0)
        state = mon._id_to_state['devA']
        self.assertEqual(state.saved_retry_limit, 5)
        # Removal hands the device back untouched.
        mon.remove(dev)
        self.assertEqual(dev.socketRetryLimit, 5)
        self.assertIsNone(dev.socket)
        self.assertNotIn('devA', mon._id_to_state)

    def test_heartbeat_failure_disconnects_and_enqueues_reconnect(self):
        disconnects = []
        mon = self._make(auto_reconnect=True,
                         on_disconnect=lambda d, e: disconnects.append(d.id))
        dev = _FakeDevice('devB')
        mon.add(dev)
        state = mon._id_to_state['devB']
        self.assertIsNotNone(state.fileno)

        # Simulate a broken connection on the next heartbeat.
        dev.heartbeat_should_fail = True
        mon._do_heartbeat(state)

        # The vanished socket must be detected as a disconnect...
        self.assertEqual(disconnects, ['devB'])
        self.assertIsNone(state.fileno)
        self.assertNotIn(state, mon._devices.values())
        # ...and the device queued for the connector thread to reconnect.
        self.assertIn('devB', mon._reconnect_queue)
        self.assertIn('devB', mon._devices_in_reconnect)

    def test_command_dropped_when_device_not_active(self):
        mon = self._make()
        dev = _FakeDevice('devC')
        mon.add(dev)
        state = mon._id_to_state['devC']
        # Emulate a device mid-reconnect (registered but not yet active).
        state.fileno = None
        mon.command(dev, 'set_value', 1, True)
        mon._drain_queue()
        self.assertEqual(dev.method_calls, [], 'command must not run on an inactive device')

    def test_proxy_injects_nowait_only_when_accepted(self):
        mon = self._make()
        dev = _FakeDevice('devD')
        mon.add(dev)
        # set_value accepts nowait -> injected
        mon.command(dev, 'set_value', 1, True)
        # set_socketPersistent has no nowait param -> must NOT be injected
        mon.command(dev, 'set_socketPersistent', True)
        queued = {name: kwargs for (_id, name, _a, kwargs) in mon._queue}
        self.assertEqual(queued['set_value'].get('nowait'), True)
        self.assertNotIn('nowait', queued['set_socketPersistent'])

    def test_stop_restores_retry_limit_for_disconnected_devices(self):
        """stop() must restore socketRetryLimit even for devices that
        disconnected before stop() was called (in _id_to_state but not _devices)."""
        mon = self._make(auto_reconnect=True)
        dev = _FakeDevice('devE', retry_limit=7)
        mon.add(dev)
        # Simulate a disconnect: device leaves _devices but stays in _id_to_state.
        state = mon._id_to_state['devE']
        dev.heartbeat_should_fail = True
        mon._do_heartbeat(state)
        # Device is now disconnected — socketRetryLimit is still 0.
        self.assertEqual(dev.socketRetryLimit, 0)
        self.assertIn('devE', mon._id_to_state)
        self.assertNotIn(state, mon._devices.values())
        # stop() must restore the original limit.
        mon.stop()
        self.assertEqual(dev.socketRetryLimit, 7)

    def test_accepts_nowait_helper(self):
        self.assertTrue(_accepts_nowait(lambda x, nowait=False: None))
        self.assertTrue(_accepts_nowait(lambda x, **kw: None))
        self.assertFalse(_accepts_nowait(lambda x: None))



class _FakeScanClock:
    """Stands in for the scanner's `time` module so scans run instantly.

    Every time() call advances 10 ms and sleep() advances by its argument, so the
    scanner's timing loops make progress without real waiting.
    """

    def __init__(self, start=1000.0):
        self.now = start

    def time(self):
        self.now += 0.01
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class TestConfiguredDeviceScanner(unittest.TestCase):
    """devices.json rows not heard over UDP are polled once at their saved IP."""

    DEV_ID = 'abcdefghijklmnopqrst'

    @classmethod
    def _row(cls, ip='192.0.2.10', version='3.5', **extra):
        # schema the wizard writes (product_id, not productKey)
        row = {'id': cls.DEV_ID, 'key': LOCAL_KEY, 'ip': ip, 'version': version,
               'name': 'Configured test device', 'product_id': 'testproduct'}
        row.update(extra)
        return row

    def _scan(self, rows, outcomes=None, broadcasts=(), verbose=False, slow_discovery=False, **kwargs):
        """Run scanner.devices() offline and return (result, stdout, polled_ips).

        outcomes: {ip: True | False | 'inflight'} for each configured poll (default True).
        broadcasts: [(seconds_after_start, payload)] UDP packets delivered once the fake
        clock passes that point (only when discover=True).
        slow_discovery: from the second discovery request on, sending it takes 100s of fake time.
        """
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        clock = _FakeScanClock()
        start = clock.now
        outcomes = outcomes or {}
        pending = sorted(broadcasts, key=lambda b: b[0])
        udp = [MagicMock(), MagicMock(), MagicMock()]
        current = {}
        polled = []
        sends = []

        def discovery_request(*args, **kw):
            sends.append(args)
            if slow_discovery and len(sends) > 1:
                clock.now += 100

        def configured_connect(dev):
            polled.append(dev.ip)
            outcome = outcomes.get(dev.ip, True)
            if outcome == 'inflight':
                dev.sock = MagicMock()
                dev.write = True
                dev.timeo = clock.now + 5
                return
            if outcome:
                dev.finished = True
                dev.deviceinfo['dps'] = {'dps': {'1': True}}
                dev.deviceinfo['err'] = ''
            else:
                dev.deviceinfo['err'] = 'No response'
            dev.close()

        def broadcast_connect(dev):
            dev.finished = True
            dev.deviceinfo['dps'] = {'dps': {'1': False}}
            dev.deviceinfo['err'] = ''
            dev.close()

        def fake_select(read_socks, write_socks, error_socks, timeout):
            if pending and clock.now >= start + pending[0][0]:
                current['payload'] = pending.pop(0)[1]
                udp[0].recvfrom.return_value = (b'packet', (current['payload']['ip'], scanner.UDPPORT))
                return ([udp[0]], [], [])
            return ([], [], [])

        kwargs.setdefault('discover', False)
        kwargs.setdefault('poll_configured', True)
        out = io.StringIO()
        with patch.object(scanner, 'time', clock), \
                patch.object(scanner.socket, 'socket', side_effect=udp), \
                patch.object(scanner.select, 'select', side_effect=fake_select), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner, 'send_discovery_request', side_effect=discovery_request), \
                patch.object(scanner, 'save_snapshotfile'), \
                patch.object(tinytuya, 'decrypt_udp', side_effect=lambda data: json.dumps(current['payload'])), \
                patch.object(scanner.ConfiguredDevice, 'connect', configured_connect), \
                patch.object(scanner.PollDevice, 'connect', broadcast_connect), \
                redirect_stdout(out):
            result = scanner.devices(verbose=verbose, byID=True, tuyadevices=rows, **kwargs)
        return result, out.getvalue(), polled

    # --- defaults and plumbing ---

    def test_library_configured_poll_defaults_are_opt_in(self):
        import inspect
        from tinytuya import scanner, wizard

        for function in (tinytuya.deviceScan, tinytuya.scan, scanner.devices,
                         scanner.scan, scanner.poll_and_display,
                         scanner.alldevices, wizard.wizard):
            with self.subTest(function=function.__name__):
                self.assertIs(inspect.signature(function).parameters[
                    'poll_configured'].default, False)
        with patch.object(scanner, 'devices', return_value={}) as devices:
            tinytuya.deviceScan()
            self.assertIs(devices.call_args[1]['poll_configured'], False)
            tinytuya.deviceScan(poll_configured=True)
            self.assertIs(devices.call_args[1]['poll_configured'], True)
        with patch.object(scanner, 'scan') as scan:
            tinytuya.scan()
            self.assertIs(scan.call_args[1]['poll_configured'], False)
            tinytuya.scan(poll_configured=True)
            self.assertIs(scan.call_args[1]['poll_configured'], True)

    def test_interactive_cli_explicitly_enables_configured_polling(self):
        import runpy
        import sys
        from tinytuya import scanner, wizard

        for command, module, target in (('scan', scanner, 'scan'),
                                        ('devices', scanner, 'alldevices'),
                                        ('wizard', wizard, 'wizard')):
            for flag in ([], ['-no-poll-configured']):
                with self.subTest(command=command, flag=flag), \
                        patch.object(sys, 'argv', ['tinytuya', command] + flag), \
                        patch.object(module, target) as run:
                    runpy.run_module('tinytuya', run_name='__main__')
                    self.assertIs(run.call_args[1]['poll_configured'], not bool(flag))

    def test_off_by_default_and_requires_poll(self):
        for kwargs in ({'poll_configured': False}, {'poll': False}):
            with self.subTest(**kwargs):
                result, _, polled = self._scan([self._row()], **kwargs)
                self.assertEqual(polled, [])
                self.assertEqual(result, {})

    # --- results ---

    def test_found_device_is_reported_as_configured(self):
        result, _, polled = self._scan([self._row()])
        self.assertEqual(polled, ['192.0.2.10'])
        dev = result[self.DEV_ID]
        self.assertEqual(dev['origin'], 'configured')
        self.assertEqual(dev['ip'], '192.0.2.10')
        self.assertEqual(dev['dps'], {'dps': {'1': True}})
        self.assertEqual(dev['productKey'], 'testproduct')

    def test_verbose_output_shows_phase_label_and_key(self):
        _, out, _ = self._scan([self._row()], verbose=True)
        self.assertIn('Polling 1 devices.json IPs not heard by broadcast', out)
        self.assertIn('[Configured IP]', out)
        # local keys are shown on purpose, like every other scan result
        self.assertIn(LOCAL_KEY, out)
        self.assertIn('Configured IPs: 1 found, 0 not found', out)
        self.assertIn('Broadcasted: 0', out)

    def test_unanswered_row_is_left_out_and_listed(self):
        result, out, polled = self._scan([self._row(name='Old Plug')], outcomes={'192.0.2.10': False}, verbose=True)
        self.assertEqual(polled, ['192.0.2.10'])
        self.assertEqual(result, {})
        self.assertIn('Configured IPs: 0 found, 1 not found', out)
        self.assertIn('Old Plug (192.0.2.10: No response)', out)
        self.assertIn('Not found at saved IP (offline, moved, or key or version changed)', out)

    def test_caller_rows_are_not_mutated(self):
        row = self._row()
        before = dict(row)
        self._scan([row])
        self.assertEqual(row, before)

    def test_configured_pass_runs_when_window_closes_at_end_of_loop(self):
        # the UDP window closes during the slow discovery send at the end of a loop pass;
        # the scan must still go round once more to run the configured-IP pass
        result, _, polled = self._scan([self._row()], discover=True, scantime=6.6, slow_discovery=True)
        self.assertEqual(polled, ['192.0.2.10'])
        self.assertIn(self.DEV_ID, result)

    # --- broadcast precedence ---

    def test_device_heard_by_broadcast_is_not_polled_again(self):
        for bcast_ip in ('192.0.2.10', '192.0.2.99'):  # same IP, and moved to a new IP
            with self.subTest(bcast_ip=bcast_ip):
                payload = {'gwId': self.DEV_ID, 'ip': bcast_ip, 'version': '3.5', 'productKey': 'p'}
                result, _, polled = self._scan([self._row()], broadcasts=[(0.5, payload)],
                                               discover=True, scantime=2)
                self.assertEqual(polled, [])
                self.assertEqual(result[self.DEV_ID]['origin'], 'broadcast')
                self.assertEqual(result[self.DEV_ID]['ip'], bcast_ip)

    def test_late_broadcast_replaces_in_flight_configured_poll(self):
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.10', 'version': '3.5', 'productKey': 'p'}
        # the UDP window is 2s, so the broadcast at 3s lands while the configured poll is in flight
        result, out, polled = self._scan([self._row()], outcomes={'192.0.2.10': 'inflight'},
                                         broadcasts=[(3, payload)], discover=True, scantime=2, verbose=True)
        self.assertEqual(polled, ['192.0.2.10'])
        self.assertEqual(result[self.DEV_ID]['origin'], 'broadcast')
        # the aborted configured poll is neither a result nor reported as not found
        self.assertIn('Configured IPs: 0 found, 0 not found', out)
        self.assertIn('Aborting configured-IP poll for device 192.0.2.10', out)

    def test_late_broadcast_suppresses_printed_configured_result(self):
        # this row's poll finishes at once, but another one keeps the scan running until the
        # broadcast for the same device lands; only the broadcast may be shown
        other = self._row(ip='192.0.2.20', id='zyxwvutsrqponmlkjihg')
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.10', 'version': '3.5', 'productKey': 'p'}
        result, out, polled = self._scan([self._row(), other], outcomes={'192.0.2.20': 'inflight'},
                                         broadcasts=[(3, payload)], discover=True, scantime=2, verbose=True)
        self.assertEqual(sorted(polled), ['192.0.2.10', '192.0.2.20'])
        self.assertEqual(result[self.DEV_ID]['origin'], 'broadcast')
        self.assertNotIn('[Configured IP]', out)

    def test_late_broadcast_of_pending_id_at_new_ip_skips_its_poll(self):
        # one poll at a time: the second row is still pending when its ID is announced at a new IP
        from tinytuya import scanner
        other = self._row(ip='192.0.2.20', id='zyxwvutsrqponmlkjihg')
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.99', 'version': '3.5', 'productKey': 'p'}
        with patch.object(scanner, 'max_parallel', 1):
            result, _, polled = self._scan([other, self._row()], outcomes={'192.0.2.20': 'inflight'},
                                           broadcasts=[(3, payload)], discover=True, scantime=2)
        self.assertEqual(polled, ['192.0.2.20'])
        self.assertEqual(result[self.DEV_ID]['ip'], '192.0.2.99')

    def test_plan_skips_ids_heard_at_other_ips(self):
        # a device that moved is heard at its new IP (by broadcast or force-scan), not polled at the old one
        from types import SimpleNamespace
        from tinytuya import scanner
        moved = self._row(ip='192.0.2.10')
        scanned = self._row(ip='192.0.2.20', id='zyxwvutsrqponmlkjihg')
        silent = self._row(ip='192.0.2.30', id='silentsilentsilentsi')
        heard = lambda gwid, found=True: SimpleNamespace(deviceinfo={'gwId': gwid}, found=found)
        configured = scanner._ConfiguredPass(True, [moved, scanned, silent], {}, [])
        ips = configured.plan({'192.0.2.99': heard(self.DEV_ID)},
                              {'192.0.2.98': heard('zyxwvutsrqponmlkjihg'), '192.0.2.97': heard('silentsilentsilentsi', False)},
                              None)
        self.assertEqual(ips, ['192.0.2.30'])
        self.assertFalse(configured.waiting)

    def test_keyless_row_keeps_its_name_for_a_broadcast(self):
        # regression guard: a broadcast device whose devices.json row has no key is
        # "Missing Local Key", not "Unknown"
        row = {'id': self.DEV_ID, 'key': '', 'name': 'Keyless Lamp'}
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.11', 'version': '3.3', 'productKey': 'p'}
        result, out, polled = self._scan([row], broadcasts=[(0.5, payload)], discover=True,
                                         scantime=2, verbose=True)
        self.assertEqual(polled, [])
        self.assertEqual(result[self.DEV_ID]['name'], 'Keyless Lamp')
        self.assertIn('Missing Local Key: 1', out)
        self.assertNotIn('Unknown Devices', out)

    # --- interaction with wantids / wantips / maxdevices ---

    def test_configured_find_satisfies_wanted_ids(self):
        result, out, _ = self._scan([self._row()], wantids=[self.DEV_ID], verbose=True)
        self.assertIn(self.DEV_ID, result)
        self.assertNotIn('Did not find', out)

    def test_wanted_ips_are_left_to_the_force_scan(self):
        from tinytuya import scanner
        rows = [self._row(), self._row(ip='192.0.2.20', id='zzzzzzzzzzzzzzzzzzzz')]
        candidates = scanner._configured_candidates(rows, set(), set(), skip_ips=['192.0.2.10'])
        self.assertEqual(list(candidates), ['192.0.2.20'])

    def test_maxdevices_caps_configured_results(self):
        rows = [self._row(), self._row(ip='192.0.2.20', id='zzzzzzzzzzzzzzzzzzzz')]
        result, _, polled = self._scan(rows, maxdevices=1)
        self.assertEqual(len(polled), 2)
        self.assertEqual(len(result), 1)

    # --- row validation ---

    def test_only_complete_top_level_rows_are_polled(self):
        from tinytuya import scanner
        good = self._row()
        self.assertIsNotNone(scanner._configured_device_info(good))
        bad_rows = (
            None, 'row', [],
            dict(good, key=''), dict(good, key=None), dict(good, key=123),
            dict(good, id=''), dict(good, id=['x']),
            dict(good, ip=''), dict(good, ip='not-an-ip'), dict(good, ip='2001:db8::40'),
            dict(good, ip='0.0.0.0'), dict(good, ip='224.0.0.1'),
            dict(good, version=''), dict(good, version='3.0'), dict(good, version='3.6'), dict(good, version='x'),
            dict(good, sub=True), dict(good, node_id='a1'), dict(good, parent='gateway01'),
        )
        for row in bad_rows:
            with self.subTest(row=row):
                self.assertIsNone(scanner._configured_device_info(row))

    def test_version_is_normalized(self):
        from tinytuya import scanner
        for version in ('3.3', '3.30', 3.3):
            with self.subTest(version=version):
                self.assertEqual(scanner._configured_device_info(self._row(version=version))['version'], '3.3')

    def test_first_row_wins_for_duplicate_ip_or_id(self):
        from tinytuya import scanner
        rows = [self._row(name='first'),
                self._row(name='same ip', id='yyyyyyyyyyyyyyyyyyyy'),
                self._row(name='same id', ip='192.0.2.30')]
        candidates = scanner._configured_candidates(rows, set(), set())
        self.assertEqual([info['name'] for info in candidates.values()], ['first'])

    # --- ConfiguredDevice ---

    def _configured_device(self):
        from tinytuya import scanner
        options = {'connect_timeout': 3, 'data_timeout': 3, 'termcolors': MagicMock(),
                   'verbose': False, 'retries': 2, 'tuyadevices': [], 'keylist': []}
        info = scanner._configured_device_info(self._row())
        return scanner.ConfiguredDevice(info['ip'], info, options, False)

    def test_single_connect_attempt(self):
        dev = self._configured_device()
        self.assertEqual(dev.retries, 0)
        dev.timeout()  # first timeout is final
        self.assertTrue(dev.remove)
        self.assertFalse(dev.found)

    def test_found_only_on_decoded_status(self):
        for finished, dps, err, expected in ((True, {'dps': {'1': True}}, '', True),
                                             (True, None, 'Unable to poll', False),
                                             (False, None, 'No response', False)):
            with self.subTest(finished=finished, err=err):
                dev = self._configured_device()
                dev.finished = finished
                dev.deviceinfo['dps'] = dps
                dev.deviceinfo['err'] = err
                dev.close()
                self.assertIs(dev.found, expected)

class TestServerStaticFiles(unittest.TestCase):
    """server/server.py get_static() must only serve files inside the web folder."""

    @classmethod
    def setUpClass(cls):
        # compile just get_static(): importing server.py loads devices.json and installs signal handlers
        import ast, os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server', 'server.py')
        tree = ast.parse(open(path, encoding='utf-8').read())
        func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'get_static')
        cls.code = compile(ast.Module(body=[func], type_ignores=[]), path, 'exec')
        cls.get_static = staticmethod(cls.load(os))

    @classmethod
    def load(cls, os_module):
        """get_static() bound to os_module, so it can run with Windows path rules too."""
        namespace = {'os': os_module}
        exec(cls.code, namespace)
        return namespace['get_static']

    def setUp(self):
        import os, tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.web = os.path.join(self.tmp.name, 'web')
        os.makedirs(os.path.join(self.web, 'css'))
        for name, body in (('web/index.html', b'<html>'), ('web/css/site.css', b'body{}'), ('tinytuya.json', b'{"apiSecret": "s"}')):
            with open(os.path.join(self.tmp.name, name), 'wb') as f:
                f.write(body)

    def test_serves_files_in_the_web_folder(self):
        self.assertEqual(self.get_static(self.web, '/'), (b'<html>', 'text/html'))
        self.assertEqual(self.get_static(self.web, '/index.html?v=2'), (b'<html>', 'text/html'))
        self.assertEqual(self.get_static(self.web, '/css/site.css'), (b'body{}', 'text/css'))
        self.assertEqual(self.get_static(self.web, '/missing.js'), (None, None))
        self.assertEqual(self.get_static(self.web, '/css'), (None, None))  # a directory is not a file

    def test_refuses_paths_outside_the_web_folder(self):
        import os
        for path in ('/../tinytuya.json', '/css/../../tinytuya.json', '//' + os.path.join(self.tmp.name, 'tinytuya.json').lstrip('/'),
                     '//etc/passwd', '/' + os.path.join(self.tmp.name, 'tinytuya.json')):
            with self.subTest(path=path):
                self.assertEqual(self.get_static(self.web, path), (None, None))

    def test_refuses_another_windows_drive_without_raising(self):
        # on Windows, "D:/..." replaces web_root; os.path.commonpath() would raise ValueError here
        import ntpath, types
        win_get_static = self.load(types.SimpleNamespace(path=ntpath, sep='\\'))
        for path in ('/D:/secret.txt', '//D:/secret.txt', '/C:/Windows/win.ini', '/../tinytuya.json'):
            with self.subTest(path=path):
                self.assertEqual(win_get_static('C:\\tinytuya\\server\\web', path), (None, None))

    def test_refuses_an_embedded_nul_without_raising(self):
        # BaseHTTPRequestHandler passes a raw NUL through; realpath() would raise ValueError
        self.assertEqual(self.get_static(self.web, '/index.html\x00.js'), (None, None))

    def test_refuses_a_sibling_folder_with_the_same_prefix(self):
        # "web2" starts with "web"; the check must compare whole path components
        import os
        os.makedirs(os.path.join(self.tmp.name, 'web2'))
        with open(os.path.join(self.tmp.name, 'web2', 'x.html'), 'wb') as f:
            f.write(b'no')
        self.assertEqual(self.get_static(self.web, '/../web2/x.html'), (None, None))

    def test_refuses_a_symlink_that_leaves_the_web_folder(self):
        import os
        os.symlink(os.path.join(self.tmp.name, 'tinytuya.json'), os.path.join(self.web, 'creds.json'))
        self.assertEqual(self.get_static(self.web, '/creds.json'), (None, None))


class TestScannerRobustness(unittest.TestCase):
    """scanner.devices() must not crash on malformed devices.json rows or an early
    Ctrl-C, and must not dispatch events for a socket a device has replaced."""

    DEV_ID = 'abcdefghijklmnopqrst'

    def _run(self, rows, select_fn=None, sleep_fn=None, payload=None, **kwargs):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        udp, tcp = MagicMock(), MagicMock()  # UDP listeners, and the TCP socket a polled device opens
        if payload:
            udp.recvfrom.return_value = (b'packet', (payload['ip'], scanner.UDPPORT))
        delivered = []

        def default_select(read_socks, write_socks, error_socks, timeout):
            if payload and not delivered and read_socks:
                delivered.append(True)
                return ([read_socks[0]], [], [])
            return ([], [], [])

        out = io.StringIO()
        with patch.object(scanner.socket, 'socket', side_effect=lambda *a, **k: tcp if a[1:2] == (scanner.socket.SOCK_STREAM,) else udp), \
                patch.object(scanner.select, 'select', side_effect=select_fn or default_select), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner, 'send_discovery_request'), \
                patch.object(scanner, 'save_snapshotfile'), \
                patch.object(scanner, 'DEVICEFILE', '/nonexistent/tinytuya-test-devices.json'), \
                patch.object(tinytuya, 'decrypt_udp', side_effect=lambda data: json.dumps(payload)), \
                patch.object(scanner.time, 'sleep', side_effect=sleep_fn), \
                redirect_stdout(out):
            result = scanner.devices(color=False, tuyadevices=rows, **kwargs)
        return result, out.getvalue()

    def test_malformed_rows_do_not_crash_a_scan(self):
        cases = {
            'row without key': [{'id': self.DEV_ID, 'name': 'No Key Field'}],
            'non-dict row': ['not-a-row', {'id': self.DEV_ID, 'key': '', 'name': 'ok'}],
            'row without id': [{'key': LOCAL_KEY, 'name': 'No Id'}],
        }
        for label, rows in cases.items():
            with self.subTest(label):
                result, _ = self._run(rows, verbose=True, scantime=0.1)
                self.assertEqual(result, {})

    def test_broadcast_lookup_skips_malformed_rows(self):
        rows = ['some-id-string', {'id': self.DEV_ID}]  # a non-dict row, and a row with only an id
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.11', 'version': '3.3', 'productKey': 'p'}
        result, _ = self._run(rows, payload=payload, byID=True, scantime=0.1)
        self.assertEqual(result[self.DEV_ID]['name'], '')
        self.assertEqual(result[self.DEV_ID]['key'], '')

    def test_keyless_row_keeps_its_name(self):
        row = {'id': self.DEV_ID, 'key': '', 'name': 'Keyless Lamp'}
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.11', 'version': '3.3', 'productKey': 'p'}
        result, out = self._run([row], payload=payload, verbose=True, byID=True, scantime=0.1)
        self.assertEqual(result[self.DEV_ID]['name'], 'Keyless Lamp')
        self.assertIn('Missing Local Key: 1', out)

    def test_force_scan_key_match_skips_malformed_rows(self):
        from types import SimpleNamespace
        from tinytuya import scanner
        rows = ['not-a-row', {'name': 'No Id', 'key': LOCAL_KEY}, {'id': self.DEV_ID, 'key': LOCAL_KEY}]
        dev = SimpleNamespace(options={'tuyadevices': rows}, deviceinfo={'key': LOCAL_KEY},
                              device=SimpleNamespace(id=None), key_found=False)
        scanner.ForceScannedDevice.found_key(dev)
        self.assertTrue(dev.key_found)
        self.assertEqual((dev.deviceinfo['id'], dev.deviceinfo['name'], dev.device.id), (self.DEV_ID, '', self.DEV_ID))

    def test_device_listing_skips_malformed_rows(self):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner
        rows = ['not-a-row', {'key': LOCAL_KEY}, {'id': ['not', 'a', 'string'], 'key': LOCAL_KEY},
                {'id': self.DEV_ID, 'key': LOCAL_KEY}]
        with patch.object(scanner, 'devices', return_value={}) as scan, \
                patch.object(tinytuya, 'load_devicefile', return_value=rows), \
                patch.object(scanner, 'save_snapshotfile'), redirect_stdout(io.StringIO()):
            scanner.alldevices(color=False, assume_yes=True)
        self.assertEqual(scan.call_args.kwargs['wantids'], [self.DEV_ID])
        self.assertIs(scan.call_args.kwargs['tuyadevices'], rows)

    def test_poll_send_failure_is_logged_not_printed(self):
        # a device that drops the connection mid-poll is reported as "Send Poll failed", without a traceback on stdout
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace
        from tinytuya import scanner
        sock = MagicMock()
        sock.sendall.side_effect = BrokenPipeError(32, 'Broken pipe')
        dev = SimpleNamespace(ip='192.0.2.10', sock=sock, debug=False, deviceinfo={}, send_queue=[], write=True, read=False,
                              options={'data_timeout': 5}, get_peer=lambda: '192.0.2.10', timeout=MagicMock(),
                              device=tinytuya.Device(self.DEV_ID, '192.0.2.10', LOCAL_KEY, version=3.3))
        out = io.StringIO()
        with self.assertLogs(scanner.log, logging.DEBUG) as logs, redirect_stdout(out):
            scanner.PollDevice.write_data(dev)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(dev.deviceinfo['err'], 'Send Poll failed')
        dev.timeout.assert_called_once_with()
        self.assertTrue(any(r.exc_info and isinstance(r.exc_info[1], BrokenPipeError) for r in logs.records))
    def _force_scanned_device(self):
        from tinytuya import scanner
        options = {'connect_timeout': 3, 'data_timeout': 3, 'termcolors': scanner.TermColors(*tinytuya.termcolor(False)),
                   'verbose': False, 'retries': 2, 'tuyadevices': [], 'keylist': []}
        with patch.object(scanner.socket, 'socket', return_value=MagicMock()):
            dev = scanner.ForceScannedDevice('192.0.2.10', None, options, False)
        dev.sock.getpeername.return_value = ('192.0.2.10', 6668)
        return dev

    def test_force_scan_resends_a_queued_frame_once(self):
        # a failed first send is queued and retried on the next write event; the retry used to
        # re-encode the already-encoded bytes and crash the scan with AttributeError
        dev = self._force_scanned_device()
        dev.sock.sendall.side_effect = [BrokenPipeError(32, 'Broken pipe'), None]
        dev.write_data()
        self.assertEqual(len(dev.send_queue), 1)
        dev.write_data()
        self.assertEqual(dev.send_queue, [])
        # the retry is a fresh frame (next seqno) carrying the same command and payload
        first, retry = [mh.unpack_message(c.args[0], no_retcode=True) for c in dev.sock.sendall.call_args_list]
        self.assertEqual((retry.cmd, retry.payload, retry.crc_good), (first.cmd, first.payload, True))
        self.assertEqual(retry.seqno, first.seqno + 1)

    def test_brute_forced_key_poll_goes_through_the_guarded_write(self):
        # brute_force_found_key() also runs from timeout(), which the scan loop calls outside
        # its socket-error guard; it used to send the poll directly and abort the scan on a dropped connection
        from tinytuya import scanner
        dev = self._force_scanned_device()
        dev.cur_key = scanner.KeyObj(self.DEV_ID, LOCAL_KEY)
        dev.sock.sendall.side_effect = BrokenPipeError(32, 'Broken pipe')
        dev.brute_force_found_key()
        dev.sock.sendall.assert_not_called()
        self.assertEqual((dev.step, dev.write, dev.read, len(dev.send_queue)), (scanner.FSCAN_FINAL_POLL, True, False, 1))
        dev.sock.sendall.side_effect = None
        dev.write_data()
        sent = mh.unpack_message(dev.sock.sendall.call_args.args[0], no_retcode=True)
        self.assertEqual((sent.cmd, dev.send_queue, dev.read), (tinytuya.DP_QUERY, [], True))

    def test_socket_error_times_out_the_device_not_the_scan(self):
        # e.g. a v3.4/3.5 device drops the connection during key negotiation
        from tinytuya import scanner
        dev = MagicMock(ip='192.0.2.10')
        with self.assertLogs(scanner.log, logging.DEBUG):
            scanner._handle_socket_event(dev, MagicMock(side_effect=ConnectionResetError(54, 'reset')))
        dev.timeout.assert_called_once_with()
        # anything other than a socket error is a bug and still surfaces
        with self.assertRaises(KeyError):
            scanner._handle_socket_event(dev, MagicMock(side_effect=KeyError('x')))

    def test_socket_error_in_a_device_does_not_abort_a_scan(self):
        from tinytuya import scanner
        payload = {'gwId': self.DEV_ID, 'ip': '192.0.2.11', 'version': '3.3', 'productKey': 'p'}
        rows = [{'id': self.DEV_ID, 'key': LOCAL_KEY, 'name': 'Lamp'}]
        for event in ('write_data', 'read_data'):
            calls = []

            def select(read_socks, write_socks, error_socks, timeout):
                calls.append(1)
                if len(calls) == 1 and read_socks:
                    return ([read_socks[0]], [], [])  # the broadcast
                if write_socks and len(calls) < 4:
                    dev_sock = write_socks[0]  # the polled device's TCP socket
                    return ([], [dev_sock], []) if event == 'write_data' else ([dev_sock], [], [])
                return ([], [], [])
            # the fake clock lets the device's timeout and retries play out instantly
            with self.subTest(event=event), patch.object(scanner, 'time', _FakeScanClock()), \
                    patch.object(scanner.PollDevice, event, side_effect=BrokenPipeError(32, 'Broken pipe')) as handler:
                result, _ = self._run(rows, select_fn=select, payload=payload, byID=True, scantime=0.1)
                self.assertTrue(handler.called)
                self.assertIn(self.DEV_ID, result)

    def test_interrupt_on_first_pass_does_not_raise(self):
        calls = []

        def sleep(seconds):
            calls.append(seconds)
            if len(calls) == 1:
                raise KeyboardInterrupt
        result, _ = self._run([], sleep_fn=sleep, discover=False)
        self.assertEqual(result, {})

    def test_event_for_replaced_socket_is_not_dispatched(self):
        from tinytuya import scanner
        old_sock, new_sock = MagicMock(), MagicMock()
        calls = []

        def connect(dev):
            dev.sock, dev.write, dev.read = old_sock, True, False
            dev.timeo = scanner.time.time() + 0.05
            dev.retries = 0

        def write_data(dev):
            calls.append('write')
            dev.sock = new_sock  # the device reconnected while handling this event

        def read_data(dev):
            calls.append('read')

        def select(read_socks, write_socks, error_socks, timeout):
            if old_sock in write_socks:
                return ([old_sock], [old_sock], [])
            return ([], [], [])

        snapshot = {'192.0.2.10': {'gwId': self.DEV_ID, 'version': '3.3', 'key': LOCAL_KEY, 'ip': '192.0.2.10'}}
        with patch.object(scanner.PollDevice, 'connect', connect), \
                patch.object(scanner.PollDevice, 'write_data', write_data), \
                patch.object(scanner.PollDevice, 'read_data', read_data):
            self._run([], select_fn=select, discover=False, snapshot=snapshot)
        self.assertEqual(calls, ['write'])


# ---------------------------------------------------------------------------
# Wire-path tests: real Device API -> framing -> crypto -> fake device -> back
# ---------------------------------------------------------------------------

import hashlib
import hmac as _hmac_mod
import sys
import types
import zlib

from tinytuya.core import command_types as CT

# tinytuya.core re-exports classes over some module names, so patch via sys.modules
_xenon_mod = sys.modules['tinytuya.core.XenonDevice']
_device_mod = sys.modules['tinytuya.core.Device']
_cloud_mod = sys.modules['tinytuya.Cloud']

HAS_GCM = bool(mh.AESCipher.CRYPTOLIB_HAS_GCM)
WRONG_KEY = 'fedcba9876543210'


# PROTOCOL.md "Command IDs".  Kept apart from command_types (like HEADERLESS below) so a
# wrong ID in the library fails the round trips instead of agreeing with itself.
CMD = types.SimpleNamespace(
    SESS_KEY_NEG_START=0x03, SESS_KEY_NEG_RESP=0x04, SESS_KEY_NEG_FINISH=0x05, CONTROL=0x07, STATUS=0x08,
    HEART_BEAT=0x09, DP_QUERY=0x0A, CONTROL_NEW=0x0D, DP_QUERY_NEW=0x10, UPDATEDPS=0x12, UDP_NEW=0x13,
    BOARDCAST_LPV34=0x23, REQ_DEVINFO=0x25, LAN_EXT_STREAM=0x40)


class FakeTuyaDevice(object):
    """Device side of the Tuya LAN protocol (3.1/3.3/3.4/3.5), per PROTOCOL.md.

    Transport-agnostic: connect() starts a TCP session and receive_bytes(data)
    returns the bytes the device answers with, so any I/O layer (the sync
    socket shim below, or a future asyncio transport) can drive it.  It frames
    and parses 55AA/6699 itself, from PROTOCOL.md, so a framing change made on
    both sides of message_helper still fails; only AES comes from AESCipher.
    Frames it cannot authenticate or decrypt, or that break the version-header rule
    (3.2+ commands outside HEADERLESS carry it), or lack this version's frame
    prefix and suffix are dropped.

    Knobs: dps / children ({cid: dps}) hold state; device22 answers DP_QUERY
    with "data unvalid"; raw_reply replaces the status body of query replies;
    retcode is put in CONTROL acks; silent records requests but never answers;
    corrupt_tags sends that many data replies with a broken GCM tag; push()
    queues unsolicited STATUS updates; noise is junk sent ahead of the next
    reply; connect_error / send_error are raised by connect() / receive_bytes();
    forge_hmac answers session negotiation with a bad HMAC (an impostor).
    """

    NONCE = b'fedcba9876543210'
    # PROTOCOL.md "Version Header": commands sent without it.  Kept apart from
    # header.NO_PROTOCOL_HEADER_CMDS so a change to that list fails the round trips.
    HEADERLESS = frozenset((CMD.DP_QUERY, CMD.DP_QUERY_NEW, CMD.UPDATEDPS, CMD.HEART_BEAT, CMD.SESS_KEY_NEG_START,
                            CMD.SESS_KEY_NEG_RESP, CMD.SESS_KEY_NEG_FINISH, CMD.LAN_EXT_STREAM))
    # PROTOCOL.md "Packet Format": 55AA = prefix, seq, cmd, length (from the retcode/payload
    # through the footer); 6699 = prefix, 2 reserved bytes, seq, cmd, length (IV through tag),
    # with those 14 bytes after the prefix as the GCM AAD, then a footer outside the length.
    PREFIX_55AA, SUFFIX_55AA, HEADER_55AA = b'\x00\x00\x55\xaa', b'\x00\x00\xaa\x55', 16
    PREFIX_6699, SUFFIX_6699, HEADER_6699 = b'\x00\x00\x66\x99', b'\x00\x00\x99\x66', 18

    def __init__(self, version, local_key=LOCAL_KEY, dev_id='DEVICE_ID_HERE', dps=None, children=None, device22=False):
        self.version = float(version)
        self.vbytes = str(self.version).encode('latin1')
        self.real_key = local_key.encode('latin1')
        self.key = self.real_key
        self.dev_id = dev_id
        self.dps = dict(dps) if dps else {'1': False, '2': 0}
        self.children = children or {}
        self.device22 = device22
        self.raw_reply = None
        self.retcode = 0
        self.silent = False
        self.corrupt_tags = 0
        self.noise = b''
        self.connect_error = None
        self.send_error = None
        self.forge_hmac = False
        self.requests = []      # (cmd, decoded JSON) for every data command received
        self.dropped = 0        # frames rejected for any of the reasons above
        self.connections = 0
        self.negotiations = 0
        self._pushes = []
        self._rx = b''
        self._seqno = 100       # v3.5 devices use a global counter, not the request seqno
        self._client_nonce = None

    def connect(self):
        if self.connect_error:
            raise self.connect_error
        self.connections += 1
        self.key = self.real_key
        self._rx = b''

    def push(self, dps, cid=None):
        self._pushes.append(self._status(dps, cid))

    def receive_bytes(self, data):
        if self.send_error:
            raise self.send_error
        self._rx += data
        out = b''
        while len(self._rx) >= 4:
            is_6699 = self._rx[:4] == self.PREFIX_6699
            if not is_6699 and self._rx[:4] != self.PREFIX_55AA:
                self.dropped += 1   # not a frame start: discard what we have
                self._rx = b''
                break
            header_len = self.HEADER_6699 if is_6699 else self.HEADER_55AA
            if len(self._rx) < header_len:
                break  # wait for the rest of the header
            total = header_len + struct.unpack('>I', self._rx[header_len - 4:header_len])[0] + (4 if is_6699 else 0)
            if len(self._rx) < total:
                break
            frame, self._rx = self._rx[:total], self._rx[total:]
            out += self._handle(frame)
        return out

    def _status(self, dps, cid=None):
        if self.version >= 3.4:
            body = {'protocol': 4, 't': 1700000000, 'data': {'dps': dps}}
            if cid:
                body['data']['cid'] = cid
        else:
            body = {'devId': self.dev_id, 'dps': dps}
            if cid:
                body['cid'] = cid
        return json.dumps(body).encode()

    def _open(self, cmd, payload):
        cipher = mh.AESCipher(self.key)
        if self.version < 3.2:
            if cmd != CMD.CONTROL:
                return payload  # 3.1 sends everything but CONTROL in the clear
            enc = payload[19:]
            if payload[:19] != self._envelope_31(enc):
                raise ValueError('3.1 CONTROL lacks the "3.1" + MD5 envelope')
            return cipher.decrypt(enc, decode_text=False)
        want_header = cmd not in self.HEADERLESS
        if self.version < 3.4:
            # the 3.2/3.3 header is sent in the clear, ahead of the ciphertext
            if payload.startswith(self.vbytes + 12 * b'\x00') != want_header:
                raise ValueError('version header rule broken')
            return cipher.decrypt(payload[15 if want_header else 0:], False, decode_text=False)
        if self.version < 3.5:
            payload = cipher.decrypt(payload, False, decode_text=False)
        # 3.4/3.5 carry the header inside the encryption (3.5: the GCM frame layer)
        if want_header:
            if not payload.startswith(self.vbytes + 12 * b'\x00'):
                raise ValueError('version header missing')
            payload = payload[15:]
        return payload

    def _seal(self, body, header=False):
        """Encrypt a reply payload the way this protocol version does."""
        hdr = self.vbytes + 12 * b'\x00' if header else b''
        if not body or self.version >= 3.5:
            return hdr + body if body else b''
        cipher = mh.AESCipher(self.key)
        if self.version >= 3.4:
            return cipher.encrypt(hdr + body, False)
        if self.version >= 3.2:
            return hdr + cipher.encrypt(body, False)
        if not header:
            return body  # v3.1 query replies are plaintext
        enc = cipher.encrypt(body)
        return self._envelope_31(enc) + enc

    def _envelope_31(self, enc):
        """The "3.1" + MD5-slice prefix of an encrypted 3.1 CONTROL payload."""
        md5 = hashlib.md5(b'data=' + enc + b'||lpv=3.1||' + self.key).hexdigest()
        return b'3.1' + md5[8:24].encode()

    def _mac(self, data):
        """55AA integrity field: HMAC-SHA256 for 3.4, CRC32 before that."""
        if self.version >= 3.4:
            return _hmac_mod.new(self.key, data, hashlib.sha256).digest()
        return struct.pack('>I', zlib.crc32(data) & 0xFFFFFFFF)

    def _frame(self, cmd, payload, seqno, retcode=0, data=True):
        """A device->client frame; the retcode leads the payload (inside the GCM ciphertext for 6699)."""
        body = struct.pack('>I', retcode) + payload
        if self.version >= 3.5:
            self._seqno += 1
            header = struct.pack('>4sHIII', self.PREFIX_6699, 0, self._seqno, cmd, 12 + len(body) + 16)
            iv = struct.pack('>III', self._seqno, cmd, 0x5a5a5a5a)  # unique per frame
            sealed = mh.AESCipher(self.key).encrypt(body, use_base64=False, pad=False, iv=iv, header=header[4:])
            if data and self.corrupt_tags:
                self.corrupt_tags -= 1
                sealed = sealed[:-1] + bytes([sealed[-1] ^ 1])
            frame = header + sealed + self.SUFFIX_6699
        else:
            header = struct.pack('>4sIII', self.PREFIX_55AA, seqno, cmd, len(body) + len(self._mac(b'')) + 4)
            frame = header + body + self._mac(header + body) + self.SUFFIX_55AA
        noise, self.noise = self.noise, b''
        return noise + frame

    def _unframe(self, frame):
        """(seqno, cmd, payload) of a client->device frame (no retcode), or ValueError."""
        if self.version >= 3.5:
            if frame[:4] != self.PREFIX_6699 or frame[-4:] != self.SUFFIX_6699:
                raise ValueError('not a 6699 frame')
            seqno, cmd = struct.unpack('>II', frame[6:14])
            iv, ciphertext, tag = frame[18:30], frame[30:-20], frame[-20:-4]
            try:
                payload = mh.AESCipher(self.key).decrypt(ciphertext, use_base64=False, decode_text=False, iv=iv,
                                                        header=frame[4:18], tag=tag)
            except Exception:  # each backend raises its own InvalidTag/ValueError
                raise ValueError('bad GCM tag')
            return seqno, cmd, payload
        mac_len = len(self._mac(b''))
        if frame[:4] != self.PREFIX_55AA or frame[-4:] != self.SUFFIX_55AA:
            raise ValueError('not a 55AA frame')
        if frame[-4 - mac_len:-4] != self._mac(frame[:-4 - mac_len]):
            raise ValueError('bad CRC/HMAC')
        seqno, cmd = struct.unpack('>II', frame[4:12])
        return seqno, cmd, frame[16:-4 - mac_len]

    def _handle(self, frame):
        try:
            seqno, cmd, payload = self._unframe(frame)
            payload = self._open(cmd, payload)
            if cmd == CMD.SESS_KEY_NEG_START:
                return self._negotiate_start(payload, seqno)
            if cmd == CMD.SESS_KEY_NEG_FINISH:
                return self._negotiate_finish(payload)
            request = json.loads(payload) if payload else {}
        except ValueError:
            self.dropped += 1
            return b''
        self.requests.append((cmd, request))
        if self.silent:
            return b''
        out = b''.join(self._frame(CMD.STATUS, self._seal(p, True), seqno) for p in self._pushes)
        self._pushes = []
        return out + self._reply(cmd, seqno, request)

    def _negotiate_start(self, client_nonce, seqno):
        self._client_nonce = client_nonce
        body = self.NONCE + _hmac_mod.new(self.real_key, client_nonce, hashlib.sha256).digest()
        if self.forge_hmac:
            body = body[:16] + bytes(32)
        return self._frame(CMD.SESS_KEY_NEG_RESP, self._seal(body), seqno, data=False)

    def _negotiate_finish(self, rkey_hmac):
        if rkey_hmac != _hmac_mod.new(self.real_key, self.NONCE, hashlib.sha256).digest():
            raise ValueError('client HMAC of the device nonce is wrong')
        tmp = bytes(a ^ b for (a, b) in zip(self._client_nonce, self.NONCE))
        cipher = mh.AESCipher(self.real_key)
        if self.version >= 3.5:
            self.key = cipher.encrypt(tmp, use_base64=False, pad=False, iv=self._client_nonce[:12])[12:28]
        else:
            self.key = cipher.encrypt(tmp, False, pad=False)
        self.negotiations += 1
        return b''

    def _reply(self, cmd, seqno, request):
        data = request.get('data') if isinstance(request.get('data'), dict) else {}
        cid = request.get('cid') or data.get('cid')
        state = self.children[cid] if cid else self.dps
        if cmd in (CMD.DP_QUERY, CMD.DP_QUERY_NEW):
            if self.device22 and cmd == CMD.DP_QUERY:
                return self._frame(cmd, self._seal(b'json obj data unvalid'), seqno)
            body = self.raw_reply if self.raw_reply is not None else self._status(state, cid)
            return self._frame(cmd, self._seal(body), seqno)
        if cmd in (CMD.CONTROL, CMD.CONTROL_NEW):
            dps = data.get('dps', request.get('dps', {}))
            if self.device22 and cmd == CMD.CONTROL_NEW and all(v is None for v in dps.values()):
                # device22 status query: answer with the requested DPs only
                found = {k: state[k] for k in dps if k in state}
                return self._frame(cmd, self._seal(self._status(found, cid)), seqno)
            state.update(dps)
            # empty ack carrying the retcode, then a STATUS push with the new values
            ack = self._frame(cmd, b'', seqno, self.retcode)
            return ack + self._frame(CMD.STATUS, self._seal(self._status(dps, cid), True), seqno)
        if cmd == CMD.HEART_BEAT:
            return self._frame(cmd, b'', seqno)
        return b''


class _FakeSocket(object):
    """In-memory TCP socket wired to a FakeTuyaDevice.  recv() on an empty
    buffer raises socket.timeout immediately, so no test waits on a clock."""

    def __init__(self, device, chunk=None):
        self.device = device
        self.chunk = chunk
        self.rx = b''

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.device.connect()

    def sendall(self, data):
        self.rx += self.device.receive_bytes(data)

    def recv(self, length):
        if not self.rx:
            raise _socket_mod.timeout('timed out')
        length = min(length, self.chunk or length)
        data, self.rx = self.rx[:length], self.rx[length:]
        return data

    def close(self):
        pass


class _FakeClock(object):
    """Stand-in for the time module: sleep() advances time instantly."""

    def __init__(self):
        self.now = 1700000000.0
        self.slept = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.slept += seconds


class _WireTestCase(unittest.TestCase):
    """Base for tests that run the real Device API against a FakeTuyaDevice."""

    VERSION = None

    def setUp(self):
        self.clock = _FakeClock()
        self._patch(_xenon_mod, 'time', self.clock)
        self._patch(_device_mod, 'time', self.clock)
        self._patch(_xenon_mod, 'DEVICEFILE', '/nonexistent/devices.json')

    def _patch(self, target, name, value):
        p = patch.object(target, name, value)
        p.start()
        self.addCleanup(p.stop)

    def attach(self, fake, chunk=None):
        """Route every socket the library opens to `fake`."""
        names = ('AF_INET', 'AF_INET6', 'SOCK_STREAM', 'IPPROTO_TCP', 'TCP_NODELAY', 'timeout')
        sockmod = types.SimpleNamespace(**{n: getattr(_socket_mod, n) for n in names})
        sockmod.socket = lambda family, kind: _FakeSocket(fake, chunk)
        self._patch(_xenon_mod, 'socket', sockmod)
        return fake

    def make(self, version=None, local_key=LOCAL_KEY, dev_id='DEVICE_ID_HERE', chunk=None, **fake_kw):
        version = version or self.VERSION
        if version >= 3.5 and not HAS_GCM:
            self.skipTest("crypto backend has no GCM support")
        fake = self.attach(FakeTuyaDevice(version, dev_id=dev_id, **fake_kw), chunk)
        d = tinytuya.Device(dev_id, '192.0.2.10', local_key, version=version)
        self.addCleanup(d.close)
        return d, fake


class _RoundTrip(object):
    """Public API round trips; mixed into one TestCase per protocol version."""

    def test_status(self):
        d, fake = self.make(dps={'1': True, '2': 42})
        result = d.status()
        self.assertEqual(result['dps'], {'1': True, '2': 42})
        cmd, request = fake.requests[-1]
        self.assertEqual(cmd, CMD.DP_QUERY_NEW if self.VERSION >= 3.4 else CMD.DP_QUERY)
        if self.VERSION < 3.4:
            self.assertEqual(request['devId'], 'DEVICE_ID_HERE')
        self.assertEqual(fake.negotiations, 1 if self.VERSION >= 3.4 else 0)

    def test_set_value(self):
        d, fake = self.make()
        result = d.set_value(2, 77)
        self.assertEqual(result['dps'], {'2': 77})
        self.assertEqual(fake.dps['2'], 77)
        cmd, request = fake.requests[-1]
        if self.VERSION >= 3.4:
            self.assertEqual(cmd, CMD.CONTROL_NEW)
            self.assertEqual(request['data']['dps'], {'2': 77})
        else:
            self.assertEqual(cmd, CMD.CONTROL)
            self.assertEqual(request['dps'], {'2': 77})
        self.assertEqual(d.cmd_retcode, 0)

    def test_set_multiple_values(self):
        d, fake = self.make()
        result = d.set_multiple_values({1: True, '2': 50})
        self.assertEqual(result['dps'], {'1': True, '2': 50})
        self.assertEqual(fake.dps, {'1': True, '2': 50})
        self.assertEqual(len(fake.requests), 1, 'both DPs go out in one CONTROL frame')

    def test_heartbeat(self):
        d, fake = self.make()
        # devices answer a heartbeat with an empty payload, which reads as None
        self.assertIsNone(d.heartbeat(nowait=False))
        self.assertEqual(fake.requests[-1][0], CMD.HEART_BEAT)
        self.assertEqual(d.cmd_retcode, 0)

    def test_new_connection_per_call(self):
        d, fake = self.make()
        d.status()
        d.set_value(1, True)
        # non-persistent sockets reconnect (and renegotiate 3.4+ session keys) per call
        self.assertEqual(fake.connections, 2)
        self.assertEqual(fake.negotiations, 2 if self.VERSION >= 3.4 else 0)

    def test_persistent_socket_reused(self):
        d, fake = self.make()
        d.set_socketPersistent(True)
        d.status()
        self.assertEqual(d.set_value(1, True)['dps'], {'1': True})
        self.assertEqual(fake.connections, 1)
        self.assertEqual(d.cached_status(nowait=True)['dps'], {'1': True, '2': 0})

    def test_partial_reads_and_leading_junk(self):
        # 3-byte recv() chunks and junk before the prefix exercise the resync loop
        d, fake = self.make(dps={'1': True}, chunk=3)
        fake.noise = b'\x01\x02\x03junk'
        self.assertEqual(d.status()['dps'], {'1': True})
        self.assertEqual(len(fake.requests), 1, 'resynced without a retry')

    def test_requests_fed_one_byte_at_a_time(self):
        # a streaming transport may hand the device any fragment, even a partial header
        d, fake = self.make()
        whole = fake.receive_bytes
        fake.receive_bytes = lambda data: b''.join(whole(data[i:i + 1]) for i in range(len(data)))
        self.assertEqual(d.set_value(2, 5)['dps'], {'2': 5})
        self.assertEqual(d.status()['dps'], {'1': False, '2': 5})
        self.assertEqual(fake.dropped, 0)


class TestWireV31(_RoundTrip, _WireTestCase):
    VERSION = 3.1


class TestWireV33(_RoundTrip, _WireTestCase):
    VERSION = 3.3


class TestWireV34(_RoundTrip, _WireTestCase):
    VERSION = 3.4


class TestWireV35(_RoundTrip, _WireTestCase):
    VERSION = 3.5


class TestWireBehavior(_WireTestCase):
    """Error handling, retries and device quirks on the wire path."""

    def test_device22_detected_and_retried_with_dps_list(self):
        d, fake = self.make(3.3, dev_id='abcdefghijklmnop123456', device22=True, dps={'1': True, '2': 5})
        result = d.status()
        self.assertEqual(result['dps'], {'1': True})
        self.assertEqual(d.dev_type, 'device22')
        # first a plain DP_QUERY, then CONTROL_NEW with an explicit null-valued DPS list
        self.assertEqual([c for c, _ in fake.requests], [CMD.DP_QUERY, CMD.CONTROL_NEW])
        self.assertEqual(fake.requests[1][1]['dps'], {'1': None})

    def test_v32_detects_available_dps_at_set_version(self):
        # 3.2 is forced to device22 and brute-forces the DP list on set_version()
        d, fake = self.make(3.2, device22=True, dps={'1': True, '5': 3, '102': 0})
        self.assertEqual(d.dev_type, 'device22')
        self.assertEqual(d.dps_to_request, {'1': None, '5': None, '102': None})
        self.assertTrue(all(cmd == CMD.CONTROL_NEW for cmd, _ in fake.requests))
        self.assertEqual(d.status()['dps'], {'1': True, '5': 3, '102': 0})

    def test_invalid_json_reply(self):
        d, fake = self.make(3.3)
        fake.raw_reply = b'{"dps":{"1":tru'
        result = d.status()
        self.assertEqual(result['Err'], str(tinytuya.ERR_JSON))
        self.assertEqual(result['invalid_json'], '{"dps":{"1":tru')
        # undecodable UTF-8 is replaced, and the raw bytes are handed back too
        fake.raw_reply = b'{"dps":{"1":"\xff"}}'
        result = d.status()
        self.assertEqual(result['dps'], {'1': '\ufffd'})
        self.assertEqual(result['invalid_json'], b'{"dps":{"1":"\xff"}}')

    def test_connection_reset_returns_connect_error(self):
        d, fake = self.make(3.3)
        fake.send_error = ConnectionResetError()
        self.assertEqual(d.status()['Err'], str(tinytuya.ERR_CONNECT))
        self.assertEqual(fake.connections, d.socketRetryLimit + 1)

    def test_retcode_captured_from_matching_ack(self):
        for version in (3.3, 3.5):
            with self.subTest(version=version):
                d, fake = self.make(version)
                fake.retcode = 1
                d.set_value(1, True)
                # the STATUS push that follows must not overwrite the ack's retcode
                self.assertEqual(d.cmd_retcode, 1)

    def test_bad_gcm_tag_rejected_then_retried(self):
        d, fake = self.make(3.5, dps={'1': True})
        fake.corrupt_tags = 1
        with self.assertLogs(_xenon_mod.log, logging.DEBUG) as logs:
            self.assertEqual(d.status()['dps'], {'1': True})
        self.assertEqual(self._gcm_rejections(logs), 1)
        # the forged frame was discarded; the library reconnected and asked again
        self.assertEqual(fake.connections, 2)
        self.assertEqual(len(fake.requests), 2)

    def test_bad_gcm_tag_every_time_returns_payload_error(self):
        d, fake = self.make(3.5)
        fake.corrupt_tags = 1000
        with self.assertLogs(_xenon_mod.log, logging.DEBUG) as logs:
            result = d.status()
        self.assertEqual(result['Err'], str(tinytuya.ERR_PAYLOAD))
        self.assertNotIn('dps', result)
        self.assertGreater(self._gcm_rejections(logs), 1)

    @staticmethod
    def _gcm_rejections(logs):
        # assertLogs also keeps these expected tracebacks off stderr, where CI's
        # Python problem matcher would turn each one into a failure annotation
        return sum(1 for r in logs.records if r.exc_info and 'GCM authentication failed' in str(r.exc_info[1]))

    def test_command_ids_match_protocol_md(self):
        self.assertEqual({name: getattr(CT, name) for name in vars(CMD)}, vars(CMD))

    def test_header_skip_list_matches_protocol_md(self):
        self.assertEqual(set(mh.H.NO_PROTOCOL_HEADER_CMDS), FakeTuyaDevice.HEADERLESS)

    def test_fake_drops_a_bad_frame_suffix(self):
        fake = FakeTuyaDevice(3.3)
        fake.connect()
        msg = mh.TuyaMessage(1, CMD.DP_QUERY, None, mh.AESCipher(fake.key).encrypt(b'{}', False), 0, True, mh.H.PREFIX_55AA_VALUE, False)
        frame = mh.pack_message(msg)
        self.assertEqual(fake.receive_bytes(frame[:-4] + bytes(4)), b'')
        self.assertEqual((fake.dropped, fake.requests), (1, []))
        self.assertNotEqual(fake.receive_bytes(frame), b'', 'the same frame with its suffix is answered')

    def test_fake_drops_the_other_versions_frame_prefix(self):
        frames = {3.5: mh.TuyaMessage(1, CMD.DP_QUERY_NEW, None, b'{}', 0, True, mh.H.PREFIX_55AA_VALUE, False)}
        if HAS_GCM:
            frames[3.4] = mh.TuyaMessage(1, CMD.DP_QUERY_NEW, None, b'{}', 0, True, mh.H.PREFIX_6699_VALUE, True)
        for version, msg in frames.items():
            with self.subTest(version=version):
                fake = FakeTuyaDevice(version)
                fake.connect()
                self.assertEqual(fake.receive_bytes(mh.pack_message(msg, hmac_key=fake.key)), b'')
                self.assertEqual((fake.dropped, fake.requests), (1, []))

    def test_silent_device_times_out(self):
        d, fake = self.make(3.3)
        fake.silent = True
        result = d.status()
        self.assertEqual(result['Err'], str(tinytuya.ERR_TIMEOUT))
        # one try plus socketRetryLimit retries, with fake-clock back-off only
        self.assertEqual(len(fake.requests), d.socketRetryLimit + 1)
        self.assertGreater(self.clock.slept, 0)

    def test_offline_device(self):
        d, fake = self.make(3.3)
        fake.connect_error = _socket_mod.timeout('timed out')
        self.assertEqual(d.status()['Err'], str(tinytuya.ERR_OFFLINE))
        fake.connect_error = ConnectionRefusedError()
        self.assertEqual(d.status()['Err'], str(tinytuya.ERR_CONNECT))
        self.assertEqual(fake.connections, 0)

    def test_wrong_key_fails_session_negotiation(self):
        for version in (3.4, 3.5):
            with self.subTest(version=version):
                d, fake = self.make(version, local_key=WRONG_KEY)
                self.assertEqual(d.status()['Err'], str(tinytuya.ERR_KEY_OR_VER))
                self.assertGreater(fake.dropped, 0)
                self.assertEqual(fake.negotiations, 0)
                self.assertEqual(fake.requests, [])

    def test_forged_negotiation_hmac_rejected(self):
        for version in (3.4, 3.5):
            with self.subTest(version=version):
                d, fake = self.make(version)
                fake.forge_hmac = True
                self.assertEqual(d.status()['Err'], str(tinytuya.ERR_KEY_OR_VER))
                # the client must abort before FINISH and never send data
                self.assertEqual(fake.negotiations, 0)
                self.assertEqual(fake.requests, [])

    def test_bad_key_length_rejected_before_connecting(self):
        d, fake = self.make(3.3, local_key='short')
        self.assertEqual(d.status()['Err'], str(tinytuya.ERR_KEY_OR_VER))
        self.assertEqual(fake.connections, 0)

    def _gateway(self, version):
        if version >= 3.5 and not HAS_GCM:
            self.skipTest("crypto backend has no GCM support")
        fake = self.attach(FakeTuyaDevice(version, dev_id='GATEWAY_ID', children={'cidA': {'1': True}, 'cidB': {'1': False}}))
        gw = tinytuya.Device('GATEWAY_ID', '192.0.2.10', LOCAL_KEY, version=version, persist=True)
        self.addCleanup(gw.close)
        child_a = tinytuya.Device('CHILD_A', cid='cidA', parent=gw)
        child_b = tinytuya.Device('CHILD_B', cid='cidB', parent=gw)
        return fake, child_a, child_b

    def test_gateway_routes_replies_by_cid(self):
        for version in (3.3, 3.5):
            with self.subTest(version=version):
                fake, child_a, child_b = self._gateway(version)
                # an async update for child B arrives ahead of child A's reply
                fake.push({'1': True}, cid='cidB')
                result = child_a.status()
                self.assertEqual(result['dps'], {'1': True})
                self.assertIs(result['device'], child_a)
                cmd, request = fake.requests[-1]
                self.assertEqual(request.get('cid') or request['data']['cid'], 'cidA')
                # child B's update was queued for it, not lost or handed to A
                queued = child_b.receive()
                self.assertIs(queued['device'], child_b)
                self.assertEqual(queued['dps'], {'1': True})
                self.assertEqual(child_b.set_value(1, False)['dps'], {'1': False})
                self.assertEqual(fake.children['cidB'], {'1': False})


# ---------------------------------------------------------------------------
# Cloud tests: requests is replaced by a scripted fake Tuya Cloud
# ---------------------------------------------------------------------------

from urllib.parse import parse_qs, urlsplit

API_KEY = 'abcdefghijklmnop1234'
API_SECRET = '0123456789abcdef0123456789abcdef'
TOKEN_REPLY = {'success': True, 't': 1700000000000, 'result': {'access_token': 'TOKEN1', 'expire_time': 7200}}
TOKEN_INVALID = {'success': False, 'code': 1010, 'msg': 'token invalid'}


def _tuya_sign(t, method, path, token='', body='', headers=''):
    """Tuya's documented request signature, computed independently of Cloud.py."""
    string_to_sign = '\n'.join([method, hashlib.sha256(body.encode()).hexdigest(), headers, path])
    msg = API_KEY + token + t + string_to_sign
    return _hmac_mod.new(API_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()


class _FakeCloud(object):
    """Stands in for requests.get/requests.request; each call pops the next
    canned reply (a dict sent as JSON, or raw bytes) and is recorded."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def get(self, url, headers=None):
        return self.request('GET', url, headers=headers)

    def request(self, method, url, headers=None, data=None):
        self.calls.append(types.SimpleNamespace(method=method, url=url, headers=headers, body=data))
        reply = self.replies.pop(0)
        content = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
        return types.SimpleNamespace(status_code=200, content=content, text=content.decode('utf-8', 'replace'))


class TestCloud(unittest.TestCase):

    def setUp(self):
        self.clock = _FakeClock()
        p = patch.object(_cloud_mod, 'time', self.clock)
        p.start()
        self.addCleanup(p.stop)

    def start(self, *replies, **kw):
        """Cloud() with the given replies, starting with the token request."""
        self.server = _FakeCloud(replies)
        for name in ('get', 'request'):
            p = patch.object(_cloud_mod.requests, name, getattr(self.server, name))
            p.start()
            self.addCleanup(p.stop)
        return tinytuya.Cloud(apiRegion='us', apiKey=API_KEY, apiSecret=API_SECRET, **kw)

    def test_token_request_signed(self):
        c = self.start(TOKEN_REPLY)
        self.assertEqual(c.token, 'TOKEN1')
        call = self.server.calls[0]
        self.assertEqual(call.url, 'https://openapi.tuyaus.com/v1.0/token?grant_type=1')
        self.assertEqual(call.headers['t'], '1700000000000')
        self.assertEqual(call.headers['client_id'], API_KEY)
        self.assertEqual(call.headers['sign'], _tuya_sign('1700000000000', 'GET', '/v1.0/token?grant_type=1'))
        self.assertNotIn('access_token', call.headers)

    def test_post_signed_with_token_body_and_headers(self):
        c = self.start(TOKEN_REPLY, {'success': True, 'result': True})
        commands = {'commands': [{'code': 'switch_1', 'value': True}]}
        self.assertEqual(c.sendcommand('DEVID', commands), {'success': True, 'result': True})
        call = self.server.calls[1]
        self.assertEqual(call.method, 'POST')
        self.assertEqual(call.url, 'https://openapi.tuyaus.com/v1.0/iot-03/devices/DEVID/commands')
        self.assertEqual(json.loads(call.body), commands)
        self.assertEqual(call.headers['access_token'], 'TOKEN1')
        self.assertEqual(call.headers['Signature-Headers'], 'Content-type')
        expected = _tuya_sign('1700000000000', 'POST', '/v1.0/iot-03/devices/DEVID/commands', 'TOKEN1',
                              call.body, 'Content-type:application/json\n')
        self.assertEqual(call.headers['sign'], expected)

    def test_query_signed_sorted_before_url_encoding(self):
        c = self.start(TOKEN_REPLY, {'success': True, 'result': {}})
        c.cloudrequest('/v1.0/devices/DEVID/logs', query={'type': '1,7', 'codes': 'a b', 'end_time': 5})
        call = self.server.calls[1]
        self.assertEqual(call.url, 'https://openapi.tuyaus.com/v1.0/devices/DEVID/logs?codes=a+b&end_time=5&type=1%2C7')
        path = '/v1.0/devices/DEVID/logs?codes=a b&end_time=5&type=1,7'
        self.assertEqual(call.headers['sign'], _tuya_sign('1700000000000', 'GET', path, 'TOKEN1'))

    def test_old_sign_algorithm(self):
        c = self.start(TOKEN_REPLY, {'success': True, 'result': []}, new_sign_algorithm=False)
        c.getstatus('DEVID')
        old_sign = lambda msg: _hmac_mod.new(API_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest().upper()
        self.assertEqual(self.server.calls[0].headers['sign'], old_sign(API_KEY + '1700000000000'))
        self.assertEqual(self.server.calls[1].headers['sign'], old_sign(API_KEY + 'TOKEN1' + '1700000000000'))

    def test_token_refresh_retry_keeps_query_and_content_type(self):
        # regression for #723: the retried request must be the same request
        token2 = {'success': True, 'result': {'access_token': 'TOKEN2'}}
        c = self.start(TOKEN_REPLY, TOKEN_INVALID, token2, {'success': True, 'result': 'ok'})
        result = c._tuyaplatform('devices/DEVID/logs', query={'size': 2}, content_type='text/plain')
        self.assertEqual(result, {'success': True, 'result': 'ok'})
        first, renew, retry = self.server.calls[1:]
        self.assertEqual(renew.url, 'https://openapi.tuyaus.com/v1.0/token?grant_type=1')
        self.assertEqual(retry.url, first.url)
        self.assertEqual(retry.url, 'https://openapi.tuyaus.com/v1.0/devices/DEVID/logs?size=2')
        self.assertEqual(retry.headers['Content-type'], 'text/plain')
        self.assertEqual(retry.headers['access_token'], 'TOKEN2')

    def test_token_refresh_gives_up(self):
        token2 = {'success': True, 'result': {'access_token': 'TOKEN2'}}
        c = self.start(TOKEN_REPLY, TOKEN_INVALID, token2, TOKEN_INVALID)
        self.assertIsNone(c.cloudrequest('/v1.0/devices/DEVID'))
        # a failed renewal stops at once and leaves the token error behind
        c = self.start(TOKEN_REPLY, TOKEN_INVALID, {'success': False, 'msg': 'sign invalid'})
        self.assertIsNone(c.cloudrequest('/v1.0/devices/DEVID'))
        self.assertEqual(c.error['Err'], str(tinytuya.ERR_CLOUDTOKEN))

    def test_token_failure_at_init(self):
        c = self.start({'success': False, 'code': 1004, 'msg': 'sign invalid'})
        self.assertIsNone(c.token)
        self.assertEqual(c.error['Err'], str(tinytuya.ERR_CLOUDTOKEN))
        self.assertIn('sign invalid', c.error['Payload'])
        self.assertIs(c.getstatus('DEVID'), c.error)
        self.assertEqual(len(self.server.calls), 1, 'no request is sent without a token')

    def test_error_dicts(self):
        c = self.start(TOKEN_REPLY, {'success': False, 'code': 1106, 'msg': 'permission deny'}, b'<html>502 Bad Gateway</html>')
        result = c.getstatus('DEVID')
        self.assertEqual(result['Err'], str(tinytuya.ERR_CLOUD))
        self.assertIn('permission deny', result['Payload'])
        # a non-JSON reply is an error dict, never an exception
        result = c.getstatus('DEVID')
        self.assertEqual(result['Err'], str(tinytuya.ERR_CLOUD))
        self.assertEqual(c.getstatus()['Err'], str(tinytuya.ERR_PARAMS))
        self.assertEqual(c.sendcommand('DEVID')['Err'], str(tinytuya.ERR_PARAMS))
        self.assertEqual(len(self.server.calls), 3)

    def test_getdevices_follows_pages_and_merges(self):
        c = self.start(
            TOKEN_REPLY,
            {'success': True, 'result': {'devices': [{'id': 'dev1', 'name': 'Lamp ', 'local_key': '', 'uid': 'u1', 'product_id': 'p1'}],
                                         'has_more': True, 'last_row_key': 'k1', 'total': 2}},
            {'success': True, 'result': {'devices': [{'id': 'dev2', 'name': 'Plug', 'local_key': 'key2', 'uid': 'u1', 'product_id': 'p2'}],
                                         'has_more': False, 'total': 2}},
            # per-user list fills in the missing local key
            {'success': True, 'result': {'list': [{'id': 'dev1', 'local_key': 'key1'}], 'has_more': False}},
            {'success': True, 'result': [{'id': 'dev1', 'mac': 'aa:bb:cc:dd:ee:ff', 'uuid': 'uuid1'}]},
        )
        devices = c.getdevices()
        self.assertEqual(devices, [
            {'name': 'Lamp', 'id': 'dev1', 'key': 'key1', 'mac': 'aa:bb:cc:dd:ee:ff', 'uuid': 'uuid1', 'product_id': 'p1'},
            {'name': 'Plug', 'id': 'dev2', 'key': 'key2', 'mac': '', 'product_id': 'p2'},
        ])
        page1, page2, by_user, factory = [urlsplit(call.url) for call in self.server.calls[1:]]
        self.assertEqual(page1.path, '/v1.0/iot-01/associated-users/devices')
        self.assertNotIn('last_row_key', parse_qs(page1.query))
        self.assertEqual(parse_qs(page2.query)['last_row_key'], ['k1'])
        self.assertEqual(by_user.path, '/v1.3/iot-03/devices')
        self.assertEqual(parse_qs(by_user.query)['source_id'], ['u1'])
        self.assertEqual(parse_qs(factory.query)['device_ids'], ['dev1,dev2'])

    def test_getdevices_by_device_id_reuses_unchanged_and_maps_changed(self):
        # the wizard path: apiDeviceID -> uid -> user's devices, diffed against devices.json
        spec = {'category': 'cz', 'status': [
            {'code': 'switch_1', 'dp_id': 1, 'type': 'Boolean', 'values': '{}'},
            {'code': 'cur_power', 'dp_id': 19, 'type': 'Integer', 'values': '{"unit":"W","min":0}'}]}
        c = self.start(
            TOKEN_REPLY,
            {'success': True, 'result': {'uid': 'u1'}},
            {'success': True, 'result': {'uid': 'u1'}},
            {'success': True, 'result': [
                {'id': 'dev1', 'name': 'Lamp', 'local_key': 'key1', 'product_id': 'p1'},
                {'id': 'dev2', 'name': 'Plug', 'local_key': 'newkey', 'product_id': 'p2'}]},
            {'success': True, 'result': spec},
            {'success': True, 'result': [{'id': 'dev2', 'mac': '11:22:33:44:55:66'}]},
            apiDeviceID='dev1, dev2')
        unchanged = {'id': 'dev1', 'name': 'Lamp', 'key': 'key1', 'product_id': 'p1', 'mapping': {}}
        oldlist = [unchanged, {'id': 'dev2', 'name': 'Plug', 'key': 'oldkey', 'product_id': 'p2'}]
        devices = c.getdevices(oldlist=oldlist, include_map=True)
        self.assertEqual(devices, [
            {'name': 'Plug', 'id': 'dev2', 'key': 'newkey', 'mac': '11:22:33:44:55:66', 'product_id': 'p2', 'mapping': {
                '1': {'code': 'switch_1', 'type': 'Boolean', 'values': {}},
                '19': {'code': 'cur_power', 'type': 'Integer', 'values': {'unit': 'W', 'min': 0}}}},
            unchanged,
        ])
        self.assertIs(devices[1], unchanged)
        paths = [urlsplit(call.url).path for call in self.server.calls[1:]]
        self.assertEqual(paths, ['/v1.0/devices/dev1', '/v1.0/devices/dev2', '/v1.0/users/u1/devices',
                                 '/v1.1/devices/dev2/specifications', '/v1.0/devices/factory-infos'])

    def test_getdevices_uid_error(self):
        c = self.start(TOKEN_REPLY, {'success': False, 'code': 1106, 'msg': 'permission deny'}, apiDeviceID='dev1')
        result = c.getdevices()
        self.assertEqual(result['Err'], str(tinytuya.ERR_CLOUD))
        self.assertIn('permission deny', result['Payload'])

    def test_getdevicelog_follows_pages(self):
        c = self.start(
            TOKEN_REPLY,
            {'success': True, 'result': {'logs': [{'value': '1'}], 'has_next': True, 'next_row_key': 'r1'}},
            {'success': True, 'result': {'logs': [{'value': '2'}], 'has_next': False, 'next_row_key': 'r2'}},
        )
        result = c.getdevicelog('DEVID', start=-1, evtype=[1, 7])
        self.assertEqual(result['result']['logs'], [{'value': '1'}, {'value': '2'}])
        self.assertEqual(result['fetches'], 2)
        first, second = [parse_qs(urlsplit(call.url).query) for call in self.server.calls[1:]]
        self.assertEqual(first['end_time'], ['1700000000000'])
        self.assertEqual(first['start_time'], [str((1700000000 - 86400) * 1000)])
        self.assertEqual(first['type'], ['1,7'])
        self.assertNotIn('start_row_key', first)
        self.assertEqual(second['start_row_key'], ['r1'])

    def test_getdevicelog_stops_on_repeated_row_key(self):
        page = {'success': True, 'result': {'logs': [{'value': '1'}], 'has_next': True, 'next_row_key': 'r1'}}
        c = self.start(TOKEN_REPLY, page, json.loads(json.dumps(page)))
        result = c.getdevicelog('DEVID')
        # a server that keeps returning the same row key must not loop forever
        self.assertEqual(result['fetches'], 2)
        self.assertEqual(len(self.server.calls), 3)


# ---------------------------------------------------------------------------
# Contract tests: API.md and the mechanically checkable AGENTS.md rules.
# Known deviations are listed for discussion, not encoded as correct: each
# gets its own @expectedFailure test asserting the documented behavior, so it
# turns into an "unexpected success" (a failure) once fixed and the entry
# must then be deleted.
# ---------------------------------------------------------------------------

import ast
import collections
import functools
import glob
import inspect
import os
import re

REPO = os.path.dirname(os.path.abspath(__file__))


def _read(*path):
    with open(os.path.join(REPO, *path), encoding='utf-8') as f:
        return f.read()


def _add_deviation_tests(cls, deviations, check):
    """Attach one @expectedFailure test per known deviation to `cls`."""
    for key in sorted(deviations):
        def test(self, key=key):
            check(self, key)
        test.__doc__ = deviations[key]
        name = 'test_deviation_' + re.sub(r'\W+', '_', key).strip('_')
        setattr(cls, name, unittest.expectedFailure(test))


_API_SECTIONS = {
    'Module-Level Functions': tinytuya, 'XenonDevice (Base Class)': tinytuya.XenonDevice,
    'Device': tinytuya.Device, 'OutletDevice': tinytuya.OutletDevice, 'BulbDevice': tinytuya.BulbDevice,
    'CoverDevice': tinytuya.CoverDevice, 'Cloud': tinytuya.Cloud,
}


@functools.lru_cache(maxsize=None)
def _api_md_sections():
    """{'## heading': [(lineno, line), ...]} for API.md."""
    sections, current = {}, None
    for lineno, line in enumerate(_read('API.md').splitlines(), 1):
        if line.startswith('## '):
            current = sections.setdefault(line[3:].strip(), [])
        elif current is not None:
            current.append((lineno, line))
    return sections


def _params_from_def(text):
    """[(name, default, kind)] from a documented parameter list, defaults evaluated."""
    args, P = ast.parse('def f(%s): pass' % text).body[0].args, inspect.Parameter
    positional = [(a, P.POSITIONAL_ONLY) for a in args.posonlyargs] + [(a, P.POSITIONAL_OR_KEYWORD) for a in args.args]
    defaults = [P.empty] * (len(positional) - len(args.defaults)) + [ast.literal_eval(d) for d in args.defaults]
    params = [(a.arg, default, kind) for (a, kind), default in zip(positional, defaults)]
    if args.vararg:
        params.append((args.vararg.arg, P.empty, P.VAR_POSITIONAL))
    params += [(a.arg, P.empty if d is None else ast.literal_eval(d), P.KEYWORD_ONLY) for a, d in zip(args.kwonlyargs, args.kw_defaults)]
    if args.kwarg:
        params.append((args.kwarg.arg, P.empty, P.VAR_KEYWORD))
    return params


@functools.lru_cache(maxsize=None)
def _api_md_signatures():
    """{'Owner.name': (lineno, owner, name, [(param, default)])} for every
    documented signature heading plus the XenonDevice constructor block."""
    found = {}
    for section, lines in _api_md_sections().items():
        owner = _API_SECTIONS.get(section)
        if owner is None:
            continue
        owner_name = getattr(owner, '__name__', 'tinytuya')
        for lineno, line in lines:
            m = re.match(r'^#{3,4} `(?:\w+\.)?(\w+)\((.*)\)`\s*$', line)
            if m:
                found['%s.%s' % (owner_name, m.group(1))] = (lineno, owner, m.group(1), _params_from_def(m.group(2)))
    # the constructor is documented as a commented call in a code block
    lines = _api_md_sections()['XenonDevice (Base Class)']
    start = next(i for i, (_, line) in enumerate(lines) if line.startswith('XenonDevice('))
    end = next(i for i in range(start, len(lines)) if lines[i][1].startswith(')'))
    text = ' '.join(line.split('#')[0].strip() for _, line in lines[start + 1:end])
    found['XenonDevice.__init__'] = (lines[start][0], tinytuya.XenonDevice, '__init__', _params_from_def(text))
    return found


def _code_params(owner, name):
    """[(param, default, kind)] of owner.name in the code, or None when it does not exist."""
    obj = getattr(owner, name, None)
    if obj is None or (inspect.isclass(owner) and name not in vars(owner) and name != '__init__'
                       and not any(name in vars(base) for base in owner.__mro__[1:] if base is not object)):
        return None
    return [(p.name, p.default, p.kind) for p in inspect.signature(obj).parameters.values() if p.name != 'self']


def _signature_problem(key):
    """None when the code matches API.md for this entry, else a description."""
    lineno, owner, name, documented = _api_md_signatures()[key]
    actual = _code_params(owner, name)
    if actual is None:
        return 'API.md:%d documents %s, which does not exist' % (lineno, key)
    if actual != documented:
        return 'API.md:%d documents %s%r, code has %r' % (lineno, key, documented, actual)
    return None


def _breaking_change(baseline, actual):
    """Why the code's `actual` parameters would break callers of `baseline`, or None."""
    P = inspect.Parameter
    if actual is None:
        return 'no longer exists'
    if len(actual) < len(baseline):
        return 'parameters removed: %r' % actual
    for (name, default, kind), (new_name, new_default, new_kind) in zip(baseline, actual):
        if (new_name, new_kind) != (name, kind):
            return '%s (%s) is now %s (%s)' % (name, kind, new_name, new_kind)
        if default is not P.empty and new_default != default:
            return '%s default changed from %r to %r' % (name, default, new_default)
    for name, default, kind in actual[len(baseline):]:
        if default is P.empty and kind not in (P.VAR_POSITIONAL, P.VAR_KEYWORD):
            return 'new required parameter %s' % name
    return None


# Public API at the time this test was written: the code's parameters for every API.md signature
# (None = documented but not in the code).  Edit API.md and the code together all you like; callers
# of these must keep working, so parameters may gain defaults and new ones go last with a default.
# Add an entry when API.md documents something new; never edit one to make a breaking change pass.
API_BASELINE = {
    'tinytuya.deviceScan': 'verbose=False, maxretry=None, color=True, poll=True, forcescan=False, byID=False, poll_configured=False',
    'tinytuya.scan': 'maxretry=None, color=True, forcescan=False, poll_configured=False',
    'tinytuya.find_device': 'dev_id=None, address=None',
    'tinytuya.device_info': 'dev_id',
    'tinytuya.assign_dp_mappings': 'tuyadevices, mappings',
    'tinytuya.decrypt_udp': 'msg',
    'tinytuya.set_debug': 'toggle=True, color=True',
    'tinytuya.load_devicefile': 'fname=None',
    'XenonDevice.set_version': 'version',
    'XenonDevice.set_socketPersistent': 'persist',
    'XenonDevice.set_socketNODELAY': 'nodelay',
    'XenonDevice.set_socketRetryLimit': 'limit',
    'XenonDevice.set_socketRetryDelay': 'delay',
    'XenonDevice.set_socketTimeout': 's',
    'XenonDevice.set_sendWait': 's',
    'XenonDevice.set_retry': 'retry',
    'XenonDevice.status': 'nowait=False',
    'XenonDevice.cached_status': 'historic=False, nowait=False',
    'XenonDevice.receive': '',
    'XenonDevice.send': 'payload',
    'XenonDevice.set_dpsUsed': 'dps_to_request',
    'XenonDevice.add_dps_to_request': 'dp_indicies',
    'XenonDevice.detect_available_dps': '',
    'XenonDevice.generate_payload': 'command, data=None, gwId=None, devId=None, uid=None, rawData=None, reqType=None',
    'XenonDevice.heartbeat': None,
    'XenonDevice.updatedps': None,
    'XenonDevice.subdev_query': 'nowait=False',
    'Device.status': 'nowait=False',
    'Device.set_status': 'on, switch=1, nowait=False',
    'Device.turn_on': 'switch=1, nowait=False',
    'Device.turn_off': 'switch=1, nowait=False',
    'Device.set_value': 'index, value, nowait=False',
    'Device.set_multiple_values': 'data, nowait=False',
    'Device.set_timer': 'num_secs, dps_id=0, nowait=False',
    'Device.heartbeat': 'nowait=True',
    'Device.product': '',
    'OutletDevice.set_dimmer': 'percentage=None, value=None, dps_id=3, nowait=False',
    'BulbDevice.set_mode': "mode='white', nowait=False",
    'BulbDevice.set_colour': 'r, g, b, nowait=False',
    'BulbDevice.set_hsv': 'h, s, v, nowait=False',
    'BulbDevice.set_white_percentage': 'brightness=100, colourtemp=0, nowait=False',
    'BulbDevice.set_brightness_percentage': 'brightness=100, nowait=False',
    'BulbDevice.set_colourtemp_percentage': 'colourtemp=100, nowait=False',
    'BulbDevice.set_scene': 'scene, scene_data=None, nowait=False',
    'BulbDevice.set_timer': 'num_secs, dps_id=0, nowait=False',
    'BulbDevice.set_musicmode': None,
    'BulbDevice.set_music_colour': 'transition, red, green, blue, brightness=None, colourtemp=None, nowait=False',
    'BulbDevice.state': 'nowait=False',
    'BulbDevice.get_mode': 'state=None, nowait=False',
    'BulbDevice.brightness': 'state=None, nowait=False',
    'BulbDevice.get_brightness_percentage': 'state=None, nowait=False',
    'BulbDevice.colourtemp': 'state=None, nowait=False',
    'BulbDevice.get_colourtemp_percentage': 'state=None, nowait=False',
    'BulbDevice.colour_rgb': 'state=None, nowait=False',
    'BulbDevice.colour_hsv': 'state=None, nowait=False',
    'BulbDevice.rgb_to_hexvalue': 'r, g, b, hexformat',
    'BulbDevice.hsv_to_hexvalue': 'h, s, v, hexformat',
    'BulbDevice.hexvalue_to_rgb': 'hexvalue, hexformat=None',
    'BulbDevice.hexvalue_to_hsv': 'hexvalue, hexformat=None',
    'BulbDevice.bulb_has_capability': 'feature, nowait=False',
    'BulbDevice.detect_bulb': 'response=None, nowait=False',
    'BulbDevice.set_bulb_type': 'bulb_type=None, mapping=None',
    'CoverDevice.open_cover': 'switch=None, nowait=False',
    'CoverDevice.close_cover': 'switch=None, nowait=False',
    'CoverDevice.stop_cover': 'switch=None, nowait=False',
    'Cloud.setregion': 'apiRegion=None',
    'Cloud.cloudrequest': 'url, action=None, post=None, query=None',
    'Cloud.getdevices': 'verbose=False, oldlist=[], include_map=False',
    'Cloud.getstatus': 'deviceid=None',
    'Cloud.getfunctions': 'deviceid=None',
    'Cloud.getproperties': 'deviceid=None',
    'Cloud.getdps': 'deviceid=None',
    'Cloud.sendcommand': "deviceid=None, commands=None, uri='iot-03/devices/'",
    'Cloud.getconnectstatus': 'deviceid=None',
    'Cloud.getdevicelog': 'deviceid=None, start=None, end=None, evtype=None, size=0, max_fetches=50, start_row_key=None, params=None',
    'XenonDevice.__init__': "dev_id, address=None, local_key='', dev_type='default', connection_timeout=5, version=3.1, persist=False, cid=None, node_id=None, parent=None, connection_retry_limit=5, connection_retry_delay=5, port=6668, max_simultaneous_dps=0",
}

# file:line in the code for each, so the list can be acted on directly
API_SIGNATURE_DEVIATIONS = {
    'XenonDevice.__init__': 'XenonDevice.py:243 has an undocumented max_simultaneous_dps=0',
    'XenonDevice.add_dps_to_request': 'XenonDevice.py:1154 names the parameter dp_indicies, not index',
    'XenonDevice.heartbeat': 'documented under XenonDevice, but only Device (core/Device.py:47) has it',
    'XenonDevice.updatedps': 'documented under XenonDevice with index=[1]; core/Device.py:62 is Device.updatedps(index=None)',
    'BulbDevice.set_musicmode': 'no such method (BulbDevice.py:24 docstring lists it too)',
    'CoverDevice.open_cover': 'CoverDevice.py:236 defaults switch=None, not 1',
    'CoverDevice.close_cover': 'CoverDevice.py:251 defaults switch=None, not 1',
    'CoverDevice.stop_cover': 'CoverDevice.py:266 defaults switch=None, not 1',
    'Cloud.setregion': 'Cloud.py:128 defaults apiRegion=None; API.md shows it required',
    'Cloud.getstatus': 'Cloud.py:626 defaults deviceid=None (returns ERR_PARAMS); API.md shows it required',
    'Cloud.getfunctions': 'Cloud.py:632 defaults deviceid=None; API.md shows it required',
    'Cloud.getproperties': 'Cloud.py:638 defaults deviceid=None; API.md shows it required',
    'Cloud.getdps': 'Cloud.py:644 defaults deviceid=None; API.md shows it required',
    'Cloud.sendcommand': 'Cloud.py:669 defaults deviceid=None, commands=None; API.md shows them required',
    'Cloud.getconnectstatus': 'Cloud.py:694 defaults deviceid=None; API.md shows it required',
    'Cloud.getdevicelog': 'Cloud.py:717 defaults deviceid=None; API.md shows it required',
}

API_CONTRIB_DEVIATIONS = {
    'FloorFanDevice': 'missing from the API.md Contrib Modules table',
    'SoriaInverterDevice': 'missing from the API.md Contrib Modules table',
    'TowelRailHeaterDevice': 'missing from the API.md Contrib Modules table',
}


def _contrib_modules():
    return sorted(os.path.basename(p)[:-3] for p in glob.glob(os.path.join(REPO, 'tinytuya', 'Contrib', '*Device.py')))


def _api_md_contrib_table():
    return re.findall(r'^\| `(\w+)` \| `(\w+)` \|', '\n'.join(l for _, l in _api_md_sections()['Contrib Modules']), re.M)


class TestApiContract(unittest.TestCase):
    """API.md is the public contract (AGENTS.md: Public API stability)."""

    def test_signatures_match_api_md(self):
        signatures = _api_md_signatures()
        self.assertGreater(len(signatures), 60, 'API.md headings no longer parse')
        for key in API_SIGNATURE_DEVIATIONS:
            self.assertIn(key, signatures, 'stale deviation entry')
        for key in sorted(set(signatures) - set(API_SIGNATURE_DEVIATIONS)):
            with self.subTest(key=key):
                self.assertIsNone(_signature_problem(key))

    def test_documented_api_stays_backward_compatible(self):
        signatures = _api_md_signatures()
        self.assertEqual(set(signatures) - set(API_BASELINE), set(), 'add new API.md signatures to API_BASELINE')
        for key, params in API_BASELINE.items():
            with self.subTest(key=key):
                self.assertIn(key, signatures, 'removed from API.md')
                if params is not None:
                    _, owner, name, _ = signatures[key]
                    self.assertIsNone(_breaking_change(_params_from_def(params), _code_params(owner, name)))

    def test_device_classes_accept_documented_constructor(self):
        # API.md: "All device classes share the constructor signature" of XenonDevice
        kwargs = {name: default for name, default, _ in _api_md_signatures()['XenonDevice.__init__'][3][1:]}
        kwargs.update(address='192.0.2.10', local_key=LOCAL_KEY, version=3.3)
        for cls in (tinytuya.Device, tinytuya.OutletDevice, tinytuya.BulbDevice, tinytuya.CoverDevice):
            with self.subTest(cls=cls.__name__):
                d = cls('DEVICE_ID_HERE', **kwargs)
                self.assertEqual((d.id, d.address, d.version, d.port), ('DEVICE_ID_HERE', '192.0.2.10', 3.3, 6668))

    def test_cloud_constructor_accepts_documented_keywords(self):
        params = inspect.signature(tinytuya.Cloud).parameters
        for name in ('apiRegion', 'apiKey', 'apiSecret', 'apiDeviceID', 'configFile'):
            self.assertIn(name, params)

    def test_cloud_region_table(self):
        rows = re.findall(r'^\| (`[\w-]+`(?: / `[\w-]+`)*) \| (.+?) \|$',
                          '\n'.join(l for _, l in _api_md_sections()['Cloud']), re.M)
        self.assertEqual(len(rows), 7)
        c = tinytuya.Cloud(apiRegion='us', apiKey=API_KEY, apiSecret=API_SECRET, initial_token='TOKEN')
        hosts = []
        for codes, _center in rows:
            row_hosts = set()
            for code in re.findall(r'`([\w-]+)`', codes):
                c.setregion(code)
                row_hosts.add(c.urlhost)
            self.assertEqual(len(row_hosts), 1, 'aliases on one row must share a data center: %s' % codes)
            hosts.append(row_hosts.pop())
        self.assertEqual(len(set(hosts)), len(hosts), 'each documented region needs its own host')

    def test_setter_defaults(self):
        # attribute behind each setter and the default API.md states for it
        attrs = {'set_socketNODELAY': 'socketNODELAY', 'set_socketRetryLimit': 'socketRetryLimit',
                 'set_socketRetryDelay': 'socketRetryDelay', 'set_socketTimeout': 'connection_timeout',
                 'set_sendWait': 'sendWait', 'set_retry': 'retry'}
        text = '\n'.join(l for _, l in _api_md_sections()['XenonDevice (Base Class)'])
        d = tinytuya.Device('DEVICE_ID_HERE', '192.0.2.10', LOCAL_KEY, version=3.3)
        for setter, attr in attrs.items():
            with self.subTest(setter=setter):
                default = re.search(r'#### `%s\(.*?Default: `([^`]+)`' % setter, text, re.S).group(1)
                self.assertEqual(getattr(d, attr), ast.literal_eval(default))
        self.assertFalse(d.socketPersistent, 'API.md: close after each command (False, default)')

    def test_error_code_table(self):
        documented = {int(code): name for code, name in re.findall(
            r'^\| (\d{3}) \| `(ERR_\w+)` \|', '\n'.join(l for _, l in _api_md_sections()['Error Codes']), re.M)}
        actual = {code: name for name, code in vars(tinytuya).items() if name.startswith('ERR_') and isinstance(code, int)}
        self.assertEqual(documented, actual)
        self.assertEqual(set(actual), {k for k in tinytuya.error_codes if k is not None})

    def test_find_device_result_shape(self):
        # API.md: {'ip', 'version', 'id', 'product_id', 'data'}, found or not
        keys = {'ip', 'version', 'id', 'product_id', 'data'}
        self.assertEqual(set(tinytuya.find_device()), keys)
        from tinytuya import scanner
        found = {'DEVICE_ID_HERE': {'ip': '192.0.2.10', 'version': '3.3', 'productKey': 'p1'}}
        for reply in ({}, found):
            with patch.object(scanner, 'devices', return_value=reply):
                self.assertEqual(set(tinytuya.find_device(dev_id='DEVICE_ID_HERE')), keys)
        with patch.object(scanner, 'devices', return_value=found):
            self.assertEqual(tinytuya.find_device(dev_id='DEVICE_ID_HERE')['product_id'], 'p1')

    def test_contrib_table_lists_real_classes(self):
        import importlib
        table = _api_md_contrib_table()
        self.assertGreater(len(table), 10)
        for module, cls in table:
            with self.subTest(module=module):
                self.assertTrue(inspect.isclass(getattr(importlib.import_module('tinytuya.Contrib.' + module), cls)))
        listed = {m for m, _ in table}
        for module in sorted(set(_contrib_modules()) - set(API_CONTRIB_DEVIATIONS)):
            with self.subTest(module=module):
                self.assertIn(module, listed)


_add_deviation_tests(TestApiContract, API_SIGNATURE_DEVIATIONS,
                     lambda self, key: self.assertIsNone(_signature_problem(key)))
_add_deviation_tests(TestApiContract, {'contrib_' + k: v for k, v in API_CONTRIB_DEVIATIONS.items()},
                     lambda self, key: self.assertIn(key[len('contrib_'):], {m for m, _ in _api_md_contrib_table()}))


def _library_sources():
    """{repo-relative path: AST} for every module in the tinytuya package."""
    paths = sorted(glob.glob(os.path.join(REPO, 'tinytuya', '**', '*.py'), recursive=True))
    return {os.path.relpath(p, REPO).replace(os.sep, '/'): ast.parse(_read(p), p) for p in paths}


def _calls(tree, names):
    """(lineno, name) of calls to any of `names` (plain or attribute calls)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, 'attr', None)
            if name in names:
                yield node.lineno, name


# AGENTS.md: "only the CLI, wizard, and scanner user-facing output may print"
PRINT_ALLOWED = {'tinytuya/__main__.py', 'tinytuya/cli.py', 'tinytuya/wizard.py', 'tinytuya/scanner.py'}
# 'path:function': (print() calls, note); a new print anywhere, even in one of these functions, fails
PRINT_DEVIATIONS = {
    'tinytuya/Cloud.py:<module>': (3, 'Cloud.py:39-41 print a WARN banner at import time when requests is missing'),
    'tinytuya/Contrib/IRRemoteControlDevice.py:head_key_to_pulses': (14, 'IRRemoteControlDevice.py:413-494 debug prints in head_key_to_pulses(), inside "if False:" blocks'),
    'tinytuya/Contrib/IRRemoteControlDevice.py:pulses_to_space_encoded_head_key': (2, 'IRRemoteControlDevice.py:930,968 print on every call of pulses_to_space_encoded_head_key()'),
    'tinytuya/Contrib/WiFiDualMeterDevice.py:print_all': (26, 'WiFiDualMeterDevice.py:217-242: print_all() is a public method that prints'),
}
HEXLIFY_DEVIATIONS = {  # 'path:function': (unguarded calls, note), as for PRINT_DEVIATIONS
    'tinytuya/core/XenonDevice.py:_negotiate_session_key_generate_step_3': (1, 'XenonDevice.py:944 HMAC-mismatch log.debug() hexlifies without an isEnabledFor() guard'),
    'tinytuya/core/message_helper.py:unpack_message': (1, 'message_helper.py:150 HMAC-mismatch log.debug() hexlifies without an isEnabledFor() guard'),
}
# AGENTS.md binds __all__ only for *new* wildcard-exported modules; these predate the rule
WILDCARD_WITHOUT_ALL = {
    'crypto_helper', 'message_helper', 'exceptions', 'error_helper', 'const', 'XenonDevice',
    'udp_helper', 'Device', 'command_types', 'header', 'core',
}
# AGENTS.md's Contrib checklist (README section, example, testcontrib) binds new modules
CONTRIB_PREDATES_CHECKLIST = {
    'AtorchTemperatureControllerDevice', 'BlanketDevice', 'ClimateDevice', 'ColorfulX7Device', 'DoorbellDevice',
    'FloorFanDevice', 'IRRemoteControlDevice', 'InverterHeatPumpDevice', 'PresenceDetectorDevice',
    'RFRemoteControlDevice', 'SocketDevice', 'SoriaInverterDevice', 'ThermostatDevice',
    'TowelRailHeaterDevice', 'WiFiDualMeterDevice',
}


def _print_sites(path, tree):
    """Counter of 'path:function' for print() calls (innermost def, or <module>)."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    sites = collections.Counter()
    for node in ast.walk(tree):
        func = getattr(node, 'func', None)
        if not (isinstance(node, ast.Call) and getattr(func, 'id', getattr(func, 'attr', None)) == 'print'):
            continue
        while node in parents and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node = parents[node]
        sites['%s:%s' % (path, getattr(node, 'name', '<module>'))] += 1
    return sites


def _unguarded_hexlify(path, tree):
    """'path:function' of log calls that hexlify outside an isEnabledFor() check."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        func = getattr(node, 'func', None)
        if not (isinstance(node, ast.Call) and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 'log'):
            continue
        if not any(getattr(getattr(n, 'func', None), 'attr', None) == 'hexlify' for arg in node.args for n in ast.walk(arg)):
            continue
        p, guarded = node, False
        while p in parents and not isinstance(p, ast.FunctionDef):
            child, p = p, parents[p]
            # only the body of `if log.isEnabledFor(logging.DEBUG):` counts, not its else or another level
            guarded = guarded or (isinstance(p, ast.If) and child in p.body
                                  and ast.unparse(p.test) == 'log.isEnabledFor(logging.DEBUG)')
        if not guarded:
            yield '%s:%s' % (path, getattr(p, 'name', '<module>'))


def _import_guarded(parents, node):
    """True when `node` sits in the body of a try whose handlers catch ImportError."""
    catches = {'ImportError', 'ModuleNotFoundError', 'Exception', 'BaseException'}
    while node in parents:
        child, node = node, parents[node]
        if isinstance(node, ast.Try) and child in node.body and any(
                h.type is None or {getattr(n, 'id', None) for n in ast.walk(h.type)} & catches for h in node.handlers):
            return True
    return False


class TestAgentsRules(unittest.TestCase):
    """Mechanically checkable AGENTS.md rules (AST/inspect, not text matching)."""

    @classmethod
    def setUpClass(cls):
        cls.sources = _library_sources()
        cls.unguarded_hexlify = collections.Counter(site for path, tree in cls.sources.items() for site in _unguarded_hexlify(path, tree))
        cls.print_sites = sum((_print_sites(path, tree) for path, tree in cls.sources.items() if path not in PRINT_ALLOWED),
                              collections.Counter())

    def _assert_only_known_sites(self, found, deviations):
        """Every site in `found` is a known deviation with exactly its recorded count (0 = fixed)."""
        known = collections.Counter({site: count for site, (count, _) in deviations.items()})
        self.assertEqual(found - known, collections.Counter())
        partly_fixed = {site for site in known if 0 < found[site] < known[site]}
        self.assertEqual(partly_fixed, set(), 'lower the deviation count')

    def test_no_print_in_library_modules(self):
        self._assert_only_known_sites(self.print_sites, PRINT_DEVIATIONS)

    def test_logging_configured_only_by_set_debug(self):
        config = {'basicConfig', 'addHandler', 'removeHandler', 'setFormatter', 'dictConfig', 'fileConfig',
                  'StreamHandler', 'FileHandler', 'NullHandler', 'Formatter'}
        for path, tree in self.sources.items():
            set_debug = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'set_debug']
            allowed = {line for f in set_debug for line in range(f.lineno, f.end_lineno + 1)}
            with self.subTest(path=path):
                self.assertEqual([c for c in _calls(tree, config) if c[0] not in allowed], [])

    def test_loggers_named_by_module(self):
        for path, tree in self.sources.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == 'getLogger':
                    with self.subTest(path=path, line=node.lineno):
                        self.assertEqual(ast.unparse(node.args[0]) if node.args else None, '__name__')

    def test_hexlify_logging_is_guarded(self):
        self._assert_only_known_sites(self.unguarded_hexlify, HEXLIFY_DEVIATIONS)

    def test_crypto_imported_only_in_crypto_helper(self):
        crypto = {'cryptography', 'Crypto', 'Cryptodome', 'pyaes'}
        for path, tree in self.sources.items():
            if path == 'tinytuya/core/crypto_helper.py':
                continue
            for node in ast.walk(tree):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                        [node.module or ''] if isinstance(node, ast.ImportFrom) and not node.level else []
                for name in names:
                    with self.subTest(path=path, line=node.lineno):
                        self.assertNotIn(name.split('.')[0], crypto)

    def test_no_type_annotations(self):
        for path, tree in self.sources.items():
            annotated = [n.lineno for n in ast.walk(tree)
                         if (isinstance(n, ast.arg) and n.annotation is not None) or isinstance(n, ast.AnnAssign)
                         or (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.returns is not None)]
            with self.subTest(path=path):
                self.assertEqual(annotated, [])

    def test_new_wildcard_modules_define_all(self):
        for init in ('tinytuya/__init__.py', 'tinytuya/core/__init__.py'):
            package = os.path.dirname(init)
            for node in self.sources[init].body:
                if isinstance(node, ast.ImportFrom) and node.level and any(a.name == '*' for a in node.names):
                    path = '%s/%s.py' % (package, node.module.replace('.', '/'))
                    if path not in self.sources:
                        path = '%s/%s/__init__.py' % (package, node.module.replace('.', '/'))
                    defines_all = any(isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == '__all__' for t in n.targets)
                                      for n in self.sources[path].body)
                    with self.subTest(module=path):
                        self.assertTrue(defines_all or node.module in WILDCARD_WITHOUT_ALL or path == 'tinytuya/core/__init__.py')

    def test_error_codes_listed_in_readme(self):
        readme = dict((int(c), (n, m)) for c, n, m in re.findall(r'^\* (\d{3}) \((ERR_\w+)\) - (.+)$', _read('README.md'), re.M))
        codes = {k: v for k, v in tinytuya.error_codes.items() if k is not None}
        self.assertEqual(set(readme), set(codes))
        for code, (name, message) in readme.items():
            self.assertEqual(getattr(tinytuya, name), code)
            self.assertEqual(message, codes[code])

    def test_supported_python_versions_in_sync(self):
        setup = ast.parse(_read('setup.py'))
        kw = {k.arg: k.value for n in ast.walk(setup) if isinstance(n, ast.Call) and getattr(n.func, 'attr', None) == 'setup' for k in n.keywords}
        classifiers = {c.split(':: ')[-1] for c in ast.literal_eval(kw['classifiers']) if re.search(r':: 3\.\d+$', c)}
        ci = re.search(r'python-version: \[([^\]]+)\]', _read('.github', 'workflows', 'ci.yml')).group(1)
        matrix = set(re.findall(r'"(3\.\d+)"', ci))
        low, high = re.search(r'Python (3\.\d+)–(3\.\d+)', _read('AGENTS.md')).groups()
        self.assertEqual(classifiers, matrix)
        self.assertEqual(ast.literal_eval(kw['python_requires']), '>=' + low)
        key = lambda v: int(v.split('.')[1])
        self.assertEqual((min(matrix, key=key), max(matrix, key=key)), (low, high))
        self.assertEqual(len(matrix), key(high) - key(low) + 1, 'no gaps in the test matrix')

    def test_no_new_hard_dependencies(self):
        setup = ast.parse(_read('setup.py'))
        install = next(ast.literal_eval(n.value) for n in setup.body if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', None) == 'INSTALL_REQUIRES')
        self.assertEqual(install, ['requests', 'colorama'])  # plus one auto-chosen AES backend
        reqs = {re.split(r'[<>=\s#]', l.strip())[0] for l in _read('requirements.txt').splitlines() if l.strip() and not l.startswith('#')}
        self.assertEqual(reqs, {'cryptography', 'requests', 'colorama'})
        for name in ('pyproject.toml', 'setup.cfg'):
            self.assertNotRegex(_read(name), r'(?m)^\s*(dependencies|install_requires)\s*=', name)

    def test_third_party_imports_are_optional(self):
        # every non-stdlib import sits in try/except ImportError today; an unguarded one is a new hard dependency
        for path, tree in self.sources.items():
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {a.name.split('.')[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    roots = {node.module.split('.')[0]}
                else:
                    continue
                third_party = roots - set(sys.stdlib_module_names) - {'tinytuya'}
                if third_party:
                    with self.subTest(path=path, line=node.lineno, modules=sorted(third_party)):
                        self.assertTrue(_import_guarded(parents, node))

    def test_version_from_version_tuple(self):
        from tinytuya.core import core
        self.assertEqual(tinytuya.__version__, '%d.%d.%d' % core.version_tuple)

    def test_is_py2_alias_kept(self):
        self.assertIs(tinytuya.IS_PY2, False)

    def test_new_contrib_modules_follow_checklist(self):
        readme = _read('tinytuya', 'Contrib', 'README.md')
        examples = ''.join(_read(p) for p in glob.glob(os.path.join(REPO, 'examples', 'Contrib', '*.py')))
        testcontrib = _read('testcontrib.py')
        self.assertEqual(CONTRIB_PREDATES_CHECKLIST - set(_contrib_modules()), set(), 'stale entry')
        for module in sorted(set(_contrib_modules()) - CONTRIB_PREDATES_CHECKLIST):
            with self.subTest(module=module):
                self.assertRegex(readme, r'(?m)^### %s$' % module)
                self.assertIn(module, examples)
                self.assertIn(module, testcontrib)


_add_deviation_tests(TestAgentsRules, {site: note for site, (_, note) in PRINT_DEVIATIONS.items()},
                     lambda self, site: self.assertEqual(self.print_sites[site], 0))
_add_deviation_tests(TestAgentsRules, {site: note for site, (_, note) in HEXLIFY_DEVIATIONS.items()},
                     lambda self, site: self.assertEqual(self.unguarded_hexlify[site], 0))


if __name__ == '__main__':
    unittest.main()
