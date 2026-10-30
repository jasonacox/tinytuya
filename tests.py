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


# ---------------------------------------------------------------------------
# Wire-path tests: real Device API -> framing -> crypto -> fake device -> back
# ---------------------------------------------------------------------------

import hashlib
import hmac as _hmac_mod
import sys
import types

from tinytuya.core import command_types as CT

# tinytuya.core re-exports classes over some module names, so patch via sys.modules
_xenon_mod = sys.modules['tinytuya.core.XenonDevice']
_device_mod = sys.modules['tinytuya.core.Device']
_cloud_mod = sys.modules['tinytuya.Cloud']

HAS_GCM = bool(mh.AESCipher.CRYPTOLIB_HAS_GCM)
WRONG_KEY = 'fedcba9876543210'


class FakeTuyaDevice(object):
    """Device side of the Tuya LAN protocol (3.1/3.3/3.4/3.5), per PROTOCOL.md.

    Transport-agnostic: connect() starts a TCP session and receive_bytes(data)
    returns the bytes the device answers with, so any I/O layer (the sync
    socket shim below, or a future asyncio transport) can drive it.  Frames it
    cannot authenticate or decrypt, or that break the version-header rule
    (3.2+ commands outside NO_PROTOCOL_HEADER_CMDS carry it), are dropped.

    Knobs: dps / children ({cid: dps}) hold state; device22 answers DP_QUERY
    with "data unvalid"; raw_reply replaces the status body of query replies;
    retcode is put in CONTROL acks; silent records requests but never answers;
    corrupt_tags sends that many data replies with a broken GCM tag; push()
    queues unsolicited STATUS updates; noise is junk sent ahead of the next
    reply; connect_error / send_error are raised by connect() / receive_bytes();
    forge_hmac answers session negotiation with a bad HMAC (an impostor).
    """

    NONCE = b'fedcba9876543210'

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
        while len(self._rx) >= 16:
            header = mh.parse_header(self._rx)
            if len(self._rx) < header.total_length:
                break
            frame, self._rx = self._rx[:header.total_length], self._rx[header.total_length:]
            out += self._handle(frame, header)
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
            if payload.startswith(b'3.1'):
                return cipher.decrypt(payload[19:], decode_text=False)  # skip "3.1" + MD5 slice
            return payload
        want_header = cmd not in mh.H.NO_PROTOCOL_HEADER_CMDS
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
        md5 = hashlib.md5(b'data=' + enc + b'||lpv=3.1||' + self.key).hexdigest()
        return b'3.1' + md5[8:24].encode() + enc

    def _frame(self, cmd, payload, seqno, retcode=0, data=True):
        if self.version >= 3.5:
            self._seqno += 1
            msg = mh.TuyaMessage(self._seqno, cmd, retcode, payload, 0, True, mh.H.PREFIX_6699_VALUE, True)
            frame = mh.pack_message(msg, hmac_key=self.key)
            if data and self.corrupt_tags:
                self.corrupt_tags -= 1
                frame = frame[:-5] + bytes([frame[-5] ^ 1]) + frame[-4:]
        else:
            payload = struct.pack('>I', retcode) + payload
            msg = mh.TuyaMessage(seqno, cmd, None, payload, 0, True, mh.H.PREFIX_55AA_VALUE, False)
            frame = mh.pack_message(msg, hmac_key=self.key if self.version >= 3.4 else None)
        noise, self.noise = self.noise, b''
        return noise + frame

    def _handle(self, frame, header):
        msg = mh.unpack_message(frame, hmac_key=self.key if self.version >= 3.4 else None, header=header, no_retcode=True)
        try:
            if not msg.crc_good:
                raise ValueError('bad CRC/HMAC/tag')
            payload = self._open(msg.cmd, msg.payload)
            if msg.cmd == CT.SESS_KEY_NEG_START:
                return self._negotiate_start(payload, msg.seqno)
            if msg.cmd == CT.SESS_KEY_NEG_FINISH:
                return self._negotiate_finish(payload)
            request = json.loads(payload) if payload else {}
        except ValueError:
            self.dropped += 1
            return b''
        self.requests.append((msg.cmd, request))
        if self.silent:
            return b''
        out = b''.join(self._frame(CT.STATUS, self._seal(p, True), msg.seqno) for p in self._pushes)
        self._pushes = []
        return out + self._reply(msg.cmd, msg.seqno, request)

    def _negotiate_start(self, client_nonce, seqno):
        self._client_nonce = client_nonce
        body = self.NONCE + _hmac_mod.new(self.real_key, client_nonce, hashlib.sha256).digest()
        if self.forge_hmac:
            body = body[:16] + bytes(32)
        return self._frame(CT.SESS_KEY_NEG_RESP, self._seal(body), seqno, data=False)

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
        if cmd in (CT.DP_QUERY, CT.DP_QUERY_NEW):
            if self.device22 and cmd == CT.DP_QUERY:
                return self._frame(cmd, self._seal(b'json obj data unvalid'), seqno)
            body = self.raw_reply if self.raw_reply is not None else self._status(state, cid)
            return self._frame(cmd, self._seal(body), seqno)
        if cmd in (CT.CONTROL, CT.CONTROL_NEW):
            dps = data.get('dps', request.get('dps', {}))
            if self.device22 and cmd == CT.CONTROL_NEW and all(v is None for v in dps.values()):
                # device22 status query: answer with the requested DPs only
                found = {k: state[k] for k in dps if k in state}
                return self._frame(cmd, self._seal(self._status(found, cid)), seqno)
            state.update(dps)
            # empty ack carrying the retcode, then a STATUS push with the new values
            ack = self._frame(cmd, b'', seqno, self.retcode)
            return ack + self._frame(CT.STATUS, self._seal(self._status(dps, cid), True), seqno)
        if cmd == CT.HEART_BEAT:
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
        self.assertEqual(cmd, CT.DP_QUERY_NEW if self.VERSION >= 3.4 else CT.DP_QUERY)
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
            self.assertEqual(cmd, CT.CONTROL_NEW)
            self.assertEqual(request['data']['dps'], {'2': 77})
        else:
            self.assertEqual(cmd, CT.CONTROL)
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
        self.assertEqual(fake.requests[-1][0], CT.HEART_BEAT)
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
        self.assertEqual([c for c, _ in fake.requests], [CT.DP_QUERY, CT.CONTROL_NEW])
        self.assertEqual(fake.requests[1][1]['dps'], {'1': None})

    def test_v32_detects_available_dps_at_set_version(self):
        # 3.2 is forced to device22 and brute-forces the DP list on set_version()
        d, fake = self.make(3.2, device22=True, dps={'1': True, '5': 3, '102': 0})
        self.assertEqual(d.dev_type, 'device22')
        self.assertEqual(d.dps_to_request, {'1': None, '5': None, '102': None})
        self.assertTrue(all(cmd == CT.CONTROL_NEW for cmd, _ in fake.requests))
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
        self.assertEqual(d.status()['dps'], {'1': True})
        # the forged frame was discarded; the library reconnected and asked again
        self.assertEqual(fake.connections, 2)
        self.assertEqual(len(fake.requests), 2)

    def test_bad_gcm_tag_every_time_returns_payload_error(self):
        d, fake = self.make(3.5)
        fake.corrupt_tags = 1000
        result = d.status()
        self.assertEqual(result['Err'], str(tinytuya.ERR_PAYLOAD))
        self.assertNotIn('dps', result)

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
    """[(name, default)] from a documented parameter list, defaults evaluated."""
    args = ast.parse('def f(%s): pass' % text).body[0].args
    first_default = len(args.args) - len(args.defaults)
    return [(a.arg, ast.literal_eval(args.defaults[i - first_default]) if i >= first_default else inspect.Parameter.empty)
            for i, a in enumerate(args.args)]


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


def _signature_problem(key):
    """None when the code matches API.md for this entry, else a description."""
    lineno, owner, name, documented = _api_md_signatures()[key]
    obj = getattr(owner, name, None)
    if obj is None or (inspect.isclass(owner) and name not in vars(owner) and name != '__init__'
                       and not any(name in vars(base) for base in owner.__mro__[1:] if base is not object)):
        return 'API.md:%d documents %s, which does not exist' % (lineno, key)
    actual = [(p.name, p.default) for p in inspect.signature(obj).parameters.values() if p.name != 'self']
    if actual != documented:
        return 'API.md:%d documents %s%r, code has %r' % (lineno, key, documented, actual)
    return None


# file:line in the code for each, so the list can be acted on directly
API_SIGNATURE_DEVIATIONS = {
    'tinytuya.deviceScan': 'core/core.py:235 has maxretry=None and an undocumented byID=False',
    'tinytuya.scan': 'core/core.py:228 is scan(maxretry=None, color=True, forcescan=False): no poll parameter',
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

    def test_device_classes_accept_documented_constructor(self):
        # API.md: "All device classes share the constructor signature" of XenonDevice
        kwargs = {name: default for name, default in _api_md_signatures()['XenonDevice.__init__'][3][1:]}
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
PRINT_DEVIATIONS = {
    'tinytuya/Cloud.py': 'Cloud.py:39-41 print a WARN banner at import time when requests is missing',
    'tinytuya/Contrib/IRRemoteControlDevice.py': 'IRRemoteControlDevice.py:930,968 print on every call of pulses_to_space_encoded_head_key(); 413-494 sit in an "if False:" block',
    'tinytuya/Contrib/WiFiDualMeterDevice.py': 'WiFiDualMeterDevice.py:217-242: print_all() is a public method that prints',
}
HEXLIFY_DEVIATIONS = {
    'tinytuya/core/XenonDevice.py:_negotiate_session_key_generate_step_3': 'XenonDevice.py:944 HMAC-mismatch log.debug() hexlifies without an isEnabledFor() guard',
    'tinytuya/core/message_helper.py:unpack_message': 'message_helper.py:150 HMAC-mismatch log.debug() hexlifies without an isEnabledFor() guard',
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
            p = parents[p]
            guarded = guarded or (isinstance(p, ast.If) and 'isEnabledFor' in ast.unparse(p.test))
        if not guarded:
            yield '%s:%s' % (path, getattr(p, 'name', '<module>'))


class TestAgentsRules(unittest.TestCase):
    """Mechanically checkable AGENTS.md rules (AST/inspect, not text matching)."""

    @classmethod
    def setUpClass(cls):
        cls.sources = _library_sources()
        cls.unguarded_hexlify = {site for path, tree in cls.sources.items() for site in _unguarded_hexlify(path, tree)}

    def test_no_print_in_library_modules(self):
        for path, tree in self.sources.items():
            if path in PRINT_ALLOWED or path in PRINT_DEVIATIONS:
                continue
            with self.subTest(path=path):
                self.assertEqual(list(_calls(tree, {'print'})), [])

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
        self.assertEqual(self.unguarded_hexlify - set(HEXLIFY_DEVIATIONS), set())
        self.assertEqual(set(HEXLIFY_DEVIATIONS) - self.unguarded_hexlify, set(), 'stale deviation entry')

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


_add_deviation_tests(TestAgentsRules, PRINT_DEVIATIONS,
                     lambda self, path: self.assertEqual(list(_calls(self.sources[path], {'print'})), []))
_add_deviation_tests(TestAgentsRules, HEXLIFY_DEVIATIONS,
                     lambda self, site: self.assertNotIn(site, self.unguarded_hexlify))


if __name__ == '__main__':
    unittest.main()
