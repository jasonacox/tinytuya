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


if __name__ == '__main__':
    unittest.main()
