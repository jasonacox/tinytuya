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

    def test_gcm_iv_is_random_and_12_bytes(self):
        cipher = mh.AESCipher(LOCAL_KEY.encode('latin1'))
        if not cipher.CRYPTOLIB_HAS_GCM:
            self.skipTest("crypto backend has no GCM support")
        if log.isEnabledFor(logging.DEBUG):
            self.skipTest("debug mode uses a fixed IV for packet troubleshooting")
        iv1 = cipher.get_encryption_iv(True)
        iv2 = cipher.get_encryption_iv(True)
        self.assertEqual(len(iv1), 12)
        self.assertEqual(len(iv2), 12)
        self.assertNotEqual(iv1, iv2, "GCM IV must be random per message")

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



class TestConfiguredDeviceScanner(unittest.TestCase):
    """Offline coverage for configured devices which do not broadcast."""

    @staticmethod
    def _configured(ip='192.0.2.10', version=3.5):
        return {
            'id': 'abcdefghijklmnopqrst',
            'key': LOCAL_KEY,
            'ip': ip,
            'version': version,
            'name': 'Configured test device',
        }

    def _run_scan(self, configured, static_success=True, broadcast=None,
                  device_file=None, verbose=False, late_broadcast=False,
                  static_inflight=False, poll_configured=True, stale_read=False,
                  on_static_connect=None,
                  **scan_options):
        from tinytuya import scanner

        class OfflineStaticDevice(scanner.StaticDevice):
            created = []

            def __init__(self, *args, **kwargs):
                super(OfflineStaticDevice, self).__init__(*args, **kwargs)
                self.created.append(self)

            def connect(self):
                if static_inflight:
                    self.sock = MagicMock()
                    self.write = True
                    self.timeo = scanner.time.time() + 1.0
                if on_static_connect:
                    on_static_connect(self)
                if static_inflight:
                    return
                if static_success:
                    self.finished = True
                    self.deviceinfo['dps'] = {'dps': {'1': True}}
                    self.deviceinfo['err'] = ''
                else:
                    self.finished = False
                    self.deviceinfo['err'] = 'No response'
                self.close()
                if late_broadcast:
                    # Keep the loop alive for one more select pass after the
                    # completed result so a late UDP packet can supersede it.
                    self.sock = MagicMock()

            def read_data(self):
                if stale_read:
                    raise AssertionError('dispatched a closed static socket')
                super(OfflineStaticDevice, self).read_data()

            def write_data(self):
                self.finished = bool(static_success)
                if static_success:
                    self.deviceinfo['dps'] = {'dps': {'1': True}}
                    self.deviceinfo['err'] = ''
                else:
                    self.deviceinfo['err'] = 'No response'
                self.close()

        def offline_broadcast_connect(device):
            device.remove = True

        udp_sockets = [MagicMock(), MagicMock(), MagicMock()]
        self.last_udp_sockets = udp_sockets
        ready = [udp_sockets[0]] if broadcast and not late_broadcast else []
        late_ready = [udp_sockets[0]] if broadcast and late_broadcast else []
        if broadcast:
            udp_sockets[0].recvfrom.return_value = (
                b'offline-broadcast',
                (broadcast.get('ip', '192.0.2.11'), scanner.UDPPORT),
            )

        def offline_select(read_socks, write_socks, error_socks, timeout):
            del read_socks, error_socks, timeout
            if ready:
                return ([ready.pop(0)], [], [])
            if late_ready and OfflineStaticDevice.created:
                sockets = [late_ready.pop(0)]
                if stale_read:
                    sockets.append(OfflineStaticDevice.created[0].sock)
                return (sockets, [], [])
            if write_socks:
                return ([], [write_socks[0]], [])
            return ([], [], [])

        with patch.object(scanner.socket, 'socket', side_effect=udp_sockets), \
                patch.object(scanner.select, 'select', side_effect=offline_select), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner, 'send_discovery_request', return_value=True), \
                patch.object(scanner, 'save_snapshotfile'), \
                patch.object(scanner, 'DEVICEFILE',
                             device_file or scanner.DEVICEFILE), \
                patch.object(scanner, 'StaticDevice', OfflineStaticDevice), \
                patch.object(scanner.PollDevice, 'connect',
                             offline_broadcast_connect), \
                patch.object(scanner.time, 'sleep'):
            # scanner calls tinytuya.decrypt_udp, not a local alias.
            with patch.object(tinytuya, 'decrypt_udp',
                              return_value=json.dumps(broadcast or {})):
                result = scanner.devices(
                    scantime=0,
                    color=False,
                    poll=True,
                    byID=True,
                    discover=True,
                    show_timer=False,
                    tuyadevices=configured,
                    verbose=verbose,
                    poll_configured=poll_configured,
                    **scan_options
                )

        return result, OfflineStaticDevice.created

    def test_interrupt_on_first_select_returns_cleanly(self):
        from tinytuya import scanner

        sockets = [MagicMock(), MagicMock(), MagicMock()]
        with patch.object(scanner.socket, 'socket', side_effect=sockets), \
                patch.object(scanner.select, 'select', side_effect=KeyboardInterrupt), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner.time, 'sleep'):
            result = scanner.devices(scantime=0, show_timer=False,
                                     tuyadevices=[self._configured()])
        self.assertEqual(result, {})
        for sock in sockets:
            sock.close.assert_called()

    def test_interrupt_during_static_construction_closes_existing_sockets(self):
        from tinytuya import scanner

        rows = [self._configured(), self._configured(ip='192.0.2.12')]
        rows[1]['id'] = 'second-device'
        original_init = scanner.PollDevice.__init__
        opened = []
        def interrupt_second(device, *args):
            if opened:
                raise KeyboardInterrupt()
            original_init(device, *args)

        def open_socket(device):
            opened.append(device.sock)

        with patch.object(scanner.PollDevice, '__init__', interrupt_second):
            with self.assertRaises(KeyboardInterrupt):
                self._run_scan(rows, static_inflight=True, on_static_connect=open_socket)
        for sock in self.last_udp_sockets:
            sock.close.assert_called()
        self.assertEqual(len(opened), 1)
        opened[0].close.assert_called()

    def test_interrupt_during_static_connect_closes_all_sockets(self):
        from tinytuya import scanner

        row = self._configured()
        opened = []
        def interrupt_connect(device):
            device.sock = MagicMock()
            opened.append(device.sock)
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self._run_scan([row], on_static_connect=interrupt_connect)
        self.assertEqual(len(opened), 1)
        opened[0].close.assert_called()
        for sock in self.last_udp_sockets:
            sock.close.assert_called()

    def test_force_result_consumes_configured_poll_budget(self):
        from tinytuya import scanner

        row = self._configured()
        class FoundForceDevice(scanner.DeviceDetect):
            def __init__(self, *args):
                super(FoundForceDevice, self).__init__(*args)
                self.sock = MagicMock()
                self.write = True
                self.timeo = scanner.time.time() + 10

            def write_data(self):
                self.scanned = self.found = True
                self.deviceinfo['gwId'] = 'force-device'
                self.close()

        with patch.object(scanner, 'ForceScannedDevice', FoundForceDevice):
            result, created = self._run_scan(
                [row], forcescan=['192.0.2.99/32'], maxdevices=1
            )
        self.assertEqual(list(result), ['force-device'])
        self.assertEqual(created, [])

    def test_static_waits_for_active_force_scan_to_drain(self):
        from tinytuya import scanner

        row = self._configured()
        class SlowForceDevice(scanner.DeviceDetect):
            created = []

            def __init__(self, *args):
                super(SlowForceDevice, self).__init__(*args)
                self.created.append(self)
                self.sock = MagicMock()
                self.write = True
                self.timeo = scanner.time.time() + 10
                self.rounds = 0

            def write_data(self):
                self.rounds += 1
                if self.rounds == 2:
                    self.close()

        drained_at_start = []
        def check_drained(device):
            del device
            drained_at_start.append(
                bool(SlowForceDevice.created) and
                all(dev.remove for dev in SlowForceDevice.created)
            )

        with patch.object(scanner, 'ForceScannedDevice', SlowForceDevice):
            result, created = self._run_scan(
                [row], forcescan=[row['ip'] + '/32'],
                on_static_connect=check_drained
            )
        self.assertEqual(drained_at_start, [True])
        self.assertEqual(len(created), 1)
        self.assertIn(row['id'], result)

    def test_udp_and_static_read_ready_together_skip_closed_socket(self):
        row = self._configured()
        broadcast = {
            'gwId': row['id'], 'ip': '192.0.2.11',
            'version': '3.5', 'productKey': 'offline-product',
        }
        result, created = self._run_scan(
            [row], broadcast=broadcast, late_broadcast=True,
            static_inflight=True, stale_read=True
        )
        self.assertEqual(result[row['id']]['origin'], 'broadcast')
        self.assertIsNone(created[0].sock)

    def test_aborted_static_read_does_not_reconnect(self):
        from tinytuya import scanner

        row = self._configured()
        options = {
            'connect_timeout': 1, 'data_timeout': 1, 'retries': 2,
            'termcolors': scanner.TermColors(*tinytuya.termcolor(False)),
            'verbose': False, 'tuyadevices': [row], 'keylist': [],
        }
        dev = scanner.StaticDevice(row['ip'], scanner._configured_device_info(row), options, False)
        dev.sock = MagicMock()
        dev.abort()
        with patch.object(dev, 'connect') as connect:
            dev.read_data()
        connect.assert_not_called()
        self.assertFalse(dev.found)
        self.assertIsNone(dev.sock)

    def test_snapshot_commands_disable_configured_fallback(self):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        for command in (scanner.snapshot, scanner.snapshotjson):
            with self.subTest(command=command.__name__), \
                    patch.object(scanner, 'load_snapshotfile',
                                 return_value={'devices': []}), \
                    patch.object(scanner, 'devices', return_value={}) as scan, \
                    redirect_stdout(io.StringIO()):
                if command is scanner.snapshot:
                    command(color=False, assume_yes=True)
                else:
                    command()
                self.assertIs(scan.call_args[1].get('poll_configured'), False)

    def test_static_wanted_device_stops_before_unrelated_configured_ips(self):
        first = self._configured()
        second = self._configured(ip='192.0.2.12')
        second['id'] = 'another-configured-device'
        for target in ({'wantids': [first['id']]}, {'wantips': [first['ip']]}):
            with self.subTest(target=target):
                result, created = self._run_scan([first, second], **target)
                self.assertEqual(list(result), [first['id']])
                self.assertEqual(len(created), 1)

    def test_static_success_removes_wanted_id(self):
        import io
        from contextlib import redirect_stdout

        configured = self._configured()
        output = io.StringIO()
        with redirect_stdout(output):
            result, _ = self._run_scan(
                [configured], wantids=[configured['id']], verbose=True
            )
        self.assertIn(configured['id'], result)
        self.assertNotIn('Did not find', output.getvalue())

    def test_failed_static_poll_releases_maxdevices_slot(self):
        first = self._configured()
        second = self._configured(ip='192.0.2.12')
        second['id'] = 'second-device'
        def fail_first(device):
            if device.ip == first['ip']:
                raise OSError('offline fixture: refused connection')
        result, created = self._run_scan(
            [first, second], maxdevices=1, on_static_connect=fail_first
        )
        self.assertEqual(list(result), [second['id']])
        self.assertEqual(len(created), 2)

    def test_broadcast_and_static_share_maxdevices_budget(self):
        rows = [self._configured(), self._configured(ip='192.0.2.12')]
        rows[1]['id'] = 'second-device'
        broadcast = {
            'gwId': 'broadcast-device', 'ip': '192.0.2.11',
            'version': '3.5', 'productKey': 'offline-product',
        }
        result, created = self._run_scan(rows, broadcast=broadcast, maxdevices=2)
        self.assertEqual(set(result), {'broadcast-device', rows[0]['id']})
        self.assertEqual(len(created), 1)

    def test_static_successes_respect_maxdevices(self):
        rows = [self._configured(ip='192.0.2.%d' % n) for n in range(20, 24)]
        for n, row in enumerate(rows):
            row['id'] = 'configured-%d' % n
        for inflight in (False, True):
            with self.subTest(inflight=inflight):
                result, created = self._run_scan(
                    rows, maxdevices=1, static_inflight=inflight
                )
                self.assertEqual(list(result), [rows[0]['id']])
                self.assertEqual(len(created), 1)

    def test_udp_early_stop_does_not_start_configured_polls(self):
        configured = self._configured()
        broadcast = {
            'gwId': 'another-device', 'ip': '192.0.2.11',
            'version': '3.5', 'productKey': 'offline-product',
        }
        for stop in ({'maxdevices': 1}, {'wantids': ['another-device']},
                     {'wantips': ['192.0.2.11']}):
            with self.subTest(stop=stop):
                result, created = self._run_scan(
                    [configured], broadcast=broadcast, **stop
                )
                self.assertEqual(list(result), ['another-device'])
                self.assertEqual(created, [])

    def test_verbose_snapshot_skips_malformed_rows(self):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        valid = self._configured()
        rows = [None, 'bad-row', {}, {'key': LOCAL_KEY}, {'id': ['bad']}, valid]
        with redirect_stdout(io.StringIO()):
            result, created = self._run_scan(rows, verbose=True)
        self.assertEqual(list(result), [valid['id']])
        self.assertEqual(len(created), 1)

    def test_force_key_lookup_skips_malformed_rows(self):
        from tinytuya import scanner

        row = self._configured()
        dev = scanner.ForceScannedDevice.__new__(scanner.ForceScannedDevice)
        dev.options = {'tuyadevices': [None, {}, {'key': row['key']}, row]}
        dev.deviceinfo = {'key': row['key']}
        dev.device = MagicMock()
        dev.key_found = False
        dev.found_key()
        self.assertTrue(dev.key_found)
        self.assertEqual(dev.deviceinfo['gwId'], row['id'])

    def test_broadcast_lookup_skips_non_string_key(self):
        row = self._configured()
        bad = dict(row, key=123)
        broadcast = {
            'gwId': row['id'], 'ip': row['ip'],
            'version': '3.5', 'productKey': 'offline-product',
        }
        result, _ = self._run_scan([bad, row], broadcast=broadcast)
        self.assertEqual(result[row['id']]['key'], row['key'])

    def test_non_string_credentials_are_skipped(self):
        from tinytuya import scanner

        for field in ('id', 'key'):
            for value in (123, ['invalid'], {'invalid': True}):
                with self.subTest(field=field, value=value):
                    item = self._configured()
                    item[field] = value
                    self.assertIsNone(scanner._configured_device_info(item))
                    result, created = self._run_scan([item])
                    self.assertEqual(result, {})
                    self.assertEqual(created, [])

    def test_configured_device_is_polled_without_udp_discovery(self):
        configured = self._configured()

        result, static_devices = self._run_scan([configured])

        self.assertIn(configured['id'], result)
        self.assertEqual(result[configured['id']]['origin'], 'static')
        self.assertEqual(result[configured['id']]['version'],
                         configured['version'])
        self.assertEqual(len(static_devices), 1)

    def test_configured_poll_can_be_disabled_without_disabling_polling(self):
        configured = self._configured()

        result, static_devices = self._run_scan(
            [configured], poll_configured=False
        )

        self.assertEqual(result, {})
        self.assertEqual(static_devices, [])

    def test_device_scan_forwards_configured_poll_opt_out(self):
        from tinytuya import scanner

        with patch.object(scanner, 'devices', return_value={}) as scan_devices:
            tinytuya.deviceScan(poll_configured=False)

        self.assertFalse(scan_devices.call_args[1]['poll_configured'])

    def test_scan_cli_forwards_configured_poll_opt_out(self):
        import runpy
        import sys
        from tinytuya import scanner

        argv = ['tinytuya', 'scan', '0', '-no-poll-configured']
        with patch.object(sys, 'argv', argv), \
                patch.object(scanner, 'scan') as scan:
            runpy.run_module('tinytuya', run_name='__main__')

        self.assertFalse(scan.call_args[1]['poll_configured'])

    def test_broadcast_discovery_suppresses_configured_duplicate(self):
        configured = self._configured()
        broadcast = {
            'gwId': configured['id'],
            'ip': '192.0.2.11',
            'version': '3.5',
            'productKey': 'offline-product',
        }

        result, static_devices = self._run_scan([configured],
                                                broadcast=broadcast)

        self.assertEqual(list(result), [configured['id']])
        self.assertEqual(result[configured['id']]['origin'], 'broadcast')
        self.assertEqual(static_devices, [])

    def test_incomplete_configured_devices_are_skipped(self):
        incomplete = []
        for field in ('id', 'key', 'ip', 'version'):
            item = self._configured()
            del item[field]
            incomplete.append(item)

        result, static_devices = self._run_scan(incomplete)

        self.assertEqual(result, {})
        self.assertEqual(static_devices, [])

    def test_failed_configured_poll_is_nonfatal_and_not_found(self):
        result, static_devices = self._run_scan(
            [self._configured()], static_success=False
        )

        self.assertEqual(result, {})
        self.assertEqual(len(static_devices), 1)
        self.assertFalse(static_devices[0].found)

    def test_alternate_device_file_is_used_for_configured_poll(self):
        import os
        import tempfile

        configured = self._configured()
        with tempfile.TemporaryDirectory() as tmpdir:
            device_file = os.path.join(tmpdir, 'alternate-devices.json')
            with open(device_file, 'w') as outfile:
                json.dump([configured], outfile)

            result, static_devices = self._run_scan(
                None, device_file=device_file
            )

        self.assertIn(configured['id'], result)
        self.assertEqual(len(static_devices), 1)

    def test_configured_version_is_used_by_static_state_machine(self):
        from tinytuya import scanner

        configured = self._configured(version=3.4)
        deviceinfo = scanner._configured_device_info(configured)
        options = {
            'connect_timeout': 0,
            'data_timeout': 0,
            'termcolors': scanner.TermColors(*tinytuya.termcolor(False)),
            'verbose': False,
            'retries': 0,
            'tuyadevices': [configured],
            'keylist': [],
        }
        tcp_socket = MagicMock()
        with patch.object(scanner.socket, 'socket', return_value=tcp_socket):
            device = scanner.StaticDevice(
                configured['ip'], deviceinfo, options, False
            )
            device.connect()

        self.assertEqual(device.device.version, configured['version'])
        device.close()

    def test_configured_path_does_not_print_or_log_local_key(self):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        configured = self._configured()
        output = io.StringIO()
        with redirect_stdout(output), \
                self.assertLogs(scanner.__name__, level='DEBUG') as captured:
            result, _ = self._run_scan([configured], verbose=True)

        self.assertIn(configured['id'], result)
        emitted = output.getvalue() + '\n'.join(captured.output)
        self.assertIn('Static Poll', emitted)
        self.assertIn('Found 1 devices', emitted)
        self.assertIn('Versions: 3.5: 1', emitted)
        self.assertNotIn(configured['key'], emitted)

    def test_multiple_configured_devices_share_the_scan_loop(self):
        first = self._configured()
        second = dict(first)
        second['id'] = 'fedcba9876543210dcba'
        second['ip'] = '192.0.2.12'

        result, static_devices = self._run_scan([first, second])

        self.assertEqual(set(result), {first['id'], second['id']})
        self.assertEqual(len(static_devices), 2)

    def test_configured_candidate_normalizes_ipv4_and_supported_version(self):
        import ipaddress
        from tinytuya import scanner

        for version in ('3.1', 3.2, '3.30', 3.4, '3.50'):
            configured = self._configured(
                ip=ipaddress.IPv4Address('192.0.2.40'),
                version=version,
            )

            deviceinfo = scanner._configured_device_info(configured)

            self.assertIsNot(deviceinfo, configured)
            self.assertEqual(deviceinfo['ip'], '192.0.2.40')
            self.assertIsInstance(deviceinfo['ip'], str)
            self.assertIsInstance(deviceinfo['version'], float)
            self.assertIn(deviceinfo['version'], (3.1, 3.2, 3.3, 3.4, 3.5))

    def test_invalid_candidates_are_skipped_before_socket_construction(self):
        import io
        from contextlib import redirect_stdout
        from tinytuya import scanner

        invalid_specs = (
            ('not-an-ip', 3.5),
            ('2001:db8::40', 3.5),
            ('192.0.2.41', 3.0),
            ('192.0.2.42', 3.6),
            ('192.0.2.43', 'not-a-version'),
        )
        configured = []
        invalid_keys = []
        for index, (ip, version) in enumerate(invalid_specs):
            item = self._configured(ip=ip, version=version)
            item['id'] = 'invalid-device-%04d' % index
            item['key'] = 'badkey%010d' % index
            configured.append(item)
            invalid_keys.append(item['key'])

        output = io.StringIO()
        with redirect_stdout(output), \
                self.assertLogs(scanner.__name__, level='DEBUG') as captured:
            result, static_devices = self._run_scan(configured, verbose=True)

        emitted = output.getvalue() + '\n'.join(captured.output)
        self.assertEqual(result, {})
        self.assertEqual(static_devices, [])
        for key in invalid_keys:
            self.assertNotIn(key, emitted)

    def test_unsupported_configured_version_is_logged_without_local_key(self):
        from tinytuya import scanner

        configured = self._configured(version=3.6)
        with self.assertLogs(scanner.__name__, level='DEBUG') as captured:
            deviceinfo = scanner._configured_device_info(configured)

        emitted = '\n'.join(captured.output)
        self.assertIsNone(deviceinfo)
        self.assertIn('unsupported configured protocol version 3.6', emitted)
        self.assertNotIn(configured['key'], emitted)

    def test_late_broadcast_by_id_invalidates_completed_static_poll(self):
        import io
        from contextlib import redirect_stdout

        configured = self._configured(ip='192.0.2.50')
        broadcast = {
            'gwId': configured['id'],
            'ip': '192.0.2.51',
            'version': '3.5',
            'productKey': 'offline-product',
        }
        output = io.StringIO()

        with redirect_stdout(output):
            result, static_devices = self._run_scan(
                [configured], broadcast=broadcast, verbose=True,
                late_broadcast=True,
            )

        self.assertEqual(list(result), [configured['id']])
        self.assertEqual(result[configured['id']]['origin'], 'broadcast')
        self.assertFalse(static_devices[0].found)
        self.assertIsNone(static_devices[0].sock)
        self.assertIn('Found 1 devices', output.getvalue())
        self.assertIn('Versions: 3.5: 1', output.getvalue())

    def test_late_broadcast_by_id_aborts_inflight_static_poll(self):
        import io
        from contextlib import redirect_stdout

        configured = self._configured(ip='192.0.2.60')
        broadcast = {
            'gwId': configured['id'],
            'ip': '192.0.2.61',
            'version': '3.5',
            'productKey': 'offline-product',
        }
        output = io.StringIO()

        with redirect_stdout(output):
            result, static_devices = self._run_scan(
                [configured], broadcast=broadcast, verbose=True,
                late_broadcast=True, static_inflight=True,
            )

        self.assertEqual(list(result), [configured['id']])
        self.assertEqual(result[configured['id']]['origin'], 'broadcast')
        self.assertFalse(static_devices[0].found)
        self.assertIsNone(static_devices[0].sock)
        self.assertIn('Found 1 devices', output.getvalue())
        self.assertIn('Versions: 3.5: 1', output.getvalue())

    def test_configured_starts_respect_max_parallel_and_all_finish(self):
        from tinytuya import scanner

        configured = []
        for index in range(5):
            item = self._configured(ip='192.0.2.%d' % (70 + index))
            item['id'] = '%020d' % (index + 1)
            configured.append(item)

        class BoundedStaticDevice(scanner.StaticDevice):
            created = []
            active = []
            peak_active = 0

            def __init__(self, *args, **kwargs):
                super(BoundedStaticDevice, self).__init__(*args, **kwargs)
                self.created.append(self)

            def connect(self):
                self.sock = MagicMock()
                self.write = True
                self.timeo = scanner.time.time() + 1.0
                self.active.append(self)
                type(self).peak_active = max(
                    type(self).peak_active, len(self.active)
                )

            def write_data(self):
                self.finished = True
                self.deviceinfo['dps'] = {'dps': {'1': True}}
                self.deviceinfo['err'] = ''
                self.close()

            def close(self):
                if self in self.active:
                    self.active.remove(self)
                super(BoundedStaticDevice, self).close()

        udp_sockets = [MagicMock(), MagicMock(), MagicMock()]

        def offline_select(read_socks, write_socks, error_socks, timeout):
            del read_socks, error_socks, timeout
            if write_socks:
                return ([], [write_socks[0]], [])
            return ([], [], [])

        with patch.object(scanner.socket, 'socket', side_effect=udp_sockets), \
                patch.object(scanner.select, 'select', side_effect=offline_select), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner, 'send_discovery_request', return_value=True), \
                patch.object(scanner, 'save_snapshotfile'), \
                patch.object(scanner, 'StaticDevice', BoundedStaticDevice), \
                patch.object(scanner, 'max_parallel', 2), \
                patch.object(scanner.time, 'sleep'):
            result = scanner.devices(
                scantime=0,
                color=False,
                poll=True,
                byID=True,
                discover=True,
                show_timer=False,
                tuyadevices=configured,
            )

        self.assertEqual(set(result), {item['id'] for item in configured})
        self.assertEqual(len(BoundedStaticDevice.created), len(configured))
        self.assertLessEqual(BoundedStaticDevice.peak_active, 2)

    def test_interrupt_stops_and_clears_configured_socket(self):
        from tinytuya import scanner

        configured = self._configured(ip='192.0.2.80')

        class InterruptStaticDevice(scanner.StaticDevice):
            created = []
            stop_calls = 0

            def __init__(self, *args, **kwargs):
                super(InterruptStaticDevice, self).__init__(*args, **kwargs)
                self.created.append(self)

            def connect(self):
                self.sock = MagicMock()
                self.write = True
                self.timeo = scanner.time.time() + 10.0

            def stop(self):
                type(self).stop_calls += 1
                super(InterruptStaticDevice, self).stop()

        udp_sockets = [MagicMock(), MagicMock(), MagicMock()]

        def interrupt_select(read_socks, write_socks, error_socks, timeout):
            del read_socks, write_socks, error_socks, timeout
            if not InterruptStaticDevice.created:
                return ([], [], [])
            raise KeyboardInterrupt()

        with patch.object(scanner.socket, 'socket', side_effect=udp_sockets), \
                patch.object(scanner.select, 'select', side_effect=interrupt_select), \
                patch.object(scanner, 'get_ip_to_broadcast', return_value={}), \
                patch.object(scanner, 'send_discovery_request', return_value=True), \
                patch.object(scanner, 'save_snapshotfile'), \
                patch.object(scanner, 'StaticDevice', InterruptStaticDevice), \
                patch.object(scanner.time, 'sleep'):
            scanner.devices(
                scantime=0,
                color=False,
                poll=True,
                byID=True,
                discover=True,
                show_timer=False,
                tuyadevices=[configured],
            )

        self.assertEqual(len(InterruptStaticDevice.created), 1)
        self.assertGreaterEqual(InterruptStaticDevice.stop_calls, 1)
        self.assertIsNone(InterruptStaticDevice.created[0].sock)

    def test_real_static_poll_connect_and_response_lifecycle(self):
        from tinytuya import scanner

        configured = self._configured(ip='192.0.2.90', version='3.3')
        deviceinfo = scanner._configured_device_info(configured)
        options = {
            'connect_timeout': 1,
            'data_timeout': 1,
            'termcolors': scanner.TermColors(*tinytuya.termcolor(False)),
            'verbose': False,
            'retries': 0,
            'tuyadevices': [configured],
            'keylist': [],
        }
        tcp_socket = MagicMock()
        tcp_socket.getpeername.return_value = (configured['ip'], scanner.TCPPORT)
        tcp_socket.recv.return_value = tinytuya.PREFIX_BIN + (b'\x00' * 6)
        message = MagicMock()
        message.cmd = tinytuya.DP_QUERY
        message.payload = b'{}'

        with patch.object(scanner.socket, 'socket', return_value=tcp_socket):
            device = scanner.StaticDevice(
                configured['ip'], deviceinfo, options, False
            )
            device.connect()
            device.write_data()
            with patch.object(tinytuya, 'unpack_message',
                              return_value=message), \
                    patch.object(device.device, '_decode_payload',
                                 return_value={'dps': {'1': True}}):
                device.read_data()

        self.assertTrue(device.found)
        self.assertTrue(device.finished)
        self.assertTrue(device.remove)
        self.assertIsNone(device.sock)
        self.assertEqual(device.deviceinfo['dps'], {'dps': {'1': True}})
        tcp_socket.sendall.assert_called()
        tcp_socket.close.assert_called()


if __name__ == '__main__':
    unittest.main()
