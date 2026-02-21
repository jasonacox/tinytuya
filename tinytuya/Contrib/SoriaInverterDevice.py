# tinytuya/Contrib/SoriaInverterDevice.py
"""
TinyTuya - Contrib - SoriaInverterDevice
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Support for SORIA solar micro-inverter (product ID: 5l1ht8jygsyr1wn1)

Protocol:
    DPS values are Base64-encoded binary frames using a repeating TLV structure:
        [PREFIX: 3 bytes] [TAG: 1 byte] [VALUE: 2 bytes big-endian]
    The prefix is detected dynamically (most frequent 3-byte sequence in the frame).

DPS keys:
    '21' : Full report  - voltages, currents, power, temperature, energy (~60s)
    '22' : Config       - firmware versions and device identifiers (read-only)
    '23' : Event status - device state flags
    '24' : Circuit status - on/off per circuit (prefix 01 01 80)
    '25' : Real-time    - active and apparent power only (~2s)
    '29' : Raw binary   - not yet decoded

Author  : Markourai (https://github.com/Markourai)
Issue   : https://github.com/jasonacox/tinytuya/issues/658
"""

import base64
from collections import Counter
from ..core import Device

# ---------------------------------------------------------------------------
# DPS keys
# ---------------------------------------------------------------------------
DPS_FULL     = '21'
DPS_CONFIG   = '22'
DPS_EVENT    = '23'
DPS_STATUS   = '24'
DPS_REALTIME = '25'
DPS_RAW      = '29'

# ---------------------------------------------------------------------------
# TAG identifiers
# ---------------------------------------------------------------------------
TAG_WIFI_SIGNAL  = 0x00  # WiFi signal level (raw)
TAG_ENERGY_KWH   = 0x02  # Energy exported, /100 -> kWh  (also 0x06, 0x4c)
TAG_V2_VOLTS     = 0x07  # Grid voltage,    /10  -> V
TAG_A2_AMPERES   = 0x1a  # Grid current,    /100 -> A
TAG_W2_WATTS     = 0x1e  # Grid power            -> W
TAG_HZ           = 0x23  # Grid frequency,  /100 -> Hz
TAG_W_AC         = 0x27  # Apparent power        -> VA  (also 0x2a)
TAG_W1_WATTS     = 0x31  # DC power              -> W
TAG_V1_VOLTS     = 0x32  # DC voltage,      /10  -> V
TAG_A1_AMPERES   = 0x33  # DC current,      /100 -> A
TAG_W_PV         = 0x49  # Active power (realtime, = 0x31)
TAG_COS_PHI      = 0x4a  # Power factor,    /100
TAG_TEMP1        = 0x57  # Temperature 1,   /10  -> C
TAG_TEMP2        = 0x58  # Temperature 2,   /10  -> C

# ---------------------------------------------------------------------------
# Internal TLV helpers
# ---------------------------------------------------------------------------

def _detect_prefix(data):
    """Return the most frequent 3-byte sequence — that is the TLV prefix.
    Falls back to 01 01 10 if detection fails."""
    counts = Counter()
    for i in range(len(data) - 5):
        candidate = data[i:i+3]
        # Ignore three null bytes, which are used as padding/noise and are not a valid TLV prefix for this device.
        if candidate != bytes(3):
            counts[candidate] += 1
    if not counts:
        return bytes.fromhex('010110')
    return counts.most_common(1)[0][0]


def _parse_tlv(data):
    """Extract all {tag: value} pairs from a binary TLV frame."""
    prefix = _detect_prefix(data)
    tags = {}
    i = 0
    while i < len(data) - 5:
        if data[i:i+3] == prefix:
            tag = data[i+3]
            val = (data[i+4] << 8) | data[i+5]
            tags[tag] = val
            i += 6
        else:
            i += 1
    return tags


def _decode_b64_tlv(value):
    """Decode a Base64 DPS string into a tag dict. Returns {} on error."""
    try:
        return _parse_tlv(base64.b64decode(value))
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Device class
# ---------------------------------------------------------------------------

class SoriaInverterDevice(Device):
    """Support for SORIA solar inverter (product ID: 5l1ht8jygsyr1wn1)

    Usage::

        from tinytuya.Contrib import SoriaInverterDevice

        d = SoriaInverterDevice(
            dev_id='abcdefghijklmnop123456',
            address='10.2.3.4',
            local_key='1234567890123abc'
        )
        d.receive()  # initial handshake

        while True:
            data = d.receive_and_update()
            print(d.get_realtime_power())
            print(d.get_full_report())
    """

    def __init__(self, *args, **kwargs):
        # set the default version to 3.5
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.5
        # set persistent so we can receive sensor broadcasts
        if 'persist' not in kwargs:
            kwargs['persist'] = True
        super(SoriaInverterDevice, self).__init__(*args, **kwargs)
        self._cached_dps = {}
        self._decoded    = {}   # decoded physical values, keyed by DPS id

    # ------------------------------------------------------------------
    # Core overrides (as advised by maintainer)
    # ------------------------------------------------------------------

    def status(self):
        """Override status — this device does not support status queries.
        Returns the last cached DPS data received asynchronously."""
        return {'dps': self._cached_dps.copy()}

    def receive_and_update(self, timeout=1):
        """Receive one async update, cache raw DPS values and decode them.

        Returns the raw tinytuya message dict, or None.
        """
        old_timeout = self.connection_timeout
        self.set_socketTimeout(timeout)
        try:
            data = self.receive()
        finally:
            self.set_socketTimeout(old_timeout)
        if data and 'dps' in data:
            self._cached_dps.update(data['dps'])
            for dp_id in [DPS_FULL, DPS_REALTIME, DPS_EVENT, DPS_STATUS, DPS_RAW]:
                if dp_id in data['dps']:
                    self._decode_dp(dp_id, data['dps'][dp_id])
        return data

    # ------------------------------------------------------------------
    # Internal decoding (fills self._decoded)
    # ------------------------------------------------------------------

    def _decode_dp(self, dp_id, value):
        """Decode a Base64-encoded DPS value and store physical results."""
        if dp_id == DPS_REALTIME:
            self._decoded[DPS_REALTIME] = self._decode_realtime(value)

        elif dp_id == DPS_FULL:
            self._decoded[DPS_FULL] = self._decode_full(value)

        elif dp_id == DPS_STATUS:
            self._decoded[DPS_STATUS] = self._decode_status(value)

        # DPS_EVENT and DPS_RAW: store raw hex for future analysis
        elif dp_id in (DPS_EVENT, DPS_RAW):
            try:
                self._decoded[dp_id] = {'raw_hex': base64.b64decode(value).hex()}
            except Exception:
                pass

    def _decode_realtime(self, value):
        """Decode DPS '25' — real-time active and apparent power."""
        tags = _decode_b64_tlv(value)
        if not tags:
            return None
        W_PV = tags.get(TAG_W_PV)
        W_AC = tags.get(TAG_W_AC)
        if W_PV is None:
            return None
        return {
            'W_PV': W_PV,
            'W_AC': W_AC,
        }

    def _decode_full(self, value):
        """Decode DPS '21' — complete electrical report."""
        tags = _decode_b64_tlv(value)
        if not tags:
            return None

        def t(tag_id):
            return tags.get(tag_id)

        if t(TAG_W1_WATTS) is None:
            return None

        return {
            # DC circuit (panel / battery)
            'V1_volts':    round(t(TAG_V1_VOLTS)   / 10,  1) if t(TAG_V1_VOLTS)   else None,
            'A1_amperes':  round(t(TAG_A1_AMPERES)  / 100, 2) if t(TAG_A1_AMPERES) else None,
            'W1_watts':    t(TAG_W1_WATTS),
            # AC grid circuit
            'V2_volts':    round(t(TAG_V2_VOLTS)   / 10,  1) if t(TAG_V2_VOLTS)   else None,
            'A2_amperes':  round(t(TAG_A2_AMPERES)  / 100, 2) if t(TAG_A2_AMPERES) else None,
            'W2_watts':    t(TAG_W2_WATTS),
            # Grid quality
            'Hz':          round(t(TAG_HZ)          / 100, 2) if t(TAG_HZ)         else None,
            'cos_phi':     round(t(TAG_COS_PHI)     / 100, 2) if t(TAG_COS_PHI)    else None,
            # Temperatures
            'temp1_C':     round(t(TAG_TEMP1)       / 10,  1) if t(TAG_TEMP1)      else None,
            'temp2_C':     round(t(TAG_TEMP2)       / 10,  1) if t(TAG_TEMP2)      else None,
            # Energy
            'energy_kwh':  round(t(TAG_ENERGY_KWH)  / 100, 2) if t(TAG_ENERGY_KWH) else None,
            # Connectivity
            'wifi_signal': t(TAG_WIFI_SIGNAL),
        }

    def _decode_status(self, value):
        """Decode DPS '24' — circuit on/off status (uses fixed prefix 01 01 80)."""
        try:
            raw    = base64.b64decode(value)
            prefix = bytes([0x01, 0x01, 0x80])
            tags   = {}
            i = 0
            while i < len(raw) - 5:
                if raw[i:i+3] == prefix:
                    tag = raw[i+3]
                    val = (raw[i+4] << 8) | raw[i+5]
                    tags[tag] = val
                    i += 6
                else:
                    i += 1
            return {f'circuit_{k}': (v != 0) for k, v in sorted(tags.items())}
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Public getters (return last decoded value from cache)
    # ------------------------------------------------------------------

    def get_realtime_power(self):
        """Return last decoded real-time power (DPS '25').

        Returns::

            {
                'W_PV':   int,   # active power in watts
                'W_AC':   int,   # apparent power in VA
            }
        """
        return self._decoded.get(DPS_REALTIME)

    def get_full_report(self):
        """Return last decoded full electrical report (DPS '21').

        Returns::

            {
                'V1_volts':    float,  # DC voltage (V)
                'A1_amperes':  float,  # DC current (A)
                'W1_watts':    int,    # DC power (W)
                'V2_volts':    float,  # Grid voltage (V)
                'A2_amperes':  float,  # Grid current (A)
                'W2_watts':    int,    # Grid power (W)
                'Hz':          float,  # Grid frequency (Hz)
                'cos_phi':     float,  # Power factor
                'temp1_C':     float,  # Temperature 1 (C) display by Tuya app
                'temp2_C':     float,  # Temperature 2 (C)
                'energy_kwh':  float,  # Cumulated energy (kWh)
                'wifi_signal': int,    # WiFi signal level
            }
        """
        return self._decoded.get(DPS_FULL)

    def get_circuit_status(self):
        """Return last decoded circuit on/off status (DPS '24').

        Returns::

            {'circuit_0': bool, 'circuit_1': bool, ...}
        """
        return self._decoded.get(DPS_STATUS)