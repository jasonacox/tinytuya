"""
    Works with the Star Projector:
    https://www.amazon.com.au/Anyuainiya-Projector-Christmas-Compatible-Adjustable/dp/B0BL9XTLMZ

     Author: Andy Voigt
"""

import colorsys
import tinytuya
from typing import Tuple

HSV = Tuple[float, float, float]
MODES = ['manual', 'scene', 'music']

class GalaxyProjectorState:
    """
    Data Points (dps):
    20 device on/off
    51 star_work_mode: manual, scene, music
    52 colour_switch (nebula on/off)
    53 laser_switch (stars on/off)
    54 laser_bright (stars brightness 10-1000)
    62 rotation_speed (rotation speed 1-100%)
    24 colour_data (nebula hsv)
    """
    def __init__(self, dps=None):
        self.dps = dps or {}

    def update(self, payload):
        payload = payload or {'dps': {}}
        if 'Err' in payload:
            raise Exception(payload)
        self.dps.update(payload['dps'])

    @property
    def device_on(self) -> bool:
        return self.dps['20']

    @property
    def stars_on(self) -> bool:
        return self.dps['53']  # laser_switch

    @property
    def nebula_on(self) -> bool:
        return self.dps['52']  # colour_switch

    @property
    def scene_mode(self) -> str:
        return self.dps['51']  # star_work_mode

    @property
    def stars_brightness_percent(self):
        return int((self.dps['54'] - 10) * 100 / (1000 - 10))  # laser_bright

    @property
    def rotation_speed_percent(self):
        return self.dps['62']  # rotation_speed is 1-100%

    @property
    def nebula_hsv(self) -> HSV:
        return tuyahex2hsv(self.dps['24'])

    def __repr__(self):
        return f'GalaxyProjectorState<{self.parsed_value}>'

    @property
    def parsed_value(self):
        return {k: getattr(self, k) for k in (
            'device_on', 'stars_on', 'nebula_on', 'scene_mode',
            'stars_brightness_percent', 'rotation_speed_percent', 'nebula_hsv')}

def tuyahex2hsv(val: str):
    return tinytuya.BulbDevice._hexvalue_to_hsv(val, bulb="B")

def hsv2tuyahex(h: float, s: float, v: float):
    (r, g, b) = colorsys.hsv_to_rgb(h, s, v)
    hexvalue = tinytuya.BulbDevice._rgb_to_hexvalue(
        r * 255.0, g * 255.0, b * 255.0, bulb='B'
    )
    return hexvalue

class GalaxyProjector:
    def __init__(self, tuya_device_id: str, device_ip_addr: str, tuya_secret_key: str):
        self.device = tinytuya.OutletDevice(tuya_device_id, device_ip_addr, tuya_secret_key)
        self.device.set_version(3.5)
        self.state = GalaxyProjectorState()
        self.update_state()

    def update_state(self):
        self.state.update(self.device.status())

    def set_device_power(self, *, on: bool):
        self.state.update(self.device.set_value(20, on))

    def set_stars_power(self, *, on: bool):
        self.state.update(self.device.set_value(53, on))

    def set_nebula_power(self, *, on: bool):
        self.state.update(self.device.set_value(52, on))

    def set_rotation_speed(self, *, percent: float):
        percent = max(1, min(100, int(percent)))
        self.state.update(self.device.set_value(62, percent))

    def set_stars_brightness(self, *, percent: float):
        percent = max(0, min(100, int(percent)))
        value = int(10 + (1000 - 10) * percent / 100)
        self.state.update(self.device.set_value(54, value))

    def set_nebula_color(self, *, hsv: HSV):
        # Scene mode must be 'manual' to set nebula color manually
        if self.state.scene_mode != 'manual':
            self.set_scene_mode(mode='manual')
        h, s, v = hsv
        h = max(0.0, min(1.0, h))
        s = max(0.0, min(1.0, s))
        v = max(0.0, min(1.0, v))
        hexvalue = hsv2tuyahex(h, s, v)
        self.state.update(self.device.set_value(24, hexvalue))

    def set_scene_mode(self, *, mode: str):
        if mode in MODES:
            self.state.update(self.device.set_value(51, mode))

if __name__ == '__main__':
    proj = GalaxyProjector(
        tuya_device_id=input('Tuya Device ID: '),
        device_ip_addr=input('Device IP Addr: '),
        tuya_secret_key=input('Tuya Device Secret/Local Key: ')
    )
    print()
    print('Current state:', proj.state.parsed_value)
    print()

    input('Turn stars off (press enter)')
    proj.set_device_power(on=True)
    proj.set_stars_power(on=False)

    input('Turn stars on (press enter)')
    proj.set_stars_power(on=True)

    input('Set stars brightness to 100% (press enter)')
    proj.set_stars_brightness(percent=100)

    input('Set stars brightness to 0% (minimal) (press enter)')
    proj.set_stars_brightness(percent=0)

    input('Set rotation speed to 100% (press enter)')
    proj.set_rotation_speed(percent=100)

    input('Set rotation speed to 0% (press enter)')
    proj.set_rotation_speed(percent=0)

    input('Set nebula color to red (press enter)')
    proj.set_nebula_color(hsv=(0, 1, 1))

    input('Reduce nebula brightness (press enter)')
    proj.set_nebula_color(hsv=(0, 1, 0.3))

    input('Turn device off (press enter)')
    proj.set_device_power(on=False)
