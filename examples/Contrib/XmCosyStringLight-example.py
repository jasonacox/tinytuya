# Works with XmCosy+ RGBW string lights.
# Model # DMD-045-W3
# FCC ID: 2AI5T-DMD-045-W3
# Amazon SKU: B0B5D643VV
#
# Tested with the above mentioned RGBW string lights and a string of 6 RGBCW flood lights.
# Both use Tuya controllers and are made by the Shenzhen Bling Lighting Technologies Co., Ltd.
# FCC ID of the tested flood lights is 2AI5T-LSE-048-W3 and Amazon SKU is B0CFV8TGBH.
#
# Author: Glen Akins, https://github.com/bikerglen
# Date:   January 2024
#
# Format of the color tuple in main is 
#
# ( HSI Flag, Hue, Sat, Int, CW, WW )
#
# HSI Flag = 0 for CW/WW mixing, 1 for HSI mixing
#
# If HSI Flag is 1:
#   Hue is 0 to 359, 0 is red, 120 is green, 240 is blue
#   Sat is 0 to 100
#   Int is 0 to 100
#   CW is 0
#   WW is 0
#
# If HSI Flag is 0:
#   Hue is 0
#   Sat is 0
#   Int is 0
#   CW is 0 to 100
#   WW is 0 to 100
#
# When using the smart life app's diy feature to set WW, NW, or CW:
#
#   WW is   0, 100
#   NW is  50, 100
#   CW is 100, 100
#
# Hue is 2 bytes, MSB first. The rest are 1 byte each.
#

import tinytuya
import time
import base64

# replace the x's with the data for your light string, IP is the local IP, not the cloud IP
DEVICE_IP = "x.x.x.x"
DEVICE_ID = "xxxxxxxxxxxxxxxxxxxxxx"
DEVICE_KEY = "xxxxxxxxxxxxxxxx"
DEVICE_VER = 3.3

def xmcosy_string_lights_encode_colors (lights, colors, offset):

  # header is 8 bytes and always the same
  header = b'\x00\xff\x00\x00\x00\x80\x01\x00'

  # replicate the specified colors across the specified number of lights as many times as possible
  light = 0
  index = offset
  levels = []
  for light in range (lights):
    levels.append (colors[index])
    index += 1
    if index >= len(colors):
      index = 0

  # form the data byte string by combining the header and all the encoded light level tuples
  data = header
  for light in range (lights):
    encoded_level = levels[light][0].to_bytes (1, 'big')  # hsi/white flag
    encoded_level += levels[light][1].to_bytes (2, 'big') # hue, 2 bytes, MSB first
    encoded_level += levels[light][2].to_bytes (1, 'big') # saturation
    encoded_level += levels[light][3].to_bytes (1, 'big') # intensity
    encoded_level += levels[light][4].to_bytes (1, 'big') # cool white
    encoded_level += levels[light][5].to_bytes (1, 'big') # warm white
    data += encoded_level

  # base 64 encode the data string and convert to ascii
  b64 = base64.b64encode (data).decode ('ascii')

  return b64

if __name__ == '__main__':

  # 30 lights
  lights = 30

  # these 6 colors will be replicated 5 times across the 30 lights
  colors = [
    ( 1,   0, 100, 100,   0,   0 ), # RED
    ( 1,  60, 100, 100,   0,   0 ), # YELLOW
    ( 1, 120, 100, 100,   0,   0 ), # GREEN
    ( 1, 180, 100, 100,   0,   0 ), # CYAN
    ( 1, 240, 100, 100,   0,   0 ), # BLUE
    ( 1, 300, 100, 100,   0,   0 ), # MAGENTA
  ]

  """
  # these 3 color temps will be replicated 10 times across the 30 lights
  colors = [
    ( 0,   0,   0,   0,   0, 100 ), # WW
    ( 0,   0,   0,   0,  50, 100 ), # NW
    ( 0,   0,   0,   0, 100, 100 ), # CW
  ]
  """

  # make the colors chase down the string
  d = tinytuya.BulbDevice(DEVICE_ID, DEVICE_IP, DEVICE_KEY, version=DEVICE_VER, persist=False)
  while True:
    for i in range (len(colors)):
      d102 = xmcosy_string_lights_encode_colors (lights, colors, len(colors)-1-i)
      d.set_value (102, d102)
      time.sleep(1)
