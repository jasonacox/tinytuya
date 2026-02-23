# TinyTuya Module
# -*- coding: utf-8 -*-
"""
 Python module to interface with Tuya WiFi smart devices

 Author: Jason A. Cox
 For more information see https://github.com/jasonacox/tinytuya
"""

from .core import *
from .core.core import __version__
from .core.core import __author__
from .core.core import __copyright__
from .core.core import __project__

from .BasicDevices import *

from .tuyacloud.Cloud import Cloud
