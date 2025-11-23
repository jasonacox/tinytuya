import json
import os
import time
import logging
from tuya_sharing import LoginControl, Manager, SharingTokenListener


class _TokenListener(SharingTokenListener):
  def __init__(self, parent):
    self.parent = parent

  def update_token(self, token_info):
    self.parent.info.update(token_info)
    self.parent._save_info()
    self.parent.logger.info("Token updated from Tuya cloud")


class TuyaWizard:
  def __init__(self, info_file="./tuyacreds.json", logger=None):
    # CONST
    self.client_id="HA_3y9q4ak7g4ephrvke"
    self.schema="haauthorize"

    self.info_file = info_file
    self.login = LoginControl()
    self.info = {}
    self.manager = None
    self.qr_callback = None
    self.logger = logger or logging.getLogger(__name__)

  def _load_saved_info(self, info=None):
    try:
      if not info:
        with open(self.info_file, "r", encoding="utf-8") as f:
          info = json.load(f)
      if "user_code" in self.info:
        info.pop("user_code", None)
      self.info.update(info)
      self.logger.info("Loaded stored login info")
      return True
    except Exception as e:
      self.logger.warning(f"Failed to load stored info: {e}")
      return False

  def _save_info(self):
    if not self.info:
      return
    try:
      with open(self.info_file, "w", encoding="utf-8") as f:
        json.dump(self.info, f, ensure_ascii=False, indent=2)
      self.logger.info(f"Login info saved to {self.info_file}")
    except Exception as e:
      self.logger.error(f"Failed to save login info: {e}")

  def get_qr_url(self):
    response = self.login.qr_code(self.client_id, self.schema, self.info.get("user_code"))
    if not response.get("success"):
      raise Exception("QR request failed: " + response.get("msg", ""))

    qr_token = response["result"]["qrcode"]
    qr_url = f"tuyaSmart--qrLogin?token={qr_token}"
    return qr_token, qr_url

  def wait_for_login_result(self, qr_token, retry_sec=5, timeout=120):
    start = time.time()
    self.logger.info("Waiting for Tuya login confirmation (Scan QR on your phone)...")
    while time.time() - start <= timeout:
      ret, info = self.login.login_result(qr_token, self.client_id, self.info.get("user_code"))
      if ret:
        if "user_code" in self.info:
          info.pop("user_code", None)
        self.info.update(info)
        self.logger.info(f"Login success: {info.get('username')}")
        return True
      time.sleep(retry_sec)
    raise TimeoutError("Login timeout: User did not scan the QR code in time.")

  def init_manager(self):
    if not self.info:
      raise RuntimeError("Login info missing")

    token_listener = _TokenListener(self)
    self.manager = Manager(
      self.client_id,
      self.info.get("user_code"),
      self.info.get("terminal_id"),
      self.info.get("endpoint"),
      self.info,
      token_listener
    )
    self.logger.info("Manager initialized")

  def convert_to_dict_recursive(self, obj):
    if isinstance(obj, dict):
      return {k: self.convert_to_dict_recursive(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
      return [self.convert_to_dict_recursive(item) for item in obj]
    elif hasattr(obj, "__dict__"):
      return self.convert_to_dict_recursive(obj.__dict__)
    elif isinstance(obj, str) and obj.startswith("{") and obj.endswith("}"):
      try:
        return json.loads(obj)
      except json.JSONDecodeError:
        pass
    return obj

  def postprocessing_device(self, tuyadevices):
    for dev in tuyadevices:
      if "key" not in dev:
        dev["key"] = dev.get("local_key", "")
      if "ip" in dev:
        dev["ip"] = ""
      if "sub" in dev and dev["sub"]:
        # no parent from cloud, try to find it via the local key
        if "parent" in dev and dev["parent"]:
          continue

        # Set "parent" to an empty string in case we can't find it
        dev["parent"] = ""

        # Only try to find the parent if the device has a local key
        if "key" in dev and dev["key"]:
          if "id" not in dev:
            dev["id"] = ""
          found = False
          # Loop through all devices again to try and find a non-sub-device with the same local key
          for parent in tuyadevices:
            if "id" not in parent or parent["id"] == dev["id"]:
              continue
            # Check for matching local keys and if device is not a sub-device then assume we found the parent
            if "key" in parent and parent["key"] and dev["key"] == parent["key"] and ( "sub" not in parent or not parent["sub"]):
              found = parent
              break
          if found:
            dev["parent"] = found["id"]

  def fetch_devices(self, save_path=None):
    if not self.manager:
      raise RuntimeError("Manager not initialized")
    self.logger.info("Fetching device cache from Tuya cloud...")
    try:
      self.manager.update_device_cache()
    except Exception as e:
      self.qr_login()
      self.manager.update_device_cache()
    tuyadevices = [self.convert_to_dict_recursive(dev) for dev in self.manager.device_map.values()]
    self.postprocessing_device(tuyadevices)
    return tuyadevices

  def qr_login(self):
    self.logger.info("Starting QR login")
    qr_token, qr_url = self.get_qr_url()
    if self.qr_callback:
      self.qr_callback(qr_url)
    else:
      self.logger.warning("No QR callback provided. The URL is: " + qr_url)
    self.wait_for_login_result(qr_token)
    self.init_manager()
    self._save_info()
    return True

  def login_auto(self, user_code=None, creds=None, qr_callback=None):
    """Try stored info first, fallback to QR login if fails"""
    if user_code:
      self.info["user_code"] = user_code
    if qr_callback:
      self.qr_callback = qr_callback
    if self._load_saved_info(creds):
      try:
        self.logger.info("Trying login from stored info...")
        self.init_manager()
        self.logger.info("Login via saved info succeeded")
        return True
      except Exception as e:
        self.logger.warning(f"Stored login info failed → fallback to QR: {e}")
    self.qr_login()

def wizard2(user_code, color, retries, forcescan, assume_yes, skip_poll, DEVICEFILE, SNAPSHOTFILE, CREDSFILE, creds=None):
  import qrcode
  import tinytuya.scanner
  import sys
  try:
    from colorama import init
    HAVE_COLORAMA = True
  except ImportError:
    HAVE_COLORAMA = False
  HAVE_COLOR = HAVE_COLORAMA or not sys.platform.startswith('win')

  def my_terminal_qr_handler(url):
    print("\n=== New QR Code Generated ===")
    print(f"URL: {url}")
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    print("Scan this code with the SmartLife or Tuya App. Waiting for scan...")

  logger = logging.getLogger(__name__)
  logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

  DEVICEFILE = tinytuya.DEVICEFILE
  SNAPSHOTFILE = tinytuya.SNAPSHOTFILE

  if not user_code and not creds:
    user_code = input("Enter User Code from SmartLife or Tuya App (Leave blank to use Stored Code): ")
  tuya = TuyaWizard(logger=logger, info_file=CREDSFILE)
  tuya.login_auto(user_code=user_code, creds=creds, qr_callback=my_terminal_qr_handler)
  tuyadevices = tuya.fetch_devices()

  if skip_poll:
    answer = "n"
  elif assume_yes:
    answer = "y"
  else:
    answer = input("\nPoll local devices? (Y/n): ")
    if answer.lower().find("n") < 0:
      tinytuya.scanner.SNAPSHOTFILE = SNAPSHOTFILE
      result = tinytuya.scanner.poll_and_display( tuyadevices, color=color, scantime=retries, forcescan=forcescan, snapshot=True )
      iplist = {}
      found = 0
      for itm in result:
        if "gwId" in itm and itm["gwId"]:
          gwid = itm["gwId"]
          ip = itm["ip"] if "ip" in itm and itm["ip"] else ""
          ver = itm["version"] if "version" in itm and itm["version"] else ""
          iplist[gwid] = (ip, ver)
      for k in range( len(tuyadevices) ):
        gwid = tuyadevices[k]["id"]
        if gwid in iplist:
          tuyadevices[k]["ip"] = iplist[gwid][0]
          tuyadevices[k]["version"] = iplist[gwid][1]
          if iplist[gwid][0]: found += 1
      if found:
        logger.info("%d device IP addresses found" % found)

  logging.info("\n>> Saving tuya devices to " + DEVICEFILE)
  output = json.dumps(tuyadevices, indent=4)
  with open(DEVICEFILE, "w") as outfile:
    outfile.write(output)
