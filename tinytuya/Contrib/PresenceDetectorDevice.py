from ..core import Device
import time
import json

class PresenceDetectorDevice(Device):
    """
    Represents a Tuya-based Presence Detector.
    """

    DPS_KEY = "dps"
    PRESENCE_KEY = "1"
    SENSITIVITY_KEY = "2"
    NEAR_DETECTION_KEY = "3"
    FAR_DETECTION_KEY = "4"
    AUTO_DETECT_RESULT_KEY = "6"
    TARGET_DISTANCE_KEY = "9"
    DETECTION_DELAY_KEY = "101"
    FADING_TIME_KEY = "102"
    LIGHT_SENSE_KEY = "104"

    def __init__(self, *args, **kwargs):
        # set the default version to 3.3 as there are no 3.1 devices
        if 'version' not in kwargs or not kwargs['version']:
            kwargs['version'] = 3.3
        super(PresenceDetectorDevice, self).__init__(*args, **kwargs)

    def status_json(self):
        """Wrapper around status() that replace DPS indices with human readable labels."""
        status = self.status()
        if "Error" in status:
           return status
        dps = status[self.DPS_KEY]
        json_string = json.dumps({
            "Presence": dps[self.PRESENCE_KEY],
            "Sensitivity": dps[self.SENSITIVITY_KEY],
            "Near detection": dps[self.NEAR_DETECTION_KEY],
            "Far detection": dps[self.FAR_DETECTION_KEY],
            "Checking result": dps[self.AUTO_DETECT_RESULT_KEY],
            "Target distance": dps[self.TARGET_DISTANCE_KEY],
            "Detection delay": dps[self.DETECTION_DELAY_KEY],
            "Fading time": dps[self.FADING_TIME_KEY],
            "Light sense": dps[self.LIGHT_SENSE_KEY]
        })
        return json_string

    def status(self):
        """In some cases the status json we received is not the standard one with all the proper keys. We will re-try 5 to get the expected one"""
        status = super().status()
        if "Error" in status:
           return status
        dps = status[self.DPS_KEY]
        retry = 5
        while(retry > 0 and not self.PRESENCE_KEY in dps):
            retry = retry - 1
            status = super().status()
            dps = status[self.DPS_KEY]
            time.sleep(5)
        return status

    def get_presence_state(self):
        """Get the presence state of the Presence Detector.

        Returns:
            str: Presence state ("none" or "presence").
        """
        status = self.status()
        if "Error" in status:
           return status
        return status[self.DPS_KEY][self.PRESENCE_KEY]

    def get_sensitivity(self):
        """Get the sensitivity level of the Presence Detector.

        Returns:
            int: Sensitivity level (0 to 9).
        """
        status = self.status()
        if "Error" in status:
            return satus
        return status[self.DPS_KEY][self.SENSITIVITY_KEY]

    def set_sensitivity(self, sensitivity):
        self.set_value(self.SENSITIVITY_KEY, sensitivity)

    def get_near_detection(self):
        """Get the near detection distance of the Presence Detector.

        Returns:
            int: Near detection distance in meters.
        """
        status = self.status()
        if "Error" in status:
            return satus
        return status[self.DPS_KEY][self.NEAR_DETECTION_KEY]

    def set_near_detection(self, distance):
        self.set_value(self.NEAR_DETECTION_KEY, distance)

    def get_far_detection(self):
        """Get the far detection distance of the Presence Detector.

        Returns:
            int: Far detection distance in meters.
        """
        status = self.status()
        if "Error" in status:
            return satus
        return status[self.DPS_KEY][self.FAR_DETECTION_KEY]

    def set_far_detection(self, distance):
        self.set_value(self.FAR_DETECTION_KEY, distance)

    def get_checking_result(self):
        """Get the checking result of the Presence Detector.

        Returns:
            str: Checking result (one of ["checking", "check_success", "check_failure", "others", "comm_fault", "radar_fault"]).
        """
        status = self.status()
        if "Error" in status:
            return satus
        return status[self.DPS_KEY][self.AUTO_DETECT_RESULT_KEY]

    def get_target_distance(self):
        """Get the closest target distance of the Presence Detector.

        Returns:
            int: Closest target distance in meters.
        """
        status = self.status()
        if "Error" in status:
            return satus
        return status[self.DPS_KEY][self.TARGET_DISTANCE_KEY]
