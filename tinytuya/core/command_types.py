# TinyTuya Module
# -*- coding: utf-8 -*-

# Tuya Command Types
# Reference: https://github.com/tuya/tuya-iotos-embeded-sdk-wifi-ble-bk7231n/blob/master/sdk/include/lan_protocol.h
AP_CONFIG       = 1  # FRM_TP_CFG_WF      # only used for ap 3.0 network config
ACTIVE          = 2  # FRM_TP_ACTV (discard) # WORK_MODE_CMD
SESS_KEY_NEG_START  = 3  # FRM_SECURITY_TYPE3 # negotiate session key
SESS_KEY_NEG_RESP   = 4  # FRM_SECURITY_TYPE4 # negotiate session key response
SESS_KEY_NEG_FINISH = 5  # FRM_SECURITY_TYPE5 # finalize session key negotiation
UNBIND          = 6  # FRM_TP_UNBIND_DEV  # DATA_QUERT_CMD - issue command
CONTROL         = 7  # FRM_TP_CMD         # STATE_UPLOAD_CMD
STATUS          = 8  # FRM_TP_STAT_REPORT # STATE_QUERY_CMD
HEART_BEAT      = 9  # FRM_TP_HB
DP_QUERY        = 0x0a # 10 # FRM_QUERY_STAT      # UPDATE_START_CMD - get data points
QUERY_WIFI      = 0x0b # 11 # FRM_SSID_QUERY (discard) # UPDATE_TRANS_CMD
TOKEN_BIND      = 0x0c # 12 # FRM_USER_BIND_REQ   # GET_ONLINE_TIME_CMD - system time (GMT)
CONTROL_NEW     = 0x0d # 13 # FRM_TP_NEW_CMD      # FACTORY_MODE_CMD
ENABLE_WIFI     = 0x0e # 14 # FRM_ADD_SUB_DEV_CMD # WIFI_TEST_CMD
WIFI_INFO       = 0x0f # 15 # FRM_CFG_WIFI_INFO
DP_QUERY_NEW    = 0x10 # 16 # FRM_QUERY_STAT_NEW
SCENE_EXECUTE   = 0x11 # 17 # FRM_SCENE_EXEC
UPDATEDPS       = 0x12 # 18 # FRM_LAN_QUERY_DP    # Request refresh of DPS
UDP_NEW         = 0x13 # 19 # FR_TYPE_ENCRYPTION
AP_CONFIG_NEW   = 0x14 # 20 # FRM_AP_CFG_WF_V40
BOARDCAST_LPV34 = 0x23 # 35 # FR_TYPE_BOARDCAST_LPV34
REQ_DEVINFO     = 0x25 # broadcast to port 7000 to get v3.5 devices to send their info
LAN_EXT_STREAM  = 0x40 # 64 # FRM_LAN_EXT_STREAM


# Tuya Device Dictionary - Command and Payload Overrides
#
# 'default' devices require the 0a command for the DP_QUERY request
# 'device22' devices require the 0d command for the DP_QUERY request and a list of
#            dps used set to Null in the request payload
#
# Any command not defined in payload_dict will be sent as-is with a
#  payload of {"gwId": "", "devId": "", "uid": "", "t": ""}

payload_dict = {
    # Default Device
    "default": {
        AP_CONFIG: {  # [BETA] Set Control Values on Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CONTROL: {  # Set Control Values on Device
            "command": {"devId": "", "uid": "", "t": ""},
        },
        STATUS: {  # Get Status from Device
            "command": {"gwId": "", "devId": ""},
        },
        HEART_BEAT: {"command": {"gwId": "", "devId": ""}},
        DP_QUERY: {  # Get Data Points from Device
            "command": {"gwId": "", "devId": "", "uid": "", "t": ""},
        },
        CONTROL_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        DP_QUERY_NEW: {"command": {"devId": "", "uid": "", "t": ""}},
        UPDATEDPS: {"command": {"dpId": [18, 19, 20]}},
        LAN_EXT_STREAM: { "command": { "reqType": "", "data": {} }},
    },
    # Special Case Device with 22 character ID - Some of these devices
    # Require the 0d command as the DP_QUERY status request and the list of
    # dps requested payload
    "device22": {
        DP_QUERY: {  # Get Data Points from Device
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command for some reason
            "command": {"devId": "", "uid": "", "t": ""},
        },
    },
    # v3.3+ devices do not need devId/gwId/uid
    "v3.4": {
        CONTROL: {
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
            },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        DP_QUERY: {
            "command_override": DP_QUERY_NEW,
            "command": {} #"protocol":4, "t": "int", "data": {}}
        },
        DP_QUERY_NEW: {
            "command": {}
        },
    },
    # v3.5 is just a copy of v3.4
    "v3.5": {
        CONTROL: {
            "command_override": CONTROL_NEW,  # Uses CONTROL_NEW command
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {}}
        },
        DP_QUERY: {
            "command_override": DP_QUERY_NEW,
            "command": {}
        },
        DP_QUERY_NEW: {
            "command": {}
        },
    },
    # placeholders, not yet needed
    "gateway": { },
    "gateway_v3.4": { },
    "gateway_v3.5": { },
    "zigbee": {
        CONTROL: { "command": {"t": "int", "cid": ""} },
        DP_QUERY: { "command": {"t": "int", "cid": ""} },
    },
    "zigbee_v3.4": {
        CONTROL: {
            "command_override": CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
    "zigbee_v3.5": {
        CONTROL: {
            "command_override": CONTROL_NEW,
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
        CONTROL_NEW: {
            "command": {"protocol":5, "t": "int", "data": {"cid":""}}
        },
    },
}
