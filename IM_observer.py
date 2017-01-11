#!/usr/bin/python
"""
BLE Observer for Raspberry Pi 3
TARGET DEVICE : OMRON BLE Environment Sensor
                (BEACON Mode = "IM" Broadcaster)
Python 2.7
VERSION : 1.3 for 2JCIE-BL01 FAE Training
"""
import sys
import requests
import subprocess
import struct
import urllib2
import time
import socket
import datetime
import threading
import math
import bluetooth._bluetooth as bluez
from fluent import sender
from fluent import event
from influxdb import InfluxDBClient

# Setting
DEBUG = False
INFINITE_LOOP = True
USE_FLUENTD = True
# True : use fluentd to upload data, False : directly upload data to influxDB

SINGLE_LOOP_COUNT = 100
LOOP_COUNT = 10
# If INIFINITE_LOOP = False, Total aquired packet would be (SINGLE_LOOP_COUNT * LOOP_COUNT)

CHECK_SENSOR_STATE_INTERVAL_SECONDS = 60
TIMEOUT_SECONDS_TICK = 30
# Sensor will be inactive state if there is no advertising data received in this timeout period.

# GEOHASH (http://geohash.org/)
GEOHASH = "xn76eyndgyk9"
GATEWAY = socket.gethostname()

SENSOR_TYPE = "IM"

#fluent-plugin-influxdb
FLUENTD_TAG = "omron-pi-im"
FLUENTD_ADDRESS = "localhost"
FLUENTD_PORT = 24224

## InfluxDB
INFLUXDB_ADDRESS = "153.122.92.93" ## GMO Cloud
INFLUXDB_PORT = 8086
INFLUXDB_PORT_STRING = "8086"
INFLUXDB_DATABASE = "omron_pi"
INFLUXDB_MEASUREMENT = "environment"
INFLUXDB_USER = "root"
INFLUXDB_PASSWORD = "root"


####################### BLE #########################
# OMRON company ID (Bluetooth SIG.)
COMPANY_ID = 0x2D5

# BEACON Measured power (RSSI at 1m distance)
BEACON_MEASURED_POWER = -59

# BLE OpCode group field for the LE related OpCodes.
OGF_LE_CTL = 0x08

# BLE OpCode Commands.
OCF_LE_SET_EVENT_MASK = 0x0001
OCF_LE_READ_BUFFER_SIZE = 0x0002
OCF_LE_READ_LOCAL_SUPPORTED_FEATURES = 0x0003
OCF_LE_SET_RANDOM_ADDRESS = 0x0005
OCF_LE_SET_ADVERTISING_PARAMETERS = 0x0006
OCF_LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x0007
OCF_LE_SET_ADVERTISING_DATA = 0x0008
OCF_LE_SET_SCAN_RESPONSE_DATA = 0x0009
OCF_LE_SET_ADVERTISE_ENABLE = 0x000A
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D
OCF_LE_CREATE_CONN_CANCEL = 0x000E
OCF_LE_READ_WHITE_LIST_SIZE = 0x000F
OCF_LE_CLEAR_WHITE_LIST = 0x0010
OCF_LE_ADD_DEVICE_TO_WHITE_LIST = 0x0011
OCF_LE_REMOVE_DEVICE_FROM_WHITE_LIST = 0x0012
OCF_LE_CONN_UPDATE = 0x0013
OCF_LE_SET_HOST_CHANNEL_CLASSIFICATION = 0x0014
OCF_LE_READ_CHANNEL_MAP = 0x0015
OCF_LE_READ_REMOTE_USED_FEATURES = 0x0016
OCF_LE_ENCRYPT = 0x0017
OCF_LE_RAND = 0x0018
OCF_LE_START_ENCRYPTION = 0x0019
OCF_LE_LTK_REPLY = 0x001A
OCF_LE_LTK_NEG_REPLY = 0x001B
OCF_LE_READ_SUPPORTED_STATES = 0x001C
OCF_LE_RECEIVER_TEST = 0x001D
OCF_LE_TRANSMITTER_TEST = 0x001E
OCF_LE_TEST_END = 0x001F

# BLE events; all LE commands result in a metaevent, specified by the subevent
# code below.
EVT_LE_META_EVENT = 0x3E

# LE_META_EVENT subevents.
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
EVT_LE_CONN_UPDATE_COMPLETE = 0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04
EVT_LE_LTK_REQUEST = 0x05

# BLE address types.
LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01

# Roles.
LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# Advertisment event types.
LE_ADV_IND = 0x00
LE_ADV_DIRECT_IND = 0x01
LE_ADV_SCAN_IND = 0x02
LE_ADV_NONCONN_IND = 0x03
LE_ADV_SCAN_RSP = 0x04

# BLE scan types.
LE_SCAN_PASSIVE = 0x00
LE_SCAN_ACTIVE = 0x01

# BLE filter policies.
LE_FILTER_ALLOW_ALL = 0x00
LE_FILTER_WHITELIST_ONLY = 0x01
LE_FILTER_DUPLICATES_OFF = 0x00
LE_FILTER_DUPLICATES_ON = 0x01

# HCI error codes.
HCI_UNKNOWN_COMMAND = 0x01
HCI_NO_CONNECTION = 0x02
HCI_HARDWARE_FAILURE = 0x03
HCI_PAGE_TIMEOUT = 0x04
HCI_AUTHENTICATION_FAILURE = 0x05
HCI_PIN_OR_KEY_MISSING = 0x06
HCI_MEMORY_FULL = 0x07
HCI_CONNECTION_TIMEOUT = 0x08
HCI_MAX_NUMBER_OF_CONNECTIONS = 0x09
HCI_MAX_NUMBER_OF_SCO_CONNECTIONS = 0x0a
HCI_ACL_CONNECTION_EXISTS = 0x0b
HCI_COMMAND_DISALLOWED = 0x0c
HCI_REJECTED_LIMITED_RESOURCES = 0x0d
HCI_REJECTED_SECURITY = 0x0e
HCI_REJECTED_PERSONAL = 0x0f
HCI_HOST_TIMEOUT = 0x10
HCI_UNSUPPORTED_FEATURE = 0x11
HCI_INVALID_PARAMETERS = 0x12
HCI_OE_USER_ENDED_CONNECTION = 0x13
HCI_OE_LOW_RESOURCES = 0x14
HCI_OE_POWER_OFF = 0x15
HCI_CONNECTION_TERMINATED = 0x16
HCI_REPEATED_ATTEMPTS = 0x17
HCI_PAIRING_NOT_ALLOWED = 0x18
HCI_UNKNOWN_LMP_PDU = 0x19
HCI_UNSUPPORTED_REMOTE_FEATURE = 0x1a
HCI_SCO_OFFSET_REJECTED = 0x1b
HCI_SCO_INTERVAL_REJECTED = 0x1c
HCI_AIR_MODE_REJECTED = 0x1d
HCI_INVALID_LMP_PARAMETERS = 0x1e
HCI_UNSPECIFIED_ERROR = 0x1f
HCI_UNSUPPORTED_LMP_PARAMETER_VALUE = 0x20
HCI_ROLE_CHANGE_NOT_ALLOWED = 0x21
HCI_LMP_RESPONSE_TIMEOUT = 0x22
HCI_LMP_ERROR_TRANSACTION_COLLISION = 0x23
HCI_LMP_PDU_NOT_ALLOWED = 0x24
HCI_ENCRYPTION_MODE_NOT_ACCEPTED = 0x25
HCI_UNIT_LINK_KEY_USED = 0x26
HCI_QOS_NOT_SUPPORTED = 0x27
HCI_INSTANT_PASSED = 0x28
HCI_PAIRING_NOT_SUPPORTED = 0x29
HCI_TRANSACTION_COLLISION = 0x2a
HCI_QOS_UNACCEPTABLE_PARAMETER = 0x2c
HCI_QOS_REJECTED = 0x2d
HCI_CLASSIFICATION_NOT_SUPPORTED = 0x2e
HCI_INSUFFICIENT_SECURITY = 0x2f
HCI_PARAMETER_OUT_OF_RANGE = 0x30
HCI_ROLE_SWITCH_PENDING = 0x32
HCI_SLOT_VIOLATION = 0x34
HCI_ROLE_SWITCH_FAILED = 0x35
HCI_EIR_TOO_LARGE = 0x36
HCI_SIMPLE_PAIRING_NOT_SUPPORTED = 0x37
HCI_HOST_BUSY_PAIRING = 0x38

# Advertisment data format
ADV_TYPE_FLAGS = 0x01
ADV_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE = 0x02
ADV_TYPE_16BIT_SERVICE_UUID_COMPLETE = 0x03
ADV_TYPE_32BIT_SERVICE_UUID_MORE_AVAILABLE = 0x04
ADV_TYPE_32BIT_SERVICE_UUID_COMPLETE = 0x05
ADV_TYPE_128BIT_SERVICE_UUID_MORE_AVAILABLE = 0x06
ADV_TYPE_128BIT_SERVICE_UUID_COMPLETE = 0x07
ADV_TYPE_SHORT_LOCAL_NAME = 0x08
ADV_TYPE_COMPLETE_LOCAL_NAME = 0x09
ADV_TYPE_TX_POWER_LEVEL = 0x0A
ADV_TYPE_CLASS_OF_DEVICE = 0x0D
ADV_TYPE_SIMPLE_PAIRING_HASH_C = 0x0E
ADV_TYPE_SIMPLE_PAIRING_RANDOMIZER_R = 0x0F
ADV_TYPE_SECURITY_MANAGER_TK_VALUE = 0x10
ADV_TYPE_SECURITY_MANAGER_OOB_FLAGS = 0x11
ADV_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE = 0x12
ADV_TYPE_SOLICITED_SERVICE_UUIDS_16BIT = 0x14
ADV_TYPE_SOLICITED_SERVICE_UUIDS_128BIT = 0x15
ADV_TYPE_SERVICE_DATA = 0x16
ADV_TYPE_PUBLIC_TARGET_ADDRESS = 0x17
ADV_TYPE_RANDOM_TARGET_ADDRESS = 0x18
ADV_TYPE_APPEARANCE = 0x19
ADV_TYPE_MANUFACTURER_SPECIFIC_DATA = 0xFF



# Global variables
sensorBeaconList = []


class SensorBeacon:
    #local fields from raw data
    btAddress = ""
    seqNum = 0
    val_temp = 0.0
    val_humi = 0.0
    val_light = 0.0
    val_uv = 0.0
    val_pressure = 0.0
    val_noise = 0.0
    val_di = 0.0
    val_heat = 0.0
    val_ax = 0.0
    val_ay = 0.0
    val_az = 0.0
    val_battery = 0.0
    
    rssi = -127
    
    distance = 0
    tick_last_update = 0
    tick_register = 0
    
    flag_active = False
    
    sensor_type = SENSOR_TYPE
    gateway = GATEWAY
    geohash = GEOHASH    
    def __init__(self, btAddress_s, pkt):
        self.btAddress = btAddress_s
        self.seqNum = c2B(pkt[7])

        self.val_temp = bytes2short(c2B(pkt[9]), c2B(pkt[8]))/ 100.0
        self.val_humi = bytes2ushort(c2B(pkt[11]), c2B(pkt[10])) / 100.0
        self.val_light = bytes2ushort(c2B(pkt[13]), c2B(pkt[12]))
        self.val_uv = bytes2ushort(c2B(pkt[15]), c2B(pkt[14])) / 100.0
        self.val_pressure = bytes2ushort(c2B(pkt[17]), c2B(pkt[16])) / 10.0
        self.val_noise = bytes2ushort(c2B(pkt[19]), c2B(pkt[18])) / 100.0
        self.val_di = 0.0
        self.val_heat = 0.0
        self.val_ax = bytes2short(c2B(pkt[21]), c2B(pkt[20])) / 10.0
        self.val_ay = bytes2short(c2B(pkt[23]), c2B(pkt[22])) / 10.0
        self.val_az = bytes2short(c2B(pkt[25]), c2B(pkt[24])) / 10.0
        self.val_battery = (c2B(pkt[26]) + 100) * 10.0
        
        self.calcFactor()
        
        self.rssi = c2b(pkt[-1])
        self.distance = self.returnAccuracy(self.rssi, BEACON_MEASURED_POWER)
        
        self.tick_register = datetime.datetime.now()
        self.tick_last_update = self.tick_register
        self.flag_active = True
        
        self.sensor_type = SENSOR_TYPE
        self.gateway = GATEWAY
        self.geohash = GEOHASH        
    def returnAccuracy(self, rssi, power): # rough distance in meter
        RSSI = abs(rssi)
        if RSSI == 0:
            return -1
        if power == 0:
            return -1
            
        ratio = RSSI * 1.0 / abs(power)
        if ratio < 1.0:
            return pow(ratio, 8.0)
        accuracy = 0.69976 * pow(ratio, 7.7095) + 0.111
        #accuracy = 0.89976 * pow(ratio, 7.7095) + 0.111
        return accuracy
        
    def checkDiffSeqNum(self, index):
        global sensorBeaconList
        result = False
        if (self.seqNum != sensorBeaconList[index].seqNum):
            result = True
        else:
            result = False
        return result
        
    def update(self, index):
        global sensorBeaconList
        sensorBeaconList[index].sensor_type = self.sensor_type
        sensorBeaconList[index].gateway = self.gateway
        sensorBeaconList[index].seqNum = self.seqNum
        sensorBeaconList[index].val_temp = self.val_temp
        sensorBeaconList[index].val_humi = self.val_humi
        sensorBeaconList[index].val_light = self.val_light
        sensorBeaconList[index].val_uv = self.val_uv
        sensorBeaconList[index].val_pressure = self.val_pressure
        sensorBeaconList[index].val_noise = self.val_noise
        sensorBeaconList[index].val_di = self.val_di
        sensorBeaconList[index].val_heat = self.val_heat
        sensorBeaconList[index].val_ax = self.val_ax
        sensorBeaconList[index].val_ay = self.val_ay
        sensorBeaconList[index].val_az = self.val_az
        sensorBeaconList[index].val_battery = self.val_battery
        sensorBeaconList[index].rssi = self.rssi
        sensorBeaconList[index].distance = self.distance
        sensorBeaconList[index].geohash = self.geohash
        sensorBeaconList[index].tick_last_update = self.tick_last_update
        sensorBeaconList[index].flag_active = True
    
    def calcFactor(self):
        self.val_di = discomfort_index_approximation(self.val_temp, self.val_humi)
        self.val_heat = wbgt_approximation(self.val_temp, self.val_humi, flagOutside = False)
    
    def debugPrint(self):
        print "\tgateway = ", self.gateway
        print "\ttype = ", self.sensor_type
        print "\tbtAddress = ", self.btAddress
        print "\tseqNum = ", self.seqNum
        print "\tval_temp = ", self.val_temp
        print "\tval_humi = ", self.val_humi
        print "\tval_light = ", self.val_light
        print "\tval_uv = ", self.val_uv
        print "\tval_pressure = ", self.val_pressure
        print "\tval_noise = ", self.val_noise
        print "\tval_di = ", self.val_di
        print "\tval_heat = ", self.val_heat
        print "\tval_ax = ", self.val_ax
        print "\tval_ay = ", self.val_ay
        print "\tval_az = ", self.val_az
        print "\tval_battery = ", self.val_battery
        print "\trssi = ", self.rssi
        print "\tdistance = ", self.distance
        print "\tgeohash = ", self.geohash
        print "\ttick_register = ", self.tick_register
        print "\ttick_last_update = ", self.tick_last_update
        print "\tflag_active = ", self.flag_active
    
    
    def upload(self):
        if (USE_FLUENTD == True):
            event.Event(INFLUXDB_MEASUREMENT, {
                'gateway': self.gateway,
                'sensor_type': self.sensor_type,
                'btAddress': self.btAddress,
                'temperature': self.val_temp,
                'humidity': self.val_humi,
                'light': self.val_light,
                'uv': self.val_uv,
                'pressure': self.val_pressure,
                'noise': self.val_noise,
                'di': self.val_di,
                'heat': self.val_heat,
                'accel_x': self.val_ax,
                'accel_y': self.val_ay,
                'accel_z': self.val_az,
                'battery': self.val_battery,
                'rssi': self.rssi,
                'distance': self.distance,
                'geohash': self.geohash
            })
        else: # direct data upload to influxDB
            json_body = [
                {
                    "measurement": INFLUXDB_MEASUREMENT,
                    "tags": {
                        "gateway": self.gateway,
                        "sensor_type": self.sensor_type,
                        "btAddress": self.btAddress
                    },
                    "fields": {
                        "temperature": self.val_temp,
                        "humidity": self.val_humi,
                        "light": self.val_light,
                        "uv": self.val_uv,
                        "pressure": self.val_pressure,
                        "noise": self.val_noise,
                        "di": self.val_di,
                        "heat": self.val_heat,
                        "accel_x": self.val_ax,
                        "accel_y": self.val_ay,
                        "accel_z": self.val_az,
                        "battery": self.val_battery,
                        "rssi": self.rssi,
                        "distance": self.distance,
                        "geohash": self.geohash
                    }
                }
            ]
            client.write_points(json_body)
        pass


















def sensorCheck_IM(report):
    result = False
    # check payload length (31byte)
    if (report["report_metadata_length"] != 31):
        return
    # check Company ID (OMRON = 0x02D5)
    if (struct.unpack("<B", report["payload_binary"][4])[0] != ADV_TYPE_MANUFACTURER_SPECIFIC_DATA):
        return
    if (get_companyid(report["payload_binary"][5:7]) != COMPANY_ID):
        return
    # check shortened local name ("IM")
    if (struct.unpack("<B", report["payload_binary"][28])[0] != ADV_TYPE_SHORT_LOCAL_NAME):
        return
    if (report["payload_binary"][29:31] != "IM"):
        return
        
    result = True
    return result



### HCI commands. ###

def hci_le_read_local_supported_features(sock):
    cmd_pkt = ""
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES, cmd_pkt)

def hci_le_read_remote_used_features(sock, handle):
    cmd_pkt = struct.pack("<H", handle)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_REMOTE_USED_FEATURES, cmd_pkt)
					   
# BLE and Bluetooth use the same disconnect command.
def hci_disconnect(sock, handle, reason = HCI_OE_USER_ENDED_CONNECTION):
    cmd_pkt = struct.pack("<HB", handle, reason)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_DISCONNECT, cmd_pkt)

# BLE and bluetooth use the same disconnect command.
#def hci_disconnect(sock, reason=bluez.HCI_OE_USER_ENDED_CONNECTION):
#    pass


def hci_le_connect(sock, peer_bdaddr, interval=0x0004, window=0x004,
                   initiator_filter=LE_FILTER_ALLOW_ALL,
                   peer_bdaddr_type=LE_RANDOM_ADDRESS,
                   own_bdaddr_type=LE_PUBLIC_ADDRESS,
                   min_interval=0x000F, max_interval=0x000F,
                   latency=0x0000, supervision_timeout=0x0C80,
                   min_ce_length=0x0001, max_ce_length=0x0001):
                   
    package_bdaddr = get_packed_bdaddr(peer_bdaddr)
    cmd_pkt = struct.pack("<HHBB", interval, window, initiator_filter, peer_bdaddr_type)
    cmd_pkt += package_bdaddr
    cmd_pkt += struct.pack("<BHHHHHH", own_bdaddr_type, min_interval, max_interval, latency, 
                            supervision_timeout, min_ce_length, max_ce_length)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_CREATE_CONN, cmd_pkt)

def hci_le_enable_scan(sock):
    hci_le_toggle_scan(sock, 0x01)

def hci_le_disable_scan(sock):
    hci_le_toggle_scan(sock, 0x00)

def hci_le_toggle_scan(sock, enable):
    if (DEBUG == True):
        print "---- toggle scan: ", enable
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)
    if (DEBUG == True):
        print "---- sent toggle command"

def hci_le_set_scan_parameters(sock, scan_type=LE_SCAN_ACTIVE, interval=0x10, window=0x10,
                               own_bdaddr_type=LE_RANDOM_ADDRESS,
                               filter_type=LE_FILTER_ALLOW_ALL):
    if (DEBUG == True):
        print "---- setting up scan"
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    if (DEBUG == True):
        print "---- got old filter"
        
    # interval and window are uint_16, so we pad them with 0x0
    cmd_pkt = struct.pack("<BBBBBBB", scan_type, 0x0, interval, 0x0, window, own_bdaddr_type, filter_type)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
    if (DEBUG == True):
        print "---- sent scan parameters command"







### HCI Response parsing ###

def hci_le_parse_response_packet(pkt):
    """
    Parse a BLE packet.

    Returns a dictionary which contains the event id, length and packet type,
    and possibly additional key/value pairs that represent the parsed content of
    the packet.
    """
    result = {}
    ptype, event, plen = struct.unpack("<BBB", pkt[:3])
    result["packet_type"] = ptype
    result["bluetooth_event_id"] = event
    result["packet_length"] = plen
    # We give the user the full packet back as the packet is small, and the user
    # may have additional parsing they want to do.
    result["packet_str"] = packet_as_hex_string(pkt)
    result["packet_bin"] = pkt

    # We only care about events that relate to BLE.
    if event == EVT_LE_META_EVENT:
        result["bluetooth_event_name"] = "EVT_LE_META_EVENT"
        result.update(_handle_le_meta_event(pkt[3:]))
        
    elif event == bluez.EVT_NUM_COMP_PKTS:
        result["bluetooth_event_name"] = "EVT_NUM_COMP_PKTS"
        result.update(_handle_num_completed_packets(pkt[3:]))
        
    elif event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
        result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT_WITH_RSSI"
        result.update(_handle_inquiry_result_with_rssi(pkt[3:]))
        
    elif event == bluez.EVT_INQUIRY_RESULT:
        result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT"
        result.update(_handle_inquiry_result(pkt[3:]))
        
    elif event == bluez.EVT_DISCONN_COMPLETE:
        result["bluetooth_event_name"] = "EVT_DISCONN_COMPLETE"
        result.update(_handle_disconn_complete(pkt[3:]))
        
    elif event == bluez.EVT_CMD_STATUS:
        result["bluetooth_event_name"] = "EVT_CMD_STATUS"
        result.update(_handle_command_status(pkt[3:]))
        
    elif event == bluez.EVT_CMD_COMPLETE:
        result["bluetooth_event_name"] = "EVT_CMD_COMPLETE"
        result.update(_handle_command_complete(pkt[3:]))
        
    elif event == bluez.EVT_INQUIRY_COMPLETE:
        raise NotImplementedError("EVT_CMD_COMPLETE")
        
    else:
        result["bluetooth_event_name"] = "UNKNOWN"
        
    return result


def _handle_num_completed_packets(pkt):
    result = {}
    num_connection_handles = struct.unpack("<B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_connection_handles"] = num_connection_handles
    result["handles"] = []
    for i in xrange(num_connection_handles):
        handle, = struct.unpack("<H", pkt[0:2])
        completed_packets, = struct.unpack("<H", pkt[2:4])
        result["handles"].append({"handle": handle, "num_completed_packets": completed_packets})
        pkt = pkt[4:]
    return result


def _handle_inquiry_result_with_rssi(pkt):
    result = {}
    num_inquiry_results = struct.unpack("B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_inquiry_results"] = num_inquiry_results
    result["inquiry_results"] = []
    for i in xrange(num_inquiry_results):
        addr = bluez.ba2str(pkt[(6 * i) : (6 * i) + 6])
        rssi = struct.unpack("b", pkt[(13 * num_inquiry_results) + i])[0]
        result["inquiry_results"].append({"Address": addr, "RSSI": rssi})
    return result


def _handle_inquiry_result(pkt):
    result = {}
    num_inquiry_results = struct.unpack("B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_inquiry_results"] = num_inquiry_results
    result["inquiry_results"] = []
    for i in xrange(num_inquiry_results):
        addr = bluez.ba2str(pkt[(6 * i) : (6 * i) + 6])
        result["inquiry_results"].append({"Address": addr})
    return result


    num_connection_handles = struct.unpack("<B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_connection_handles"] = num_connection_handles
    result["handles"] = []
    for i in xrange(num_connection_handles):
        handle, = struct.unpack("<H", pkt[0:2])
        completed_packets, = struct.unpack("<H", pkt[2:4])
        result["handles"].append({"handle": handle, "num_completed_packets": completed_packets})
        pkt = pkt[4:]
    return result


def _handle_disconn_complete(pkt):
    status, handle, reason = struct.unpack("<BHB", pkt)
    return {"status": status, "handle": handle, "reason": reason}


def _handle_le_meta_event(pkt):
    result = {}
    subevent, = struct.unpack("B", pkt[0])
    result["bluetooth_le_subevent_id"] = subevent
    pkt = pkt[1:]
    if subevent == EVT_LE_ADVERTISING_REPORT:
        result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
        result.update(_handle_le_advertising_report(pkt))
        
    elif subevent == EVT_LE_CONN_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_COMPLETE"
        result.update(_handle_le_connection_complete(pkt))
        
    elif subevent == EVT_LE_CONN_UPDATE_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_UPDATE_COMPLETE"
        raise NotImplementedError("EVT_LE_CONN_UPDATE_COMPLETE")
        
    elif subevent == EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
        result["bluetooth_le_subevent_name"] = "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
        result.update(_handle_le_read_remote_used_features(pkt))
        
    elif subevent == EVT_LE_ADVERTISING_REPORT:
        result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
        result.update(_handle_le_advertising_report(pkt))
        
    else:
        result["bluetooth_le_subevent_name"] = "UNKNOWN"
        
    return result


def _handle_command_status(pkt):
    result = {}
    status, ncmd, opcode = struct.unpack("<BBH", pkt)
    (ogf, ocf) = ogf_and_ocf_from_opcode(opcode)
    result["status"] = status
    result["number_of_commands"] = ncmd
    result["opcode"] = opcode
    result["opcode_group_field"] = ogf
    result["opcode_command_field"] = ocf
    return result


def _handle_command_complete(pkt):
    result = {}
    ncmd, opcode = struct.unpack("<BH", pkt[:3])
    (ogf, ocf) = ogf_and_ocf_from_opcode(opcode)
    result["number_of_commands"] = ncmd
    result["opcode"] = opcode
    result["opcode_group_field"] = ogf
    result["opcode_command_field"] = ocf
    result["command_return_values"] = ""
    if len(pkt) > 3:
        result["command_return_values"] = pkt[3:]
    # Since we only care about BLE commands, we ignore the command return values
    # here. A full-powered bluetooth parsing module would check the OCF above
    # and parse the return values based on that OCF. We return the return values
    # to the user should the used want to parse the return values.
    return result


def _handle_le_connection_complete(pkt):
    result = {}
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    device_address = packed_bdaddr_to_string(pkt[5:11])
    interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])
    result["status"] = status
    result["handle"] = handle
    result["role"] = role
    result["peer_bluetooth_address_type"] = peer_bdaddr_type
    result["peer_device_address"] = device_address
    result["interval"] = interval
    result["latency"] = latency
    result["supervision_timeout"] = supervision_timeout
    result["master_clock_accuracy"] = master_clock_accuracy
    return result


def _handle_le_read_remote_used_features(pkt):
    result = {}
    result["features"] = []
    status, handle = struct.unpack("<BH", pkt[:3])
    result["status"] = status
    result["handle"] = status
    for i in range(8):
        result["features"].append(struct.unpack("<B", pkt[3 + i])[0])
    return result


def _handle_le_advertising_report(pkt):
    result = {}
    num_reports = struct.unpack("<B", pkt[0])[0]
    report_pkt_offset = 0
    result["number_of_advertising_reports"] = num_reports
    result["advertising_reports"] = []
    for i in xrange(0, num_reports):
        report = {}
        
        report_event_type = struct.unpack("<B", pkt[report_pkt_offset + 1])[0]
        report["report_type_id"] = report_event_type
        
        bdaddr_type = struct.unpack("<B", pkt[report_pkt_offset + 2])[0]
        report["peer_bluetooth_address_type"] = bdaddr_type
        
        device_addr = packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
        report["peer_bluetooth_address"] = device_addr.upper()
        report["peer_bluetooth_address_s"] = shortBTAddr (report["peer_bluetooth_address"])
        
        report_data_length, = struct.unpack("<B", pkt[report_pkt_offset + 9])
        report["report_metadata_length"] = report_data_length
        
        if report_event_type == LE_ADV_IND:
            report["report_type_string"] = "LE_ADV_IND"
            
        elif report_event_type == LE_ADV_DIRECT_IND:
            report["report_type_string"] = "LE_ADV_DIRECT_IND"
            
        elif report_event_type == LE_ADV_SCAN_IND:
            report["report_type_string"] = "LE_ADV_SCAN_IND"
            
        elif report_event_type == LE_ADV_NONCONN_IND:
            report["report_type_string"] = "LE_ADV_NONCONN_IND"
            
        elif report_event_type == LE_ADV_SCAN_RSP:
            report["report_type_string"] = "LE_ADV_SCAN_RSP"
            
        else:
            report["report_type_string"] = "UNKNOWN"
            
        if report_data_length > 0:
            report["payload_binary"] = pkt[report_pkt_offset + 10 : report_pkt_offset + 10 + report_data_length + 1]
            
        # Each report length is (2 (event type, bdaddr type) + 6 (the address)
        #    + 1 (data length field) + data length + 1 (rssi)) bytes long.
        report_pkt_offset = report_pkt_offset +  10 + report_data_length + 1
        rssi, = struct.unpack("<b", pkt[report_pkt_offset - 1])
        report["rssi"] = rssi
        result["advertising_reports"].append(report)
        
    return result




def parse_events(sock, loop_count=10):
    global sensorBeaconList
    
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )
    
    done = False
    results = []
    myFullList = []
    
    for i in xrange(0, loop_count):
        pkt = sock.recv(255)
        
        # Raw avertise packet data from Bluez scan
        # Packet Type (1byte) + BT Event ID (1byte) + Packet Length (1byte) + 
        # BLE sub-Event ID (1byte) + Number of Advertising reports (1byte) + 
        # Report type ID (1byte) + BT Address Type (1byte) + BT Address (6byte) + 
        # Data Length (1byte) + Data ((Data Length)byte) + RSSI (1byte)
        #
        # Packet Type = 0x04
        # BT Event ID = EVT_LE_META_EVENT = 0x3E (BLE events)
        # (All LE commands result in a metaevent, specified by BLE sub-Event ID)
        # BLE sub-Event ID = {
        #                       EVT_LE_CONN_COMPLETE = 0x01
        #                       EVT_LE_ADVERTISING_REPORT = 0x02
        #                       EVT_LE_CONN_UPDATE_COMPLETE = 0x03
        #                       EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04
        #                       EVT_LE_LTK_REQUEST = 0x05
        #                     }
        # Number of Advertising reports = 0x01 (normally)
        # Report type ID = {
        #                       LE_ADV_IND = 0x00
        #                       LE_ADV_DIRECT_IND = 0x01
        #                       LE_ADV_SCAN_IND = 0x02
        #                       LE_ADV_NONCONN_IND = 0x03
        #                       LE_ADV_SCAN_RSP = 0x04
        #                   }
        # BT Address Type = {
        #                       LE_PUBLIC_ADDRESS = 0x00
        #                       LE_RANDOM_ADDRESS = 0x01
        #                    }
        # Data Length = 0x00 - 0x1F
        # * Maximum Data Length of an advertising packet = 0x1F
        
        parsed_packet = hci_le_parse_response_packet(pkt)
        
        
        if "bluetooth_le_subevent_name" in parsed_packet and \
                parsed_packet["bluetooth_le_subevent_name"] == 'EVT_LE_ADVERTISING_REPORT':
                
            if (DEBUG == True):
                for report in parsed_packet["advertising_reports"]:
                    print "----------------------------------------------------"
                    print packet_as_hex_string(pkt, flag_with_spacing = True, flag_force_capitalize = True)
                    print "Found BLE device:", report['peer_bluetooth_address']
                    for k, v in report.items():
                        print "\t%s: %s" % (k, v)
                        
            for report in parsed_packet["advertising_reports"]:
                if (sensorCheck_IM(report)):
                    
                    sensorBeacon = SensorBeacon(report["peer_bluetooth_address_s"], report["payload_binary"])
                    index = sensorInList(sensorBeacon, sensorBeaconList)
                    
                    if (DEBUG == True):
                        print (" -- sensor data ---")
                        sensorBeacon.debugPrint()
                    
                    lock = threading.Lock()
                    lock.acquire()
                    
                    if (index != -1): # BT Address found in sensorBeaconList
                        if (sensorBeacon.checkDiffSeqNum(index)):
                            sensorBeacon.upload()
                        sensorBeacon.update(index)
                    else : # new SensorBeacon
                        sensorBeaconList.append(sensorBeacon)
                        sensorBeacon.upload()
                    lock.release()
                else:
                    pass
        else:
            pass
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return sensorBeaconList



#check timeout sensor and update flag
def checkSensorStates():
    nowtick = datetime.datetime.now()
    for sensor in sensorBeaconList:
        if (sensor.flag_active):
            pastSec = (nowtick - sensor.tick_last_update).total_seconds()
            if (pastSec > TIMEOUT_SECONDS_TICK):
                if (DEBUG == True):
                    print "timeout sensor : " + sensor.btAddress 
                sensor.flag_active = False
    t = threading.Timer(CHECK_SENSOR_STATE_INTERVAL_SECONDS, checkSensorStates)
    t.setDaemon(True)
    t.start()




###  Utility function ###

def returnnumberpacket(pkt):
    myInteger = 0
    multiple = 256
    for c in pkt:
        myInteger +=  struct.unpack("B",c)[0] * multiple
        multiple = 1
    return myInteger 

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr:
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))

def shortBTAddr(btAddr):
    return ''.join(btAddr.split(':'))

def get_companyid(pkt):
    return (struct.unpack("<B", pkt[1])[0] << 8) | struct.unpack("<B", pkt[0])[0]

def packet_as_hex_string(pkt, flag_with_spacing=False, flag_force_capitalize=False):
    packet = ""
    space = ""
    if (flag_with_spacing):
        space = " "
    for b in pkt:
        packet = packet + "%02x" % struct.unpack("<B",b)[0] + space
    if (flag_force_capitalize):
        packet = packet.upper()
    return packet

def returnstringpacket(pkt):
    myString = "";
    for c in pkt:
        myString +=  "%02x" %struct.unpack("B",c)[0]
    return myString 

# From the spec, 5.4.1, page 427 (Core Spec v4.0 Vol 2):
# "Each command is assigned a 2 byte Opcode used to uniquely identify different
# types of commands. The Opcode parameter is divided into two fields, called the
# OpCode Group Field (OGF) and OpCode Command Field (OCF). The OGF occupies the
# upper 6 bits of the Opcode, while the OCF occupies the remaining 10 bits"
def ogf_and_ocf_from_opcode(opcode):
    ogf = opcode >> 10
    ocf = opcode & 0x03FF
    return (ogf, ocf)

def c2B(char): #character to Byte conversion
    return struct.unpack("B", char)[0]

def c2b(char): #character to signed char conversion
    return struct.unpack("b", char)[0]

def checksum(hexlist):
    result = hexlist[0] 
    for hex in hexlist[1:]:
        result = result ^ hex
    return result

def tohex(val, nbits):
    newval = (val + (1 << nbits)) % (1 << nbits)
    if (DEBUG == True):
        print hex(newval)
    return newval

def bytes2ushort(hi, lo):
    ushort_val =  ((hi << 8) | lo)
    return ushort_val

def bytes2short(hi, lo):
    val = (hi << 8) | lo
    if (hi & 0b10000000) == 0b10000000:
        val_inv = val ^ 0b1111111111111111 
        val_inv = val_inv + 1
        short_val = val_inv * (-1)
    else:
        short_val = val
    return short_val

def ushort2short(val):
    if ((val & 0x8000) == 0x8000):
        val_inv = val ^ 0b1111111111111111 
        val_inv = val_inv + 1
        short_val = val_inv * (-1)
    else:
        short_val = val
    return short_val

def sensorInList(sensor, List):
    index = -1
    count = 0
    for i in List:
        if sensor.btAddress == i.btAddress:	
            index = count
            break
        else:
            count += 1
    return index

def reset_hci():
    # resetting bluetooth dongle
    cmd = "sudo hciconfig hci0 down"
    subprocess.call( cmd, shell=True )
    cmd = "sudo hciconfig hci0 up"
    subprocess.call( cmd, shell=True )

def check_internet_connection():
    try:
        response = urllib2.urlopen('http://www.google.com/',timeout=15)
        return True
    except urllib2.URLError as err: pass
    return False


### Index Calc ###
def discomfort_index_approximation(temp, humi):
    return (0.81 * temp) + 0.01 * humi * ((0.99 * temp) - 14.3) + 46.3

def wbgt_approximation(temp, humi, flagOutside = False):
    wbgt = 0
    if (temp < 0):
        temp = 0
    if (humi < 0):
        humi = 0
    if (humi > 100):
        humi = 100
    wbgt = (0.567 * temp) + 0.393 * (humi / 100 * 6.105 * math.exp(17.27 * temp / (237.7 + temp ))) + 3.94
    if (flagOutside != True):
        wbgt = (wbgt + (1.1 * (1 - (humi / 62) * 1.6)) * (temp - 30) * 0.17 - abs(temp - 30) * 0.09) / 1.135
    return wbgt




### Serial function ###

def initSerial():
    ser.port = '/dev/ttyUSB0'
    ser.baudrate = 115200
    ser.timeout = 1
    ser.open()

def sendHexStr(item):
    if (DEBUG == True):
        print "start to send via serial port:"
    newMacAdr = item.macAdr.translate(None, ':')
    if (DEBUG == True):
        print newMacAdr
    mac = bytearray(newMacAdr.decode('hex'))
    if (DEBUG == True):
        print item.rssi 
    str = ''
    li = []
    li.append(0xFF)
    li.append(0x08)
    li.append(0x90)
    li.append(0x01)
    li.append(0xEA)
    li.append(0x10)
    li.append(mac[0])
    li.append(mac[1])
    li.append(mac[2])
    li.append(mac[3])
    li.append(mac[4])
    li.append(mac[5])
    li.append(item.eventtype)
    li.append(item.eventcode)
    li.append(tohex(item.rssi, 8))
    li.append(checksum(li))	
    str = array.array('B', li).tostring()
    ser.write(str)

def sendAsciiStr(item):
    str = "at$app msg "
    str += "ZZ"
    str += "%02x"%item.eventtype
    str += "%02x"%item.eventcode
    str += item.macAdr.translate(None,':')
    str += "%02x"%tohex(item.rssi, 8)
    str += " 1\r\n"
    if (DEBUG == True):
        print str
    ser.write(str)


## init fluentd interface
def fluentdInit():
    sender.setup(FLUENTD_TAG, host=FLUENTD_ADDRESS, port=FLUENTD_PORT)
    v="q=CREATE DATABASE " + INFLUXDB_DATABASE + "\n"
    uri = "http://" + INFLUXDB_ADDRESS + ":" + INFLUXDB_PORT_STRING + "/query"
    r = requests.get(uri, params=v)
    #print r.status_code




# main function

if __name__ == "__main__":
    # reset bluetooth functionality
    try:
        reset_hci()
    except:
        print "error enabling bluetooth device"
        sys.exit(1)
        
    # make sure internet connection available
    try:
        if (check_internet_connection() == False):
            print "failed to access internet!!"
            sys.exit(1)
    except:
        print "error cheking internet connection"
        sys.exit(1)
        
    try:
        if (USE_FLUENTD == True):
            fluentdInit()
        else:
            client = InfluxDBClient(INFLUXDB_ADDRESS, INFLUXDB_PORT, INFLUXDB_USER, INFLUXDB_PASSWORD, INFLUXDB_DATABASE)
            client.create_database(INFLUXDB_DATABASE)
    except:
        print "error initializing fluentd"
        sys.exit(1)
        
    dev_id = 0
    
    try:
        sock = bluez.hci_open_dev(dev_id)
        if (DEBUG == True):
            print "-- BLE thread started"
    except:
        print "error accessing bluetooth device : ", dev_id
        sys.exit(1)
        
    try:
        if (DEBUG == True):
            print "-- set ble scan parameters"
        hci_le_set_scan_parameters(sock)
    except Exception as e:
        print "failed to set scan parameter!!"
        print (str(e))
        sys.exit(1)
        
    try:
        if (DEBUG == True):
            print "-- enable ble scan"
        hci_le_enable_scan(sock)
    except:
        print "failed to activate scan!!"
        sys.exit(1)
    
    print ("IM_observer for Raspberry Pi 3 : Start")
    
    t = threading.Timer(CHECK_SENSOR_STATE_INTERVAL_SECONDS, checkSensorStates)
    t.setDaemon(True)
    t.start()
    loopCount = 1
    while True:
        returnedList = parse_events(sock, SINGLE_LOOP_COUNT)
        print "----------"
        for sensors in returnedList:
            print sensors.btAddress, " : ", sensors.flag_active
        if (INFINITE_LOOP != True):
            loopCount += 1
            if (loopCount > LOOP_COUNT):
                break
    hci_le_disable_scan(sock)
    