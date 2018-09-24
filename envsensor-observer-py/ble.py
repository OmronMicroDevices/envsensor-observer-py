#!/usr/bin/python

import subprocess
import bluetooth._bluetooth as bluez
import struct

# python library for linux bluez ##############################################

# constants -------------------------------------------------------------------

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


# HCI commands. ---------------------------------------------------------------

def hci_le_read_local_supported_features(sock):
    cmd_pkt = ""
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_LOCAL_SUPPORTED_FEATURES,
                       cmd_pkt)


def hci_le_read_remote_used_features(sock, handle):
    cmd_pkt = struct.pack("<H", handle)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_READ_REMOTE_USED_FEATURES,
                       cmd_pkt)


# BLE and Bluetooth use the same disconnect command.
def hci_disconnect(sock, handle, reason=HCI_OE_USER_ENDED_CONNECTION):
    cmd_pkt = struct.pack("<HB", handle, reason)
    bluez.hci_send_cmd(sock, bluez.OGF_LINK_CTL, bluez.OCF_DISCONNECT, cmd_pkt)


def hci_le_connect(sock, peer_bdaddr, interval=0x0004, window=0x004,
                   initiator_filter=LE_FILTER_ALLOW_ALL,
                   peer_bdaddr_type=LE_RANDOM_ADDRESS,
                   own_bdaddr_type=LE_PUBLIC_ADDRESS,
                   min_interval=0x000F, max_interval=0x000F,
                   latency=0x0000, supervision_timeout=0x0C80,
                   min_ce_length=0x0001, max_ce_length=0x0001):

    package_bdaddr = get_packed_bdaddr(peer_bdaddr)
    cmd_pkt = struct.pack("<HHBB", interval, window, initiator_filter,
                          peer_bdaddr_type)
    cmd_pkt += package_bdaddr
    cmd_pkt += struct.pack("<BHHHHHH", own_bdaddr_type, min_interval,
                           max_interval, latency, supervision_timeout,
                           min_ce_length, max_ce_length)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_CREATE_CONN, cmd_pkt)


def hci_le_enable_scan(sock):
    hci_le_toggle_scan(sock, 0x01)


def hci_le_disable_scan(sock):
    hci_le_toggle_scan(sock, 0x00)


def hci_le_toggle_scan(sock, enable):
    # toggle scan
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)
    # sent toggle command"


def hci_le_set_scan_parameters(sock, scan_type=LE_SCAN_ACTIVE, interval=0x10,
                               window=0x10, own_bdaddr_type=LE_RANDOM_ADDRESS,
                               filter_type=LE_FILTER_ALLOW_ALL):
    # setting up scan

    # interval and window are uint_16, so we pad them with 0x0
    cmd_pkt = struct.pack("<BBBBBBB", scan_type, 0x0, interval, 0x0, window,
                          own_bdaddr_type, filter_type)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
    # sent scan parameters command


# HCI Response parsing --------------------------------------------------------

def hci_le_parse_response_packet(pkt):
    """
    Parse a BLE packet.

    Returns a dictionary which contains the event id, length and packet type,
    and possibly additional key/value pairs that represent the parsed content
    of the packet.
    """
    result = {}
    ptype, event, plen = struct.unpack("<BBB", pkt[:3])
    result["packet_type"] = ptype
    result["bluetooth_event_id"] = event
    result["packet_length"] = plen
    # We give the user the full packet back as the packet is small, and
    # the user may have additional parsing they want to do.
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
        result["handles"].append(
            {"handle": handle, "num_completed_packets": completed_packets})
        pkt = pkt[4:]
    return result


def _handle_inquiry_result_with_rssi(pkt):
    result = {}
    num_inquiry_results = struct.unpack("B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_inquiry_results"] = num_inquiry_results
    result["inquiry_results"] = []
    for i in xrange(num_inquiry_results):
        addr = bluez.ba2str(pkt[(6 * i):(6 * i) + 6])
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
        addr = bluez.ba2str(pkt[(6 * i):(6 * i) + 6])
        result["inquiry_results"].append({"Address": addr})
    return result

    num_connection_handles = struct.unpack("<B", pkt[0])[0]
    pkt = pkt[1:]
    result["num_connection_handles"] = num_connection_handles
    result["handles"] = []
    for i in xrange(num_connection_handles):
        handle, = struct.unpack("<H", pkt[0:2])
        completed_packets, = struct.unpack("<H", pkt[2:4])
        result["handles"].append(
            {"handle": handle, "num_completed_packets": completed_packets})
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
        result["bluetooth_le_subevent_name"] = \
            "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
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
    # Since we only care about BLE commands, we ignore the command return
    # values here. A full-powered bluetooth parsing module would check the OCF
    # above and parse the return values based on that OCF. We return the return
    # values to the user should the used want to parse the return values.
    return result


def _handle_le_connection_complete(pkt):
    result = {}
    status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
    device_address = packed_bdaddr_to_string(pkt[5:11])
    interval, latency, supervision_timeout, master_clock_accuracy = \
        struct.unpack("<HHHB", pkt[11:])
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

        device_addr = packed_bdaddr_to_string(
            pkt[report_pkt_offset + 3:report_pkt_offset + 9])
        report["peer_bluetooth_address"] = device_addr.upper()
        report["peer_bluetooth_address_s"] = \
            short_bt_address(report["peer_bluetooth_address"])

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
            report["payload_binary"] = \
                (pkt[report_pkt_offset +
                 10:report_pkt_offset +
                 10 + report_data_length + 1])
            report["payload"] = packet_as_hex_string(
                report["payload_binary"], flag_with_spacing=True,
                flag_force_capitalize=True)

        # Each report length is (2 (event type, bdaddr type) + 6 (the address)
        #    + 1 (data length field) + data length + 1 (rssi)) bytes long.
        report_pkt_offset = report_pkt_offset + 10 + report_data_length + 1
        rssi, = struct.unpack("<b", pkt[report_pkt_offset - 1])
        report["rssi"] = rssi
        result["advertising_reports"].append(report)

    return result


# utility function ------------------------------------------------------------

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr:
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)


def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x' % i for i in struct.unpack("<BBBBBB",
                                                      bdaddr_packed[::-1]))


def short_bt_address(btAddr):
    return ''.join(btAddr.split(':'))


def packet_as_hex_string(pkt, flag_with_spacing=False,
                         flag_force_capitalize=False):
    packet = ""
    space = ""
    if (flag_with_spacing):
        space = " "
    for b in pkt:
        packet = packet + "%02x" % struct.unpack("<B", b)[0] + space
    if (flag_force_capitalize):
        packet = packet.upper()
    return packet


# From the spec, 5.4.1, page 427 (Core Spec v4.0 Vol 2):
# "Each command is assigned a 2 byte Opcode used to uniquely identify different
# types of commands. The Opcode parameter is divided into two fields, called
# the OpCode Group Field (OGF) and OpCode Command Field (OCF). The OGF occupies
# the upper 6 bits of the Opcode, while the OCF occupies the remaining 10 bits"
def ogf_and_ocf_from_opcode(opcode):
    ogf = opcode >> 10
    ocf = opcode & 0x03FF
    return (ogf, ocf)


def reset_hci():
    # resetting bluetooth dongle
    cmd = "sudo hciconfig hci0 down"
    subprocess.call(cmd, shell=True)
    cmd = "sudo hciconfig hci0 up"
    subprocess.call(cmd, shell=True)


def get_companyid(pkt):
    return (struct.unpack("<B", pkt[1])[0] << 8) | \
        struct.unpack("<B", pkt[0])[0]


# verify received beacon packet format
def verify_beacon_packet(report):
    result = False
    # check payload length (31byte)
    if (report["report_metadata_length"] != 31):
        return result
    # check Company ID (OMRON = 0x02D5)
    if (struct.unpack("<B", report["payload_binary"][4])[0] !=
            ADV_TYPE_MANUFACTURER_SPECIFIC_DATA):
        return result
    if (get_companyid(report["payload_binary"][5:7]) != COMPANY_ID):
        return result
    # check shortened local name
    if (struct.unpack("<B", report["payload_binary"][28])[0] ==
            ADV_TYPE_SHORT_LOCAL_NAME):
        if ((report["payload_binary"][29:31] == "IM") or
                (report["payload_binary"][29:31] == "EP")):
            pass
        else:
            return result
    elif (struct.unpack("<B", report["payload_binary"][27])[0] ==
            ADV_TYPE_SHORT_LOCAL_NAME):
        if ((report["payload_binary"][28:31] == "Rbt") and
            ((struct.unpack("<B", report["payload_binary"][7])[0] == 0x01) or
             (struct.unpack("<B", report["payload_binary"][7])[0] == 0x02))):
            pass
        else:
            return result
    else:
        return result

    result = True
    return result


# classify beacon type sent from the sensor
def classify_beacon_packet(report):
    if (report["payload_binary"][29:31] == "IM"):
        return "IM"
    elif (report["payload_binary"][29:31] == "EP"):
        return "EP"
    elif (report["payload_binary"][28:31] == "Rbt"):
        if (struct.unpack("<B", report["payload_binary"][7])[0] == 0x01):
            return "Rbt 0x01"
        elif (struct.unpack("<B", report["payload_binary"][7])[0] == 0x02):
            return "Rbt 0x02"
        elif (struct.unpack("<B", report["payload_binary"][7])[0] == 0x03):
            return "Rbt 0x03"
        elif (struct.unpack("<B", report["payload_binary"][7])[0] == 0x04):
            return "Rbt 0x04"
        elif (struct.unpack("<B", report["payload_binary"][7])[0] == 0x05):
            return "Rbt 0x05"
        elif (struct.unpack("<B", report["payload_binary"][7])[0] == 0x06):
            return "Rbt 0x06"
    else:
        return "UNKNOWN"
