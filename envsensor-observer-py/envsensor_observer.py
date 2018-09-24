#!/usr/bin/python
#
# python Environment Sensor Observer for Linux
#
# target device : OMRON Environment Sensor (2JCIE-BL01 & BU01) in Broadcaster mode
#
# require : python-bluez
#         : fluent-logger-python (when FLUENTD_FORWARD = True in configuration)
#               $ sudo pip install fluent-logger
#         : influxdb-python (when INFLUXDB_OUTPUT = True in configuration)
#               $ sudo pip install influxdb
#               $ sudo pip install --upgrade influxdb
#
# Note: Proper operation of this sample application is not guaranteed.

import sys
import os
import argparse
import requests
import socket
import datetime
import threading
import struct

import sensor_beacon as envsensor
import conf
import ble

if conf.CSV_OUTPUT:
    import logging
    import csv_logger
if conf.FLUENTD_FORWARD:
    from fluent import sender
    from fluent import event
if conf.INFLUXDB_OUTPUT:
    from influxdb import InfluxDBClient

# constant
VER = 1.2

# ystem constant
GATEWAY = socket.gethostname()

# Global variables
influx_client = None
sensor_list = []
flag_update_sensor_status = False


def parse_events(sock, loop_count=10):
    global sensor_list

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

    parsed_packet = ble.hci_le_parse_response_packet(pkt)

    if "bluetooth_le_subevent_name" in parsed_packet and \
            (parsed_packet["bluetooth_le_subevent_name"]
                == 'EVT_LE_ADVERTISING_REPORT'):

        if debug:
            for report in parsed_packet["advertising_reports"]:
                print "----------------------------------------------------"
                print "Found BLE device:", report['peer_bluetooth_address']
                print "Raw Advertising Packet:"
                print ble.packet_as_hex_string(pkt, flag_with_spacing=True,
                                               flag_force_capitalize=True)
                print ""
                for k, v in report.items():
                    if k == "payload_binary":
                        continue
                    print "\t%s: %s" % (k, v)
                print ""

        for report in parsed_packet["advertising_reports"]:
            if (ble.verify_beacon_packet(report)):
                sensor = envsensor.SensorBeacon(
                    report["peer_bluetooth_address_s"],
                    ble.classify_beacon_packet(report),
                    GATEWAY,
                    report["payload_binary"])

                index = find_sensor_in_list(sensor, sensor_list)

                if debug:
                    print ("\t--- sensor data ---")
                    sensor.debug_print()
                    print ""

                lock = threading.Lock()
                lock.acquire()

                if (index != -1):  # BT Address found in sensor_list
                    if sensor.check_diff_seq_num(sensor_list[index]):
                        handling_data(sensor)
                    sensor.update(sensor_list[index])
                else:  # new SensorBeacon
                    sensor_list.append(sensor)
                    handling_data(sensor)
                lock.release()
            else:
                pass
    else:
        pass
    return


# data handling
def handling_data(sensor):
    if conf.INFLUXDB_OUTPUT:
        sensor.upload_influxdb(influx_client)
    if conf.FLUENTD_FORWARD:
        sensor.forward_fluentd(event)
    if conf.CSV_OUTPUT:
        log.info(sensor.csv_format())


# check timeout sensor and update flag
def eval_sensor_state():
    global flag_update_sensor_status
    global sensor_list
    nowtick = datetime.datetime.now()
    for sensor in sensor_list:
        if (sensor.flag_active):
            pastSec = (nowtick - sensor.tick_last_update).total_seconds()
            if (pastSec > conf.INACTIVE_TIMEOUT_SECONDS):
                if debug:
                    print "timeout sensor : " + sensor.bt_address
                sensor.flag_active = False
    flag_update_sensor_status = True
    timer = threading.Timer(conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS,
                            eval_sensor_state)
    timer.setDaemon(True)
    timer.start()


def print_sensor_state():
    print "----------------------------------------------------"
    print ("sensor status : %s (Intvl. %ssec)" % (datetime.datetime.today(),
           conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS))
    for sensor in sensor_list:
        print " " + sensor.bt_address, ": %s :" % sensor.sensor_type, \
            ("ACTIVE" if sensor.flag_active else "DEAD"), \
            "(%s)" % sensor.tick_last_update
    print ""


#  Utility function ###
def return_number_packet(pkt):
    myInteger = 0
    multiple = 256
    for c in pkt:
        myInteger += struct.unpack("B", c)[0] * multiple
        multiple = 1
    return myInteger


def return_string_packet(pkt):
    myString = ""
    for c in pkt:
        myString += "%02x" % struct.unpack("B", c)[0]
    return myString


def find_sensor_in_list(sensor, List):
    index = -1
    count = 0
    for i in List:
        if sensor.bt_address == i.bt_address:
            index = count
            break
        else:
            count += 1
    return index


# init fluentd interface
def init_fluentd():
    sender.setup(conf.FLUENTD_TAG, host=conf.FLUENTD_ADDRESS,
                 port=conf.FLUENTD_PORT)


# create database on influxdb
def create_influx_database():
    v = "q=CREATE DATABASE " + conf.FLUENTD_INFLUXDB_DATABASE + "\n"
    uri = ("http://" + conf.FLUENTD_INFLUXDB_ADDRESS + ":" +
           conf.FLUENTD_INFLUXDB_PORT_STRING + "/query")
    r = requests.get(uri, params=v)
    if debug:
        print "-- create database : " + str(r.status_code)


# command line argument
def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='debug mode',
                        action='store_true')
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + str(VER))
    args = parser.parse_args()
    return args


# main function
if __name__ == "__main__":
    try:
        flag_scanning_started = False

        # process command line arguments
        debug = False
        args = arg_parse()
        if args.debug:
            debug = True

        # reset bluetooth functionality
        try:
            if debug:
                print "-- reseting bluetooth device"
            ble.reset_hci()
            if debug:
                print "-- reseting bluetooth device : success"
        except Exception as e:
            print "error enabling bluetooth device"
            print str(e)
            sys.exit(1)

        # initialize cloud (influxDB) output interface
        try:
            if conf.INFLUXDB_OUTPUT:
                if debug:
                    print "-- initialize influxDB interface"
                influx_client = InfluxDBClient(conf.INFLUXDB_ADDRESS,
                                               conf.INFLUXDB_PORT,
                                               conf.INFLUXDB_USER,
                                               conf.INFLUXDB_PASSWORD,
                                               conf.INFLUXDB_DATABASE)
                influx_client.create_database(conf.INFLUXDB_DATABASE)
                if debug:
                    print "-- initialize influxDB interface : success"
        except Exception as e:
            print "error initializing influxDB output interface"
            print str(e)
            sys.exit(1)

        # initialize fluentd forwarder
        try:
            if conf.FLUENTD_FORWARD:
                if debug:
                    print "-- initialize fluentd"
                init_fluentd()
                # create database when using influxDB through fluentd.
                if conf.FLUENTD_INFLUXDB:
                    create_influx_database()
                if debug:
                    print "-- initialize fluentd : success"
        except Exception as e:
            print "error initializing fluentd forwarder"
            print str(e)
            sys.exit(1)

        # initialize csv output interface
        try:
            if conf.CSV_OUTPUT:
                if debug:
                    print "-- initialize csv logger"

                if not os.path.isdir(conf.CSV_DIR_PATH):
                    os.makedirs(conf.CSV_DIR_PATH)
                csv_path = conf.CSV_DIR_PATH + "/env_sensor_log.csv"
                # create time-rotating log handler
                loghndl = csv_logger.CSVHandler(csv_path, 'midnight', 1)
                form = '%(message)s'
                logFormatter = logging.Formatter(form)
                loghndl.setFormatter(logFormatter)

                # create logger
                log = logging.getLogger('CSVLogger')
                loghndl.configureHeaderWriter(envsensor.csv_header(), log)
                log.addHandler(loghndl)
                log.setLevel(logging.INFO)
                log.info(envsensor.csv_header())

                if debug:
                    print "-- initialize csv logger : success"
        except Exception as e:
            print "error initializing csv output interface"
            print str(e)
            sys.exit(1)

        # initialize bluetooth socket
        try:
            if debug:
                print "-- open bluetooth device"
            sock = ble.bluez.hci_open_dev(conf.BT_DEV_ID)
            if debug:
                print "-- ble thread started"
        except Exception as e:
            print "error accessing bluetooth device: ", str(conf.BT_DEV_ID)
            print str(e)
            sys.exit(1)

        # set ble scan parameters
        try:
            if debug:
                print "-- set ble scan parameters"
            ble.hci_le_set_scan_parameters(sock)
            if debug:
                print "-- set ble scan parameters : success"
        except Exception as e:
            print "failed to set scan parameter!!"
            print str(e)
            sys.exit(1)

        # start ble scan
        try:
            if debug:
                print "-- enable ble scan"
            ble.hci_le_enable_scan(sock)
            if debug:
                print "-- ble scan started"
        except Exception as e:
            print "failed to activate scan!!"
            print str(e)
            sys.exit(1)

        flag_scanning_started = True
        print ("envsensor_observer : complete initialization")
        print ""

        # activate timer for sensor status evaluation
        timer = threading.Timer(conf.CHECK_SENSOR_STATE_INTERVAL_SECONDS,
                                eval_sensor_state)
        timer.setDaemon(True)
        timer.start()

        # preserve old filter setting
        old_filter = sock.getsockopt(ble.bluez.SOL_HCI,
                                     ble.bluez.HCI_FILTER, 14)
        # perform a device inquiry on bluetooth device #0
        # The inquiry should last 8 * 1.28 = 10.24 seconds
        # before the inquiry is performed, bluez should flush its cache of
        # previously discovered devices
        flt = ble.bluez.hci_filter_new()
        ble.bluez.hci_filter_all_events(flt)
        ble.bluez.hci_filter_set_ptype(flt, ble.bluez.HCI_EVENT_PKT)
        sock.setsockopt(ble.bluez.SOL_HCI, ble.bluez.HCI_FILTER, flt)

        while True:
            # parse ble event
            parse_events(sock)
            if flag_update_sensor_status:
                print_sensor_state()
                flag_update_sensor_status = False

    except Exception as e:
        print "Exception: " + str(e)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        if flag_scanning_started:
            # restore old filter setting
            sock.setsockopt(ble.bluez.SOL_HCI, ble.bluez.HCI_FILTER,
                            old_filter)
            ble.hci_le_disable_scan(sock)
        print "Exit"
