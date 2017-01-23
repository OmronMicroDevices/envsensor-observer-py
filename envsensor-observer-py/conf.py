#!/usr/bin/python

import os

# envsensor_observer configuration ############################################

# Bluetooth adaptor
BT_DEV_ID = 0

# time interval for sensor status evaluation (sec.)
CHECK_SENSOR_STATE_INTERVAL_SECONDS = 300
INACTIVE_TIMEOUT_SECONDS = 60
# Sensor will be inactive state if there is no advertising data received in
# this timeout period.


# csv output to local file system
CSV_OUTPUT = True
# the directory path for csv output
CSV_DIR_PATH = os.path.dirname(os.path.abspath(__file__)) + "/log"


# use fluentd forwarder
FLUENTD_FORWARD = True
# fluent-logger-python
FLUENTD_TAG = "envsensor_observer"
FLUENTD_ADDRESS = "localhost"
FLUENTD_PORT = 24224
# fluent-plugin-influxdb (when using influxDB through fluentd.)
FLUENTD_INFLUXDB_ADDRESS = "164.70.7.153"  # IP address of Cloud Server
FLUENTD_INFLUXDB_PORT_STRING = "8086"
FLUENTD_INFLUXDB_DATABASE = "envsensor_fluent"


# uploading data to the cloud (required influxDB 0.9 or higher)
INFLUXDB_OUTPUT = True
# InfluxDB
INFLUXDB_ADDRESS = "164.70.7.153"  # IP address of Cloud Server
INFLUXDB_PORT = 8086
INFLUXDB_DATABASE = "envsensor"
INFLUXDB_MEASUREMENT = "environment"
INFLUXDB_USER = "root"
INFLUXDB_PASSWORD = "root"
