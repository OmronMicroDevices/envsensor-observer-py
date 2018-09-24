#!/usr/bin/python

import math
import conf
import datetime

import str_util
import ble


# Env Senor (OMRON 2JCIE-BL01 Broadcaster) ####################################

class SensorBeacon:

    # local fields from raw data
    bt_address = ""
    seq_num = 0
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
    val_etvoc = 0.0
    val_eco2 = 0.0

    val_pga = 0.0
    val_si = 0.0
    val_seismic = 0.0
    vibinfo = "-"

    rssi = -127
    distance = 0
    tick_last_update = 0
    tick_register = 0

    flag_active = False

    sensor_type = "UNKNOWN"
    gateway = "UNKNOWN"

    def __init__(self, bt_address_s, sensor_type_s, gateway_s, pkt):
        self.bt_address = bt_address_s

        if ((sensor_type_s == "IM") or (sensor_type_s == "EP")):
            self.seq_num = str_util.c2B(pkt[7])

            self.val_temp = str_util.bytes2short(
                str_util.c2B(pkt[9]), str_util.c2B(pkt[8])) / 100.0
            self.val_humi = str_util.bytes2ushort(
                str_util.c2B(pkt[11]), str_util.c2B(pkt[10])) / 100.0
            self.val_light = str_util.bytes2ushort(
                str_util.c2B(pkt[13]), str_util.c2B(pkt[12]))
            self.val_uv = str_util.bytes2ushort(
                str_util.c2B(pkt[15]), str_util.c2B(pkt[14])) / 100.0
            self.val_pressure = str_util.bytes2ushort(
                str_util.c2B(pkt[17]), str_util.c2B(pkt[16])) / 10.0
            self.val_noise = str_util.bytes2ushort(
                str_util.c2B(pkt[19]), str_util.c2B(pkt[18])) / 100.0
            self.val_battery = (str_util.c2B(pkt[26]) + 100) * 10.0

            if sensor_type_s == "IM":
                self.val_ax = str_util.bytes2short(
                    str_util.c2B(pkt[21]), str_util.c2B(pkt[20])) / 10.0
                self.val_ay = str_util.bytes2short(
                    str_util.c2B(pkt[23]), str_util.c2B(pkt[22])) / 10.0
                self.val_az = str_util.bytes2short(
                    str_util.c2B(pkt[25]), str_util.c2B(pkt[24])) / 10.0
                self.val_di = 0.0
                self.val_heat = 0.0
                self.calc_factor()
            elif sensor_type_s == "EP":
                self.val_ax = 0.0
                self.val_ay = 0.0
                self.val_az = 0.0
                self.val_di = str_util.bytes2short(
                    str_util.c2B(pkt[21]), str_util.c2B(pkt[20])) / 100.0
                self.val_heat = str_util.bytes2short(
                    str_util.c2B(pkt[23]), str_util.c2B(pkt[22])) / 100.0
            else:
                self.val_ax = 0.0
                self.val_ay = 0.0
                self.val_az = 0.0
                self.val_di = 0.0
                self.val_heat = 0.0
                self.calc_factor()
        else:  # Rbt
            self.seq_num = str_util.c2B(pkt[8])
            if (sensor_type_s == "Rbt 0x01"):
                self.val_temp = str_util.bytes2short(
                    str_util.c2B(pkt[10]), str_util.c2B(pkt[9])) / 100.0
                self.val_humi = str_util.bytes2ushort(
                    str_util.c2B(pkt[12]), str_util.c2B(pkt[11])) / 100.0
                self.val_light = str_util.bytes2ushort(
                    str_util.c2B(pkt[14]), str_util.c2B(pkt[13]))
                self.val_pressure = str_util.bytes2uint32(
                    str_util.c2B(pkt[18]), str_util.c2B(pkt[17]),
                    str_util.c2B(pkt[16]), str_util.c2B(pkt[15])) / 1000.0
                self.val_noise = str_util.bytes2ushort(
                    str_util.c2B(pkt[20]), str_util.c2B(pkt[19])) / 100.0
                self.val_etvoc = str_util.bytes2ushort(
                    str_util.c2B(pkt[22]), str_util.c2B(pkt[21]))
                self.val_eco2 = str_util.bytes2ushort(
                    str_util.c2B(pkt[24]), str_util.c2B(pkt[23]))
                self.calc_factor()
            elif (sensor_type_s == "Rbt 0x02"):
                self.val_di = str_util.bytes2short(
                    str_util.c2B(pkt[10]), str_util.c2B(pkt[9])) / 100.0
                self.val_heat = str_util.bytes2short(
                    str_util.c2B(pkt[12]), str_util.c2B(pkt[11])) / 100.0
                self.val_si = str_util.bytes2ushort(
                    str_util.c2B(pkt[15]), str_util.c2B(pkt[14])) / 10.0
                self.val_pga = str_util.bytes2ushort(
                    str_util.c2B(pkt[17]), str_util.c2B(pkt[16])) / 10.0
                self.val_seismic = str_util.bytes2ushort(
                    str_util.c2B(pkt[19]), str_util.c2B(pkt[18])) / 1000.0
                self.val_ax = str_util.bytes2short(
                    str_util.c2B(pkt[21]), str_util.c2B(pkt[20])) / 10.0
                self.val_ay = str_util.bytes2short(
                    str_util.c2B(pkt[23]), str_util.c2B(pkt[22])) / 10.0
                self.val_az = str_util.bytes2short(
                    str_util.c2B(pkt[25]), str_util.c2B(pkt[24])) / 10.0
                if (str_util.c2B(pkt[13]) == 0x00):
                    self.vibinfo = "NONE"
                elif (str_util.c2B(pkt[13]) == 0x01):
                    self.vibinfo = "VIBRATION"
                elif (str_util.c2B(pkt[13]) == 0x02):
                    self.vibinfo = "EARTHQUAKE"
                else:
                    pass

        self.rssi = str_util.c2b(pkt[-1])
        self.distance = self.return_accuracy(
            self.rssi, ble.BEACON_MEASURED_POWER)

        self.tick_register = datetime.datetime.now()
        self.tick_last_update = self.tick_register
        self.flag_active = True

        self.sensor_type = sensor_type_s
        self.gateway = gateway_s

    def return_accuracy(self, rssi, power):  # rough distance in meter
        RSSI = abs(rssi)
        if RSSI == 0:
            return -1
        if power == 0:
            return -1

        ratio = RSSI * 1.0 / abs(power)
        if ratio < 1.0:
            return pow(ratio, 8.0)
        accuracy = 0.69976 * pow(ratio, 7.7095) + 0.111
        # accuracy = 0.89976 * pow(ratio, 7.7095) + 0.111

        return accuracy

    def check_diff_seq_num(self, sensor_beacon):
        result = False
        if (self.seq_num != sensor_beacon.seq_num):
            result = True
        else:
            result = False
        return result

    def update(self, sensor_beacon):
        sensor_beacon.sensor_type = self.sensor_type
        sensor_beacon.gateway = self.gateway
        sensor_beacon.seq_num = self.seq_num
        sensor_beacon.val_temp = self.val_temp
        sensor_beacon.val_humi = self.val_humi
        sensor_beacon.val_light = self.val_light
        sensor_beacon.val_uv = self.val_uv
        sensor_beacon.val_pressure = self.val_pressure
        sensor_beacon.val_noise = self.val_noise
        sensor_beacon.val_di = self.val_di
        sensor_beacon.val_heat = self.val_heat
        sensor_beacon.val_ax = self.val_ax
        sensor_beacon.val_ay = self.val_ay
        sensor_beacon.val_az = self.val_az
        sensor_beacon.val_battery = self.val_battery
        sensor_beacon.val_etvoc = self.val_etvoc
        sensor_beacon.val_eco2 = self.val_eco2
        sensor_beacon.val_si = self.val_si
        sensor_beacon.val_pga = self.val_pga
        sensor_beacon.val_seismic = self.val_seismic
        sensor_beacon.vibinfo = self.vibinfo
        sensor_beacon.rssi = self.rssi
        sensor_beacon.distance = self.distance
        sensor_beacon.tick_last_update = self.tick_last_update
        sensor_beacon.flag_active = True

    def calc_factor(self):
        self.val_di = self.__discomfort_index_approximation(
            self.val_temp, self.val_humi)
        self.val_heat = self.__wbgt_approximation(
            self.val_temp, self.val_humi, flag_outside=False)

    # Index Calc ###
    def __discomfort_index_approximation(self, temp, humi):
        return (0.81 * temp) + 0.01 * humi * ((0.99 * temp) - 14.3) + 46.3

    def __wbgt_approximation(self, temp, humi, flag_outside=False):
        wbgt = 0
        if (temp < 0):
            temp = 0
        if (humi < 0):
            humi = 0
        if (humi > 100):
            humi = 100
        wbgt = (0.567 * temp) + 0.393 * (
            humi / 100 * 6.105 * math.exp(
                17.27 * temp / (237.7 + temp))) + 3.94
        if not flag_outside:
            wbgt = (wbgt + (1.1 * (1 - (humi / 62) * 1.6)) * (temp - 30) *
                    0.17 - abs(temp - 30) * 0.09) / 1.135
        return wbgt

    def forward_fluentd(self, fluent_event):
        fluent_event.Event(conf.INFLUXDB_MEASUREMENT, {
            'gateway': self.gateway,
            'sensor_type': self.sensor_type,
            'bt_address': self.bt_address,
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
            'etvoc': self.val_etvoc,
            'eco2': self.val_eco2,
            'si': self.val_si,
            'pga': self.val_pga,
            'seismic': self.val_seismic,
            'vibinfo': self.vibinfo,
            'battery': self.val_battery,
            'rssi': self.rssi,
            'distance': self.distance
        })

    def upload_influxdb(self, client_influxdb):
        # direct data upload to influxDB
        json_body = [
            {
                "measurement": conf.INFLUXDB_MEASUREMENT,
                "tags": {
                    "gateway": self.gateway,
                    "sensor_type": self.sensor_type,
                    "bt_address": self.bt_address
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
                    "etvoc": self.val_etvoc,
                    "eco2": self.val_eco2,
                    "si": self.val_si,
                    "pga": self.val_pga,
                    "seismic": self.val_seismic,
                    "vibinfo": self.vibinfo,
                    "battery": self.val_battery,
                    "rssi": self.rssi,
                    "distance": self.distance
                }
            }
        ]
        client_influxdb.write_points(json_body)

    def debug_print(self):
        print "\tgateway = ", self.gateway
        print "\ttype = ", self.sensor_type
        print "\tbt_address = ", self.bt_address
        print "\tseq_num = ", self.seq_num
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
        print "\tval_etvoc = ", self.val_etvoc
        print "\tval_eco2 = ", self.val_eco2
        print "\tval_si = ", self.val_si
        print "\tval_pga = ", self.val_pga
        print "\tval_seismic = ", self.val_seismic
        print "\tval_vibinfo = ", self.vibinfo
        print "\tval_battery = ", self.val_battery
        print "\trssi = ", self.rssi
        print "\tdistance = ", self.distance
        print "\ttick_register = ", self.tick_register
        print "\ttick_last_update = ", self.tick_last_update
        print "\tflag_active = ", self.flag_active

    def csv_format(self):
        str_data = str(self.tick_last_update) + "," + \
                   str(self.gateway) + "," + \
                   str(self.bt_address) + "," + \
                   str(self.sensor_type) + "," + \
                   str(self.rssi) + "," + \
                   str(self.distance) + "," + \
                   str(self.seq_num) + "," + \
                   str(self.val_battery) + "," + \
                   str(self.val_temp) + "," + \
                   str(self.val_humi) + "," + \
                   str(self.val_light) + "," + \
                   str(self.val_uv) + "," + \
                   str(self.val_pressure) + "," + \
                   str(self.val_noise) + "," + \
                   str(self.val_di) + "," + \
                   str(self.val_heat) + "," + \
                   str(self.val_ax) + "," + \
                   str(self.val_ay) + "," + \
                   str(self.val_az) + "," + \
                   str(self.val_etvoc) + "," + \
                   str(self.val_eco2) + "," + \
                   str(self.val_si) + "," + \
                   str(self.val_pga) + "," + \
                   str(self.val_seismic) + "," + \
                   str(self.vibinfo)
        return str_data


def csv_header():
    str_head = "Time" + "," + \
               "Gateway" + "," + \
               "Address" + "," + \
               "Type" + "," + \
               "RSSI (dBm)" + "," + \
               "Distance (m)" + "," + \
               "Sequence No." + "," + \
               "Battery (mV)" + "," + \
               "Temperature (degC)" + "," + \
               "Humidity (%%RH)" + "," + \
               "Light (lx)" + "," + \
               "UV Index" + "," + \
               "Pressure (hPa)" + "," + \
               "Noise (dB)" + "," + \
               "Discomfort Index" + "," + \
               "Heat Stroke Risk" + "," + \
               "Accel.X (mg)" + "," + \
               "Accel.Y (mg)" + "," + \
               "Accel.X (mg)" + "," + \
               "eTVOC (ppb)" + "," + \
               "eCO2 (ppm)" + "," + \
               "SI (kine)" + "," + \
               "PGA (gal)" + "," + \
               "Seismic Intensity" + "," + \
               "Vibration Info"
    return str_head
