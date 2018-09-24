#!/usr/bin/python

import struct


def c2B(char):  # character to Byte conversion
    return struct.unpack("B", char)[0]


def c2b(char):  # character to signed char conversion
    return struct.unpack("b", char)[0]


def bytes2ushort(hi, lo):
    ushort_val = ((hi << 8) | lo)
    return ushort_val


def bytes2uint32(highest, high, low, lowest):
    uint32_val = ((highest << 24) | (high << 16) | (low << 8) | lowest)
    return uint32_val


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
