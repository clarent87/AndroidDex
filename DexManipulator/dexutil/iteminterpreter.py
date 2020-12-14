# -*- coding: utf-8 -*-
import mmap
import struct
import dextypes


def accsess_flag_parser(integer_value):
    access_flag = ""
    for k, v in dextypes.access_flag.items():
        if integer_value & k:
            access_flag += " | " + v

    # temp
    for k, v in dextypes.undocumented_access_flag.items():
        if integer_value & k:
            access_flag += " | " + v

    return access_flag[3:]


# uleb128 decoder!
def uleb128_value(m, off):
    size = 1
    result = ord(m[off + 0])
    if result > 0x7f:
        cur = ord(m[off + 1])
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        size += 1
        if cur > 0x7f:
            cur = ord(m[off + 2])
            result |= ((cur & 0x7f) << 14)
            size += 1
            if cur > 0x7f:
                cur = ord(m[off + 3])
                result |= ((cur & 0x7f) << 21)
                size += 1
                if cur > 0x7f:
                    cur = ord(m[off + 4])
                    result |= (cur << 28)
                    size += 1
    return result, size

def uleb128_encode(value):
    """
    integer value to
    :param value:
    :return:
    """
    size = 1
    result = []
    for i in range(5):
        if value < 0x7f:
            result.append(chr(value))
            break
        else:
            # 마지막 7 bit 빼기
            cur = value & 0x7f
            value = value >> 7
            result.append(chr(cur | 0x80))
    return ''.join(result), size + i


def type_list_item(m, off):
    # type: (mmap, long ) -> dict
    """
    :param m:
    :param off:
    :return: type_idx_list
    """
    size = struct.unpack('<L', m[off:off + 4])[0]
    item_start = off + 4

    idx_list = []
    for i in range(size):
        idx = struct.unpack('<H', m[item_start + (i * 2): item_start + (i * 2) + 2])[0]
        idx_list.append(idx)
    return idx_list


# 아래 부터는 검증 안됨
def encoded_field(mmap, offset):
    myoff = offset

    field_idx_diff, size = uleb128_value(mmap, myoff)
    myoff += size
    access_flags, size = uleb128_value(mmap, myoff)
    myoff += size

    size = myoff - offset

    return [field_idx_diff, access_flags, size]


def encoded_method(mmap, offset):
    myoff = offset

    method_idx_diff, size = uleb128_value(mmap, myoff)
    myoff += size
    access_flags, size = uleb128_value(mmap, myoff)
    myoff += size
    code_off, size = uleb128_value(mmap, myoff)
    myoff += size

    size = myoff - offset

    return [method_idx_diff, access_flags, code_off, size]


def encoded_annotation(mmap, offset):
    myoff = offset

    type_idx_diff, size = uleb128_value(mmap, myoff)
    # print hex(type_idx_diff), size
    myoff += size
    size_diff, size = uleb128_value(mmap, myoff)
    # print hex(size_diff), size
    myoff += size
    name_idx_diff, size = uleb128_value(mmap, myoff)
    # print hex(name_idx_diff)
    myoff += size
    value_type = mmap[myoff:myoff + 1]
    encoded_value = mmap[myoff + 1:myoff + 2]

    return [type_idx_diff, size_diff, name_idx_diff, value_type, encoded_value]
