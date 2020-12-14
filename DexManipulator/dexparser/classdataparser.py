# -*- coding: utf-8 -*-
import dexparser
from dexutil.iteminterpreter import *
import mmap
import struct

__all__ = [ 'ClassDataParser' ]

uL = lambda x: struct.unpack('<L', x)[0]
uH = lambda x: struct.unpack('<H', x)[0]
NO_INDEX = 0xffffffff


class ClassDataParser(object):

    def __init__(self, m, dp):
        """
        :param m: mmap
        :param dp: dexparser instance
        """
        if not isinstance(m, mmap.mmap) and not isinstance(dp, dexparser.DexParser):
            print " param type error"
            return

        self.mmap = m
        self.dex = dp

    @staticmethod
    def _uleb128(m):
        """
        offset을 받지 않고 현재 mmap position 기준으로 parsing한뒤
        mmap 의 position을 변경한다.
        :param mmap:
        :return:
        """
        value, size = uleb128_value(m, m.tell())  # 현재 위치 기준 parsing
        m.seek(size, 1)  # 현재위치에서 위치 변경

        return value

    @staticmethod
    def _get_idx(idx=0):
        idx = [idx]

        def calculate_idx(diff):
            idx[0] += diff
            return idx[0]

        return calculate_idx

    def _class_data_item_parser(self):
        """
        마찬가지로. mmap pointer은 핸들링 하지 않는다.
        해당 내용은 caller에서 처리 하도록 한다. annotation 처럼..
        encoded_field , encoded_method 는 list 형태로.. 넣에 주어야 한다.
        (!) 죄다 uleb라서 read를 써먹을수가 없다.
        :return:
        """

        m = self.mmap
        static_fields_size = ClassDataParser._uleb128(m)
        instance_fields_size = ClassDataParser._uleb128(m)
        direct_methods_size = ClassDataParser._uleb128(m)
        virtual_methods_size = ClassDataParser._uleb128(m)
        static_fields = []
        instance_fields = []
        direct_methods = []
        virtual_methods = []

        # static_fields
        for x in range(static_fields_size):
            field_idx_diff = ClassDataParser._uleb128(m)
            access_flags = ClassDataParser._uleb128(m)
            static_fields.append((field_idx_diff, access_flags))

        # instance_fields
        for x in range(instance_fields_size):
            field_idx_diff = ClassDataParser._uleb128(m)
            access_flags = ClassDataParser._uleb128(m)
            instance_fields.append((field_idx_diff, access_flags))

        # direct_methods
        for x in range(direct_methods_size):
            method_idx_diff = ClassDataParser._uleb128(m)
            access_flags = ClassDataParser._uleb128(m)
            code_off = ClassDataParser._uleb128(m)
            direct_methods.append((method_idx_diff, access_flags, code_off))

        # virtual_methods
        for x in range(virtual_methods_size):
            method_idx_diff = ClassDataParser._uleb128(m)
            access_flags = ClassDataParser._uleb128(m)
            code_off = ClassDataParser._uleb128(m)
            virtual_methods.append((method_idx_diff, access_flags, code_off))

        return [static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size,
                static_fields, instance_fields, direct_methods, virtual_methods]

    def _code_item_parser(self):
        """
        [registers_size,ins_size, outs_size, tries_size, Debug_info_off, Insns_size, insns_off_end]
        (!) insns_off_end => instruction이 끝나는 지점.  ( 임의로 추가 하였음 )
        :return:
        """
        m = self.mmap

        registers_size = uH(m.read(2))
        ins_size = uH(m.read(2))
        outs_size = uH(m.read(2))
        tries_size = uH(m.read(2))
        Debug_info_off = uL(m.read(4))
        Insns_size = uL(m.read(4))
        # Insns
        insns_off_end = m.tell() +Insns_size * 2 # instruction 마지막 위치 파악. ( instruction 이 끝난 지점을 가리킴 )
        # Padding
        padding = uH(m.read(2)) if Insns_size%2 == 1 and  tries_size > 0 else False
        # Tries
        tries_start_address =  uL(m.read(4)) if tries_size >0 else False
        # Handlers
        return [registers_size,ins_size, outs_size, tries_size, Debug_info_off, Insns_size, insns_off_end, padding, tries_start_address ]

    def print_class_data_item(self, offset):
        """
        class_data_item을 보기 좋게 일부분을 hex string으로 변경해서 출력
        :param offset:
        :return:
        """
        self.mmap.seek(offset)
        cdi = self._class_data_item_parser()
        self.mmap.seek(0)

        get_static_field_idx = ClassDataParser._get_idx()
        get_instance_field_idx = ClassDataParser._get_idx()
        get_direct_methods_idx = ClassDataParser._get_idx()
        get_virtual_methods_idx = ClassDataParser._get_idx()

        pretty_class_data_item = [
            cdi[0], cdi[1], cdi[2], cdi[3],
            [(self.dex._field_ids[get_static_field_idx(diff)][3], accsess_flag_parser(flag)) for diff, flag in cdi[4]],
            [(self.dex._field_ids[get_instance_field_idx(diff)][3], accsess_flag_parser(flag)) for diff, flag in  cdi[5]],
            [(self.dex._method_ids[get_direct_methods_idx(diff)][3], accsess_flag_parser(flag), hex(codoff)) for diff, flag, codoff in cdi[6]],
            [(self.dex._method_ids[get_virtual_methods_idx(diff)][3], accsess_flag_parser(flag), hex(codoff)) for diff, flag, codoff in cdi[7]]
        ]

        return pretty_class_data_item

    def get_class_data_item(self, offset):
        """
        [ [direct_methods 의 code_off] virtual_methods 의 code_off] ]
        :param offset:
        :return:
        """
        save_point= self.mmap.tell()

        self.mmap.seek(offset)
        cdi = self._class_data_item_parser()

        self.mmap.seek(save_point)

        direct_methods = [ encoded_method[2] for encoded_method in cdi[6] ]
        virtual_methods = [ encoded_method[2] for encoded_method in cdi[7] ]

        return [ direct_methods, virtual_methods ]

    def print_code_item(self, offset):
        self.mmap.seek(offset)
        ci = self._code_item_parser()
        self.mmap.seek(0)

        ci[4] = hex(ci[4])
        ci[6] = hex(ci[6])
        return ci

    def get_code_item(self, offset):
        self.mmap.seek(offset)
        ci = self._code_item_parser()
        self.mmap.seek(0)
        return ci

    @property
    def class_data_list(self):
        pass

    @property
    def code_item_list(self):
        """
        보류.. sleb 따로 구현하고 나머지 encoded된 부분을 전부다 parsing해야 한다..
        (!) modifiy할때에는 결국 class_data를 기반으로 순회하면서 진행할 수 밖에 없을거 같다.
        :return:
        """
        pass
