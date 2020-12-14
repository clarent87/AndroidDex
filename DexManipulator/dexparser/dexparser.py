# -*- coding: utf-8 -*-

import collections
import mmap
import struct
from .annotationparser import *
from .classdataparser import *
from dexutil import *

uL = lambda x: struct.unpack('<L', x)[0]
uH = lambda x: struct.unpack('<H', x)[0]
NO_INDEX = 0xffffffff


# file close와 mmap close 위치를 결정하지 못하였다.. 이건 이슈 인듯.
class DexParser(object):

    def __init__(self, dexfile):
        """
        :param dexfile: filepath여도 되고 mmap object여도 된다.
        """

        if not isinstance(dexfile, mmap.mmap):
            f = open(dexfile, 'r+b')
            f.flush()
            self.mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) # parser에서 수정하지는 않겠지만.. 일단은 rx
        else:
            self.mmap = dexfile

        self._header_parser()
        self._map_list_parser()
        self._string_ids_parser()
        self._type_ids_parser()
        self._proto_ids_parser()
        self._field_ids_parser()
        self._method_ids_parser()
        self._class_defs_parser()
        self._type_list_parser()

    def _header_parser(self):
        m = self.mmap

        header = collections.OrderedDict()

        header['magic']             = m[0:8]
        header['checksum']          = uL(m[8:0xC])
        header['signature']         = m[0xC:0x20]
        header['file_size']         = uL(m[0x20:0x24])
        header['header_size']       = uL(m[0x24:0x28])
        header['endian_tag']        = uL(m[0x28:0x2C])
        header['link_size']         = uL(m[0x2C:0x30])
        header['link_off']          = uL(m[0x30:0x34])
        header['map_off']           = uL(m[0x34:0x38])
        header['string_ids_size']   = uL(m[0x38:0x3C])
        header['string_ids_off']    = uL(m[0x3C:0x40])
        header['type_ids_size']     = uL(m[0x40:0x44])
        header['type_ids_off']      = uL(m[0x44:0x48])
        header['proto_ids_size']    = uL(m[0x48:0x4C])
        header['proto_ids_off']     = uL(m[0x4C:0x50])
        header['field_ids_size']    = uL(m[0x50:0x54])
        header['field_ids_off']     = uL(m[0x54:0x58])
        header['method_ids_size']   = uL(m[0x58:0x5C])
        header['method_ids_off']    = uL(m[0x5C:0x60])
        header['class_defs_size']   = uL(m[0x60:0x64])
        header['class_defs_off']    = uL(m[0x64:0x68])
        header['data_size']         = uL(m[0x68:0x6C])
        header['data_off']          = uL(m[0x6C:0x70])

        self._header = header

    def _link_parser(self):
        """공홈에 내용이 없음"""
        pass

    def _map_list_parser(self):
        m = self.mmap
        m.seek(self._header['map_off'])

        map_list_size = uL(m.read(4))
        map_items = []  # type / size / offset

        for i in range(map_list_size):
            type    = uH(m.read(2))
            m.read(2)  # unused field
            size    = uL(m.read(4))
            offset  = uL(m.read(4))
            map_items.append([type, size, offset])

        self._map_list = map_items
        m.seek(0)  # 꼭 pointer를 file 처음으로 다시 돌려주어야 한다.

    def _string_ids_parser(self):
        """ 
        :return: [ offset, string size, string ]
        offset만 ids내용이고 string size, string은 offset을 따라가서 나온내용
        """
        m = self.mmap

        string_ids_size = self._header['string_ids_size']
        string_ids_off = self._header['string_ids_off']

        string_ids = []

        for i in range(string_ids_size):
            offset = uL( m[string_ids_off + (i * 4): string_ids_off + (i * 4) + 4])

            string_size, leb_size = iteminterpreter.uleb128_value(m, offset)
            string_ = m[offset + leb_size: offset + leb_size + string_size]

            string_ids.append([offset, string_size, string_])

        self._string_ids = string_ids

    def _type_ids_parser(self):
        """
        :return: [ idx, 해당하는 string ]
        idx 만 ids의 내용
        """
        m = self.mmap
        m.seek(self._header['type_ids_off'])
        type_ids_size = self._header['type_ids_size']

        type_ids = []

        for i in range(type_ids_size):
            idx = uL(m.read(4))
            type_ids.append([idx, self._string_ids[idx][2]])

        self._type_ids = type_ids
        m.seek(0)

    def _proto_ids_parser(self):
        """
        :return: [ shorty_idx(string_idx), return_type_idx(type_idx), parameter_off, [ 해석한 내용 ] ]
        """
        m = self.mmap
        m.seek(self._header['proto_ids_off'])
        proto_ids_size = self._header['proto_ids_size']

        proto_ids = []

        for i in range(proto_ids_size):
            shorty_idx      = uL(m.read(4))
            return_type_idx = uL(m.read(4))
            parameter_off   = uL(m.read(4))
            proto_ids.append([shorty_idx, return_type_idx, parameter_off])

        self._proto_ids = proto_ids
        m.seek(0)

        # -- 내용 해석 --
        for x in self._proto_ids:
            shorty_descriptor = self._string_ids[x[0]][2]
            return_type = self._type_ids[x[1]][1]
            param_types = ""

            if x[2] != 0:  # param_off가 0이 아닌 경우만 parameter가 있다는 얘기
                idx_list = iteminterpreter.type_list_item(m, x[2])
                param_types = "/".join(self._type_ids[y][1] for y in idx_list)

            x.append([shorty_descriptor, return_type, param_types])

    def _field_ids_parser(self):
        """
        :return: [ class_idx , type_idx, name_idx, [ 해석한 내용 ]]
        """

        m = self.mmap
        m.seek(self._header['field_ids_off'])
        field_ids_size = self._header['field_ids_size']

        field_ids = []

        for i in range(field_ids_size):
            class_idx   = uH(m.read(2))
            type_idx    = uH(m.read(2))
            name_idx    = uL(m.read(4))
            field_ids.append([class_idx, type_idx, name_idx])

        self._field_ids = field_ids
        m.seek(0)

        # -- 내용 해석 --
        for x in self._field_ids:
            class_ = self._type_ids[x[0]][1]
            type_ = self._type_ids[x[1]][1]
            name_ = self._string_ids[x[2]][2]
            x.append([class_, type_, name_])

    def _method_ids_parser(self):
        """
        :return:  [ class_idx , proto_idx, name_idx, [ 해석한 내용 ]]
        """
        m = self.mmap
        m.seek(self._header['method_ids_off'])
        method_ids_size = self._header['method_ids_size']

        method_ids = []

        for i in range(method_ids_size):
            class_idx   = uH(m.read(2))
            proto_idx   = uH(m.read(2))
            name_idx    = uL(m.read(4))
            method_ids.append([class_idx, proto_idx, name_idx])

        self._method_ids = method_ids
        m.seek(0)

        # -- 내용 해석 --
        for x in self._method_ids:
            class_ = self._type_ids[x[0]][1]
            proto_ = self._proto_ids[x[1]][3]
            name_ = self._string_ids[x[2]][2]
            x.append([class_, proto_, name_])

    def _class_defs_parser(self):
        """
        :return: [[ class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off , [클래스 이름]]]
        class_defs의 index를 이용해서 해당 클래스를 파싱하는 것을 따로 둔다.
        """

        m = self.mmap
        m.seek(self._header['class_defs_off'])
        class_defs_size = self._header['class_defs_size']

        class_defs = []

        for i in range(class_defs_size):
            class_idx           = uL(m.read(4))
            access_flags        = uL(m.read(4))
            superclass_idx      = uL(m.read(4))
            interfaces_off      = uL(m.read(4))
            source_file_idx     = uL(m.read(4))
            annotations_off     = uL(m.read(4))
            class_data_off      = uL(m.read(4))
            static_values_off   = uL(m.read(4))
            class_defs.append(
                [class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off,
                 class_data_off, static_values_off])

        self._class_defs = class_defs
        m.seek(0)

        # -- 내용 해석 --
        for x in self._class_defs:
            x.append(self._type_ids[x[0]][1])


    def _type_list_parser(self):
        """
        offset이 중요
        [ offset(-), size(4), type_idx( 2 * size) ]
        널문자는? size + type_idx가 4의 배수여야 한다..

        확실히 map은 잘못 짯네..
        """
        m = self.mmap
        type_list = []
        # type_list 정보 찾기
        for x in self._map_list:
            if x[0] == 0x1001:
                map_item_type_list = x
                break
        else:
            # error
            return None


        # type_list 위치로 변경
        m.seek(map_item_type_list[2])

        # type_list 아이템 수만큼 loop
        for x in range(map_item_type_list[1]):
            offset = m.tell()
            size = uL(m.read(4))
            type_idxs = [ uH(m.read(2)) for _ in range(size) ]
            # 4byte align 확인
            if size % 2 != 0:
                uH(m.read(2))
            type_list.append([offset, size, type_idxs])

        m.seek(0)
        self._type_list = type_list


    # ---------- property --------------

    @property
    def header_info(self):
        """ 일부 데이터를 hex로 변환해서 출력"""
        header_info = collections.OrderedDict()
        for k, v in self._header.items():
            if k == 'signature':
                header_info[k] = '0x' + ''.join(x.encode('hex') for x in v)
            elif k == 'magic':
                header_info[k] = v
            else:
                header_info[k] = hex(v)
        return header_info

    @property
    def map_list_info(self):
        """ 일부 데이터를 hex로 변환해서 출력"""
        map_list_info = []
        for x in self._map_list:
            map_list_info.append([dextypes.typecode[x[0]], hex(x[1]), hex(x[2])])
        return map_list_info

    @property
    def string_ids_info(self):
        """ 일부 데이터를 hex로 변환해서 출력"""
        string_ids_info = []
        for x in self._string_ids:
            string_ids_info.append([hex(x[0]), hex(x[1]), x[2]])
        return string_ids_info

    @property
    def type_ids_info(self):
        return self._type_ids

    @property
    def proto_ids_info(self):
        """param_off만 hex로 전환해서 보여줌"""
        proto_ids = []
        for x in self._proto_ids:
            import copy
            y = copy.deepcopy(x)
            y[2] = hex(y[2])
            proto_ids.append(y)
        return proto_ids

    @property
    def field_ids_info(self):
        return self._field_ids

    @property
    def method_ids_info(self):
        return self._method_ids

    @property
    def class_defs_info(self):
        """
        offset 및 flag는 format을 변경.
        """
        class_defs = []

        for x in self._class_defs:
            class_idx = self._type_ids[x[0]][1]
            access_flags = iteminterpreter.accsess_flag_parser(x[1])
            superclass_idx = self._type_ids[x[2]][1] if x[2] != NO_INDEX else 'NO_INDEX'
            interfaces_off = iteminterpreter.type_list_item(self.mmap, x[3]) if x[3] != 0 else 0
            source_file_idx = self._string_ids[x[4]][2] if x[4] != NO_INDEX else 'NO_INDEX'
            annotations_off = hex(x[5])
            class_data_off = hex(x[6])
            static_values_off = hex(x[7])
            class_defs.append(
                [class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off,
                 class_data_off, static_values_off])

        return class_defs

    def _get_selected_class_info(self, index_of_class_defs):
        """
        (!) 단순 검증용.. test API
        (!) 향후 삭제하고 다시 작성해야 함
        Annotations_off / class_data_off / static_value_off( 이건 생략.. array encoding 파싱 해야 한다. 따라서 그냥 offset만 출력. )
        관련한 데이터 묶음을 보여 준다.
        :param index_of_class_defs:
        :return:

        """
        # annotation
        # (!) annotation_set_itme의 경우 profiler와는 다르게 offset이 1차이 난다. ( profiler는 visibiity를 파싱한 다음의 offset임 )
        ap = AnnotationParser(self.mmap, self)
        annotations_off = self._class_defs[index_of_class_defs][5]

        if annotations_off == 0 :
            return []

        adi = ap.get_annotations_directory_item(annotations_off)
        adi[0] = ap.get_annotation_set_item(int(adi[0],16)) # offset을 기반으로 annotation_set_item을 가져온다.

        return adi

    def get_class_data_item(self, idx):
        cp = ClassDataParser(self.mmap, self)
        class_data_off = self._class_defs[idx][6]
        if class_data_off == 0 :
            return []
        cdi = cp.print_class_data_item(class_data_off)
        return cdi


    def get_get_code_item(self,offset):
        """
        TEST API
        :param offset:
        :return:
        """

        cp = ClassDataParser(self.mmap, self)
        return cp.print_code_item(offset)

    def get_annotation_directory_item(self):
        ap = AnnotationParser(self.mmap, self)
        return  ap.annotations_directory_list
