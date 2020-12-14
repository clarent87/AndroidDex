# -*- coding: utf-8 -*-
import dexparser
import mmap
import struct

__all__ = [ 'AnnotationParser' ]

uL = lambda x: struct.unpack('<L', x)[0]
uH = lambda x: struct.unpack('<H', x)[0]
NO_INDEX = 0xffffffff


class AnnotationParser(object):

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

    def _annotations_directory_parser(self):
        """
        [ usage ] 단일 class_def에서 offset 이용해서 parsing 할때 쓰임
        :param offset: annotation_directory 시작 위치
        :return:
        [
            "class_annotation_off": ,
            "fields_size": ,
            "annotated_methods_size": ,
            "annotated_parameters_size": ,
            "field_annotations" : [ ( field_idx:4 + annotations_off:4 (set_item) )  ]
            "method_annotations " : [ ( method_idx:4 + annotations_off:4 (set_item) ) ]
            "parameter_annotations" :  [ ( method_idx:4+ annotations_off:4 (ref_list) ) ]
        ]
        (!) mmap position은 고려하지 않는다. ( 즉 caller에서 다뤄야 함 )
        (!) modifier에서는 field_annotations/method_annotations/parameter_annotations 다수정 해야 함.
        """
        m = self.mmap

        class_annotation_off = uL(m.read(4))
        fields_size = uL(m.read(4))
        annotated_methods_size = uL(m.read(4))
        annotated_parameters_size = uL(m.read(4))

        field_annotations = []  # 튜플로 저장 ( 이래도 상관없다.. 수정시에는 어짜피 읽으면서 진행해야 한다. )
        method_annotations = []
        parameter_annotations = []

        for x in range(fields_size):
            field_annotations.append((uL(m.read(4)), uL(m.read(4))))
        for x in range(annotated_methods_size):
            method_annotations.append((uL(m.read(4)), uL(m.read(4))))
        for x in range(annotated_parameters_size):
            parameter_annotations.append((uL(m.read(4)), uL(m.read(4))))

        return [class_annotation_off, fields_size, annotated_methods_size,
                annotated_parameters_size, field_annotations,
                method_annotations, parameter_annotations]

    def _annotation_set_item_parser(self):
        """
        annotation item을 가리키는 부분이 있지만 annotation item은 parsing 하지 않는다.. ( 일단.. )
        annotation_set_item := [ size, [ annotation_off ] ]
        :return:
        """
        m = self.mmap

        size = uL(m.read(4))
        annotation_offs = []

        for x in range(size):
            annotation_offs.append(uL(m.read(4)))

        return [size, annotation_offs]

    def _annotation_set_ref_list_parser(self):
        """
        annotation_set_ref_list := [ size, [ annotation_off->annotation_set_item ] ]
        offset을 다시 순회 하는것은 annotation_set_item_parser으로 알아서 진행해야 할듯..
        (!) _annotation_set_item_parser와 동일한 구조
        (!) 테스트 안함..
        :return:
        """
        m = self.mmap

        size = uL(m.read(4))
        annotation_offs = []

        for x in range(size):
            annotation_offs.append(uL(m.read(4)))

        return [size, annotation_offs]


    def get_annotations_directory_item(self, offset):
        """
        검증용으로 쓰는 API (parser ) offset을 hex로 출력
        :param offset:
        :return:
        (!) modify할때는 개별 아이템을 보고 진행하지 않는다.. ( 따로 만들 api에서 maplist 보고 진행)
        """
        self.mmap.seek(offset)
        adi = self._annotations_directory_parser()
        self.mmap.seek(0)

        pretty_annotations_directory_item = [
            hex(adi[0]),
            adi[1],
            adi[2],
            adi[3],
            [(idx, hex(offset)) for idx, offset in adi[4]],
            [(idx, hex(offset)) for idx, offset in adi[5]],
            [(idx, hex(offset)) for idx, offset in adi[6]],
        ]

        return pretty_annotations_directory_item

    def get_annotation_set_item(self, offset):
        self.mmap.seek(offset)
        asi = self._annotation_set_item_parser()
        self.mmap.seek(0)

        pretty_annotation_set_item = [
            asi[0],
            [hex(off) for off in asi[1]]
        ]
        return pretty_annotation_set_item

    @property
    def annotations_directory_list(self):
        """
        메모리를 어느정도나 먹을지...
        :return: [ annotations_directory_items ]
        """
        # 0. maplist에서 annotation directory 정보 찾기
        ad = None # map_list의 annotations_directory 정보
        for x in self.dex._map_list:
            if x[0] == 0x2006 :
                ad = x
                break
        if ad == None:
            return []

        # 1. mmap 초기화
        origin_position = self.mmap.tell()
        self.mmap.seek(ad[2])

        # 2. 순회
        adl = []
        for i in range(ad[1]):
            item = self._annotations_directory_parser()
            adl.append(item)

        # 3. mmap 초기화
        self.mmap.seek(origin_position)

        return adl


    @property
    def annotation_set_item_list(self):
        """
        메모리를 어느정도나 먹을지...
        :return: [ annotations_directory_items ]
        """
        # 0. maplist에서 annotation directory 정보 찾기
        annotation_set = None
        for x in self.dex._map_list:
            if x[0] == 0x1003 :
                annotation_set = x
                break

        if annotation_set == None:
            return []

        # 1. mmap 초기화
        origin_position = self.mmap.tell()
        self.mmap.seek(annotation_set[2])

        # 2. 순회
        asi = []
        for i in range(annotation_set[1]):
            item = self._annotation_set_item_parser()
            asi.append(item)

        # 3. mmap 초기화
        self.mmap.seek(origin_position)

        return asi

    @property
    def annotation_set_ref_list(self):
        """
        메모리를 어느정도나 먹을지...
        :return: [ annotations_directory_items ]
        """
        # 0. maplist에서 annotation directory 정보 찾기
        asr= None
        for x in self.dex._map_list:
            if x[0] == 0x1002 :
                asr = x
                break

        if asr == None:
            return []

        # 1. mmap 초기화
        origin_position = self.mmap.tell()
        self.mmap.seek(asr[2])

        # 2. 순회
        arl = []
        for i in range(asr[1]):
            item = self._annotation_set_ref_list_parser()
            arl.append(item)

        # 3. mmap 초기화
        self.mmap.seek(origin_position)

        return arl
