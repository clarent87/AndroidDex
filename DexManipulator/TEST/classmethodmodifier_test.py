# -*- coding: utf-8 -*-
import unittest
from dexmodifier import *


class ClassMethodModifierTest(unittest.TestCase):
    dex_file_name = "classes.dex"
    cm = None

    @classmethod
    def setUpClass(cls):
        ClassMethodModifierTest.cm = classmethodmodifer.DexModifier(ClassMethodModifierTest.dex_file_name)

    def test01_insert_string(self):
        data_string = ("FFFF03" + "56" + "4c" * 65534 + "00" + "00").decode('hex')
        self.cm._calculate_total_inst_bytes()
        self.cm._insert_string(data_string)

    def test02_search_type(self):
        print self.cm._search_type('V')
        print self.cm._search_type('java/lang/String')
        print self.cm._search_type('I')

    def test03_insert_type_list(self):
        string_type_idx = self.cm._search_type('java/lang/String')
        data_string = "\xFF\xFF" + classmethodmodifer.pH(string_type_idx)*0xFFFF
        print self.cm._insert_type_list(data_string)

    def test04_insert_proto_ids(self):
        first_proto_data = self.cm.origin_dexparser._proto_ids[1]
        shorty_idx = first_proto_data[0]
        return_type_ids = first_proto_data[1]
        parameter_off = first_proto_data[2]
        print self.cm._insert_proto_ids(shorty_idx, return_type_ids, parameter_off)

    def test05_search_method_idx(self):
        print self.cm._search_method_idx("com/example/clarent/myapplication/Test","testMethod")
        print self.cm._search_method_idx("com/example/clarent/myapplication/Test","testMethod2")

    def test06_modify_method_ids(self):
        """
        15번이 testMethod이고 proto idx가 0 번 V V 이다.
        이걸 proto_idx 4로 바꿔어서 LL / Ljava/lang/StringBuilder/ Ljava/lang/StringBuilder 로 만드는 테스트.
        :return:
        """
        self.cm._modify_method_ids(15, 4)


    def test07_method_ids_modifier(self):
        """
        test가 _modify_method_ids에서 같이 된다.
        :return:
        """
        pass

    def test08_modify_direct_method_code_itemm(self):
        self.cm._modify_direct_method_code_item("com/example/clarent/myapplication/Test","testprivate")

    def test09_get_modified_dex(self):
        self.cm.get_modified_dex()

    def test10_get_modified_dex2(self):
        self.cm.get_modified_dex2()

    def test11_search_code_item_offset(self):
        print self.cm._search_code_item_offset('a','b')

    def test12__modify_instruction(self):
        offset  = self.cm._search_code_item_offset('a','b')
        self.cm._modify_instruction(offset)

    # @unittest.skip("demonstrating skipping")
    def test00_combination_test(self):
        # string 추가 ( Shorty_idx => return + param 56, VL~ 00 은 align  00 은 문자열 끗)
        # data_string = ("FFFF03" + "56" + "4c" * 65534 + "00" + "00").decode('hex')
        # data_string = ("02564900").decode('hex')
        # shorty_idx = self.cm._insert_string(data_string)
        shorty_idx = 36

        # type list추가 ( )
        # string_type_idx = self.cm._search_type('java/lang/String')
        # data_string = "\xFF\xFF\x00\x00" + classmethodmodifer.pH(string_type_idx) * 0xFFFF  # 이거 틀린거 같다.. size 가 4byte가 아니네..
        string_type_idx = self.cm._search_type('I')
        data_string = "\x01\x00\x00\x00" + classmethodmodifer.pH(string_type_idx)
        parameter_off =  self.cm._insert_type_list(data_string)

        # return type 탐색
        return_type_ids = self.cm._search_type('V')

        # proto_id 추가 .
        # proto_idx = self.cm._insert_proto_ids(shorty_idx, return_type_ids, parameter_off)
        proto_idx=2

        # method_id 탐색
        method_idx  = self.cm._search_method_idx("a","a")

        # method_id 수정
        self.cm._modify_method_ids(method_idx, proto_idx)
        # code_item 수정.
        # self.cm._modify_direct_method_code_item("a", "a")

        # sha~ 맞추기.
        self.cm._set_sha_one()
        self.cm._set_adler_checksum()


if __name__ == '__main__':
    unittest.main()

