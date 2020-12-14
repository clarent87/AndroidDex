import unittest
from dexmodifier import *


class DexModifierTest(unittest.TestCase):
    dex_file_name = "classes.dex"
    dxm = None

    @classmethod
    def setUpClass(cls):
        DexModifierTest.dxm = dexmodifier.DexModifier(DexModifierTest.dex_file_name)

    @unittest.skip("demonstrating skipping")
    def test01_make_class_offset_repo_for_modifier(self):
        for x in self.dxm._make_class_offset_repo_for_modifier():
            print x

    @unittest.skip("demonstrating skipping")
    def test02_find_selected_classes_index(self):
        print  self.dxm._find_selected_classes_index("Test") # MainActivity

    @unittest.skip("demonstrating skipping")
    def test03_calculate_total_inst_bytes(self):
        print self.dxm._calculate_total_inst_bytes()

    @unittest.skip("demonstrating skipping")
    def test04_new_update_class_offset_repo(self):
        for x in self.dxm._new_update_class_offset_repo():
            print x
        print "----------counter--------------------"
        print self.dxm.counter


    @unittest.skip("demonstrating skipping")
    def test05_insert_sudo_instruction(self):
        for offset, count in self.dxm.counter:
            current_offset = offset + (count-1)*self.dxm.INSTRUCTION_BYTES
            self.dxm._insert_sudo_instruction(current_offset)

    @unittest.skip("demonstrating skipping")
    def test06_header_modifier(self):
        print "----------------------origin(header)-----------------------"
        for k, v in self.dxm.origin_dexparser.header_info.items():
            print "{ " + k + " : " + v + " }"

        print "----------------------modified(header)---------------------"
        self.dxm._header_modifier()
        for k, v in self.dxm.origin_dexparser.header_info.items():
            print "{ " + k + " : " + v + " }"

    @unittest.skip("demonstrating skipping")
    def test07_map_list_modifier(self):
        print "----------------------orgin(maplist)-----------------------"
        for x in self.dxm.origin_dexparser.map_list_info:
            print x

        print "----------------------modified(maplist)---------------------"
        self.dxm._map_list_modifier()
        for x in self.dxm.origin_dexparser.map_list_info:
            print x

    @unittest.skip("demonstrating skipping")
    def test08_string_ids_modifier(self):
        print "----------------------string ids---------------------"
        print self.dxm.origin_dexparser.string_ids_info
        self.dxm._string_ids_modifier()
        print self.dxm.origin_dexparser.string_ids_info

    @unittest.skip("demonstrating skipping")
    def test09_proto_ids_modifier(self):
        print "----------------------proto ids---------------------"
        print self.dxm.origin_dexparser.proto_ids_info
        self.dxm._proto_ids_modifier()
        print self.dxm.origin_dexparser.proto_ids_info

    @unittest.skip("demonstrating skipping")
    def test10_class_defs_modifier(self):
        # print "----------------------class defs(origin)---------------------"
        # for k in self.dxm.origin_dexparser.class_defs_info:
        #     print k
        self.dxm._class_defs_modifier()
        print "----------------------class defs(modified)---------------------"
        for k in self.dxm.origin_dexparser.class_defs_info:
            print k

    @unittest.skip("demonstrating skipping")
    def test11_annotation_modifier(self):
        print "---------------------------annotation(origin)---------------------"
        for x in self.dxm.atp.annotations_directory_list:
            print x
        for x in self.dxm.atp.annotation_set_item_list:
            print x
        for x in self.dxm.atp.annotation_set_ref_list:
            print x

        self.dxm._annotation_modifier()

        print "---------------------------annotation(modified)---------------------"
        for x in self.dxm.atp.annotations_directory_list:
            print x
        for x in self.dxm.atp.annotation_set_item_list:
            print x
        for x in self.dxm.atp.annotation_set_ref_list:
            print x

    @unittest.skip("demonstrating skipping")
    def test12_class_data_item_modifier(self):
        for idx, class_data_off in enumerate( [ x[6] for x in self.dxm.origin_dexparser._class_defs ] ):
            if class_data_off == 0:
                continue
            self.dxm.mmap.seek(class_data_off)
            self.dxm._class_data_item_modifier(self.dxm.code_item_collection[idx])
            self.dxm.mmap.seek(0)



    # @unittest.skip("demonstrating skipping")
    def test00_get_obfuscated_dex(self):
        self.dxm.get_obfuscated_dex('TargetClass')


if __name__ == '__main__':
    unittest.main()
