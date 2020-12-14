# -*- coding: utf-8 -*-

import mmap
import struct
from dexutil import *
from dexparser import *

pL = lambda x: struct.pack("<L", x)


class DexModifier(object):
    """
    annotation section 및 type list section이 code_item 위에 있을 수 있어서,
    섹션이 code_item 밑인지 위인지 판단하는 logic 필요.

    pseudo instruction 을 앞 또는 뒤에 넣는 모듈이었던것으로 추정..
    """

    # 삽입할 instruction에 대한 정보 
    class Instruction(object): 
        def __init__(self, bytcode , isend = False):
            """
            :param bytcode: String Type (ex: "00030000BCCF13ED" )
            :param isend: 마지막 위치에 넣을지 결정
            """
            self.fill_array_data_payload = bytcode
            self.INSTRUCTION_BYTES = len(bytcode)/2
            self.INSTRUCTION_SIZE = self.INSTRUCTION_BYTES/2
            self.isEnd = isend

    def __init__(self, filepath):
        if isinstance(filepath, file):
            f = filepath
        else:
            f = open(self._copy_file_for_modifer(filepath), 'r+b')  # file 복사
        f.flush()
        self.mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
        self.origin_dexparser = dexparser.DexParser(self.mmap)
        self.cdp = dexparser.ClassDataParser(self.mmap, self.origin_dexparser)
        self.atp = dexparser.AnnotationParser(self.mmap, self.origin_dexparser)
        self.origin_size = self.mmap.size()
        self.additional_instruction = self.Instruction("00030000BCCF13ED", True) # 이게 슈도 인스트럭션 뒤에 넣는거 같음..
        # self.additional_instruction = self.Instruction("0000"+"2805"+"0003020004000000", False) # 이건 junkcode 인젝션 앞에 하는 스타일..
        # self.additional_instruction = self.Instruction("0000"+"2801", False) ; 아 goto test 였던거 같다...

    # __del__ 넣어 줘야 할까?


    @staticmethod
    def _uleb128(m):
        """
        offset을 받지 않고 현재 mmap position 기준으로 parsing한뒤
        mmap 의 position을 변경한다.
        :param mmap:
        :return:
        """
        value, size = iteminterpreter.uleb128_value(m, m.tell())  # 현재 위치 기준 parsing
        m.seek(size, 1)  # 현재위치에서 위치 변경

        return value

    @staticmethod
    def _uleb128_write(m, value):
        ulebdata, size = iteminterpreter.uleb128_encode(value)
        m.write(ulebdata)

    def _copy_file_for_modifer(self, filepath):
        """
        ( TEST API )
        원본에서 복사본을 생성하여 복사본으로 작업하기 위함
        향후 원본을 backup하는 api 로 수정 요망
        """
        import shutil
        new_file_name = filepath.split('.')[0] + "_copy.dex"
        shutil.copy(filepath, new_file_name)
        return new_file_name

    def _make_class_offset_repo_for_modifier(self):
        """
        code_item으로 가는 offset을 저장하기 위한 api
        code_item_collection = [

            [ [direct_methods_code_off],[virtual_methods_code_off] ]
            [ [direct_methods_code_off],[virtual_methods_code_off] ]
            [ [direct_methods_code_off],[virtual_methods_code_off] ]
            [ [direct_methods_code_off],[virtual_methods_code_off] ]
            ....
        ]
        """
        code_item_collection = []
        for class_defs in self.origin_dexparser._class_defs:
            code_item_collection.append(self.cdp.get_class_data_item(class_defs[6]))
        self.code_item_collection = code_item_collection
        return code_item_collection

    def _find_selected_classes_index(self, class_name):
        """
        주어진 class_name에 처음으로 매칭되는 class의 index list를 생성
        (!) 추측컨데, class_name에 매칭되는 class는 순차적일 것이다. (directory 경로라면.. )
        """
        selected_classes_index = []
        for index, cdi in enumerate(self.origin_dexparser._class_defs):
            if cdi[8].find(class_name) > 0:
                selected_classes_index.append(index)
        self.selected_classes_index = selected_classes_index
        return self.selected_classes_index

    def _calculate_total_inst_bytes(self):
        """
        최종적으로 추가되는 byte가 몇인지 카운드
        해당 값으로 나머지 모든 값을 update
        """
        count = 0
        for x in [self.code_item_collection[x] for x in self.selected_classes_index]:

            dmc = len( [ i for i in x[0] if i != 0])
            vmc = len( [ i for i in x[1] if i != 0])
            count += dmc + vmc

        self.total_inserted_bytes = count * self.additional_instruction.INSTRUCTION_BYTES  # 일단 fill-array 명령어가 8바이트라 * 8 함.
        return self.total_inserted_bytes

    def _new_update_class_offset_repo(self):
        """
        self.counter는 아래 형태 ..
        [
            [offset, count]
            [offset, count]
        ]
        :return:
        """
        # 1. step. counting ( 삽입 정렬 느낌 )
        # (!) 주의 offset은 같은게 없을 것이라는 가정하에 작성. !
        self.counter = []
        for cdi in [self.code_item_collection[x] for x in self.selected_classes_index]:  # [ [dm] [vm] ]
            for dm_offset in cdi[0]:
                if dm_offset == 0: # abstract 나 native인경우. offset이 없다.
                    break
                # 초기값. ( counter에 아무 값도 없을것을 대비 )
                idx = 0
                count = 0

                # 들어갈 위치 파악
                for idx, offset, count in [ (index,item[0], item[1] ) for index, item in enumerate(self.counter) ]:  # counter에 있는 offset들과 비교
                    if dm_offset < offset:
                        break
                else: # 현재 offset이 가장 클때.
                    idx +=1
                    count +=1

                # 삽입
                self.counter.insert(idx,[dm_offset,count])

                # 남은것들 counter 재 계산
                for x in self.counter[idx+1:]:
                    x[1] += 1


            for vm_offset in cdi[1]:
                if vm_offset == 0:  # abstract 나 native인경우. offset이 없다.
                    break
                # 초기값. ( counter에 아무 값도 없을것을 대비 )
                idx = 0
                count = 1

                # 들어갈 위치 파악
                for idx, offset, count in [ (index,item[0], item[1] ) for index, item in enumerate(self.counter) ]:  # counter에 있는 offset들과 비교
                    if vm_offset < offset:
                        break
                else: # 현재 offset이 가장 클때.
                    idx +=1
                    count +=1

                # 삽입
                self.counter.insert(idx,[vm_offset,count])

                # 남은것들 counter 재계산
                for x in self.counter[idx+1:]:
                    x[1] += 1

        # 2. upadate ( 전체 item_collection 순회하면서 counter랑 비교해서 증가 시켜주어야 한다. )
        for cdi in self.code_item_collection:
            for index, dm_offset in enumerate(cdi[0]):
                for offset, count in self.counter:
                    if dm_offset <= offset:
                        break
                else:
                    count += 1
                cdi[0][index] = dm_offset + (count - 1) * self.additional_instruction.INSTRUCTION_BYTES

            for index, vm_offset in enumerate(cdi[1]):
                for offset, count in self.counter:
                    if vm_offset <= offset:
                        break
                else:
                    count +=1
                cdi[1][index] = vm_offset + (count - 1) * self.additional_instruction.INSTRUCTION_BYTES

        return self.code_item_collection


    def _update_class_offset_repo(self):
        """
        ( main )
        code_item 찾아가는 offset을 upate한다.
        """
        # cod_item off_set 순차적으로 밀리는 부분
        # 순차적이라는 가정이어서 아래와 같이 구현, 만약 중간중간 비게 되는경우,, 해당하는 item의 offset도 증가시켜주어야 함.
        inc = 0
        for cdi in [self.code_item_collection[x] for x in self.selected_classes_index]:
            for index, dm_offset in enumerate(cdi[0]):
                cdi[0][index] = dm_offset + inc
                inc += self.additional_instruction.INSTRUCTION_BYTES

            for index, vm_offset in enumerate(cdi[1]):
                cdi[1][index] = vm_offset + inc
                inc += self.additional_instruction.INSTRUCTION_BYTES

        # 나머지 off_set 한번에 미는 부분.
        for cdi in self.code_item_collection[self.selected_classes_index[-1] + 1:]:
            for index, dm_offset in enumerate(cdi[0]):
                cdi[0][index] = dm_offset + inc

            for index, vm_offset in enumerate(cdi[1]):
                cdi[1][index] = vm_offset + inc

        return self.code_item_collection

    def _insert_sudo_instruction(self, offset):
        """
        ( main )
        일단 offset 하나에 대해서만 진행한다. ( 나중에 loop 도는 함수 따로 작성 ) code_item offset
        offset은 codeitem offset
        => 0 ) 선택한 class list index를 기준으로..
        => 1 ) codeitem parsing
        => 2 ) mmap에 inst 갯수 증가 및 쓰기 ( 이때 mmap size 변경도 8 byte씩 진행 )

        mmap move로 위치도 옮겨야 함.
        * Debug_info_off 수정하는 것은 안한듯.
        """
        # step 1 ( parse a code_item )
        ci = self.cdp.get_code_item(offset)

        # step 2 ( make blank for sudo_instruction)
        self.mmap.resize(self.mmap.size() + self.additional_instruction.INSTRUCTION_BYTES)

        # step 3 ( insert sudo_instruction )
        if self.additional_instruction.isEnd :
            self.mmap.move( ci[6] + self.additional_instruction.INSTRUCTION_BYTES, ci[6], self.mmap.size() - self.additional_instruction.INSTRUCTION_BYTES - ci[6])
            self.mmap[ci[6]: ci[6] + self.additional_instruction.INSTRUCTION_BYTES] = self.additional_instruction.fill_array_data_payload.decode("hex")
        else :
            first_location = ci[6] - ci[5]*2
            self.mmap.move( first_location + self.additional_instruction.INSTRUCTION_BYTES, first_location ,  self.mmap.size() - self.additional_instruction.INSTRUCTION_BYTES - first_location )
            self.mmap[first_location: first_location + self.additional_instruction.INSTRUCTION_BYTES] = self.additional_instruction.fill_array_data_payload.decode("hex")

        # step 4 ( modify inst_size )
        self.mmap[offset + 12: offset + 16] = struct.pack("<L", ci[5] + self.additional_instruction.INSTRUCTION_SIZE)

        # TODO setp 5 ( optional modify try ) ==> 이건 맨 앞에 바이트 코드 넣을 때만일듯.....( 마지막에 추가할때는 이거 타지 않도록 수정 필요._!!!!!!!!!)
        if ci[3] > 0 and self.additional_instruction.isEnd: # try_size > 0
            if ci[7] is True : # padding
                self.mmap[ci[6]+2: ci[6] + 6] = struct.pack("<L", ci[8] + self.additional_instruction.INSTRUCTION_SIZE)  # start_address
            else:
                self.mmap[ci[6]: ci[6]+4] = struct.pack("<L", ci[8] + self.additional_instruction.INSTRUCTION_SIZE)  # start_address

    def get_obfuscated_dex(self, classpath=None):
        """
        위 함수들 전부다 쓰고, insert_instruction loop 돌고.. 한다.
        아래 수정도 다하고..
        :param classname: 난독화할 class 경로..
        :return:
        """

        # step 1 : code item offset 만 전부 모은다.
        self._make_class_offset_repo_for_modifier()

        # step 2 : 원하는 class가 있는 class_def의 index를 모은다.
        self._find_selected_classes_index(classpath)

        # step 3 : 최종적으로 추가될 byte를 계산한다. ( header 및 나머지 수정에 쓰임  self.total_inserted_bytes )
        self._calculate_total_inst_bytes()

        # step 4 : 추가될 byte에 따라서 변경되는 code item offset을 미리 계산해서 준비 한다.
        self._new_update_class_offset_repo()

        # step 5 : 순회 하면서 instruction 추가 ( 이때 선택한 class index는 순차적일것으로 추정 )
        # for cdi in [self.code_item_collection[x] for x in self.selected_classes_index]:
        #     for dm_offset in cdi[0]:
        #         self._insert_sudo_instruction(dm_offset)
        #
        #     for vm_offset in cdi[1]:
        #         self._insert_sudo_instruction(vm_offset)

        # step 5 : self.counter의 offset count를 기준으로 insert 진행함.
        for offset, count in self.counter:
            current_offset = offset + (count-1)*self.additional_instruction.INSTRUCTION_BYTES
            self._insert_sudo_instruction(current_offset)

        # step 6 : header 수정
        self._header_modifier()
        # step 7 : map list 수정
        self._map_list_modifier()
        # step 8 : string ids 수정 ( 경우에 따라서.. )
        self._string_ids_modifier()
        # step 9 : proto ids 수정
        self._proto_ids_modifier()
        # step 10 : class_def 수정
        self._class_defs_modifier()
        # step 11 : annotation 수정 ( 경우에 따라서.. )
        self._annotation_modifier()
        # step 12 : class_data_item 수정 ( for 문 돌아야 함 )
        for idx, class_data_off in enumerate( [ x[6] for x in self.origin_dexparser._class_defs ] ):
            if class_data_off == 0:
                continue
            self.mmap.seek(class_data_off)
            self._class_data_item_modifier(self.code_item_collection[idx])
            self.mmap.seek(0)
        # step 13 : sha-1 계산
        self._set_sha_one()
        # step 14 : checksum 계산
        self._set_adler_checksum()

    # modifier
    def _header_modifier(self):
        """
        수정 사항 : map_offset, file_size / origin_dexparser의 내용도 수정한다.
        비고 : link는 일단 고려하지 않음. checksum, signature는 따로 함수로 뺀다.
        """
        self.origin_dexparser._header['file_size'] += self.total_inserted_bytes
        self.origin_dexparser._header['map_off'] += self.total_inserted_bytes
        self.origin_dexparser._header['data_size'] += self.total_inserted_bytes

        self.mmap[0x20:0x24] = pL(self.origin_dexparser._header['file_size'])
        self.mmap[0x34:0x38] = pL(self.origin_dexparser._header['map_off'])

        # data size도 수정 진행 필요 ( code_item은 무조건 data_size안에 있다. )
        self.mmap[0x68:0x6c] = pL(self.origin_dexparser._header['data_size'])

    def _map_list_modifier(self):
        """
        반드시 header부터 수정되어야 한다.
        :return:
        """
        m = self.mmap
        m.seek(self.origin_dexparser._header['map_off'])

        map_list_size = dexparser.uL(m.read(4))

        for i in range(map_list_size):
            type = dexparser.uH(m.read(2))
            m.read(2)  # unused field
            m.read(4)  # size

            if type >= 0x1000 and type != 0x2001:
                self.origin_dexparser._map_list[i][2] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._map_list[i][2]))
            else:
                m.read(4)  # offset

        m.seek(0)

    def _string_ids_modifier(self):
        m = self.mmap

        string_ids_size = self.origin_dexparser._header['string_ids_size']
        m.seek(self.origin_dexparser._header['string_ids_off'])

        for i in range(string_ids_size):
            self.origin_dexparser._string_ids[i][0] += self.total_inserted_bytes
            m.write(pL(self.origin_dexparser._string_ids[i][0]))
        m.seek(0)

    def _proto_ids_modifier(self):
        m = self.mmap
        m.seek(self.origin_dexparser._header['proto_ids_off'])
        proto_ids_size = self.origin_dexparser._header['proto_ids_size']

        for i in range(proto_ids_size):
            m.read(4)  # shorty_idx
            m.read(4)  # return_type_idx

            # offset
            if self.origin_dexparser._proto_ids[i][2] != 0:
                self.origin_dexparser._proto_ids[i][2] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._proto_ids[i][2]))
            else:
                m.read(4)
        m.seek(0)

    def _class_defs_modifier(self):
        m = self.mmap
        m.seek(self.origin_dexparser._header['class_defs_off'])
        class_defs_size = self.origin_dexparser._header['class_defs_size']

        for i in range(class_defs_size):
            m.read(12)
            # m.read(4)  # class_idx
            # if i  in  self.selected_classes_index: # 선택한 클래스 이면
            #     m.write( pL( self.origin_dexparser._class_defs[i][1] | 0x10000 ) )  # access_flags / 수정
            # else:
            #     m.read(4)  # access_flags
            # m.read(4)  # superclass_idx

            # interfaces_off
            if self.origin_dexparser._class_defs[i][3] != 0:
                self.origin_dexparser._class_defs[i][3] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][3]))
            else:
                m.read(4)

            # source_file_idx
            m.read(4)

            # annotations_off
            if self.origin_dexparser._class_defs[i][5] != 0:
                self.origin_dexparser._class_defs[i][5] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][5]))
            else:
                m.read(4)

            # class_data_off
            if self.origin_dexparser._class_defs[i][6] != 0:
                self.origin_dexparser._class_defs[i][6] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][6]))
            else:
                m.read(4)

            # static_values_off
            if self.origin_dexparser._class_defs[i][7] != 0:
                self.origin_dexparser._class_defs[i][7] += self.total_inserted_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][7]))
            else:
                m.read(4)

        m.seek(0)

    def _annotation_modifier(self):
        """
        annotations_directory_item / annotation_set_item / annotation_set_ref_list
        중요!) 일단 code 영역의 밀린 byte를 저장하고 해당 byte를 기반해서 작업해야 한다..
        중요!) file_size를 늘려야 하기 때문에 전처리를 통해서 몇바이트가 더 필요한지 파악해야 한다.
        :return:
        """
        # map_list에서 정보를 받아 온다.  ( type, size, offset )
        adi = None  # annotations_directory_item / 초기는 그냥 빈 list로 둔다. 일부러..
        asi = None  # annotation_set_item
        arl = None  # annotation_set_ref_list
        for x in self.origin_dexparser._map_list:
            if x[0] == 0x2006:
                adi = x
            elif x[0] == 0x1003:
                asi = x
            elif x[0] == 0x1002:
                arl = x

        # 1. annotations_directory_item
        if adi is not None:
            self.mmap.seek(adi[2])
            origin_adi_data = self.atp.annotations_directory_list
            for i in range(adi[1]):
                self._annotations_directory_modifier(origin_adi_data[i])
            self.mmap.seek(0)

        # 2. annotation_set_item
        if asi is not None:
            self.mmap.seek(asi[2])
            original_asi_data = self.atp.annotation_set_item_list
            for i in range(asi[1]):
                self._annotations_set_item_modifier(original_asi_data[i])
            self.mmap.seek(0)

        # 3. annotation_set_ref_list
        if arl is not None :
            self.mmap.seek(arl[2])
            original_arl_data = self.atp.annotation_set_ref_list
            for i in range(arl[1]):
                self._annotations_set_item_modifier(original_arl_data[i])
            self.mmap.seek(0)

    def _annotations_directory_modifier(self, original_data):
        """
        item 한개에 대해서만 작업하는 형태.
        mmap의 현재 위치 기준으로 작업을 진행한다. 즉 상위에서 mmap 위치 수정을 해주어야 함.
        original_data : annotaion_directory_item 한개
        """
        m = self.mmap

        m.write(pL(original_data[0] + self.total_inserted_bytes))  # class_annotation_off
        m.read(12)  # field_size / annotated_methods_size / annotated_parameters_size

        for i in range(original_data[1]):
            m.read(4)  # field_idx
            m.write(pL(original_data[4][i][1] + self.total_inserted_bytes))
        for i in range(original_data[2]):
            m.read(4)  # method_idx
            m.write(pL(original_data[5][i][1] + self.total_inserted_bytes))
        for i in range(original_data[3]):
            m.read(4)  # method_idx
            m.write(pL(original_data[6][i][1] + self.total_inserted_bytes))

    def _annotations_set_item_modifier(self, original_data):
        m = self.mmap

        m.read(4) # size

        for i in range(original_data[0]):
            m.write( pL(original_data[1][i] + self.total_inserted_bytes))

    def _annotations_set_ref_modifier(self, original_data):
        m = self.mmap

        m.read(4) # size

        for i in range(original_data[0]):
            m.write( pL(original_data[1][i] + self.total_inserted_bytes))

    def _class_data_item_modifier(self, code_item_offsets):
        """
        code_item_offsets = [ [direct_methods][virtual_methods]  ]
        mmap 위치를 현재 위치 기준으로 진행.
        encoded_mothod 항목을 전부 순회하면서 수정해 주어야 한다.
        :return:
        """

        m = self.mmap
        static_fields_size = self._uleb128(m) # static_fields_size
        instance_fields_size =self._uleb128(m) # instance_fields_size
        direct_methods_size = self._uleb128(m) # direct_methods_size
        virtual_methods_size = self._uleb128(m) # virtual_methods_size

        # static_fields ( skip )
        for x in range(static_fields_size):
            self._uleb128(m) # field_idx_diff
            self._uleb128(m) # access_flags

        # instance_fields ( skip )
        for x in range(instance_fields_size):
            self._uleb128(m) # field_idx_diff
            self._uleb128(m) # access_flags

        # direct_methods
        for i in range(direct_methods_size):
            self._uleb128(m) # method_idx_diff
            self._uleb128(m) # access_flags
            self._uleb128_write(m, code_item_offsets[0][i]) # code_off

        # virtual_methods
        for i in range(virtual_methods_size):
            self._uleb128(m) # method_idx_diff
            self._uleb128(m) # access_flags
            self._uleb128_write(m, code_item_offsets[1][i])  # code_off

    # set sha & adler
    def _set_sha_one(self):
        import hashlib
        signature = hashlib.sha1(self.mmap[32:]).digest()
        self.mmap[12:32]  = signature

    def _set_adler_checksum(self):
        import zlib
        adler = zlib.adler32(self.mmap[12:])
        if adler < 0:
            checksum = struct.pack('<l', adler)
        else :
            checksum = pL(adler )
        self.mmap[8:12] = checksum
