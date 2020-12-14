# -*- coding: utf-8 -*-

import mmap
import struct
from dexutil import *
from dexparser import *

pL = lambda x: struct.pack("<L", x)
pH = lambda x: struct.pack("<H", x)

class DexModifier(object):
    """
    annotation section 및 type list section이 code_item 위에 있을 수 있어서,
    섹션이 code_item 밑인지 위인지 판단하는 logic 필요.

    전반적으로 api 수정좀 진행해야 할듯.. 객체에 파라메터 달알서 쓰니까 코드 수정이나.. 여러모로 보기 힘드네..
    """

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
        new_file_name = filepath.split('.')[0] + "_cm_copy.dex"
        shutil.copy(filepath, new_file_name)
        return new_file_name

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

    def _insert_string(self, data_string, string_idx):
        """
        data_string = "FFFF03"+"56"+"4c"*65534 +"00"+"00".decode('hex')
        :param data_string:  byte 형태로 넣어주어야 한다.
        :parma string_idx : 해당하는 string_idx의 offset 값을 넣은 스트링의 offset으로수정해 준다.
        :return: None
        """
        # step 1 : string offset 찾기.
        for x in  self.origin_dexparser._map_list: # map list 정렬해서 파악해도 될거 같은데.. ( 일단은 이렇게.. )
            if x[0] == 0x2004:
                offset = x[2] # dec

        # step 2 : string 입력 ( 이건 insert byte 이용하면 될듯.. )
        self._insert_data(offset, data_string)

        # step 3 : string_idx offset 수정.( 4byte 단위였으니까.. type_ids있는 곳에다가 넣으면 될듯. )
        string_id_start_offset = self.origin_dexparser._header['string_ids_off']
        self.mmap[ string_id_start_offset + string_idx * 4 : string_id_start_offset + string_idx * 4 + 4] = pL(offset)
        self.origin_dexparser._string_ids[string_idx] = offset

        # step 4 : header 수정
        header_modify = {
            'file_size' : len(data_string),
            'map_off':len(data_string),
            'data_size': len(data_string),
        }
        self._header_modifier(header_modify)

        # step 5 : map list 수정 ( string data 변경 필요 할듯.. )
        chaged_maplist = [
            [0x2002, 1, len(data_string)]
        ]
        self._map_list_modifier(chaged_maplist)


        # step 8 : class_def 수정 ( 다 밀렸으니까.. offset들..) ( 일단 type_list 아래쪽이 string이로 보고 있으므로..
        self._class_defs_modifier( len(data_string) )

        # step 9 : annotation 수정 ( 경우에 따라서.. )
        self.total_inserted_bytes = len(data_string)  # string 만.
        self._annotation_modifier()

        # step 10 : class_data_item 수정 ( for 문 돌아야 함 ) ( 다 밀렸으니까.. offset들.. ) ( string 이 code 아래라서 추가 필요 없음 )


    def _insert_proto_ids(self, shorty_idx, return_type_ids,  parameter_off):
        """
        shorty_idx : 마지막에 추가한 string_ids 섹션 인덱스
        return type : void 타입 찾아야 함.( type_idx )
        Parameter_off : type_list offset
        :return: proto_idx

        1) ids 추가 후 ..
        2) 아래 다 밀리니까 4byte.씩 -> string_ids 처럼 진행하면 될거 같긴하다..
        """
        # step 1 : field_ids 시작 위치에 넣는다.  총 12bytes / 4byte-align도 되네.. ( proto 뒤에 field가 옮을 전제로.. )
        proto_id_item =  pL(shorty_idx)+pL(return_type_ids)+pL(parameter_off)
        self._insert_data(self.origin_dexparser._header['field_ids_off'],proto_id_item)
        self.origin_dexparser._proto_ids.append([shorty_idx,return_type_ids,parameter_off])

        # step 2 : header 수정
        header_modify = {
            'file_size': 12,
            'map_off': 12,
            'proto_ids_size':1,
            'field_ids_off': 12,
            'method_ids_off': 12,
            'class_defs_off': 12,
            'data_off': 12
        }
        self._header_modifier(header_modify)

        # step 3 : map list 수정 ( string data 변경 필요 할듯.. )
        chaged_maplist = [
            [0x0003, 1, 12],
        ]
        self._map_list_modifier(chaged_maplist)

        # step 4 : string ids 수정 ( 필수.. proto ids 추가되는 바람에 string_Data 다밀림.. )
        self._string_ids_modifier(12)

        # step 5 : proto ids 수정
        self._proto_ids_modifier(12)

        # step 6 : class_def 수정
        self._class_defs_modifier(12, Interface_offset=12)

        # step 7 : annotation 수정
        self.total_inserted_bytes = 12
        self._annotation_modifier()

        # step 8 : class_data_item 수정
        for idx, class_data_off in enumerate([x[6] for x in self.origin_dexparser._class_defs]):
            if class_data_off == 0:
                continue
            self.mmap.seek(class_data_off)
            self._class_data_item_modifier(self.cdp.get_class_data_item(class_data_off),  12)
            self.mmap.seek(0)

        return len(self.origin_dexparser._proto_ids) - 1  # proto_idx 전달.

    def _insert_type_list(self, byte_sequence):
        """
        :param byte_sequence: 어떤 byte를 넣을것인지는 위에서 전달해야 한다.  ( 4byte align )
        :return: 추가한 type list의  offset ( 이거 수정되지 않나?? ) proto를 먼저 만들고  작업해야 할듯 하다. => 이건 proto에서 작업해야 하는것.. 여기서 추가한 offset이 밀리지는 않는다.. 이단계 에서는..
        """

        # step 0 : type list parsing. 다시.. ( string 이후에 하면 list값 업데이트 안되기 때문.. 향후에 따로 구조체 수정하는 로직들 모아서 다시 parsing하는 식으로 진행해야 할듯.. )
        self.origin_dexparser._type_list_parser()
        # step 1 : type list offset 찾기. ( parser 만드는 수밖에.. ) type_list 마지막꺼는 align 필요 없다. 그다음이 string이기 때문에 string은 align없음.
        last_type_list_item = self.origin_dexparser._type_list[-1]
        offset = last_type_list_item[0] + 4+ 2*last_type_list_item[1] # 아이템 추가할 offset.
        padding = 0

        # 마지막 item의 align을 살려준다.
        if last_type_list_item[1] % 2 != 0:
            byte_sequence = '\x00\x00' + byte_sequence
            padding = 2

        # 전체 파일을위해 4byte align을 맞추어 준다.
        remain = len(byte_sequence) % 4
        if remain :
            byte_sequence += '\x00' * (4- remain)

        # step 2 : insert byte.
        self._insert_data(offset, byte_sequence)

        # step 3 : header 수정 ( file size, maplist offset, data size)
        total_len = len(byte_sequence)
        header_modify = {
            'file_size' : total_len,
            'map_off':total_len,
            'data_size': total_len,
        }
        self._header_modifier(header_modify)

        # step 4 : map list 수정
        chaged_maplist = [
            [0x1001, 1, total_len] # type list item 하나 추가 되었으므로..
        ]
        self._map_list_modifier(chaged_maplist)

        # step 5 : string ids 수정 ( 일단 type list가 string ids위에 있어서.. 이렇게 하긴 하지만..  )
        self._string_ids_modifier(total_len)

        # step 6 : class_def 수정 ( 다 밀렸으니까.. offset들..)
        self._class_defs_modifier(total_len)

        # class_data_item 수정 필요 없다. ( code_item위치는 변함 없음 )

        # step 7 : annotation 수정
        self.total_inserted_bytes = total_len
        self._annotation_modifier()

        return offset+padding

    def _search_type(self, needed_type):
        """
        'V'
         'Ljava/lang/String;'

        :param needed_type: string...
        :return: type_idx
        """
        for index, x in enumerate(self.origin_dexparser._type_ids):
            if needed_type in x[1]:
                return index
        return None

    def _insert_data(self, offset, data_expression):
        """
        :param offset: 추가할 위치
        :param data_expression: byte array or bytes
        :return:
        """
        original_size = self.mmap.size()

        # file size 수정
        self.mmap.resize(self.mmap.size() + len(data_expression))

        # offset 부터 공각 확보
        self.mmap.move(offset + len(data_expression), offset, original_size - offset)

        # data 추가 .
        self.mmap[offset: offset+len(data_expression)] = data_expression

    def _modify_method_ids(self, method_idx, proto_idx):
        """
        :param method_idx: 수정할 method_idx
        :param proto_idx: 바꿔칠 proto_idx
        :return:
        """
        # step1 : 구조체에서 method_idx 수정
        self.origin_dexparser._method_ids[method_idx][1] = proto_idx
        # setp2 : 다시 file에 씀.
        self._method_ids_modifier()

    def _method_ids_modifier(self):
        """
        _modify_method_ids에서 말고는 쓸일이 없다.!
        수정된 _method_ids를 그대로 file에 작성해 준다. ( size는 변함이 없을때. )
        :return:
        """
        m = self.mmap
        method_ids_size = self.origin_dexparser._header['method_ids_size']
        m.seek(self.origin_dexparser._header['method_ids_off'])

        for i in range(method_ids_size):
            m.write(pH(self.origin_dexparser._method_ids[i][0]))
            m.write(pH(self.origin_dexparser._method_ids[i][1]))
            m.write(pL(self.origin_dexparser._method_ids[i][2]))
        m.seek(0)

    def _modify_direct_method_code_item(self, class_name, function_name):
        """
        register / ins size 65534 만들어야 함..
        :return:
        """
        # step 1 : class_def에서 class_datat_off 찾기
        for x  in self.origin_dexparser._class_defs:
            if x[8][1:-1] == class_name:
                class_data_offset = x[6]

        # step 2 : Class_data_item parsing
        direct_methods = self.cdp.print_class_data_item(class_data_offset)[6]

        # step 3 : direct_method에서 method_idx를 비교하거나, method_idx parsing후 function 네임 비교
        for x in direct_methods:
            if x[0][2] == function_name:
                code_item_offset = int(x[2],16)

        # step 4 : code_item parsing => 그냥 register_size / ins_size 에  65534 그대로 넣는다.
        self.mmap[code_item_offset: code_item_offset + 2 ] = pH(65534)
        self.mmap[code_item_offset +2: code_item_offset + 4] = pH(65534)

    def get_modified_dex(self, classpath=None):
        """
        [ * ] 현재 동작 안함 ( verifier 때문 )
        method parameter를 VLLL~ 로 변경하는 기법
        : proto_ids item을 생성해서 넣는 형태인데, runtime verifier에서 걸림 ( proto_ids의 ordering 이 필요함 )
        :param classpath:
        :return:
        """
        # step 1 :  shorty_idx 생성 ( string_idx의 경우 string 순서로 정렬이 되야 하는거 같음.. 이경우 string idx 이용하는 거 전부 수정해야 함..
        data_string = ("FFFF03" + "56" + "4c" * 65534 + "00" + "00").decode('hex')
        shorty_idx = self._insert_string(data_string)

        # step 2:  type_list 추가 ( 이건 문제 없음 )
        string_type_idx = self._search_type('java/lang/String')
        data_string = "\xFF\xFF\x00\x00" + pH(string_type_idx) * 0xFFFF
        parameter_off =  self._insert_type_list(data_string)

        # step 3 : return type 찾기
        return_type_ids = self._search_type('V')

        # step 4:  proto_idx 추가 ( 이것도 순서대로 정렬이 되야 함.. string_idx 순 인듯.. )
        proto_idx = self._insert_proto_ids(shorty_idx, return_type_ids, parameter_off)

        # step 5 : method 탐색 and 수정 (TODO : 일단 a,a로 하드 코딩 )
        method_idx  = self._search_method_idx("a","a")
        self._modify_method_ids(method_idx, proto_idx)

        # step 6 : code_item 수정.
        self._modify_direct_method_code_item("a", "a")

        # step 7 : sha~ 맞추기.
        self._set_sha_one()
        self._set_adler_checksum()

    def get_modified_dex2(self,classpath="a",methodname="massiveParameterAttack", classpath2="com/example/jeongbeenpark/golf/IllegalInstruction", methodname2="incorrectInstruntion"):
        """
        method parameter를 VLL~로 만드는 것인데, proto_ids 아이템 추가 없이 작업하는 기법
        ( 대신 android studio에서 임의의 class 및 method 생성시 method의 파라메터 형태를 String ,String , ...  으로 맞춘다 (string param갯수는 다른곳에서 쓰지 않을 정도만 작업 )
        ( 이걸 탐색해서 string_ids의 offset을 수정하는 형태의 작업을 진행함.. string ids도 ordering이 필요한 구조체 이기 때문ㅇ. )

        classpath : class 이름
        methodname : parameter 증가시킬 method이름 ( prototype을 특이하게 구현해둔다. 다른곳에서 중복 사용할수 없게// )
        methodname2 : invoke-super 기법 이용할 메소드
        :return:

        """

        # step 1 : type_list 추가.
        string_type_idx = self._search_type('java/lang/String')
        data_string = "\xFE\xFF\x00\x00" + pH(string_type_idx) * 0xFFFE # !!) FFFF에서 변경하였따.
        parameter_off = self._insert_type_list(data_string)

        # step 2 : method_idx 확인 및 reg 수정. ( class_def에서 찾아갈 필요는 없겠지.. )
        method_idx  = self._search_method_idx(classpath,methodname)


        # step 3 : method_idx 찾기 => shorty_idx 확인 => 변조
        """
        shorty_idx ( string_idx ) 의 값 확인  string offset
        string 추가후
            ==> string table의 맨앞에 VLLLL~~~을 하나 넣는다.. ( 이쪽는 아마 ordering 안되어 있어도 될거 같은데.. ) 
        sting_idx의 offset 변경 
            ==> 추가한 offset으로 변경
            
        * 혹시 ordering문제 생기면 다시 해결해야 한다. 
        * ( 그리고 기존에는 string_id를 만들어서 뒤에 추가하는 형태였는데, ,여기서는 있는것을 변경하는것.. )
        """
        proto_idx = self.origin_dexparser._method_ids[method_idx][1]
        shorty_idx = self.origin_dexparser._proto_ids[proto_idx][0]
        data_string = ("FFFF03" + "56" + "4c" * 65534 + "00" + "00").decode('hex')
        self._insert_string(data_string,shorty_idx)

        # step 4 : 위에서 proto_idx 를 보고 paramoff수정 typelist로..
        """
        method_idx -> proto_idx 찾고 param_off 만 변조 한다. ( 차피.. STring~~~ *N 개 함수를 작성했으니까.. proto는 따로 생성되었을듯.. )
        """
        proto_ids_start_off = self.origin_dexparser._header['proto_ids_off']
        self.mmap[proto_ids_start_off + proto_idx * 12 + 8 : proto_ids_start_off + proto_idx * 12 + 8 + 4] = pL(parameter_off)
        self.origin_dexparser._proto_ids[proto_idx] = parameter_off


        # step 6 : code_item 수정.
        self._modify_direct_method_code_item(classpath,methodname)

        """
        code_off 찾아가서 짜피 instruction 수정 및 size 수정 진행. / 이때 instruction 은 원래 홀수라서 뒤에 00 00의 padding이 붙어 있음 ( try가 없어도.. 4byte align 에 따라. ) 
        """
        self._modify_instruction(self._search_code_item_offset(classpath2,methodname2))

        # step 7 : sha~ 맞추기.
        self._set_sha_one()
        self._set_adler_checksum()

    def _modify_instruction(self, offset):
        """
        인스트럭션을 수정하는 모듈 ( 다른것은 인스트럭션 추가 였음. )
        인스트럭션 첫 바이트만 수정한다. 6F로..
        기능이 제한적인 모듈.
        ( 미리 class에 b라는 static method 를 준비한다. inst_size는 1 이고 return만 있는..
        이때 inst_size가 1이므로 2로 수정 진행해 준다.
        :param offset: code_item offset
        :return:
        """
        # modify the size
        ins_size_offset = offset + ( 2 * 4 ) + 4
        self.mmap[ins_size_offset: ins_size_offset + 4] = pL(2)
        # modify the instruction
        inst_start_offset = offset + ( 2 * 4 ) + 4 + 4
        self.mmap[ inst_start_offset: inst_start_offset + 2 ] = pH(0x6f6f)


    def _search_code_item_offset(self, class_name, method_name):
        """
        class_def -> class_data -> direct_method 탐색.
        :param class_name:
        :param method_name:
        :return:
        에러 처리 전혀 안함.. ( 짜피 a class 의 b method 는 있을거기 때문에.. .)
        """
        # search_class_def ( 가장 처음 나오는 class_name으로 선택.. class_name은 중복되지 않겠지.. pcakge 경로 포함)
        for x in self.origin_dexparser._class_defs:
            if x[8][1:-1] == class_name:
                class_data_item =  self.cdp.print_class_data_item( x[6] )

        # class_data_methods 와 method_name 비교 진행
        for x in class_data_item[6]: # method list
            if x[0][2] == method_name:
                code_item_offset = int(x[2],16)

        return code_item_offset

    def _search_method_idx(self, class_name, function_name ):
        """
        * method_idx는 있는데 code가 없는 경우도 존재한다. ( 여기서는 무시해도 되지만.. )
        * method_id_item은 메소드 마다 개별적으로 존재할 것임을 가정.. 아마 그렇겠지..

        code item에서 올필요 없이 method_id_list 순회해서 파악 가능할듯..
        :param class_name: package path포함
        :param function_name: 함수 이름.
        :return: 찾은 method_idx 반환
        """
        for index, x in enumerate(self.origin_dexparser._method_ids):
            if class_name == x[3][0][1:-1] and function_name == x[3][2]: # class name은 L과 ; 문자를 떼고 정확히 일치 해야 함, function name도 정확히 일치해야 함. <init>같은 function은 고려안함
                return index
        else:
            return None

    # modifier
    def _header_modifier(self, dict):
        """
        :param dict: key에 헤더 item이름, v에 더해질 값.
        :return:
        """
        for k, v in dict.items():
            self.origin_dexparser._header[k] += v

        self. mmap[0x20:0x24] = pL(self.origin_dexparser._header['file_size'])
        self. mmap[0x24:0x28] = pL(self.origin_dexparser._header['header_size'])
        self. mmap[0x28:0x2C] = pL(self.origin_dexparser._header['endian_tag'])
        self. mmap[0x2C:0x30] = pL(self.origin_dexparser._header['link_size'])
        self. mmap[0x30:0x34] = pL(self.origin_dexparser._header['link_off'])
        self. mmap[0x34:0x38] = pL(self.origin_dexparser._header['map_off'])
        self. mmap[0x38:0x3C] = pL(self.origin_dexparser._header['string_ids_size'])
        self. mmap[0x3C:0x40] = pL(self.origin_dexparser._header['string_ids_off'])
        self. mmap[0x40:0x44] = pL(self.origin_dexparser._header['type_ids_size'])
        self. mmap[0x44:0x48] = pL(self.origin_dexparser._header['type_ids_off'])
        self. mmap[0x48:0x4C] = pL(self.origin_dexparser._header['proto_ids_size'])
        self. mmap[0x4C:0x50] = pL(self.origin_dexparser._header['proto_ids_off'])
        self. mmap[0x50:0x54] = pL(self.origin_dexparser._header['field_ids_size'])
        self. mmap[0x54:0x58] = pL(self.origin_dexparser._header['field_ids_off'])
        self. mmap[0x58:0x5C] = pL(self.origin_dexparser._header['method_ids_size'])
        self. mmap[0x5C:0x60] = pL(self.origin_dexparser._header['method_ids_off'])
        self. mmap[0x60:0x64] = pL(self.origin_dexparser._header['class_defs_size'])
        self. mmap[0x64:0x68] = pL(self.origin_dexparser._header['class_defs_off'])
        self. mmap[0x68:0x6C] = pL(self.origin_dexparser._header['data_size'])
        self. mmap[0x6C:0x70] = pL(self.origin_dexparser._header['data_off'])

    def _map_list_modifier(self, changed_maplist):
        """
         chaged_maplist = [
            [0x0001, 1, 4],
            [0x2002, 1, len(data_string)]
            [type, count of the number of items, 늘어난 byte(이 section이 늘어난 size)]
        ]

        :param changed_maplist
        :return:
        """

        # offset table 을 준비
        offset_table = {}
        for type_value, _, offset  in self.origin_dexparser._map_list:
                offset_table[type_value] = offset

        # 돌면서 map_list upate 해준다.
        for c_type, c_size, c_bytes in changed_maplist: # 변경할 data 입력해 준것
            for map_item in self.origin_dexparser._map_list: # index 필요없다.. list ref 받아서 안의 내용만 고칠꺼므로..
                if c_type == map_item[0]: # type이 같은 경우 size 바꿔야 한다.
                    map_item[1]+=c_size

                if map_item[2] > offset_table[c_type] :
                    map_item[2] += c_bytes
                    offset_table[map_item[0]] = map_item[2] # offset table update

        # file 에 write
        m = self.mmap
        m.seek(self.origin_dexparser._header['map_off'])
        m.write( pL(len(offset_table)) ) # map_list size 쓰기

        for map_item in self.origin_dexparser._map_list:
            m.write(pH(map_item[0]))
            m.write(pH(0))
            m.write(pL(map_item[1]))
            m.write(pL(map_item[2]))
        m.seek(0)

    def _string_ids_modifier(self, size):
        """
        :param size: string_data_item_offset을 밀기위한 size를 말함.
        :return:
        """
        m = self.mmap

        string_ids_size = self.origin_dexparser._header['string_ids_size']
        m.seek(self.origin_dexparser._header['string_ids_off'])

        for i in range(string_ids_size):
            self.origin_dexparser._string_ids[i][0] += size
            m.write(pL(self.origin_dexparser._string_ids[i][0]))
        m.seek(0)

    def _proto_ids_modifier(self, size):
        m = self.mmap
        m.seek(self.origin_dexparser._header['proto_ids_off'])
        proto_ids_size = self.origin_dexparser._header['proto_ids_size']

        for i in range(proto_ids_size):
            m.read(4)  # shorty_idx
            m.read(4)  # return_type_idx

            # offset
            if self.origin_dexparser._proto_ids[i][2] != 0:
                self.origin_dexparser._proto_ids[i][2] += size
                m.write(pL(self.origin_dexparser._proto_ids[i][2]))
            else:
                m.read(4)
        m.seek(0)

    def _class_defs_modifier(self, insert_bytes, Interface_offset=0):
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
                self.origin_dexparser._class_defs[i][3] += Interface_offset # 일단 임의로 수정.. 이렇게..
                m.write(pL(self.origin_dexparser._class_defs[i][3]))
            else:
                m.read(4)

            # source_file_idx
            m.read(4)

            # annotations_off
            if self.origin_dexparser._class_defs[i][5] != 0:
                self.origin_dexparser._class_defs[i][5] += insert_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][5]))
            else:
                m.read(4)

            # class_data_off
            if self.origin_dexparser._class_defs[i][6] != 0:
                self.origin_dexparser._class_defs[i][6] += insert_bytes
                m.write(pL(self.origin_dexparser._class_defs[i][6]))
            else:
                m.read(4)

            # static_values_off
            if self.origin_dexparser._class_defs[i][7] != 0:
                self.origin_dexparser._class_defs[i][7] += insert_bytes
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

    def _class_data_item_modifier(self, code_item_offsets, additional_bytes_size=0):
        """
        code_offset 을 일단 수정해 주어야 한다.
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
            self._uleb128_write(m, code_item_offsets[0][i]+additional_bytes_size) # code_off

        # virtual_methods
        for i in range(virtual_methods_size):
            self._uleb128(m) # method_idx_diff
            self._uleb128(m) # access_flags
            self._uleb128_write(m, code_item_offsets[1][i]+additional_bytes_size)  # code_off

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
