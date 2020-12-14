from dexparser import *
from dexutil import *
import sys

if __name__ == "__main__":
    # need to copy the file
    # FILE_NAME = sys.argv[1]
    dex = dexparser.DexParser("./classes.dex")

    # print header
    # for k,v  in dex.header_info.items():
    #     print "{ "+ k + " : "+ v +" }"

    # for k in dex.type_ids_info:
    #     print k

    # for idx, k in enumerate(dex.class_defs_info):
    #     # print k
    #     print idx
    #     print dex.get_class_data_item(idx)

    for x in  dex.get_class_data_item(0)[6]:
        print x
    # f = open("log.txt",'w')
    # for idx, k in enumerate(dex.proto_ids_info):
    #     if idx >11490 and idx <11574:
    #         f.write(str(idx)+" ")
    #         f.write(str(k))
    #         f.write('\n')
    # f.close()
    #
    # f =open("log_11550.txt",'w')
    # f.write(str(dex.proto_ids_info[11550 ]))
    # f.close()

    # for x in dex.map_list_info:
    #     print x

    # for x in dex._class_defs:
    #     print x

    # for x in dex._type_list:
    #     print x

    # for x in dex._method_ids:
    #     print x

    # data = ("FFFF03" + "56" + "4c" + "00" + "00").decode('hex')
    # data2 =  '\x00\x00'+data
    #
    # print data2.encode('hex')

    # print int ("0x59c",16)

    print int(hex(123), 16)


