# import sys
#
#
#
# if __name__ == "__main__":
#     import mmap
#     import struct
#
#     f = open("TESTTEXT", 'r+b')
#     f.flush()
#     mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
#
#     # test1 -- mmap. modify
#     # mmap[0] = 'A'
#
#     # test2 --
#     # mmap[0] = 'ZX' // error - must be single-char
#
#     # test3 - write
#     # mmap.write("ABCD")
#
#     # test4 - slicing
#     # mmap[0:4] = struct.pack("<L",1)
#
#     # test5 - move / resize
#     # a = "ZXCV"
#     # mmap.resize(mmap.size() + len(a))
#     # mmap.move(len(a), 0, 4)
#
#     # test6
#     # print copy_file_for_modifer(".dex")
#
#
#     # test7
#     # ar = [ [1,2,3,4],[5,6,7,8]]
#     # for x in ar:
#     #     for i,y in enumerate(x):
#     #         x[i] =  y + 10
#     #
#     # print ar
#     # print "TEST"
#     # print ar[2:]
#
#     #test8
#     # fill_array_data_payload = "00030000BCCF13ED"
#     # offset = 2
#     # origin_size = mm.size()
#     # mm.resize(mm.size() + 8)
#     # mm.move(offset + 8 ,offset, origin_size - offset )
#     # mm[offset: offset+8] = fill_array_data_payload.decode("hex")
#     #
#     # print [x for x in range(6)]
#
#     a = ['a','b','c']
#     print ''.join(a)
#     mm.write(''.join(a))

import mmap
import sys
import hashlib


def _set_sha_one( mm):
    import hashlib
    signature = hashlib.sha1(mm[32:]).digest()
    mm[12:32] = signature


def _set_adler_checksum( mm):
    import zlib
    import struct
    # print zlib.adler32(mm[12:])
    checksum = struct.pack( "<l",zlib.adler32(mm[12:]))
    # print len(mm[8:12])
    # print len(checksum)
    mm[8:12] = checksum

def test():
    print " this is test"

if __name__ == "__main__":

    sha = hashlib.sha1()
    with open("classes.dex", 'r+b') as f:
        map = mmap.mmap(f.fileno(), 0 , access=mmap.ACCESS_WRITE)
        _set_sha_one(map)
        _set_adler_checksum(map)
        map.close()

