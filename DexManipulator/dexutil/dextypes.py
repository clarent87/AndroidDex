# -*- coding: utf-8 -*-

# type code list
typecode = {

    0x0000: 'TYPE_HEADER_ITEM',
    0x0001: 'TYPE_STRING_ID_ITEM',
    0x0002: 'TYPE_TYPE_ID_ITEM',
    0x0003: 'TYPE_PROTO_ID_ITEM',
    0x0004: 'TYPE_FIELD_ID_ITEM',
    0x0005: 'TYPE_METHOD_ID_ITEM',
    0x0006: 'TYPE_CLASS_DEF_ITEM',
    0x0007: 'TYPE_CALL_SITE_ID_ITEM',
    0x0008: 'TYPE_METHOD_HANDLE_ITEM',
    0x1000: 'TYPE_MAP_LIST', ##--
    0x1001: 'TYPE_TYPE_LIST',
    0x1002: 'TYPE_ANNOTATION_SET_REF_LIST',
    0x1003: 'TYPE_ANNOTATION_SET_ITEM',
    0x2000: 'TYPE_CLASS_DATA_ITEM',
    0x2001: 'TYPE_CODE_ITEM',
    0x2002: 'TYPE_STRING_DATA_ITEM',
    0x2003: 'TYPE_DEBUG_INFO_ITEM',
    0x2004: 'TYPE_ANNOTATION_ITEM',
    0x2005: 'TYPE_ENCODED_ARRAY_ITEM',
    0x2006: 'TYPE_ANNOTATIONS_DIRECTORY_ITEM'

}

access_flag = {
    0x1: 'public',
    0x2: 'private',
    0x4: 'protected',
    0x8: 'static',
    0x10: 'final',
    0x20: 'synchronized',
    0x40: 'bridge',
    0x80: 'varargs',
    0x100: 'native',
    0x200: 'interface',
    0x400: 'abstract',
    0x800: 'strictfp',
    0x1000: 'synthetic',
    0x2000: 'annotation',
    0x4000: 'enum',
    0x8000: 'unused',
    0x10000: 'constructor',
    0x20000: 'synchronized'
}
undocumented_access_flag ={
    0x10000 : 'CLASS_ISPREVERIFIED'
}

access_flag_classes = {
    0x1: 'public',
    0x2: 'private',
    0x4: 'protected',
    0x8: 'static',
    0x10: 'final',
    0x200: 'interface',
    0x400: 'abstract',
    0x1000: 'synthetic',
    0x2000: 'annotation',
    0x4000: 'enum',
}

access_flag_fields = {
    0x1: 'public',
    0x2: 'private',
    0x4: 'protected',
    0x8: 'static',
    0x10: 'final',
    0x40: 'volatile',
    0x80: 'transient',
    0x1000: 'synthetic',
    0x4000: 'enum',
}

access_flag_methods = {
    0x1: 'public',
    0x2: 'private',
    0x4: 'protected',
    0x8: 'static',
    0x10: 'final',
    0x20: 'synchronized',
    0x40: 'bridge',
    0x80: 'varargs',
    0x100: 'native',
    0x400: 'abstract',
    0x800: 'strictfp',
    0x1000: 'synthetic',
    0x10000: 'constructor',
    0x20000: 'declared_synchronized',
}

ACCESS_ORDER = [0x1, 0x4, 0x2, 0x400, 0x8, 0x10,
                0x80, 0x40, 0x20, 0x100, 0x800,
                0x200, 0x1000, 0x2000, 0x4000,
                0x10000, 0x20000]

field_descriptor = {

    'V': 'void',
    'B': 'byte',
    'C': 'char',
    'D': 'double',
    'F': 'float',
    'I': 'int',
    'J': 'long',
    'S': 'short',
    'Z': 'boolean',
    '[': 'array',

}

type_descriptor = {

    'V': 'void',
    'Z': 'boolean',
    'B': 'byte',
    'S': 'short',
    'C': 'char',
    'I': 'int',
    'J': 'long',
    'F': 'float',
    'D': 'double',
    'L': 'class',
    '[': 'array'

}

visibility_values = {

    0x00: 'VISIBILITY_BUILD',
    0x01: 'VISIBILITY_RUNTIME',
    0x02: 'VISIBILITY_SYSTEM'

}

value_type = {

    0x00: 'VALUE_BYTE',
    0x02: 'VALUE_SHORT',
    0x03: 'VALUE_CHAR',
    0x04: 'VALUE_INT',
    0x06: 'VALUE_LONG',
    0x10: 'VALUE_FLOAT',
    0x11: 'VALUE_DOUBLE',
    0x17: 'VALUE_STRING',
    0x18: 'VALUE_TYPE',
    0x19: 'VALUE_FIELD',
    0x1a: 'VALUE_METHOD',
    0x1b: 'VALUE_ENUM',
    0x1c: 'VALUE_ARRAY',
    0x1d: 'VALUE_ANNOTATION',
    0x1e: 'VALUE_NULL',
    0x1f: 'VALUE_BOOLEAN'
}
