import ida_bytes
import ida_nalt
import idaapi
import ida_idaapi
import ida_ida
from enum import Enum, IntFlag
from collections import OrderedDict

# https://github.com/protobuf-c/protobuf-c/blob/master/protobuf-c/protobuf-c.h

PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC = 0x14159bc3
PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC = 0x28aaeef9
PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC = 0x114315af


class ProtobufCFieldFlag(IntFlag):
    PROTOBUF_C_FIELD_FLAG_PACKED = (1 << 0)
    PROTOBUF_C_FIELD_FLAG_DEPRECATED = (1 << 1)
    PROTOBUF_C_FIELD_FLAG_ONEOF = (1 << 2)


class ProtobufCLabel(Enum):
    PROTOBUF_C_LABEL_REQUIRED = 0
    PROTOBUF_C_LABEL_OPTIONAL = 1
    PROTOBUF_C_LABEL_REPEATED = 2
    PROTOBUF_C_LABEL_NONE = 3


map_label = {
    ProtobufCLabel.PROTOBUF_C_LABEL_REQUIRED: 'required',
    ProtobufCLabel.PROTOBUF_C_LABEL_OPTIONAL: 'optional',
    ProtobufCLabel.PROTOBUF_C_LABEL_REPEATED: 'repeated',
    ProtobufCLabel.PROTOBUF_C_LABEL_NONE: ''
}


class ProtobufCType(Enum):
    PROTOBUF_C_TYPE_INT32 = 0  # /**< int32 */
    PROTOBUF_C_TYPE_SINT32 = 1  # /**< signed int32 */
    PROTOBUF_C_TYPE_SFIXED32 = 2  # /**< signed int32 (4 bytes) */
    PROTOBUF_C_TYPE_INT64 = 3  # /**< int64 */
    PROTOBUF_C_TYPE_SINT64 = 4  # /**< signed int64 */
    PROTOBUF_C_TYPE_SFIXED64 = 5  # /**< signed int64 (8 bytes) */
    PROTOBUF_C_TYPE_UINT32 = 6  # /**< unsigned int32 */
    PROTOBUF_C_TYPE_FIXED32 = 7  # /**< unsigned int32 (4 bytes) */
    PROTOBUF_C_TYPE_UINT64 = 8  # /**< unsigned int64 */
    PROTOBUF_C_TYPE_FIXED64 = 9  # /**< unsigned int64 (8 bytes) */
    PROTOBUF_C_TYPE_FLOAT = 10  # /**< float */
    PROTOBUF_C_TYPE_DOUBLE = 11  # /**< double */
    PROTOBUF_C_TYPE_BOOL = 12  # /**< boolean */
    PROTOBUF_C_TYPE_ENUM = 13  # /**< enumerated type */
    PROTOBUF_C_TYPE_STRING = 14  # /**< UTF-8 or ASCII string */
    PROTOBUF_C_TYPE_BYTES = 15  # /**< arbitrary byte sequence */
    PROTOBUF_C_TYPE_MESSAGE = 16  # /**< nested message */


map_type = {
    ProtobufCType.PROTOBUF_C_TYPE_INT32: 'int32',
    ProtobufCType.PROTOBUF_C_TYPE_SINT32: 'sint32',
    ProtobufCType.PROTOBUF_C_TYPE_SFIXED32: 'sfixed32',
    ProtobufCType.PROTOBUF_C_TYPE_INT64: 'int64',
    ProtobufCType.PROTOBUF_C_TYPE_SINT64: 'sint64',
    ProtobufCType.PROTOBUF_C_TYPE_SFIXED64: 'sfixed64',
    ProtobufCType.PROTOBUF_C_TYPE_UINT32: 'uint32',
    ProtobufCType.PROTOBUF_C_TYPE_FIXED32: 'fixed32',
    ProtobufCType.PROTOBUF_C_TYPE_UINT64: 'uint64',
    ProtobufCType.PROTOBUF_C_TYPE_FIXED64: 'fixed64',
    ProtobufCType.PROTOBUF_C_TYPE_FLOAT: 'float',
    ProtobufCType.PROTOBUF_C_TYPE_DOUBLE: 'double',
    ProtobufCType.PROTOBUF_C_TYPE_BOOL: 'bool',
    ProtobufCType.PROTOBUF_C_TYPE_ENUM: 'enum',
    ProtobufCType.PROTOBUF_C_TYPE_STRING: 'string',
    ProtobufCType.PROTOBUF_C_TYPE_BYTES: 'bytes',
    ProtobufCType.PROTOBUF_C_TYPE_MESSAGE: 'message',
}


def get_str(addr):
    p_name = ida_bytes.get_qword(addr)
    str = ida_bytes.get_strlit_contents(p_name, -1, ida_nalt.STRTYPE_C)
    if str == None:
        return None
    return str.decode()


class ProtobufCEnumValue:
    def __init__(self, addr) -> None:
        self.name = get_str(addr)
        self.c_name = get_str(addr+8)
        self.value = ida_bytes.get_dword(addr+0x10)
        if self.name == '_':
            self.name = f'value_{self.value}'


class ProtobufCEnumValueIndex:
    def __init__(self, addr) -> None:
        self.name = get_str(addr)
        self.index = ida_bytes.get_dword(addr+0x8)


class ProtobufCEnumDescriptor:
    def __init__(self, addr) -> None:
        assert idaapi.inf_is_64bit()
        self.magic = ida_bytes.get_dword(addr)
        assert self.magic == PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC
        self.name = get_str(addr+8)
        if self.name == '_':
            self.name = f'enum_{addr:08X}'
        self.short_name = get_str(addr+0x10)
        self.c_name = get_str(addr+0x18)
        self.package_name = get_str(addr+0x20)

        self.n_values = ida_bytes.get_dword(addr+0x28)
        p_values = ida_bytes.get_qword(addr+0x30)
        self.values = []
        for i in range(self.n_values):
            self.values.append(ProtobufCEnumValue(p_values+i*0x18))

        self.n_value_names = ida_bytes.get_dword(addr+0x38)
        p_values_by_name = ida_bytes.get_qword(addr+0x40)
        self.values_by_name = []
        for i in range(self.n_value_names):
            self.values_by_name.append(
                ProtobufCEnumValueIndex(p_values_by_name+i*0x10))

        self.n_value_ranges = ida_bytes.get_dword(addr+0x48)
        p_value_ranges = ida_bytes.get_qword(addr+0x50)


class ProtobufCFieldDescriptor:
    def __init__(self, addr) -> None:
        self.name = get_str(addr)
        self.id = ida_bytes.get_dword(addr+8)
        self.label = ProtobufCLabel(ida_bytes.get_dword(addr+0xC))
        self.type = ProtobufCType(ida_bytes.get_dword(addr+0x10))
        self.quantifier_offset = ida_bytes.get_dword(addr+0x14)
        self.offset = ida_bytes.get_dword(addr+0x18)
        self.p_descriptor = ida_bytes.get_qword(addr+0x20)
        self.p_default_value = ida_bytes.get_qword(addr+0x28)
        self.flags = ProtobufCFieldFlag(ida_bytes.get_qword(addr+0x30))
        if self.name == '_':
            self.name = f'field_{self.offset:04X}'


class ProtobufCMessageDescriptor:
    def __init__(self, addr) -> None:
        assert idaapi.inf_is_64bit()
        self.magic = ida_bytes.get_dword(addr)
        assert self.magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC
        self.name = get_str(addr+8)
        self.short_name = get_str(addr+0x10)
        self.c_name = get_str(addr+0x18)
        self.package_name = get_str(addr+0x20)

        self.sizeof_message = ida_bytes.get_qword(addr+0x28)
        self.n_fields = ida_bytes.get_dword(addr+0x30)
        p_fields = ida_bytes.get_qword(addr+0x38)
        self.fields = []
        for i in range(self.n_fields):
            self.fields.append(ProtobufCFieldDescriptor(p_fields+i*0x48))
        self.n_field_ranges = ida_bytes.get_dword(addr+0x40)
        p_field_ranges = ida_bytes.get_qword(addr+0x48)
        self.message_init = ida_bytes.get_qword(addr+0x50)

        if self.name == '_':
            self.name = f'message_{addr:08X}'


def my_bin_search(pattern, start=None, end=None):
    binpat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(binpat, 0, pattern, 16)
    if start is None:
        start = ida_ida.inf_get_min_ea()
    if end is None:
        end = ida_ida.inf_get_max_ea()
    while True:
        ea = ida_bytes.bin_search(
            start, end, binpat, ida_bytes.BIN_SEARCH_FORWARD)
        if ea == ida_idaapi.BADADDR:
            break
        yield ea
        start = ea+1


dict_enum = OrderedDict()
dict_message = OrderedDict()

for ea in my_bin_search('AF 15 43 11'):
    dict_enum[ea] = ProtobufCEnumDescriptor(ea)

for ea in my_bin_search('F9 EE AA 28'):
    dict_message[ea] = ProtobufCMessageDescriptor(ea)

for ea, desc in dict_enum.items():
    print('//', hex(ea))
    print('enum', desc.name)
    print('{')
    for value in desc.values:
        print(f'    {value.name} = {value.value};')
    print('}')

for ea, desc in dict_message.items():
    print('//', hex(ea))
    desc = ProtobufCMessageDescriptor(ea)

    print('message', desc.name)
    print('{')
    for field in desc.fields:
        s = f'/*+{field.offset:04X}*/ '
        if field.label != ProtobufCLabel.PROTOBUF_C_LABEL_NONE:
            s += map_label[field.label]+' '
        if field.flags & ProtobufCFieldFlag.PROTOBUF_C_FIELD_FLAG_ONEOF:
            s += 'oneof '
        type_name = map_type[field.type]
        if field.type == ProtobufCType.PROTOBUF_C_TYPE_MESSAGE:
            type_name = dict_message[field.p_descriptor].name
        if field.type == ProtobufCType.PROTOBUF_C_TYPE_ENUM:
            type_name = dict_enum[field.p_descriptor].name

        s += f'{type_name} {field.name} = {field.id}'
        if field.flags & ProtobufCFieldFlag.PROTOBUF_C_FIELD_FLAG_PACKED:
            s += ' [packed=true]'
        s += ';'
        if field.p_descriptor:
            s += f' // {hex(field.p_descriptor)} '
        print(s)
    print('}')
