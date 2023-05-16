import struct
import ida_segment
from idc import *
import idautils

segm_txt = ida_segment.get_segm_by_name('.text')

junks = [
    '03 00 00 94 01 D0 00 91 20 00 1F D6 FF 43 00 D1 FD 7B 00 A9 E0 07 40 F9 FD 7B 40 A9 FF 43 00 91 C0 03 5F D6 E3 0B 41 A9 E0 07 40 A9 FD 7B 43 A9 01 00 00 D4 ?? ?? ?? ?? F5 FF FF 97 06 20 00 91 C0 00 1F D6',
    '04 00 00 94 E1 03 00 AA 21 E0 00 91 20 00 1F D6 FF 43 00 D1 FD 7B 00 A9 E0 07 40 F9 FD 7B 40 A9 FF 43 00 91 C0 03 5F D6 FF 03 01 D1 FD 7B 03 A9 ?? ?? ?? ?? 01 00 00 D4 FF 43 01 91',
    # antidbg
    '01 42 3B D5 E0 03 1F AA 1F 00 1F EB 00 42 1B D5 61 00 00 54 5F 3F 03 D5 60 00 20 D4 01 42 1B D5',
]


def patch_jump(src, dst):
    off = (dst-src)//4
    b = struct.pack('<i', off)[:3]
    if off >= 0:  # ?? ?? ??  14
        b += b'\x14'
    else:  # ?? ?? ??  17
        b += b'\x17'
    ida_bytes.patch_bytes(src, b)
    return True


def find_all(p, start_ea, end_ea):
    ea = start_ea
    while True:
        ea = ida_search.find_binary(ea, end_ea, p, 16,
                                    SEARCH_DOWN | SEARCH_NEXT | SEARCH_CASE)
        if ea == BADADDR:
            break
        yield ea


def de_crc():
    for ea in find_all('?? 00 00 10 ?? ?? ?? B4 ?? ?? ?? B4', start_ea, end_ea):
        if ea & 3 == 0:
            print(hex(ea))
            patch_jump(ea+4, get_operand_value(ea+4, 1))


def de_junks():
    for junk in junks:
        print('junk: ', junk)
        size = len(junk.split(' '))
        assert size % 4 == 0
        for ea in find_all(junk, start_ea, end_ea):
            print(hex(ea))
            ida_bytes.patch_bytes(ea, bytes.fromhex('1F 20 03 D5')*(size//4))
            patch_jump(ea, ea+size)


def is_bad_branch(ea):
    insn = idautils.DecodeInstruction(ea)
    if insn is None:
        return True
    # 只处理mov指令, 其他的不管
    if insn.get_canon_mnem() == 'MOV' and not ida_ua.can_decode(ea+insn.size):
        return True
    return False


def de_junk_branch():
    for ea in range(segm_txt.start_ea, segm_txt.end_ea-4, 4):
        dst = None
        if ida_bytes.get_byte(ea+3) == 0x54 and is_bad_branch(ea+4):
            '''
            .text:00000000000621A4 E1 01 00 54                 B.NE            loc_621E0
            .text:00000000000621A8 0A                          DCB  0xA
            '''
            dst = get_operand_value(ea, 0)
        elif ida_bytes.get_byte(ea+3) == 0x35 and is_bad_branch(ea+4):
            '''
            .text:0000000000062804 E8 01 00 35                 CBNZ            W8, loc_62840
            .text:0000000000062808 BE 2B 0A 22+                DCQ 0xC7F6ADCE220A2BBE
            '''
            dst = get_operand_value(ea, 1)
        elif ida_bytes.get_byte(ea+3) == 0x54:
            _dest = get_operand_value(ea, 0)
            if is_bad_branch(_dest):
                # patch nop 1F 20 03 D5
                print(f'patch junk branch(nop) 0x{ea:08X} {GetDisasm(ea)}   ')
                ida_bytes.patch_bytes(ea, bytes.fromhex('1F 20 03 D5'))
                continue
        if dst:
            print(
                f'patch junk branch(b) 0x{ea:08X} {GetDisasm(ea)} # dst:0x{dst:08X}')
            patch_jump(ea, dst)


start_ea = segm_txt.start_ea
end_ea = segm_txt.end_ea
de_crc()
de_junks()
de_junk_branch()

ida_auto.auto_mark_range(start_ea, end_ea, ida_auto.AU_UNK)
