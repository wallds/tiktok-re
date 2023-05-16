import random
from unicorn import *
from unicorn.arm64_const import *
from pprint import pprint
import struct
import ctypes
import os

import ida_ida
import ida_bytes
import idaapi
from idc import *

from ctypes import *

from ida_kernwin import Choose
from collections import OrderedDict

ENABLE_DEBUG_TRACE = 0

min_ea = ida_ida.inf_get_min_ea() & ~0xFFF
max_ea = ((ida_ida.inf_get_max_ea()+0xFFF) & ~0xFFF)
native_code = ida_bytes.get_bytes(min_ea, max_ea)
start_ea = idaapi.get_func(get_screen_ea()).start_ea

V2_OPCODE1 = None
V2_OPCODE2 = None

opcode_v1 = {}
opcode_v2 = {}


tracer_list = []

trace_regs = OrderedDict()
trace_regs[UC_ARM64_REG_X0] = 0
trace_regs[UC_ARM64_REG_X1] = 0
trace_regs[UC_ARM64_REG_X2] = 0
trace_regs[UC_ARM64_REG_X3] = 0
trace_regs[UC_ARM64_REG_X4] = 0
trace_regs[UC_ARM64_REG_X5] = 0
trace_regs[UC_ARM64_REG_X6] = 0
trace_regs[UC_ARM64_REG_X7] = 0
trace_regs[UC_ARM64_REG_X8] = 0
trace_regs[UC_ARM64_REG_X9] = 0
trace_regs[UC_ARM64_REG_X10] = 0
trace_regs[UC_ARM64_REG_X11] = 0
trace_regs[UC_ARM64_REG_X12] = 0
trace_regs[UC_ARM64_REG_X13] = 0
trace_regs[UC_ARM64_REG_X14] = 0
trace_regs[UC_ARM64_REG_X15] = 0
trace_regs[UC_ARM64_REG_X16] = 0
trace_regs[UC_ARM64_REG_X17] = 0
trace_regs[UC_ARM64_REG_X18] = 0
trace_regs[UC_ARM64_REG_X19] = 0
trace_regs[UC_ARM64_REG_X20] = 0
trace_regs[UC_ARM64_REG_X21] = 0
trace_regs[UC_ARM64_REG_X22] = 0
trace_regs[UC_ARM64_REG_X23] = 0
trace_regs[UC_ARM64_REG_X24] = 0
trace_regs[UC_ARM64_REG_X25] = 0
trace_regs[UC_ARM64_REG_X26] = 0
trace_regs[UC_ARM64_REG_X27] = 0
trace_regs[UC_ARM64_REG_X28] = 0


class TracerListView(Choose):
    class Item():
        def __init__(self, index, address, disasm, comment='') -> None:
            self.index = index
            self.address = address
            self.disasm = disasm
            self.comment = comment

        def to_strings(self):
            s = [f'{self.index}', f'{self.address:016X}',
                 self.disasm, self.comment]
            return s

    def __init__(self, title, flags=0):
        Choose.__init__(self, title,
                        [["Index", 10], ["Address", 15], [
                            "Disasm", 20], ["comment", 20]],
                        flags=flags | Choose.CH_CAN_REFRESH)

        self.items = []
        self.reload()

    def reload(self):
        self.items = []
        for i, v in enumerate(tracer_list):
            self.items.append(TracerListView.Item(
                i, v['address'], v['disasm'], v['comment']))

    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n].to_strings()

    def OnGetIcon(self, n):
        return 0

    def OnGetLineAttr(self, n):
        return None

    def OnRefresh(self, n):
        self.reload()
        return None

    def OnSelectionChange(self, sel):
        jumpto(tracer_list[sel]['address'], -1, 0)

    def OnClose(self):
        return

    def show(self):
        self.reload()
        return self.Show(False) >= 0


_tracer_list_viewer = TracerListView("TracerListView")


class InstV1(ctypes.LittleEndianStructure):
    _fields_ = [
        ("opcode", c_uint32, 6),
        ("imm2", c_uint32, 6),
        ("imm0", c_uint32, 4),
        ("dst", c_uint32, 5),
        ("src", c_uint32, 5),
        ("imm1", c_uint32, 6),
    ]


class InstV2(ctypes.LittleEndianStructure):
    _fields_ = [
        ("opcode", c_uint32, 6),
        ("opcode_ext", c_uint32, 6),
        ("ext0", c_uint32, 4),
        ("dst", c_uint32, 5),
        ("src", c_uint32, 5),
        ("imm", c_uint32, 5),
        ("ext1", c_uint32, 1),
    ]


class Inst(ctypes.Union):
    _fields_ = [("v1", InstV1),
                ("v2", InstV2),
                ("asdword", c_uint32)]

    def __init__(self, v) -> None:
        self.asdword = v

    @property
    def dst(self):
        return self.v1.dst

    @property
    def src(self):
        return self.v1.src

    @property
    def opcode(self):
        return self.v2.opcode

    @property
    def opcode_ext(self):
        return self.v2.opcode_ext


def hook_code(uc: Uc, address, size, user_data):
    vm: TiktokVM = user_data
    vm.debug_trace.append(address)
    if address == 0xDEAD00000000:
        uc.emu_stop()
        return
    if address in vm.walked:
        # print('twice', hex(address))
        vm.hit_walked = True
        uc.emu_stop()
        return
    vm.walked.add(address)
    if ENABLE_DEBUG_TRACE:
        comment = ''
        for k, v in trace_regs.items():
            new_value = uc.reg_read(k)
            if new_value != v:
                comment += f'{k} = {new_value:016X}, '
                trace_regs[k] = new_value

        item = dict()
        item['address'] = address
        item['disasm'] = GetDisasm(address)
        item['comment'] = comment
        tracer_list.append(item)
        print(hex(address), GetDisasm(address))
    pass


def hook_mem_write(uc: Uc, access, address, size, value, user_data):
    # print(f'[mem_write] 0x{address:08X} {size}')
    pass


def hook_mem_unmapped(uc: Uc, access, address, size, value, user_data):
    # print(f'[mem_unmapped] 0x{address:08X} {size}')
    return False


def p32(n):
    return struct.pack('<I', n)


def p64(n):
    return struct.pack('<Q', n)


def u64(n):
    return struct.unpack('<Q', n)[0]


def make_inst_v1(opcode, dst, src, imm):
    inst = Inst(0)
    inst.v1.opcode = opcode
    inst.v1.dst = dst
    inst.v1.src = src
    inst.v1.imm0 = (imm >> 12) & 0xF
    inst.v1.imm1 = (imm >> 6) & 0x3F
    inst.v1.imm2 = (imm >> 0) & 0x3F
    return inst.asdword


def make_inst_v1_x(opcode, imm):
    inst = Inst(0)
    inst.v1.opcode = opcode
    inst.v1.src = (imm >> 21) & 0x1F
    inst.v1.dst = (imm >> 16) & 0x1F
    inst.v1.imm0 = (imm >> 12) & 0xF
    inst.v1.imm1 = (imm >> 6) & 0x3F
    inst.v1.imm2 = (imm >> 0) & 0x3F
    return inst.asdword


def make_inst_v2(opcode, opcode_ext, ext, dst, src, imm):
    inst = Inst(0)
    inst.v2.opcode = opcode
    inst.v2.opcode_ext = opcode_ext
    inst.v2.dst = dst
    inst.v2.src = src
    inst.v2.imm = imm
    inst.v2.ext0 = (ext >> 1) & 0xF
    inst.v2.ext1 = ext & 1
    return inst.asdword


class TiktokVMContext:
    def __init__(self) -> None:
        self.field_0 = 0
        self.field_8 = 0
        self.field_10 = 0
        self.ip = 0
        self.regs = [0]*32
        self.field_120 = 0
        self.field_128 = 0
        self.field_130 = 0
        self.cached_target = 0
        self.field_140 = 0
        self.p_vm_bytecode = 0

    # def __repr__(self) -> str:
    #     f'''
    #     '''


'''
00000000 vm              struc ; (sizeof=0x150, align=0x8, copyof_12)
00000000 field_0         DCQ ?
00000008 field_8         DCQ ?
00000010 field_10        DCQ ?
00000018 ip              DCQ ?
00000020 regs            DCQ 32 dup(?)
00000120 field_120       DCQ ?
00000128 field_128       DCQ ?
00000130 field_130       DCQ ?
00000138 cached_target   DCQ ?
00000140 field_140       DCQ ?
00000148 p_vm_bytecode   DCQ ?                   ; offset
00000150 vm              ends
'''

# unserialize from uc memory


def read_vm_ctx(uc: Uc, addr):
    ctx = TiktokVMContext()
    ctx.field_0 = u64(uc.mem_read(addr, 8))
    ctx.field_8 = u64(uc.mem_read(addr+8, 8))
    ctx.field_10 = u64(uc.mem_read(addr+0x10, 8))
    ctx.ip = u64(uc.mem_read(addr+0x18, 8))
    for i in range(32):
        ctx.regs[i] = u64(uc.mem_read(addr+0x20+i*8, 8))
    ctx.field_120 = u64(uc.mem_read(addr+0x120, 8))
    ctx.field_128 = u64(uc.mem_read(addr+0x128, 8))
    ctx.field_130 = u64(uc.mem_read(addr+0x130, 8))
    ctx.cached_target = u64(uc.mem_read(addr+0x138, 8))
    ctx.field_140 = u64(uc.mem_read(addr+0x140, 8))
    ctx.p_vm_bytecode = u64(uc.mem_read(addr+0x148, 8))

    return ctx

# serialize to uc memory


def write_vm_ctx(uc: Uc, addr, ctx: TiktokVMContext):
    uc.mem_write(addr, p64(ctx.field_0))
    uc.mem_write(addr+8, p64(ctx.field_8))
    uc.mem_write(addr+0x10, p64(ctx.field_10))
    uc.mem_write(addr+0x18, p64(ctx.ip))
    for i in range(32):
        uc.mem_write(addr+0x20+i*8, p64(ctx.regs[i]))
    uc.mem_write(addr+0x120, p64(ctx.field_120))
    uc.mem_write(addr+0x128, p64(ctx.field_128))
    uc.mem_write(addr+0x130, p64(ctx.field_130))
    uc.mem_write(addr+0x138, p64(ctx.cached_target))
    uc.mem_write(addr+0x140, p64(ctx.field_140))
    uc.mem_write(addr+0x148, p64(ctx.p_vm_bytecode))


class TiktokVM:
    def __init__(self, inst_code) -> None:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.stack_address = 0x7F10010000
        self.ctx = TiktokVMContext()
        self.hit_walked = False
        self.walked = set()
        self.debug_trace = list()

        uc.mem_map(min_ea, max_ea-min_ea, UC_PROT_ALL)
        uc.mem_map(self.stack_address, 0x100000, UC_PROT_ALL)

        uc.mem_write(min_ea, native_code)

        uc.reg_write(UC_ARM64_REG_SP, self.stack_address + 0x4000)
        uc.reg_write(UC_ARM64_REG_X29, self.stack_address + 0x10000)

        uc.mem_map(0xDEAD00000000, 0x1000, UC_PROT_ALL)
        uc.reg_write(UC_ARM64_REG_LR, 0xDEAD00000000)

        self.chunk_address = 0x8000010000
        uc.mem_map(self.chunk_address, 0x100000, UC_PROT_ALL)

        self.temp_address = 0x9000010000
        uc.mem_map(self.temp_address, 0x100000, UC_PROT_ALL)

        self.syscall_stub_address = 0xA000010000

        self.vm_ctx_address = self.chunk_address+0x5000
        self.bytecode_start = self.chunk_address
        self.bytecode_end = self.bytecode_start+4

        uc.mem_write(self.bytecode_start, p32(inst_code))

        uc.reg_write(UC_ARM64_REG_X0, self.bytecode_start)  # bytecode

        uc.reg_write(UC_ARM64_REG_X1, self.chunk_address+0x1000)  # args
        uc.reg_write(UC_ARM64_REG_X2, self.chunk_address+0x2000)  # enc_globals
        uc.reg_write(UC_ARM64_REG_X3, self.chunk_address+0x3000)  # enc_funcs
        uc.reg_write(UC_ARM64_REG_X4, self.chunk_address+0x4000)  # a5

        uc.mem_write(self.chunk_address+0x4000,
                     p64(self.syscall_stub_address))  # call stub (SYSCALL)
        uc.mem_write(self.chunk_address+0x4008,
                     p64(self.vm_ctx_address+0x150))  # ctx
        uc.mem_write(self.chunk_address+0x4010,
                     p64(self.bytecode_end))  # bytecode end
        uc.hook_add(UC_HOOK_CODE, hook_code, self)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
        # uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        self.uc = uc

    def update_vm_ctx(self):
        write_vm_ctx(self.uc, self.vm_ctx_address, self.ctx)

    def fetch_vm_ctx(self):
        self.ctx = read_vm_ctx(self.uc, self.vm_ctx_address)

    def run(self):
        self.update_vm_ctx()
        try:
            timeout = 4000
            if ENABLE_DEBUG_TRACE:
                timeout = 0
            self.uc.emu_start(start_ea, 0, timeout, 4000)
        except Exception as e:
            if ENABLE_DEBUG_TRACE:
                print(e)
            return False
        self.fetch_vm_ctx()
        return True


def dump_test_rules(test_rules):
    # pprint(test_rules)
    for rule in test_rules:
        m = sorted(list(rule.m))
        if len(m) == 1:
            print(f'{rule.name} = 0x{m[0]:02X}')
        elif len(m) == 2:
            print(f'{rule.name} = 0x{m[0]:02X}')
            print(f'{rule.name}_1 = 0x{m[1]:02X}')
        else:
            print(f'# {rule.name} = {m}')


def update_opcode(g, test_rules):
    for rule in test_rules:
        m = sorted(list(rule.m))
        if len(m) == 1:
            assert m[0] not in g
            g[m[0]] = rule.name
        elif len(m) == 2:
            assert m[0] not in g
            assert m[1] not in g

            g[m[0]] = rule.name
            g[m[1]] = f'{rule.name}_1'


def make_test_rules(rules, knowns=None):
    if knowns is None:
        knowns = set()
    test_rules = []
    for name, expr in rules:
        m = set(range(64)) - knowns
        test_rules.append(TestRule(name, expr, m))
    return test_rules


class TestRule:
    def __init__(self, name: str, expr, m) -> None:
        self.name = name
        self.expr = expr
        self.m = m


def test_v1_alu():
    print('# test_v1_alu')
    test_rule = make_test_rules([
        ('V1_XOR', lambda: imm ^ src_val),
        ('V1_ADD', lambda: c_int16(imm).value+src_val),
        ('V1_ADD_I32', lambda: c_int16(imm).value+c_int32(src_val).value),
        ('V1_AND', lambda: imm & src_val),
        ('V1_OR', lambda: imm | src_val),
        ('V1_MOVH', lambda: c_int16(imm).value << 16),
        ('V1_CMP', lambda: c_int64(src_val).value < c_int16(imm).value),
        ('V1_CMP_U64', lambda: src_val < c_uint64(c_int16(imm).value).value),
    ], set(opcode_v1.keys()))

    for _ in range(30):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode in sorted(list(g_set)):
            src_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
            imm = random.randint(0, 0xFFFF)

            vm = TiktokVM(make_inst_v1(opcode, 16, 17, imm))
            vm.ctx.regs[16] = 0
            vm.ctx.regs[17] = src_val
            success = vm.run()
            for rule in test_rule:
                if (success and vm.ctx.regs[16] != c_uint64(rule.expr()).value) or not success:
                    if opcode in rule.m:
                        rule.m.remove(opcode)
    dump_test_rules(test_rule)
    update_opcode(opcode_v1, test_rule)


def test_v1_read_memory():
    print('# test_v1_read_memory')
    test_rule = make_test_rules([
        ('V1_READ_I8', lambda: c_int8(dst_val).value),
        ('V1_READ_I16', lambda: c_int16(dst_val).value),
        ('V1_READ_I32', lambda: c_int32(dst_val).value),
        ('V1_READ_U8', lambda: c_uint8(dst_val).value),
        ('V1_READ_U16', lambda: c_uint16(dst_val).value),
        ('V1_READ_U32', lambda: c_uint32(dst_val).value),
        ('V1_READ_U64', lambda: c_uint64(dst_val).value),
    ], set(opcode_v1.keys()))

    for _ in range(30):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode in sorted(list(g_set)):
            imm = random.randint(0, 8)
            test = os.urandom(8)
            dst_val = struct.unpack('<Q', test)[0]
            vm = TiktokVM(make_inst_v1(opcode, 16, 17, imm))
            vm.uc.mem_write(vm.temp_address+imm, test)

            vm.ctx.regs[16] = 0  # dst
            vm.ctx.regs[17] = vm.temp_address  # src

            success = vm.run()

            for rule in test_rule:
                if (success and vm.ctx.regs[16] != c_uint64(rule.expr()).value) or not success:
                    if opcode in rule.m:
                        rule.m.remove(opcode)

    dump_test_rules(test_rule)
    update_opcode(opcode_v1, test_rule)


def test_v1_write_memory():
    print('# test_v1_write_memory')
    test_rule = make_test_rules([
        ('V1_WRITE_U8', lambda: c_uint8(dst_val).value),
        ('V1_WRITE_U16', lambda: c_uint16(dst_val).value),
        ('V1_WRITE_U32', lambda: c_uint32(dst_val).value),
        ('V1_WRITE_U64', lambda: c_uint64(dst_val).value),
    ], set(opcode_v1.keys()))

    for _ in range(30):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode in sorted(list(g_set)):
            imm = random.randint(0, 8)
            vm = TiktokVM(make_inst_v1(opcode, 16, 17, imm))
            # vm.uc.mem_write(vm.temp_address, temp_data)
            dst_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)

            vm.ctx.regs[16] = dst_val
            vm.ctx.regs[17] = vm.temp_address  # [r17+imm] <= r16

            success = vm.run()
            temp_val = u64(vm.uc.mem_read(vm.temp_address+imm, 8))

            for rule in test_rule:
                if (success and temp_val != c_uint64(rule.expr()).value) or not success:
                    if opcode in rule.m:
                        rule.m.remove(opcode)

    dump_test_rules(test_rule)
    update_opcode(opcode_v1, test_rule)


def test_v1_write_memory2():
    print('# test_v1_write_memory2')
    test_rule = make_test_rules([
        ('V1_WRITE_U64_SHL', lambda: c_uint64(dst_val << (shift*8)).value),
        ('V1_WRITE_U64_SHR', lambda: c_uint64(dst_val >> ((8-shift-1)*8)).value),
    ], set(opcode_v1.keys()))

    for _ in range(30):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode in sorted(list(g_set)):
            offset = random.randint(0, 0x20)*8
            shift = random.randint(0, 7)
            imm = offset | shift
            vm = TiktokVM(make_inst_v1(opcode, 16, 17, imm))
            # vm.uc.mem_write(vm.temp_address, temp_data)
            dst_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)

            vm.ctx.regs[16] = dst_val
            vm.ctx.regs[17] = vm.temp_address  # [r17+imm] <= r16

            success = vm.run()
            temp_val = u64(vm.uc.mem_read(vm.temp_address+offset, 8))

            for rule in test_rule:
                if (success and temp_val != c_uint64(rule.expr()).value) or not success:
                    if opcode in rule.m:
                        rule.m.remove(opcode)

    dump_test_rules(test_rule)
    update_opcode(opcode_v1, test_rule)


def test_v1_control_flow():
    print('# test_v1_control_flow')
    test_rule = make_test_rules([
        ('V1_JUMP_EQ', lambda: 0x404 if src_val == dst_val else 0x8),
        ('V1_JUMP_NE', lambda: 0x404 if src_val != dst_val else 0x8),
        ('V1_JUMP_GT_ZERO', lambda: 0x404 if src_val > 0 else 0x8),
        ('V1_JUMP_LE_ZERO', lambda: 0x404 if src_val <= 0 else 0x8),
        # ('V1_JUMP_TEST', lambda: 0x404 if src_val != dst_val else 0x8),

        ('V1_JUMP', lambda: 0x8880400),
    ], set(opcode_v1.keys()))
    for _ in range(40):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode in sorted(list(g_set)):
            vm = TiktokVM(make_inst_v1_x(opcode, 0x2220100))
            dst_val = c_int64(random.choice(
                [-10, -1, 0, 1, 0xFFFFFFFFFFFFFFFF, random.randint(0, 0xFFFFFFFFFFFFFFFF)])).value
            src_val = c_int64(random.choice(
                [-10, -1, 0, 1, 0xFFFFFFFFFFFFFFFF, random.randint(0, 0xFFFFFFFFFFFFFFFF)])).value
            if random.randint(0, 1):
                dst_val = src_val
            # dst_val = random.randint(0, 7)
            # src_val = random.randint(0, 7)
            # 0x0C 0x26
            vm.ctx.regs[2] = c_uint64(dst_val).value
            vm.ctx.regs[17] = c_uint64(src_val).value
            success = vm.run()
            off = 0
            if vm.ctx.cached_target:
                off = vm.ctx.cached_target-vm.bytecode_start
            for rule in test_rule:
                if ((success and off != c_uint64(rule.expr()).value)
                        or not success or not vm.ctx.cached_target):
                    if opcode in rule.m:
                        rule.m.remove(opcode)

    dump_test_rules(test_rule)
    update_opcode(opcode_v1, test_rule)


def test_v2_alu():
    global V2_OPCODE1
    print('# test_v2_alu')
    # test v2
    for i in range(100):
        for opcode in (set(range(64))-set(opcode_v1.keys())):
            dst_val = 0x9123456789abcdef
            src_val = 0x8122334455667788
            imm = 10
            ext = random.randint(0, 63)

            vm = TiktokVM(make_inst_v2(opcode, ext, 16, 17, 18, imm))
            vm.ctx.regs[16] = 0
            vm.ctx.regs[17] = dst_val
            vm.ctx.regs[18] = src_val
            success = vm.run()
            if success and vm.ctx.regs[16]:
                V2_OPCODE1 = opcode
                break
        if V2_OPCODE1 is not None:
            break
    print(f'V2_OPCODE1 = 0x{V2_OPCODE1:02X}')
    opcode_v1[V2_OPCODE1] = 'V2_OPCODE1'


    if V2_OPCODE1 is not None:
        test_rule = make_test_rules([
            ('V2_XOR', lambda: src_val ^ dst_val),
            ('V2_ADD', lambda: src_val + dst_val),
            ('V2_ADD_I32', lambda: c_int32(
                c_int32(src_val).value + c_int32(dst_val).value).value),
            ('V2_SUB', lambda: src_val - dst_val),
            ('V2_SUB_I32', lambda: c_int32(
                c_int32(src_val).value - c_int32(dst_val).value).value),
            ('V2_AND', lambda: src_val & dst_val),
            ('V2_OR', lambda: src_val | dst_val),
            ('V2_NOR', lambda: ~(src_val | dst_val)),
            ('V2_SHL', lambda: dst_val << imm),
            ('V2_SHL_X', lambda: dst_val << (imm+32)),
            ('V2_SHR', lambda: dst_val >> imm),
            ('V2_SHR_X', lambda: dst_val >> (imm+32)),

            ('V2_SHR_U32', lambda: c_int32(c_uint32(dst_val).value >> imm).value),
            # ('V2_ROL_U32', lambda: c_uint32((dst_val << (imm)) | (dst_val >> (32 - (imm)))).value),

            # ('V2_ROL_X', lambda: (dst_val << (imm+32)) | (dst_val >> (64 - (imm+32)))),
            # ('V2_ROR_X', lambda: (dst_val >> (imm+32)) | (dst_val << (64 - (imm+32)))),

            ('V2_SAR', lambda: c_int64(dst_val).value >> imm),
            ('V2_SAR_X', lambda: c_int64(dst_val).value >> (imm+32)),
            ('V2_SAR_I32', lambda: c_int32(dst_val).value >> imm),
            ('V2_SAL_I32', lambda: c_int32(c_int32(dst_val).value << imm).value),

            ('V2_CMP_I64', lambda: c_int64(src_val).value < c_int64(dst_val).value),
            ('V2_CMP_U64', lambda: src_val < dst_val),

            ('V2_MOVEQ', lambda: src_val if dst_val else ext_val),
            ('V2_MOVNE', lambda: src_val if not dst_val else ext_val),


            # special
            ('V2_MUL_I32', None),
            ('V2_MUL_I64', None),
            ('V2_MUL_U64', None),
            ('V2_GET_PRODUCT_LOW', lambda: product_low_val),
            ('V2_GET_PRODUCT_HIGH', lambda: product_high_val),

            ('V2_SYSCALL', None),
            ('V2_RETURN', None),

        ])
        for r in range(30):
            g_set = set()
            for rule in test_rule:
                g_set |= rule.m
            for opcode_ext in sorted(list(g_set)):
                ext_val = 0
                dst_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
                src_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
                product_low_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
                product_high_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
                if r == 0:
                    dst_val = 0
                imm = random.randint(0, 0x1f)
                vm = TiktokVM(make_inst_v2(opcode,
                                           opcode_ext,
                                           16, 17, 18,
                                           imm))
                vm.ctx = TiktokVMContext()
                vm.ctx.regs[16] = ext_val
                vm.ctx.regs[17] = dst_val
                vm.ctx.regs[18] = src_val
                vm.ctx.field_120 = product_low_val
                vm.ctx.field_128 = product_high_val

                success = vm.run()
                for rule in test_rule:
                    rule: TestRule
                    if rule.name == 'V2_SYSCALL':
                        # field_140 -> LR
                        if (success and not (vm.ctx.field_130 != 0 and vm.ctx.field_140)) or not success:
                            if opcode_ext in rule.m:
                                rule.m.remove(opcode_ext)
                    elif rule.name == 'V2_RETURN':
                        #
                        # V2_RETURN
                        # d:r0 s:r31 x:r0 imm:0; r31指向bytecode_end
                        #
                        if (success and not (vm.ctx.field_130 == 2 and vm.ctx.cached_target == src_val and not vm.ctx.field_140)) or not success:
                            if opcode_ext in rule.m:
                                rule.m.remove(opcode_ext)
                    elif rule.name == 'V2_MUL_I32':
                        product = c_int64(
                            c_int32(dst_val).value*c_int32(src_val).value).value
                        product_low = c_uint64(c_int32(product).value).value
                        product_high = c_uint64(
                            c_int32(product >> 32).value).value
                        if (success and not (vm.ctx.field_120 == product_low and vm.ctx.field_128 == product_high)) or not success:
                            if opcode_ext in rule.m:
                                rule.m.remove(opcode_ext)
                    elif rule.name == 'V2_MUL_I64':
                        product = (c_int64(dst_val).value *
                                   c_int64(src_val).value) & (2**128-1)
                        product_low = c_uint64(c_int64(product).value).value
                        product_high = c_uint64(
                            c_int64(product >> 64).value).value
                        if (success and not (vm.ctx.field_120 == product_low and vm.ctx.field_128 == product_high)) or not success:
                            if opcode_ext in rule.m:
                                rule.m.remove(opcode_ext)
                    elif rule.name == 'V2_MUL_U64':
                        product = (c_uint64(dst_val).value *
                                   c_uint64(src_val).value) & (2**128-1)
                        product_low = c_uint64(product).value
                        product_high = c_uint64(product >> 64).value
                        if (success and not (vm.ctx.field_120 == product_low and vm.ctx.field_128 == product_high)) or not success:
                            if opcode_ext in rule.m:
                                rule.m.remove(opcode_ext)
                    elif (success and vm.ctx.regs[16] != c_uint64(rule.expr()).value) or not success:
                        if opcode_ext in rule.m:
                            rule.m.remove(opcode_ext)

        dump_test_rules(test_rule)
        update_opcode(opcode_v2, test_rule)


def test_v2_2():
    global V2_OPCODE2
    print('# test_v2_2')
    remain = set(range(64))-set(opcode_v1.keys())
    counts = {}
    for opcode in remain:
        for opcode_ext in range(64):
            src_val = 0x1122334455667788
            ext = random.randint(0, 31)
            shift = random.randint(0, 31)

            vm = TiktokVM(make_inst_v2(opcode, opcode_ext, ext, 17, 18, shift))
            vm.ctx.regs[16] = 0
            vm.ctx.regs[17] = 0
            vm.ctx.regs[18] = src_val
            success = vm.run()
            if success and vm.ctx.regs[16] == 0 and vm.ctx.regs[17] and vm.ctx.regs[18] == src_val:
                # print(hex(vm.ctx.regs[17]))
                counts[opcode] = counts.get(opcode, 0) + 1
    if counts:
        V2_OPCODE2 = max(counts, key=counts.get)
    
    # V2_OPCODE2 = 63

    if V2_OPCODE2 is None:
        V2_OPCODE2 = 0xFFFF  # invalid
    print(f'V2_OPCODE2 = 0x{V2_OPCODE2:02X}')
    opcode_v1[V2_OPCODE2] = 'V2_OPCODE2'

    test_rule = make_test_rules([
        ('?1?', lambda: (src_val >> shift) & mask),
        ('?2?', lambda: (src_val << shift) & mask),
        ('?3?', lambda: (c_uint32(src_val).value >> shift) & mask),
    ])

    for _ in range(20):
        g_set = set()
        for rule in test_rule:
            g_set |= rule.m
        for opcode_ext in sorted(list(g_set)):
            dst = 17
            src = 18
            src_val = random.randint(0, 0xFFFFFFFFFFFFFFFF)
            ext = random.randint(0, 31)
            shift = random.randint(0, 31)
            mask = ~(-1 << (ext + 1))

            vm = TiktokVM(make_inst_v2(V2_OPCODE2, opcode_ext, ext, dst, src, shift))
            vm.ctx.regs[dst] = 0
            vm.ctx.regs[src] = src_val
            success = vm.run()
            for rule in test_rule:
                if (success and vm.ctx.regs[dst] != c_uint64(rule.expr()).value) or not success:
                    if opcode_ext in rule.m:
                        rule.m.remove(opcode_ext)
    dump_test_rules(test_rule)


test_v1_alu()
test_v1_read_memory()
test_v1_write_memory()
test_v1_write_memory2()
test_v1_control_flow()
test_v2_alu()
test_v2_2()


if ENABLE_DEBUG_TRACE:
    # /*v1 2F 02CD0DEF*/ d:r13 s:r22 imm:0x0037
    dst = 13
    src = 22
    vm = TiktokVM(make_inst_v1(60, dst, src, 5))
    # vm.uc.mem_write(vm.temp_address, b'\x11'*0x40)  # bytes(list(range(0x40)))
    
    vm.ctx.regs[dst] = 0x1122334455667788
    vm.ctx.regs[src] = 5# vm.temp_address
    # src_val < imm
    bak_regs = vm.ctx.regs[:]

    success = vm.run()
    print(success)

    print(vm.uc.mem_read(vm.temp_address, 0x40).hex())
    for i in range(32):
        if bak_regs[i] != vm.ctx.regs[i]:
            print(f'r{i} {bak_regs[i]:08X} => {vm.ctx.regs[i]:08X}')
    if vm.ctx.cached_target:
        print(hex(vm.ctx.cached_target-vm.bytecode_start))

    _tracer_list_viewer.show()
