import ctypes
from ctypes import c_int16, c_uint32
from string import Template
from idc import *
import idaapi
import ida_hexrays
import ida_bytes
import ida_kernwin
import importlib
import sys
import idautils
from ops import TiktokOps

if 'ops' in sys.modules:
    importlib.reload(sys.modules['ops'])
    from ops import TiktokOps

"""
用于定位VM函数

arm64-v8a
E2 03 00 AA E0 03 01 AA 40 00 1F D6

armeabi-v7a
02 46 08 46 10 47
"""


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
    def ext(self):
        assert self.v2.opcode in [TiktokOps.V2_OPCODE1, TiktokOps.V2_OPCODE2]
        return (self.v2.ext0 << 1) | self.v2.ext1

    @property
    def imm(self):
        if self.v2.opcode in [TiktokOps.V2_OPCODE1, TiktokOps.V2_OPCODE2]:
            return self.v2.imm
        return (self.v1.imm0 << 12) | (self.v1.imm1 << 6) | (self.v1.imm2)

    @property
    def imm_ext(self):
        assert self.v1.opcode not in [
            TiktokOps.V2_OPCODE1, TiktokOps.V2_OPCODE2]
        return (self.v1.src << 21) | (self.v1.dst << 16) | (self.v1.imm0 << 12) | (self.v1.imm1 << 6) | (self.v1.imm2)

    @property
    def opcode(self):
        return self.v2.opcode

    @property
    def opcode_ext(self):
        return self.v2.opcode_ext


headers = """
#include <stdint.h>
#include <stdio.h>

typedef void (*PFN_CALLSTUB)(uint64_t, void *);
"""

templ = """
void ${name}(uint64_t *p_args, uint64_t *g_vars, uint64_t *p_funcs, PFN_CALLSTUB callstub) {
  uint64_t r0 = 0;
  uint64_t r1 = 0;
  uint64_t r2 = 0;
  uint64_t r3 = 0;
  uint64_t r4 = (uint64_t)p_args;
  uint64_t r5 = (uint64_t)g_vars;
  uint64_t r6 = (uint64_t)p_funcs;
  uint64_t r7 = (uint64_t)callstub;
  uint64_t r8 = 0;
  uint64_t r9 = 0;
  uint64_t r10 = 0;
  uint64_t r11 = 0;
  uint64_t r12 = 0;
  uint64_t r13 = 0;
  uint64_t r14 = 0;
  uint64_t r15 = 0;
  uint64_t r16 = 0;
  uint64_t r17 = 0;
  uint64_t r18 = 0;
  uint64_t r19 = 0;
  uint64_t r20 = 0;
  uint64_t r21 = 0;
  uint64_t r22 = 0;
  uint64_t r23 = 0;
  uint64_t r24 = 0;
  uint64_t r25 = 0;
  uint64_t r26 = 0;
  uint64_t r27 = 0;
  uint64_t r28 = 0;
  uint64_t r30 = 0;
  uint64_t r31 = 0;

  uint64_t field_120 = 0;
  uint64_t field_128 = 0;

  uint8_t stack_buffer[${stack_size}];
  uint64_t r29 = (uint64_t)&stack_buffer[sizeof(stack_buffer)];

${pcode}

}
"""

footers = """
int main(void) {
  return 0;
}
"""

templ_obj = Template(templ)


class VMInfo():
    def __init__(self, vmentry, size, g_vars, funcs) -> None:
        self.vmentry = vmentry
        self.size = size
        self.g_vars = g_vars
        self.funcs = funcs

    def __str__(self) -> str:
        return f'VMInfo(vmentry=0x{self.vmentry:08X}, size={self.size}, g_vars=0x{self.g_vars:08X}, funcs=0x{self.funcs:08X})'


class Pcode:
    def __init__(self, label, pcode) -> None:
        self.label = label
        self.pcode = pcode

    def __str__(self) -> str:
        return self.label+self.pcode


def decompile(vm: VMInfo, gen_c=False):
    def label(pc):
        return f"L_{pc:08X}"
    stack_size = 0
    pcodes = []
    for i in range(vm.size):
        pc = vm.vmentry + i * 4
        inst = Inst(ida_bytes.get_dword(pc))
        if inst.asdword == 0:
            break
        if inst.opcode in [TiktokOps.V2_OPCODE1, TiktokOps.V2_OPCODE2]:
            text = f'puts("/*v2 {inst.opcode_ext:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} x:r{inst.ext} imm:{inst.imm}");'
            if inst.opcode == TiktokOps.V2_OPCODE1:
                match inst.opcode_ext:
                    case TiktokOps.V2_MUL_I32:
                        text = f"field_120 = (int32_t)((int64_t)(int32_t)r{inst.dst}*(int64_t)(int32_t)r{inst.src});"
                        text += f"field_128 = ((int64_t)(int32_t)r{inst.dst}*(int64_t)(int32_t)r{inst.src}) >> 32;"
                    case TiktokOps.V2_GET_PRODUCT_LOW:
                        text = f"r{inst.ext} = field_120;"
                    case TiktokOps.V2_GET_PRODUCT_HIGH:
                        text = f"r{inst.ext} = field_128;"
                    case TiktokOps.V2_NOR:
                        text = f"r{inst.ext} = ~(r{inst.dst} | r{inst.src});"
                    case TiktokOps.V2_AND:
                        text = f"r{inst.ext} = r{inst.dst} & r{inst.src};"
                    case TiktokOps.V2_OR:
                        text = f"r{inst.ext} = r{inst.dst} | r{inst.src};"
                    case TiktokOps.V2_XOR:
                        text = f"r{inst.ext} = r{inst.dst} ^ r{inst.src};"
                    case TiktokOps.V2_SAR_I32:
                        text = f"r{inst.ext} = (int32_t)r{inst.dst} >> {inst.imm};"
                    case TiktokOps.V2_SAL_I32:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} << {inst.imm});"
                    case TiktokOps.V2_SHR_U32:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} >> {inst.imm});"
                    case TiktokOps.V2_SHL_X:
                        text = f"r{inst.ext} = r{inst.dst} << {inst.imm|0x20};"
                    case TiktokOps.V2_SHL:
                        text = f"r{inst.ext} = r{inst.dst} << {inst.imm};"
                    # case 0x16:  # NOP ?
                    #     text = ';/* nop */'
                    #     pass
                    case TiktokOps.V2_SYSCALL:  # V2_SYSCALL
                        text = f"((PFN_CALLSTUB)r{inst.src})(r4, (void *)r5); /* call r{inst.src}(r4, r5) */"
                        # text = f"((void (*)(void *))r4)((void *)r5); /* call r{inst.src}(r4, r5) */"
                    case TiktokOps.V2_RETURN:  # V2_RETURN
                        text = f"return; // d:r{inst.dst} s:r{inst.src} x:r{inst.ext} imm:{inst.imm};"
                    case TiktokOps.V2_SUB | TiktokOps.V2_SUB_1:  # V2_SUB
                        text = f"r{inst.ext} = r{inst.src} - r{inst.dst};"
                    case TiktokOps.V2_ADD | TiktokOps.V2_ADD_1:  # V2_ADD
                        text = f"r{inst.ext} = r{inst.dst} + r{inst.src};"
                    case TiktokOps.V2_CMP_U64:
                        text = f"r{inst.ext} = r{inst.src} < r{inst.dst};"
                    case TiktokOps.V2_CMP_I64:
                        text = f"r{inst.ext} = (int64_t)r{inst.src} < (int64_t)r{inst.dst};"
                    case TiktokOps.V2_ADD_I32 | TiktokOps.V2_ADD_I32_1:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} + (uint32_t)r{inst.src});"
                    case TiktokOps.V2_SUB_I32 | TiktokOps.V2_SUB_I32_1:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.src} - (uint32_t)r{inst.dst});"
                    case TiktokOps.V2_MOVEQ:
                        text = f"if (r{inst.dst}) r{inst.ext} = r{inst.src};"
                    case TiktokOps.V2_MOVNE:
                        text = f"if (!r{inst.dst}) r{inst.ext} = r{inst.src};"
                    case TiktokOps.V2_SHR_X:
                        text = f"r{inst.ext} = r{inst.dst} >> {inst.imm|0x20};"
                    case TiktokOps.V2_SHR:
                        text = f"r{inst.ext} = r{inst.dst} >> {inst.imm};"
            elif inst.opcode == TiktokOps.V2_OPCODE2:
                text = f'puts("/*v2@{inst.opcode_ext:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} x:{inst.ext} imm:{inst.imm})"'
                match inst.opcode_ext:
                    case 0x17:
                        mask = ~(-1 << (inst.ext + 1))
                        shift = inst.imm
                        text = f"r{inst.dst} = (r{inst.src} >> {shift}) & {hex(mask)};"
                    case 0x18:
                        mask = ~(-1 << (inst.ext + 1))
                        shift = inst.imm
                        text = f"r{inst.dst} = ((uint32_t)r{inst.src} >> {shift}) & {hex(mask)};"
                    case 0x2F:
                        mask1 = -1 << inst.ext
                        mask2 = ~(-1 << (inst.ext - inst.imm + 1))
                        mask3 = ~(-1 << inst.imm)
                        assert inst.ext >= inst.imm
                        text = f"r{inst.dst} = r{inst.dst} & {hex(mask1)} | (r{inst.src} & {hex(mask2)}) << {inst.imm} | r{inst.dst} & {hex(mask3)};"
        else:
            imm_s = c_int16(inst.imm).value
            text = f'puts("/*v1 {inst.opcode:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} imm:0x{inst.imm:04X}");'
            match inst.opcode:
                case TiktokOps.V1_MOVH:
                    text = f"r{inst.dst} = {hex(imm_s<<16)};"
                # case 0x03:
                #     # float handler
                #     pass
                case TiktokOps.V1_JUMP_EQ | TiktokOps.V1_JUMP_EQ_1:
                    target = pc + 4 + imm_s * 4
                    text = f"if (r{inst.dst} == r{inst.src}) goto {label(target)};"
                case TiktokOps.V1_JUMP_NE | TiktokOps.V1_JUMP_NE_1:
                    target = pc + 4 + imm_s * 4
                    text = f"if (r{inst.dst} != r{inst.src}) goto {label(target)};"
                case TiktokOps.V1_JUMP_GT_ZERO | TiktokOps.V1_JUMP_GT_ZERO_1:
                    target = pc + 4 + imm_s * 4
                    text = f"if ((int64_t)r{inst.src} > 0) goto {label(target)};"
                case TiktokOps.V1_JUMP_LE_ZERO | TiktokOps.V1_JUMP_LE_ZERO_1:
                    target = pc + 4 + imm_s * 4
                    text = f"if ((int64_t)r{inst.src} <= 0) goto {label(target)};"
                case TiktokOps.V1_ADD | TiktokOps.V1_ADD_1:
                    if inst.dst == inst.src and inst.dst == 29:
                        stack_size = abs(imm_s)
                    text = f"r{inst.dst} = r{inst.src} + {hex(imm_s)};"
                case TiktokOps.V1_ADD_I32:
                    text = f"r{inst.dst} = (int32_t)r{inst.src} + (int64_t){hex(imm_s)};"
                case TiktokOps.V1_JUMP | TiktokOps.V1_JUMP_1:
                    text = f"goto {label(vm.vmentry+inst.imm_ext*4)};"
                case TiktokOps.V1_CMP:
                    text = f"r{inst.dst} = (int64_t)r{inst.src} < {imm_s};"
                case TiktokOps.V1_READ_I8:
                    text = f"r{inst.dst} = *(int8_t *)(r{inst.src}+{hex(imm_s)});"
                case TiktokOps.V1_READ_I32:
                    text = f"r{inst.dst} = *(int32_t *)(r{inst.src}+{hex(imm_s)});"
                case TiktokOps.V1_READ_U8:
                    text = f"r{inst.dst} = *(uint8_t *)(r{inst.src}+{hex(imm_s)});"
                case TiktokOps.V1_READ_U16:
                    text = f"r{inst.dst} = *(uint16_t *)(r{inst.src}+{hex(imm_s)});"
                case TiktokOps.V1_READ_U32:
                    text = f"r{inst.dst} = *(uint32_t *)(r{inst.src}+{hex(imm_s)});"
                case TiktokOps.V1_READ_U64:
                    enc_addr = 0
                    text = f"r{inst.dst} = *(uint64_t *)(r{inst.src}+{hex(inst.imm)});"
                    if vm.g_vars and inst.src == 5:
                        # enc_addr = ida_bytes.get_qword(vm.g_vars+inst.imm)
                        text = f"r{inst.dst} = {hex(ida_bytes.get_qword(vm.g_vars+inst.imm))};"
                    elif vm.funcs and inst.src == 6:
                        # enc_addr = ida_bytes.get_qword(vm.funcs+inst.imm)
                        text = f"r{inst.dst} = {hex(ida_bytes.get_qword(vm.funcs+inst.imm))};"
                case TiktokOps.V1_WRITE_U8:
                    text = f"*(uint8_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case TiktokOps.V1_WRITE_U16:
                    text = f"*(uint16_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case TiktokOps.V1_WRITE_U32:
                    text = f"*(uint32_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case TiktokOps.V1_WRITE_U64:
                    text = f"*(uint64_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case TiktokOps.V1_WRITE_U64_SHL:
                    offset = imm_s & 0xFFF8
                    shift = imm_s % 8
                    text = f"*(uint64_t *)(r{inst.src}+{offset}) = r{inst.dst} << {shift*8};"
                case TiktokOps.V1_WRITE_U64_SHR:
                    offset = imm_s & 0xFFF8
                    shift = imm_s % 8
                    text = f"*(uint64_t *)(r{inst.src}+{offset}) = r{inst.dst} >> {(8-shift-1)*8};"
                case TiktokOps.V1_AND:
                    text = f"r{inst.dst} = r{inst.src} & {hex(inst.imm)};"
                case TiktokOps.V1_OR:
                    text = f"r{inst.dst} = r{inst.src} | {hex(inst.imm)};"
                case TiktokOps.V1_XOR:
                    text = f"r{inst.dst} = r{inst.src} ^ {hex(inst.imm)};"
        pcodes.append(Pcode(f"{label(pc)}: ", text))

    # tiktokvm的转移指令是滞后一条指令才生效的, 需要和下一条指令交换位置.
    i = 0
    while i + 1 < len(pcodes):
        if "call" in pcodes[i].pcode or "goto" in pcodes[i].pcode or "return" in pcodes[i].pcode:
            pcodes[i+1].pcode, pcodes[i].pcode = pcodes[i].pcode, pcodes[i+1].pcode
            i += 1
        i += 1

    s = ''
    for i in range(len(pcodes)):
        print(pcodes[i])
        s += str(pcodes[i])+"\n"
    s = s.rstrip('\n')
    source = templ_obj.substitute(
        name=f'foo_{vm.vmentry:08X}', stack_size=hex(stack_size), pcode=s)
    if gen_c:
        open(f"vm_{vm.vmentry:08X}_{vm.size}.c", "w").write(
            headers + source + footers)
        # 生成后直接用gcc编译, 然后使用IDA打开分析.
    return source


def parse_expr(expr):
    n = None
    if expr.op == idaapi.cot_num:
        n = expr.numval()
    elif expr.op == idaapi.cot_obj:
        n = expr.obj_ea
    elif expr.op == idaapi.cot_cast:
        n = parse_expr(expr.x)
    elif expr.op == idaapi.cot_var:
        pass
    elif expr.op == idaapi.cot_ref:
        n = parse_expr(expr.x)
    else:
        raise Exception('ERROR ' + expr.opname + str(expr.operands))
    return n


class my_super_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        # CV_FAST does not keep parents nodes in CTREE
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.calls = []

    def visit_insn(self, i):
        return 0

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_call:
            return 0
        if e.x.obj_ea == BADADDR:
            return 0
        if e.a.size() in [5, 6]:
            args = tuple(parse_expr(arg) for arg in e.a)
            self.calls.append((e.x.obj_ea, args))
        return 0


def decompile_here():
    func = idaapi.get_func(here())
    cfunc = idaapi.decompile(func, None, idaapi.DECOMP_NO_CACHE)
    v = my_super_visitor()
    v.apply_to(cfunc.body, None)
    for ea, args in v.calls:
        vm_info = VMInfo(args[0], get_item_size(args[0])//4, args[2], args[3])
        print(vm_info)
        decompile(vm_info, ida_kernwin.ask_yn(
            0, 'gen c file?') == ida_kernwin.ASKBTN_BTN1)
        break


def decompile_batch(vm_infos, output):
    source = ''
    source += headers
    for vm_info in vm_infos:
        source += decompile(vm_info, False)
    source += footers

    open(output, "w").write(source)


def find_all(p, start_ea=None, end_ea=None):
    start_ea = start_ea or ida_ida.inf_get_min_ea()
    end_ea = end_ea or ida_ida.inf_get_max_ea()
    ea = start_ea
    while True:
        ea = ida_search.find_binary(
            ea, end_ea, p, 16, SEARCH_DOWN | SEARCH_NEXT | SEARCH_CASE)
        if ea == BADADDR:
            break
        yield ea


def find_vm() -> list[VMInfo]:
    vm_infos = []
    processed = set()
    for vm_stub in find_all('E2 03 00 AA E0 03 01 AA 40 00 1F D6'):
        print(f'======stub:{vm_stub:08X}======')
        for xref in idautils.XrefsTo(vm_stub):
            func = idaapi.get_func(xref.frm)
            if func:
                if func.start_ea not in processed:
                    processed.add(func.start_ea)
                    print(f'func {func.start_ea:08X}')
                    cfunc = idaapi.decompile(
                        func, None, idaapi.DECOMP_NO_CACHE)
                    v = my_super_visitor()
                    v.apply_to(cfunc.body, None)
                    for ea, args in v.calls:
                        apply_type(ea, parse_decl(
                            'void __fastcall f(uint32_t *p_bytecode, void *p_args, uint64_t *g_vals, uint64_t *p_funcs, void *pfn_callstub)', 0))
                        idaapi.decompile(func, None, idaapi.DECOMP_NO_CACHE)
                        vm_info = VMInfo(args[0], get_item_size(
                            args[0])//4, args[2], args[3])
                        print(vm_info)
                        vm_infos.append(vm_info)
            else:
                print('[OOPS]')
    return vm_infos


def decompile_all(output='vm_all.c'):
    vm_infos = find_vm()
    decompile_batch(vm_infos, output)


# gcc vm_all.c -o vm_all -O2 -g -fno-stack-protector
decompile_all()
# decompile_here()
