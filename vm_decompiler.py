import ctypes
from ctypes import c_int16, c_uint32
from string import Template
import ida_bytes
import ida_kernwin

# tiktok-26-1-1.apk libmetasec_ov.so

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
        assert self.v2.opcode in [1, 0x3E]
        return (self.v2.ext0 << 1) | self.v2.ext1

    @property
    def imm(self):
        if self.v2.opcode in [1, 0x3E]:
            return self.v2.imm
        return (self.v1.imm0 << 12) | (self.v1.imm1 << 6) | (self.v1.imm2)

    @property
    def imm_ext(self):
        assert self.v1.opcode not in [1, 0x3E]
        return (self.v1.src << 21) | (self.v1.dst << 16) | (self.v1.imm0 << 12) | (self.v1.imm1 << 6) | (self.v1.imm2)

    @property
    def opcode(self):
        return self.v2.opcode

    @property
    def opcode_ext(self):
        return self.v2.opcode_ext


templ = """
#include <stdint.h>
#include <stdio.h>

void ${name}(uint64_t r4 /*args*/, uint64_t r5 /*g_vars*/, uint64_t r6 /*funcs*/, uint64_t r7 /*stub*/) {
  uint64_t r0 = 0;
  uint64_t r1 = 0;
  uint64_t r2 = 0;
  uint64_t r3 = 0;
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

  uint8_t stack_buffer[0x8000];
  uint64_t r29 = (uint64_t)&stack_buffer[sizeof(stack_buffer)];

${pcode}

}

int main(void) {
  printf("%p", ${name});
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


vms = [
    VMInfo(0xD3350, 360, 0, 0x116450),

    VMInfo(0xD3D70, 68, 0, 0x1169A0),

    VMInfo(0xD4BB0, 420, 0x1173C0, 0x1173E0),
    VMInfo(0xD5240, 404, 0x117490, 0x1174B0),

    VMInfo(0xD6F90, 42, 0x117A58, 0),

    VMInfo(0xD7950, 36, 0, 0),
    VMInfo(0xD79E0, 16, 0, 0),
    VMInfo(0xD7A20, 2315, 0x1181D0, 0x1182A0),
    VMInfo(0xD9E50, 48, 0, 0x1184B0),
    VMInfo(0xD9F10, 412, 0x1184D0, 0x118510),
    VMInfo(0xDA580, 1351, 0x1185B0, 0x1185E0),
    VMInfo(0xDBAA0, 37, 0, 0),
    VMInfo(0xDBB40, 24, 0, 0),
    VMInfo(0xDBBA0, 24, 0, 0),

    VMInfo(0xDC630, 491, 0x119AC0, 0x119AE0),

    VMInfo(0xDD200, 420, 0, 0x11A170),
    VMInfo(0xDD890, 464, 0, 0x11A210),

    VMInfo(0xDE440, 316, 0, 0x11B1D0),
    VMInfo(0xDE930, 152, 0, 0x11B270),
    VMInfo(0xDEB90, 384, 0x11B2C0, 0x11B2D0),
    VMInfo(0xDF190, 581, 0x11B388, 0x11B3A0),

    VMInfo(0xDFE40, 504, 0x11B8C8, 0x11B8E0),
]


class Pcode:
    def __init__(self, label, pcode) -> None:
        self.label = label
        self.pcode = pcode

    def __str__(self) -> str:
        return self.label+self.pcode


def decompile(vm: VMInfo, gen_c=False):
    def label(pc):
        return f"L_{pc:08X}"

    pcodes = []
    for i in range(vm.size):
        pc = vm.vmentry + i * 4
        inst = Inst(ida_bytes.get_dword(pc))
        if inst.asdword == 0:
            break
        if inst.opcode in [1, 0x3E]:
            text = f"/*v2 {inst.opcode_ext:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} x:r{inst.ext} imm:{inst.imm}"
            if inst.opcode == 1:
                match inst.opcode_ext:
                    case 0x04:
                        text = f"field_120 = (int32_t)((int64_t)(int32_t)r{inst.dst}*(int64_t)(int32_t)r{inst.src}); field_128 = ((int64_t)(int32_t)r{inst.dst}*(int64_t)(int32_t)r{inst.src}) >> 32;"
                    case 0x0F:
                        text = f"r{inst.ext} = field_128;"
                    case 0x13:
                        text = f"r{inst.ext} = ~(r{inst.dst} | r{inst.src});"
                    case 0x09:
                        text = f"r{inst.ext} = r{inst.dst} & r{inst.src};"
                    case 0x30:
                        text = f"r{inst.ext} = r{inst.dst} | r{inst.src};"
                    case 0x31:
                        text = f"r{inst.ext} = r{inst.dst} ^ r{inst.src};"
                    case 0x2C:
                        text = f"r{inst.ext} = (int32_t)r{inst.dst} >> {inst.imm};"
                    case 0x0A:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} << {inst.imm});"
                    case 0x15:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} >> {inst.imm});"
                    case 0x01:
                        text = f"r{inst.ext} = r{inst.dst} << {inst.imm|0x20};"
                    case 0x17:
                        text = f"r{inst.ext} = r{inst.dst} << {inst.imm};"
                    case 0x16:  # NOP ?
                        text = ';/* nop */'
                        pass
                    case 0x3C:
                        text = f"((void (*)(uint64_t, uint64_t))r{inst.src})(r4, r5); /* call r{inst.src}(r4, r5) */"
                    case 0x34:
                        text = f"return; // d:r{inst.dst} s:r{inst.src} x:r{inst.ext} imm:{inst.imm};"
                    case 0x29:
                        text = f"r{inst.ext} = r{inst.src} - r{inst.dst};"
                    case 0x32:
                        text = f"r{inst.ext} = r{inst.dst} + r{inst.src};"
                    case 0x2B:
                        text = f"r{inst.ext} = r{inst.src} < r{inst.dst};"
                    case 0x2D:
                        text = f"r{inst.ext} = (int64_t)r{inst.src} < (int64_t)r{inst.dst};"
                    case 0x18:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.dst} + (uint32_t)r{inst.src});"
                    case 0x39:
                        text = f"r{inst.ext} = (int32_t)((uint32_t)r{inst.src} - (uint32_t)r{inst.dst});"
                    case 0x1F:
                        text = f"if (r{inst.dst}) r{inst.ext} = r{inst.src};"
                    case 0x2E:
                        text = f"if (!r{inst.dst}) r{inst.ext} = r{inst.src};"
                    case 0x10:
                        text = f"r{inst.ext} = (r{inst.dst} >> {inst.imm|0x20}) | (r{inst.dst} << {64-(inst.imm|0x20)});"
                    case 0x3E:
                        text = f"r{inst.ext} = (r{inst.dst} >> {inst.imm}) | (r{inst.dst} << {64-inst.imm});"
            elif inst.opcode == 0x3E:
                text = f"/*v2@{inst.opcode_ext:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} x:{inst.ext} imm:{inst.imm}"
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
            text = f"/*v1 {inst.opcode:02X} {inst.asdword:08X}*/ d:r{inst.dst} s:r{inst.src} imm:0x{inst.imm:04X}"
            match inst.opcode:
                case 0x0F:
                    text = f"r{inst.dst} = {hex(imm_s<<16)};"
                case 0x03:
                    # float handler
                    pass
                case 0x04:
                    target = pc + 4 + imm_s * 4
                    text = f"if (r{inst.dst} != r{inst.src}) goto {label(target)};"
                case 0x00:
                    target = pc + 4 + imm_s * 4
                    text = f"if (r{inst.dst} == r{inst.src}) goto {label(target)};"
                case 0x05:
                    target = pc + 4 + imm_s * 4
                    text = f"if ((int64_t)r{inst.src} < 1) goto {label(target)};"
                case 0x0B:
                    target = pc + 4 + imm_s * 4
                    text = f"if ((int64_t)r{inst.src} > 0) goto {label(target)};"
                case 0x20:
                    text = f"r{inst.dst} = r{inst.src} + {hex(imm_s)};"
                case 0x39:
                    text = f"r{inst.dst} = r{inst.src} + {hex(imm_s)};"
                case 0x2F:
                    text = f"r{inst.dst} = (int32_t)r{inst.src} + (int64_t){hex(imm_s)};"
                case 0x09:
                    text = f"goto {label(vm.vmentry+inst.imm_ext*4)};"
                case 0x24:
                    text = f"r{inst.dst} = (int64_t)r{inst.src} < {imm_s};"
                case 0x1E:
                    text = f"r{inst.dst} = *(int8_t *)(r{inst.src}+{hex(imm_s)});"
                case 0x2D:
                    text = f"r{inst.dst} = *(int32_t *)(r{inst.src}+{hex(imm_s)});"
                case 0x37:
                    text = f"r{inst.dst} = *(uint8_t *)(r{inst.src}+{hex(imm_s)});"
                case 0x0E:
                    text = f"r{inst.dst} = *(uint16_t *)(r{inst.src}+{hex(imm_s)});"
                case 0x12:
                    text = f"r{inst.dst} = *(uint32_t *)(r{inst.src}+{hex(imm_s)});"
                case 0x07:
                    # if vm.g_vars and inst.src == 5:
                    #     text = f"r{inst.dst} = {hex(ida_bytes.get_qword(vm.g_vars+inst.imm))}; // replace: *(uint64_t *)(r{inst.src}+{hex(inst.imm)})"
                    # elif vm.funcs and inst.src == 6:
                    #     text = f"r{inst.dst} = {hex(ida_bytes.get_qword(vm.funcs+inst.imm))}; // replace: *(uint64_t *)(r{inst.src}+{hex(inst.imm)})"
                    # else:
                    text = f"r{inst.dst} = *(uint64_t *)(r{inst.src}+{hex(inst.imm)});"
                case 0x15:
                    text = f"*(uint8_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case 0x3F:
                    text = f"*(uint16_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case 0x06:
                    text = f"*(uint32_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case 0x38:
                    text = f"*(uint64_t *)(r{inst.src}+{hex(imm_s)}) = r{inst.dst};"
                case 0x33:
                    text = f"r{inst.dst} = r{inst.src} & {hex(inst.imm)};"
                case 0x1A:
                    text = f"r{inst.dst} = r{inst.src} | {hex(inst.imm)};"
                case 0x0A:
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

    if gen_c:
        open(f"vm_{vm.vmentry:08X}_{vm.size}.c", "w").write(
            templ_obj.substitute(name=f'foo_{vm.vmentry:08X}', pcode=s))
        # 生成后直接用gcc编译, 然后使用IDA打开分析.


decompile(vms[2], ida_kernwin.ask_yn(0, 'gen c file?') == 1)

# for vm in vms:
#     decompile(vm, True)
