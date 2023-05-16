class TiktokOps_tt_v29_3_4(int):
    # test_v1_alu
    V1_XOR = 0x0A
    V1_ADD = 0x20
    V1_ADD_1 = 0x39
    V1_ADD_I32 = 0x2F
    V1_AND = 0x33
    V1_OR = 0x1A
    V1_MOVH = 0x0F
    V1_CMP = 0x24
    V1_CMP_U64 = 0x35
    # test_v1_read_memory
    V1_READ_I8 = 0x1E
    V1_READ_I16 = 0x26
    V1_READ_I32 = 0x2D
    V1_READ_U8 = 0x37
    V1_READ_U16 = 0x0E
    V1_READ_U32 = 0x12
    V1_READ_U64 = 0x07
    # test_v1_write_memory
    V1_WRITE_U8 = 0x15
    V1_WRITE_U16 = 0x3F
    V1_WRITE_U32 = 0x06
    V1_WRITE_U64 = 0x38
    # test_v1_write_memory2
    V1_WRITE_U64_SHL = 0x22
    V1_WRITE_U64_SHR = 0x28
    # test_v1_control_flow
    V1_JUMP_EQ = 0x00
    V1_JUMP_EQ_1 = 0x18
    V1_JUMP_NE = 0x04
    V1_JUMP_NE_1 = 0x16
    V1_JUMP_GT_ZERO = 0x0B
    V1_JUMP_GT_ZERO_1 = 0x0C
    V1_JUMP_LE_ZERO = 0x05
    V1_JUMP_LE_ZERO_1 = 0x17
    V1_JUMP = 0x09
    V1_JUMP_1 = 0x27
    # test_v2_alu
    V2_OPCODE1 = 0x01
    V2_XOR = 0x31
    V2_ADD = 0x22
    V2_ADD_1 = 0x32
    V2_ADD_I32 = 0x18
    V2_ADD_I32_1 = 0x1A
    V2_SUB = 0x25
    V2_SUB_1 = 0x29
    V2_SUB_I32 = 0x1D
    V2_SUB_I32_1 = 0x39
    V2_AND = 0x09
    V2_OR = 0x30
    V2_NOR = 0x13
    V2_SHL = 0x17
    V2_SHL_X = 0x01
    V2_SHR = 0x3E
    V2_SHR_X = 0x10
    V2_SHR_U32 = 0x15
    V2_SAR = 0x0B
    V2_SAR_X = 0x14
    V2_SAR_I32 = 0x2C
    V2_SAL_I32 = 0x0A
    V2_CMP_I64 = 0x2D
    V2_CMP_U64 = 0x2B
    V2_MOVEQ = 0x1F
    V2_MOVNE = 0x2E
    V2_MUL_I32 = 0x04
    V2_MUL_I64 = 0x08
    V2_MUL_U64 = 0x2F
    V2_GET_PRODUCT_LOW = 0x3F
    V2_GET_PRODUCT_HIGH = 0x0F
    V2_SYSCALL = 0x3C
    V2_RETURN = 0x34
    # test_v2_2
    V2_OPCODE2 = 0x3E
    # ?1? = 0x17
    # ?2? = 0x05
    # ?2?_1 = 0x2F
    # # ?3? = []

TiktokOps = TiktokOps_tt_v29_3_4
