pub fn add(left: usize, right: usize) -> usize {
    left + right
}
#[repr(C)]
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
}

#[repr(C)]
struct xdp_md {
    // u32 data,
    // u32 data_end,
    // u32 data_meta,
    // /* Below access go through struct xdp_rxq_info */
    // u32 ingress_ifindex, /* rxq->dev->ifindex */
    // u32 rx_queue_index,  /* rxq->queue_index  */
    // u32 egress_ifindex,  /* txq->dev->ifindex */
}

// ebpf have 10 internal registers and a read-only frame pointer

// Therefore, eBPF calling convention is defined as:
//   * R0	- return value from in-kernel function, and exit value for eBPF program
//   * R1 - R5	- arguments from eBPF program to in-kernel function
//   * R6 - R9	- callee saved registers that in-kernel function will preserve
//   * R10	- read-only frame pointer to access stack

// how if-else work:
// "if (cond) jump_true; /* else fall-through */".

// 函数参数是R1-R5, 函数内不能修改这些寄存器的值

/// Registers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Register {
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    FP, // read-only frame pointer
}

impl From<u8> for Register {
    fn from(val: u8) -> Self {
        assert!(val < 12);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Register) }
    }
}

// eBPF is limited to 4096 insns

// So far 87 internal BPF instructions were implemented

// All eBPF instructions have the same basic encoding:

// msb                                                        lsb
// +------------------------+----------------+----+----+--------+
// |immediate               |offset          |src |dst |opcode  |
// +------------------------+----------------+----+----+--------+

// From least significant to most significant bit:
//     8  bit opcode (下面分两种情况讨论这8-bit code)
//     4  bit destination register (dst)
//     4  bit source register (src)
//     16 bit offset
//     32 bit immediate (imm)

#[derive(Debug)]
struct Instruction {
    imm: u32,      // 32-bits
    off: u16,      // 16-bits
    src: Register, // 4-bits
    dst: Register, // 4-bits
    code: Code,    // 8-bits
}

impl From<u64> for Instruction {
    fn from(ins: u64) -> Self {
        Self {
            imm: (ins >> 32) as u32,
            off: ((ins >> 16) & 0xffff) as u16,
            src: (((ins >> 12) & 0xf) as u8).into(),
            dst: (((ins >> 8) & 0xf) as u8).into(),
            code: ((ins & 0xff) as u8).into(),
        }
    }
}

#[test]
fn test_ins() {
    // b700 0000 0000 0000
    let ins1: u64 = 0x0000_0000_0000_00b7;

    let ins: Instruction = ins1.into();
    dbg!(ins);
}

// For arithmetic and jump, 8-bit 'code' field is divided into three parts:
// ALU/ALU64/JMP
// +----------------+--------+--------------------+
// |   4 bits       |  1 bit |   3 bits           |
// | operation code | source | instruction class  |
// +----------------+--------+--------------------+
// (MSB)                                      (LSB)

// For load and store instructions the 8-bit 'code' field is divided as:
// LD/LDX/ST/STX

//   +--------+--------+-------------------+
//   | 3 bits | 2 bits |   3 bits          |
//   |  mode  |  size  | instruction class |
//   +--------+--------+-------------------+
//   (MSB)                             (LSB)

#[derive(Debug)]
enum Code {
    AJ(AJcode), // arithmetic and jump: ALU/ALU64/JMP
    LS(LScode), // load and store:  LD/LDX/ST/STX
}

impl From<u8> for Code {
    fn from(code: u8) -> Self {
        let class = code & 0b111;
        if [CLASS_ALU, CLASS_ALU64, CLASS_JMP].contains(&class) {
            Code::AJ(AJcode::from(code))
        } else if [CLASS_LD, CLASS_LDX, CLASS_ST, CLASS_STX].contains(&class) {
            Code::LS(LScode::from(code))
        } else {
            unimplemented!()
        }
    }
}

#[derive(Debug)]
struct AJcode {
    op: Op,         // 4bits
    source: Source, // 1bits
    class: Class,   // 3bits
}

#[derive(Debug)]
struct LScode {
    mode: u8,     // 3bits
    size: u8,     // 2bits
    class: Class, // 3bits
}

#[derive(Debug)]
#[repr(u8)]
enum Source {
    IMM = 0,
    SRC,
}

impl From<u8> for Source {
    fn from(val: u8) -> Self {
        assert!(val <= 0x1);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Source) }
    }
}
#[derive(Debug)]
#[repr(u8)]
enum Op {
    ADD = 0,
    SUB,
    MUL,
    DIV,
    OR,
    AND,
    LSH,
    RSH,
    NEG,
    MOD,
    XOR,
    MOV,
    ARSH,
    END,
}

impl From<u8> for Op {
    fn from(val: u8) -> Self {
        assert!(val <= 0xd);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Op) }
    }
}
#[derive(Debug)]
#[repr(u8)]
enum Class {
    LD = 0,
    LDX,
    ST,
    STX,
    ALU,
    JMP,
    JMP32,
    ALU64,
}

impl From<u8> for Class {
    fn from(val: u8) -> Self {
        assert!(val <= 7);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Class) }
    }
}

impl From<u8> for AJcode {
    fn from(code: u8) -> Self {
        AJcode {
            op: (code >> 4).into(),
            source: ((code >> 3) & 0b1).into(),
            class: (code & 0b111).into(),
        }
    }
}

impl From<u8> for LScode {
    fn from(code: u8) -> Self {
        LScode {
            mode: code >> 5,
            size: (code >> 3) & 0b11,
            class: (code & 0b111).into(),
        }
    }
}
/// eBPF classes: BPF_CLASS(code)
/// 占用3bits

const CLASS_LD: u8 = 0x00;
const CLASS_LDX: u8 = 0x01;
const CLASS_ST: u8 = 0x02;
const CLASS_STX: u8 = 0x03;
const CLASS_ALU: u8 = 0x04;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const CLASS_ALU64: u8 = 0x07;

///  BPF_SRC(code) == BPF_X - use 'src_reg' register as source operand
///  BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand
/// 这一位决定了右操作数是imm还是src
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

/// Opcode examples:
/// 64-bit CLASS_ALU64
// 0x07 0b0000_0111 add dst, imm
// 0x0f 0b0000_1111 add dst, src
// 0x17 0b0001_0111 sub dst, imm
// 0x1f 0b0001_1111 sub dst, src

/// 32-bit CLASS_ALU
// 0x04 0b0000_0100 add32 dst, imm
// 0x0c 0b0000_1100 add32 dst, src
// 0x14 0b0001_0100 sub32 dst, imm
// 0x1c 0b0001_1100 sub32 dst, src

/// Byteswap instructions class=CLASS_ALU op=BPF_END
// 0xd4 0b1101_0100 (imm=16) le16 dst : dst = htole16(dst)
// 0xd4 0b1101_0100 (imm=32) le32 dst
// 0xdc 0b1101_0100 (imm=16) be16 dst

/// Branch instructions class=CLASS_JMP
// 0x05 0b0000_0101 ja +off
// 0x3d 0b0011_1101 jge dst,src,+off
// op=OP_CALL
// 0x85 0b1000_0101 call imm
// 0x95 0b1001_0101 exit

/// If BPF_CLASS(code) == BPF_ALU or BPF_ALU64 [ in eBPF ], BPF_OP(code) is one of:

/// BPF_OP(code) == 4bits (operation code)

const OP_ADD: u8 = 0x00;
const OP_SUB: u8 = 0x10;
const OP_MUL: u8 = 0x20;
const OP_DIV: u8 = 0x30;
const OP_OR: u8 = 0x40;
const OP_AND: u8 = 0x50;
const OP_LSH: u8 = 0x60;
const OP_RSH: u8 = 0x70;
const OP_NEG: u8 = 0x80;
const OP_MOD: u8 = 0x90;
const OP_XOR: u8 = 0xa0;
const OP_MOV: u8 = 0xb0; /* eBPF only: mov reg to reg */
const OP_ARSH: u8 = 0xc0; /* eBPF only: sign extending shift right */
const OP_END: u8 = 0xd0; /* eBPF only: endianness conversion */

/// If BPF_CLASS(code) == BPF_JMP or BPF_JMP32 [ in eBPF ], BPF_OP(code) is one of:

const OP_JA: u8 = 0x00; /* BPF_JMP only */
const OP_JEQ: u8 = 0x10;
const OP_JGT: u8 = 0x20;
const OP_JGE: u8 = 0x30;
const OP_JSET: u8 = 0x40;
const OP_JNE: u8 = 0x50; /* eBPF only: jump != */
const OP_JSGT: u8 = 0x60; /* eBPF only: signed '>' */
const OP_JSGE: u8 = 0x70; /* eBPF only: signed '>=' */
const OP_CALL: u8 = 0x80; /* eBPF BPF_JMP only: function call */
const OP_EXIT: u8 = 0x90; /* eBPF BPF_JMP only: function return */
const OP_JLT: u8 = 0xa0; /* eBPF only: unsigned '<' */
const OP_JLE: u8 = 0xb0; /* eBPF only: unsigned '<=' */
const OP_JSLT: u8 = 0xc0; /* eBPF only: signed '<' */
const OP_JSLE: u8 = 0xd0; /* eBPF only: signed '<=' */

/// Example: Memory instructions
/// class=BPF_LD
// 0x18 0b0001_1000 lddw dst, imm
// 0x20 0b0010_0000 ldabsw src, dst, imm
// 0x28 0b0010_1000 ldabsh src, dst, imm

/// class=BPF_LDX
// 0x61 0b0110_0001 ldxw dst, [src+off]

// size占2个bits
const SIZE_W: u8 = 0x00; // 0_0 word        4-bytes
const SIZE_H: u8 = 0x08; // 0_1 half-word   2-bytes
const SIZE_B: u8 = 0x10; // 1_0 byte        1-bytes
const SIZE_DW: u8 = 0x18; // 1_1 double-word 8-bytes

// mode占3个bits
const MODE_IMM: u8 = 0x00; // 000?_ used for 32-bit mov in classic BPF and 64-bit in eBPF
const MODE_ABS: u8 = 0x20; // 001?_
const MODE_IND: u8 = 0x40; // 010?_
const MODE_MEM: u8 = 0x60; // 011?_
const MODE_LEN: u8 = 0x80; // 100?_ classic BPF only, reserved in eBPF
const MODE_MSH: u8 = 0xa0; /* classic BPF only, reserved in eBPF */
const MODE_XADD: u8 = 0xc0; /* eBPF only, exclusive add */

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
