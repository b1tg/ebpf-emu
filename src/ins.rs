use std::u64;

/// eBPF classes: BPF_CLASS(code)
/// 占用3bits
use crate::Source::IMM;
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
// 0x71 0b0111_0001 ldxb dst, [src+off]

// size占2个bits
const SIZE_W: u8 = 0x00; // 0_0 word        4-bytes
const SIZE_H: u8 = 0x08; // 0_1 half-word   2-bytes
const SIZE_B: u8 = 0x10; // 1_0 byte        1-bytes
const SIZE_DW: u8 = 0x18; // 1_1 double-word 8-bytes

// mode占3个bits
// constant
// const MODE_IMM: u8 = 0x00; // 000?_ used for 32-bit mov in classic BPF and 64-bit in eBPF
// packet data  at a fixed offset
// legacy BPF packet access (absolute)
// const MODE_ABS: u8 = 0x20; // 001?_
// packet data at a variable offset
// const MODE_IND: u8 = 0x40; // 010?_
// a word in the scratch memory store
// const MODE_MEM: u8 = 0x60; // 011?_
// the packet length
// const MODE_LEN: u8 = 0x80; // 100?_ classic BPF only, reserved in eBPF

// const MODE_MSH: u8 = 0xa0; /* classic BPF only, reserved in eBPF */
// const MODE_XADD: u8 = 0xc0; /* eBPF only, exclusive add */
#[cfg(test)]
mod tests {
    use super::*;
    use crate::AOp::*;
    use crate::Class::*;
    use crate::Code::*;
    use crate::JOp::EXIT;
    use crate::Source::*;
    use crate::OP::alu;
    use crate::OP::jmp;
    #[test]
    fn basic_ins() {
        let hx = "b7  00  00  00  00  00  00  00  17  00  00  00  01  00  00  00  74  00  00  00  08  00  00  00  95  00  00  00  00  00  00  00";
        let hx = hx.trim().replace(" ", "");
        let byte_code: Vec<u64> = (0..hx.len())
            .step_by(16)
            .map(|i| u64::from_str_radix(&hx[i..i + 16], 16).unwrap())
            .collect();
        let ins_list = u64s_to_instructions(&byte_code);
        // bpf_conformance/tests/rsh32-imm.data
        assert_eq!(
            ins_list,
            vec![
                // mov %r0, 0
                Instruction {
                    imm: 0,
                    imm64: 0,
                    off: 0,
                    src: Register::R0,
                    dst: Register::R0,
                    code: AJ {
                        op: alu(AOp::MOV,),
                        source: IMM,
                        class: ALU64,
                    },
                },
                // sub %r0, 1
                Instruction {
                    imm: 1,
                    imm64: 1,
                    off: 0,
                    src: Register::R0,
                    dst: Register::R0,
                    code: AJ {
                        op: alu(AOp::SUB,),
                        source: IMM,
                        class: ALU64,
                    },
                },
                // rsh32 %r0, 8
                Instruction {
                    imm: 8,
                    imm64: 8,
                    off: 0,
                    src: Register::R0,
                    dst: Register::R0,
                    code: AJ {
                        op: alu(RSH,),
                        source: IMM,
                        class: ALU,
                    },
                },
                // exit
                Instruction {
                    imm: 0,
                    imm64: 0,
                    off: 0,
                    src: Register::R0,
                    dst: Register::R0,
                    code: AJ {
                        op: jmp(EXIT,),
                        source: IMM,
                        class: JMP,
                    },
                },
            ]
        );
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub imm: i32,      // 32-bits
    pub imm64: i64,    // 64-bits
    pub off: i16,      // 16-bits
    pub src: Register, // 4-bits
    pub dst: Register, // 4-bits
    pub code: Code,    // 8-bits
                       // pub backing_data: u64,    // 8-bits
}
pub fn hexs_to_u8s(hx: &str) -> Result<Vec<u8>, String> {
    let hx = hx.trim().replace(" ", "");
    let mut res: Vec<u8> = vec![];
    for i in (0..hx.len()).step_by(2) {
        res.push(
            u8::from_str_radix(
                hx.get(i..i + 2).ok_or("invalid hex format".to_string())?,
                16,
            )
            .map_err(|e| e.to_string())?,
        );
    }
    Ok(res)
}
pub fn hexs_to_u64s(hx: &str) -> Result<Vec<u64>, String> {
    let hx = hx.trim().replace(" ", "");
    let mut res: Vec<u64> = vec![];
    for i in (0..hx.len()).step_by(16) {
        res.push(
            u64::from_str_radix(
                hx.get(i..i + 16)
                    .ok_or("invalid hex format for u64".to_string())?,
                16,
            )
            .map_err(|e| e.to_string())?,
        );
    }
    Ok(res)
}

pub fn hexs_to_u64s_le(hx: &str) -> Result<Vec<u64>, String> {
    let hx = hx.trim().replace(" ", "");
    let mut res: Vec<u64> = vec![];
    for i in (0..hx.len()).step_by(16) {
        let num = u64::from_str_radix(
            hx.get(i..i + 16)
                .ok_or("invalid hex format for u64".to_string())?,
            16,
        )
        .map_err(|e| e.to_string())?;
        res.push(u64::from_be(num));
    }
    Ok(res)
}

#[test]
fn test_hexs_to_u8s() {
    assert_eq!(hexs_to_u8s("b7 00  17 "), Ok(vec![0xb7, 0x00, 0x17]));
    assert_eq!(
        hexs_to_u8s("b7 00  170 "),
        Err("invalid hex format".to_string())
    );
    assert_eq!(hexs_to_u8s(""), Ok(vec![]));
    assert_eq!(
        hexs_to_u64s("7b  21  02  00  00  00  00  00 "),
        Ok(vec![0x7b210200_00000000])
    );
    assert_eq!(
        hexs_to_u64s_le("7b  21  02  00  00  00  00  00 "),
        Ok(vec![0x00000000_0002217b])
    );
    assert_eq!(
        hexs_to_u64s("b7 00 17 "),
        Err("invalid hex format for u64".to_string())
    );
    assert_eq!(hexs_to_u64s(""), Ok(vec![]));
}

pub fn hexs_to_instructions(hx: &str) -> Result<Vec<Instruction>, String> {
    let u64s = hexs_to_u64s(hx)?;
    Ok(u64s_to_instructions(&u64s))
}

#[test]
fn test_atomic() {
    //
    use crate::Class::*;
    use crate::Code::*;
    use crate::Register::*;
    // lock xor [%r10-8], %r1
    let hx = "db  1a  f8  ff  a0  00  00  00";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0xa0,
            imm64: 0xa0,
            off: -8,
            src: R1,
            dst: R10,
            code: LS {
                mode: Mode::ATOMIC,
                size: 24,
                class: STX,
            },
        },])
    );
    // lock or [%r10-8], %r1
    let hx = "db  1a  f8  ff  40  00  00  00 ";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0x40,
            imm64: 0x40,
            off: -8,
            src: R1,
            dst: R10,
            code: LS {
                mode: Mode::ATOMIC,
                size: 0x18,
                class: STX
            }
        }])
    );
    // lock or32 [%r10-8], %r1
    // the difference lies in size
    let hx = "c3  1a  f8  ff  40  00  00  00 ";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0x40,
            imm64: 0x40,
            off: -8,
            src: R1,
            dst: R10,
            code: LS {
                mode: Mode::ATOMIC,
                size: 0,
                class: STX
            }
        }])
    );
}

#[test]

fn test_abc() {
    use crate::Class::*;
    use crate::Code::*;
    use crate::Register::*;
    // lddw %r0, 0x80000000
    let hx = "18  00  00  00  00  00  00  80 \
    00  00  00  00  00  00  00  00";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0,
            imm64: 0x80000000,
            off: 0,
            src: R0,
            dst: R0,
            code: LS {
                mode: Mode::IMM,
                size: 24,
                class: LD
            }
        }])
    );
    // stxdw [%r1+2], %r2
    let hx = "7b  21  02  00  00  00  00  00";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0,
            imm64: 0,
            off: 2,
            src: R2,
            dst: R1,
            code: LS {
                mode: Mode::MEM,
                size: 24,
                class: STX
            }
        }])
    );
    // lddw %r0, 0x123456789abcdef0
    let hx = "18  00  00  00  f0  de  bc  9a \
        00  00  00  00  78  56  34  12";
    assert_eq!(
        hexs_to_instructions(hx),
        Ok(vec![Instruction {
            imm: 0,
            imm64: 0x123456789abcdef0,
            off: 0,
            src: R0,
            dst: R0,
            code: LS {
                mode: Mode::IMM,
                size: 24,
                class: LD
            }
        }])
    );
}

pub fn u64s_to_instructions(u64s0: &[u64]) -> Vec<Instruction> {
    let u64s: Vec<u64> = u64s0.into_iter().map(|x| u64::from_be(*x)).collect();
    // for u in u64s {
    //     let ins = Instruction::from(u)
    // }
    let mut res = vec![];
    let mut i = 0;
    loop {
        if i >= u64s.len() {
            break;
        }
        let mut ins = Instruction::from(u64s[i]);
        if let Code::LS { size, mode, .. } = ins.code {
            // TODO: lddw 这类指令会占用两个64位，暂时忽略第二个处理
            // lddw %r0, 0x8000_0000
            // 18  00  00  00  00  00  00  80
            // 00  00  00  00  00  00  00  00
            // bpf_conformance/tests/neg32-intmin-imm.data
            // 0: Instruction { imm: -2147483648, imm64: -2147483648, off: 0, src: R0,
            // dst: R0, code: LS { mode: IMM, size: 24, class: LD } }
            // 但 stxdw 在size==24时为什么不用64， bpf_conformance/tests/stxdw.data
            // stxdw [%r1+2], %r2
            // 7b  21  02  00  00  00  00  00
            // 3: Instruction { imm: 0, imm64: 135289, off: 2, src: R2,
            // dst: R1, code: LS { mode: MEM, size: 24, class: STX } }
            ins.imm64 = ins.imm as i64;
            // 24意思是8+16，32 bit immediate (imm) + 后面一整个u64
            if size == 24 && mode == Mode::IMM {
                i += 1;
                ins.imm64 = ins.imm as u32 as i64 + (u64s[i]) as i64;
                ins.imm = 0;
            }
        }
        res.push(ins);
        i += 1;
    }
    res
}

impl From<u64> for Instruction {
    fn from(ins: u64) -> Self {
        Self {
            imm: (ins >> 32) as i32,
            imm64: (ins >> 32) as i64,
            off: ((ins >> 16) & 0xffff) as i16,
            src: (((ins >> 12) & 0xf) as u8).into(),
            dst: (((ins >> 8) & 0xf) as u8).into(),
            code: ((ins & 0xff) as u8).into(),
            // backing_data: ins,
        }
    }
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

// #[derive(Debug, Clone)]
// enum Code {
//     AJ(AJcode), // arithmetic and jump: ALU/ALU64/JMP
//     LS(LScode), // load and store:  LD/LDX/ST/STX
// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    AJ {
        op: OP,         // 4bits
        source: Source, // 1bits
        class: Class,   // 3bits
    },
    LS {
        mode: Mode,   // 3bits
        size: u8,     // 2bits
        class: Class, // 3bits
    },
}

impl From<u8> for Code {
    fn from(code: u8) -> Self {
        let class = code & 0b111;
        if [CLASS_ALU, CLASS_ALU64].contains(&class) {
            Code::AJ {
                op: OP::alu((code >> 4).into()),
                source: ((code >> 3) & 0b1).into(),
                class: (code & 0b111).into(),
            }
        } else if [CLASS_JMP, CLASS_JMP32].contains(&class) {
            Code::AJ {
                op: OP::jmp((code >> 4).into()),
                source: ((code >> 3) & 0b1).into(),
                class: (code & 0b111).into(),
            }
        } else if [CLASS_LD, CLASS_LDX, CLASS_ST, CLASS_STX].contains(&class) {
            Code::LS {
                mode: (code & 0b1110_0000).into(),
                size: code & 0b0001_1000,
                class: (code & 0b111).into(),
            }
        } else {
            unimplemented!("class: 0x{:x}", class)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[repr(u8)]
pub enum Mode {
    IMM = 0x00,
    ABS = 0x20,
    IND = 0x40,
    MEM = 0x60,
    ATOMIC = 0xc0,
}

impl From<u8> for Mode {
    fn from(val: u8) -> Self {
        assert!(val <= 0xc0);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Mode) }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Source {
    IMM = 0,
    SRC,
}

impl From<u8> for Source {
    fn from(val: u8) -> Self {
        assert!(val <= 0x1);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const Source) }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum OP {
    alu(AOp),
    jmp(JOp),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum AOp {
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum JOp {
    JA = 0,
    JEQ,
    JGT,
    JGE,
    JSET,
    JNE,
    JSGT,
    JSGE,
    CALL,
    EXIT,
    JLT,
    JLE,
    JSLT,
    JSLE,
}

impl From<u8> for AOp {
    fn from(val: u8) -> Self {
        assert!(val <= 0xd);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const AOp) }
    }
}
impl From<u8> for JOp {
    fn from(val: u8) -> Self {
        assert!(val <= 0xd);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const JOp) }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
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
