const CLASS_LD: u8 = 0x00;
const CLASS_LDX: u8 = 0x01;
const CLASS_ST: u8 = 0x02;
const CLASS_STX: u8 = 0x03;
const CLASS_ALU: u8 = 0x04;
const CLASS_JMP: u8 = 0x05;
const CLASS_JMP32: u8 = 0x06;
const CLASS_ALU64: u8 = 0x07;
/// only use 3-bits 0b111
const MASK_CLASS: u8 = 0b111;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub imm: i32,      // 32-bits
    pub imm64: i64,    // 64-bits
    pub off: i16,      // 16-bits
    pub src: Register, // 4-bits
    pub dst: Register, // 4-bits
    pub code: Code,    // 8-bits
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

pub fn hexs_to_instructions(hx: &str) -> Result<Vec<Instruction>, String> {
    let u64s = hexs_to_u64s(hx)?;
    Ok(u64s_to_instructions(&u64s))
}

pub fn u64s_to_instructions(u64s0: &[u64]) -> Vec<Instruction> {
    let u64s: Vec<u64> = u64s0.into_iter().map(|x| u64::from_be(*x)).collect();
    let mut res = vec![];
    let mut i = 0;
    loop {
        if i >= u64s.len() {
            break;
        }
        let mut ins = Instruction::from(u64s[i]);
        // Instructions with the BPF_IMM mode modifier use the wide instruction
        // encoding for an extra imm64 value.
        if let Code::LS {
            mode: Mode::IMM, ..
        } = ins.code
        {
            i += 1;
            ins.imm64 = ins.imm as u32 as i64 + (u64s[i]) as i64;
            ins.imm = 0;
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
        }
    }
}

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
        let class = code & MASK_CLASS;
        if [CLASS_ALU, CLASS_ALU64].contains(&class) {
            Code::AJ {
                op: OP::Alu((code >> 4).into()),
                source: ((code >> 3) & 0b1).into(),
                class: (code & MASK_CLASS).into(),
            }
        } else if [CLASS_JMP, CLASS_JMP32].contains(&class) {
            Code::AJ {
                op: OP::Jmp((code >> 4).into()),
                source: ((code >> 3) & 0b1).into(),
                class: (code & MASK_CLASS).into(),
            }
        } else if [CLASS_LD, CLASS_LDX, CLASS_ST, CLASS_STX].contains(&class) {
            Code::LS {
                mode: (code & 0b1110_0000).into(),
                size: code & 0b0001_1000,
                class: (code & MASK_CLASS).into(),
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
    Alu(AOp),
    Jmp(JOp),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AOp::*;
    use crate::Class::*;
    use crate::Code::*;
    use crate::JOp::EXIT;
    use crate::Source::*;
    use crate::OP::Alu;
    use crate::OP::Jmp;
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

    #[test]
    fn test_atomic() {
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

    fn test_wide() {
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
                        op: Alu(AOp::MOV,),
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
                        op: Alu(AOp::SUB,),
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
                        op: Alu(RSH,),
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
                        op: Jmp(EXIT,),
                        source: IMM,
                        class: JMP,
                    },
                },
            ]
        );
    }
}
