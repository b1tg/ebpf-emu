use std::ptr::copy_nonoverlapping;

use crate::{AOp, Class, Code, Instruction, JOp, Mmu, Mode, Source, OP};
const ATOMIC_XOR: i64 = 0xa0; // 0
const ATOMIC_AND: i64 = 0x50;
const ATOMIC_OR: i64 = 0x40;
const ATOMIC_ADD: i64 = 0x00;
const _ATOMIC_FETCH_ADD: i64 = 0x01; // FETCH instructions with 0x01
const ATOMIC_XCHG: i64 = 0xe0; // 0xe1
const ATOMIC_CMPXCHG: i64 = 0xf0; // 0xf1
#[derive(Debug)]
pub struct State {
    pub regs: [i64; 11],
    pub mmu: Mmu,
}

#[derive(Debug)]
pub struct Emu {
    pub state: State,
    ins_count: u32,
    pc: u32,
    pub instructions: Vec<Instruction>,
    is_xdp: bool,
    pub fp: Vec<u32>,
    debug: bool,
}

impl Default for Emu {
    fn default() -> Self {
        Self {
            pc: 0,
            state: State {
                regs: [0; 11],
                mmu: Mmu { memory: vec![] },
            },
            instructions: Vec::new(),
            ins_count: 0,
            is_xdp: false,
            fp: vec![],
            debug: std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string()) == "1",
        }
    }
}

impl Emu {
    fn step(&mut self) -> Option<()> {
        if let Some(ins) = self.instructions.get(self.pc as usize) {
            if self.debug {
                println!(
                    "regs: pc={} r0=0x{:x}, r1=0x{:x}, r2=0x{:x}, r3=0x{:x}, r4=0x{:x}, r10=0x{:x}",
                    self.pc,
                    self.state.regs[0],
                    self.state.regs[1],
                    self.state.regs[2],
                    self.state.regs[3],
                    self.state.regs[4],
                    self.state.regs[10],
                );
                println!("{}: {:?}", self.pc, ins);
            }
            self.pc += 1;
            match &ins.code {
                Code::AJ { op, source, class } => {
                    let (mut src, _src_desc) = match &source {
                        Source::IMM => (ins.imm as i64, format!("0x{:x}", ins.imm)),
                        Source::SRC => (
                            self.state.regs[ins.src as u8 as usize] as i64,
                            format!("{:?}", ins.src),
                        ),
                    };
                    match &class {
                        Class::ALU | Class::ALU64 => {
                            let dst = &mut self.state.regs[ins.dst as u8 as usize];
                            if *class == Class::ALU && *op != OP::Alu(AOp::END) {
                                *dst = *dst as u32 as i64;
                                src = src as u32 as i64;
                            }
                            match op {
                                OP::Alu(AOp::ADD) => {
                                    *dst = (*dst).wrapping_add(src);
                                }
                                OP::Alu(AOp::SUB) => {
                                    *dst = (*dst).wrapping_sub(src);
                                }
                                OP::Alu(AOp::MUL) => {
                                    *dst = (*dst).wrapping_mul(src);
                                }
                                OP::Alu(AOp::DIV) => {
                                    if src != 0 {
                                        // so, ebpf want unsigned div here, signed div have another instruction sdiv
                                        // but, why other instructions use signed ops
                                        // https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=d548d7e7229257857d075d2964c13bf5
                                        (*dst) = (*dst as u64).wrapping_div(src as u64) as i64;
                                    } else {
                                        // case: div32-by-zero-reg.data wants this
                                        *dst = 0;
                                    }
                                }
                                OP::Alu(AOp::OR) => {
                                    (*dst) |= src;
                                }
                                OP::Alu(AOp::AND) => {
                                    (*dst) &= src;
                                }
                                OP::Alu(AOp::LSH) => {
                                    // case lsh32-reg-neg.data
                                    // why lsh32 0x11(0x0000_0011) -4 get 0x1000_0000 ?
                                    // because -4 is fffffffc, the shift here use unsigned value
                                    // fffffffc = 7*4 + (8*4)*n
                                    if *class == Class::ALU {
                                        (*dst) = (*dst as u32).wrapping_shl(src as u32) as i64;
                                    } else {
                                        (*dst) = (*dst as u64).wrapping_shl(src as u32) as i64;
                                    }
                                }
                                OP::Alu(AOp::RSH) => {
                                    if *class == Class::ALU {
                                        (*dst) = (*dst as u32).wrapping_shr(src as u32) as i64;
                                    } else {
                                        (*dst) = (*dst as u64).wrapping_shr(src as u32) as i64;
                                    }
                                }
                                OP::Alu(AOp::NEG) => (*dst) = dst.wrapping_mul(-1),
                                OP::Alu(AOp::MOD) => {
                                    if src != 0 {
                                        // mod need unsigned values too
                                        (*dst) = ((*dst as u64) % (src as u64)) as i64;
                                    } else {
                                        // mod64-by-zero-reg.data don't want this
                                        // why not like div?
                                        // *dst = 0;
                                    }
                                }
                                OP::Alu(AOp::XOR) => {
                                    (*dst) ^= src;
                                }
                                OP::Alu(AOp::MOV) => {
                                    (*dst) = src;
                                }
                                OP::Alu(AOp::ARSH) => {
                                    let sign = if *class == Class::ALU && (*dst as i32) < 0 {
                                        -1
                                    } else if *class == Class::ALU64 && *dst < 0 {
                                        -1
                                    } else {
                                        1
                                    };
                                    // case: arsh32-imm-high.data
                                    // WTF: how the shift happend? the shift wrapping from one side to another
                                    // # %r0 == 0x8000_0000
                                    // arsh32 %r0, 48
                                    // -- result
                                    // 0xffff8000
                                    if *class == Class::ALU {
                                        let mut dst32 = *dst as u32 as i32;
                                        dst32 = dst32.rotate_right(src as u32);
                                        (*dst) = dst32 as i64 * sign as i64
                                    } else {
                                        (*dst) = dst.rotate_right(src as u32);
                                        (*dst) = *dst as i64 * sign as i64
                                    }
                                }
                                OP::Alu(AOp::END) => {
                                    // Byteswap instructions class=CLASS_ALU op=BPF_END
                                    // 0xd4 0b1101_0100 (imm=16) le16 dst : dst = htole16(dst)
                                    // 0xd4 0b1101_0100 (imm=32) le32 dst
                                    // 0xdc 0b1101_1100 (imm=16) be16 dst
                                    match ins.imm {
                                        16 => {
                                            match &source {
                                                Source::IMM => {
                                                    (*dst) =
                                                        i16::to_le(*dst as u16 as i16) as u16 as i64
                                                }
                                                Source::SRC => {
                                                    (*dst) =
                                                        i16::to_be(*dst as u16 as i16) as u16 as i64
                                                }
                                            };
                                        }
                                        32 => {
                                            match &source {
                                                Source::IMM => {
                                                    (*dst) =
                                                        i32::to_le(*dst as u32 as i32) as u32 as i64
                                                }
                                                Source::SRC => {
                                                    (*dst) =
                                                        i32::to_be(*dst as u32 as i32) as u32 as i64
                                                }
                                            };
                                        }
                                        64 => {
                                            match &source {
                                                Source::IMM => {
                                                    (*dst) = i64::to_le(*dst as i64) as i64
                                                }
                                                Source::SRC => {
                                                    (*dst) = i64::to_be(*dst as i64) as i64;
                                                }
                                            };
                                        }
                                        _ => {
                                            unreachable!("unsupported BPF_END bits {}", ins.imm);
                                        }
                                    }
                                }
                                _ => {
                                    unimplemented!();
                                }
                            }
                            if *class == Class::ALU && *op != OP::Alu(AOp::END) {
                                *dst = *dst as u32 as i64;
                            }
                        }
                        Class::JMP | Class::JMP32 => {
                            let off = ins.off as i32;
                            let mut dst = self.state.regs[ins.dst as u8 as usize];
                            if *class == Class::JMP32 {
                                dst = dst as i32 as i64;
                                src = src as i32 as i64;
                            }
                            match op {
                                OP::Jmp(JOp::JA) => {
                                    self.pc = self.pc.wrapping_add_signed(off);
                                }
                                OP::Jmp(JOp::JEQ) => {
                                    if dst as i64 == src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JGT) => {
                                    if dst as i64 > src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JGE) => {
                                    if dst as i64 >= src {
                                        // TODO: 到底是用wrapping还是用符号数
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JSET) => {
                                    if (dst as i64 & src) != 0 {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JNE) => {
                                    if dst as i64 != src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JSGT) => {
                                    if dst as i64 > src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JSGE) => {
                                    if dst as i64 >= src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::CALL) => {
                                    if source == &Source::IMM {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                        self.fp.push(self.pc + 1);
                                    } else {
                                        todo!()
                                    }
                                }
                                OP::Jmp(JOp::EXIT) => {
                                    if self.is_xdp {
                                        // println!(
                                        //     "exit, R0={:?}(0x{:x})",
                                        //     xdp_action::from(self.state.regs[0] as u8),
                                        //     self.state.regs[0]
                                        // );
                                    } else {
                                        // println!(
                                        //     "exit, R0={:?}(0x{:x})",
                                        //     self.state.regs[0] as u8,
                                        //     self.state.regs[0]
                                        // );
                                    }
                                    if self.fp.len() > 0 {
                                        self.pc = self.fp.pop().unwrap();
                                    } else {
                                        return None;
                                    }
                                }
                                OP::Jmp(JOp::JLT) => {
                                    if (dst as i64) < src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JLE) => {
                                    if dst as i64 <= src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JSLT) => {
                                    if (dst as i64) < src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::Jmp(JOp::JSLE) => {
                                    if (dst as i64) <= src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                _ => {
                                    unreachable!();
                                }
                            }
                        }
                        _ => {
                            unimplemented!();
                        }
                    }
                }
                // Load & Store
                Code::LS { mode, size, class } => {
                    let (w, size_sign) = match size {
                        0x00 => (4, "W"),
                        0x08 => (2, "H"),
                        0x10 => (1, "B"),
                        0x18 => (8, "DW"),
                        _ => unreachable!(),
                    };
                    let imm = ins.imm64;
                    let mut src = self.state.regs[ins.src as u8 as usize];
                    let mut R0 = self.state.regs[0];
                    let dst = &mut self.state.regs[ins.dst as u8 as usize];
                    if self.debug {
                        println!(
                            "{:?}[{}] {:?}, [{:?} +off]",
                            &class, size_sign, &ins.dst, &ins.src
                        );
                    }
                    match &class {
                        Class::LD | Class::LDX => {
                            match *mode {
                                Mode::IMM => {
                                    // panic!("???");
                                    // BPF_LD | BPF_DW | BPF_IMM
                                    // assert!(w == 0xffff_ffff);
                                    // dbg!(imm, w, imm & (1 << w * 8 - 1));
                                    // (*dst) = imm & (1 << w * 8 - 1);
                                    (*dst) = imm; // & (1 << w * 8 - 1);
                                }
                                // | 0x40
                                Mode::ABS | Mode::IND => {
                                    // ABS: legacy BPF packet access (absolute)
                                    // IDN: legacy BPF packet access (indirect)
                                    // (deprecated)
                                    unreachable!();
                                }
                                // 0x60
                                Mode::MEM => {
                                    assert!(class == &Class::LDX);
                                    // regular load and store operations
                                    // dst_reg = *(size *) (src_reg + off)
                                    unsafe {
                                        copy_nonoverlapping(
                                            self.state.mmu.read_ptr_mut::<u8>(
                                                (src as i64 + ins.off as i64) as usize,
                                            ),
                                            dst as *mut i64 as *mut u8,
                                            w as _,
                                        );
                                    };
                                }
                                _ => unreachable!(),
                            }
                        }
                        Class::ST | Class::STX => {
                            let mut source = match &class {
                                Class::ST => imm,
                                Class::STX => src,
                                _ => unreachable!(),
                            };
                            match *mode {
                                Mode::MEM => {
                                    // regular load and store operations
                                    // *(size *) (dst_reg + off) = src_reg
                                    unsafe {
                                        copy_nonoverlapping(
                                            &mut source as *mut i64 as *mut u8,
                                            self.state.mmu.read_ptr_mut::<u8>(
                                                (*dst as i64 + ins.off as i64) as usize,
                                            ),
                                            w as _,
                                        )
                                    };
                                }
                                Mode::ATOMIC => {
                                    let mut tmp_dst = self
                                        .state
                                        .mmu
                                        .read::<i64>((*dst + ins.off as i64) as usize);
                                    let with_fetch = imm & 0x01 == 0x01;
                                    let mut old_dst: i64 = 0;
                                    if with_fetch {
                                        old_dst = tmp_dst;
                                    }
                                    let mut high_dst = 0;
                                    if *size == 0 {
                                        src = src as u32 as i64;
                                        high_dst = tmp_dst as u64 >> 32;
                                        tmp_dst = tmp_dst as u32 as i64;
                                        R0 = R0 as u32 as i64;
                                        old_dst = old_dst as u32 as i64;
                                    }
                                    // use imm to encode atomic operations
                                    match imm & 0b1111_1110 {
                                        ATOMIC_ADD => {
                                            tmp_dst += src;
                                        }
                                        ATOMIC_OR => {
                                            tmp_dst |= src;
                                        }
                                        ATOMIC_AND => {
                                            tmp_dst &= src;
                                        }
                                        ATOMIC_XOR => {
                                            tmp_dst ^= src;
                                        }
                                        ATOMIC_XCHG => {
                                            // lock xchg [%r10-8], %r1
                                            (tmp_dst, old_dst) = (src, tmp_dst);
                                        }
                                        ATOMIC_CMPXCHG => {
                                            // # Atomically compare %r0 and [%r10-8] and \
                                            //  set [%r10-8] to %r1 if matches.
                                            // lock cmpxchg [%r10-8], %r1
                                            // lock cmpxchg32 [%r10-8], %r1
                                            // TODO: should R1 changed?
                                            // println!("== cmpxchg, {:x} => {:x}, old_dst: {:x}", tmp_dst, R0, old_dst);
                                            if tmp_dst == R0 {
                                                tmp_dst = src;
                                            }
                                            R0 = old_dst;
                                        }
                                        _ => {
                                            unimplemented!(
                                                "unknow atomic instruction, imm=0x{:x}",
                                                imm
                                            )
                                        }
                                    };
                                    tmp_dst = tmp_dst + (high_dst << 32) as i64;
                                    self.state.mmu.write(
                                        (*dst + ins.off as i64) as usize,
                                        &tmp_dst.to_le_bytes(),
                                    );
                                    if with_fetch {
                                        src = old_dst;
                                        self.state.regs[ins.src as u8 as usize] = src;
                                    }
                                    // TODO: ugly
                                    if imm & 0b1111_1110 == ATOMIC_CMPXCHG {
                                        self.state.regs[0] = R0;
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                        _ => todo!(),
                    }
                }
            }
            self.ins_count += 1;
            return Some(());
        } else {
            return None;
        }
    }
    pub fn run(&mut self) {
        loop {
            if self.step().is_none() {
                break;
            }
        }
    }
}
