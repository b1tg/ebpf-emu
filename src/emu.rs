use std::{
    ops::{Shr, SubAssign},
    ptr::copy_nonoverlapping,
};

use crate::{AOp, Class, Code, Instruction, JOp, Mmu, Mode, Source, OP};

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
    DEBUG: bool,
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
            DEBUG: std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string()) == "1",
        }
    }
}

impl Emu {
    // fn init(&mut self, r1: usize, ins: Vec<Instruction>) {
    //     self.state.regs[1] = r1 as u64;
    //     self.instructions = ins;
    //     self.DEBUG = std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string()) == "1";
    // }
    fn step(&mut self) -> Option<()> {
        if let Some(ins) = self.instructions.get(self.pc as usize) {
            // Mnemonic
            let mut mne = "".to_string();
            if self.DEBUG {
                println!(
                    "regs: pc={} r0=0x{:x}, r1=0x{:x}, r2=0x{:x}, r3=0x{:x}, r4=0x{:x}",
                    self.pc,
                    self.state.regs[0],
                    self.state.regs[1],
                    self.state.regs[2],
                    self.state.regs[3],
                    self.state.regs[4]
                );
                println!("{}: {:?}", self.pc, ins);
            }
            self.pc += 1;
            match &ins.code {
                Code::AJ { op, source, class } => {
                    let (mut src, src_desc) = match &source {
                        Source::IMM => (ins.imm as i64, format!("0x{:x}", ins.imm)),
                        Source::SRC => (
                            self.state.regs[ins.src as u8 as usize] as i64,
                            format!("{:?}", ins.src),
                        ),
                    };
                    // dbg!(src, ins.src, self.state.regs[ins.src as u8 as usize], &source);
                    match &class {
                        Class::ALU | Class::ALU64 => {
                            // let src1: i32 = match &source {
                            //     Source::IMM => {
                            //         if DEBUG {
                            //             println!("{:?} {:?}, 0x{:x}", op, ins.dst, ins.imm);
                            //         }
                            //         self.state.regs[ins.src as u8 as usize] as i32
                            //     }
                            //     Source::SRC => {
                            //         if DEBUG {
                            //             println!("{:?} {:?}, {:?}", op, ins.dst, ins.src);
                            //         }
                            //         ins.imm
                            //     }
                            // };
                            let dst = match &class {
                                Class::ALU => {
                                    let dst = &mut self.state.regs[ins.dst as u8 as usize];
                                    // (*dst) &= 0x0000_0000_ffff_ffff;
                                    if *op != OP::alu(AOp::END) {
                                        *dst = *dst as u32 as i64;
                                    }
                                    dst
                                }
                                Class::ALU64 => &mut self.state.regs[ins.dst as u8 as usize],
                                _ => unreachable!(),
                            };
                            if *class == Class::ALU && *op != OP::alu(AOp::END) {
                                src = src as u32 as i64;
                            }

                            mne = format!("{:?} {:?}, {}", op, ins.dst, src_desc).to_lowercase();
                            match op {
                                OP::alu(AOp::ADD) => {
                                    // do we need wrapping_add ?
                                    (*dst) += src;
                                    // (*dst) = *dst+(src as i64);
                                }
                                OP::alu(AOp::SUB) => {
                                    (*dst) -= src;
                                    // (*dst) = dst.sub_assign(-src as i64);
                                }
                                OP::alu(AOp::MUL) => {
                                    (*dst, _) = (*dst).overflowing_mul(src as _);
                                }
                                OP::alu(AOp::DIV) => {
                                    // bpf_conformance/tests/div64-by-zero-reg.data
                                    // so we should do nothing?
                                    if src != 0 {
                                        if *class == Class::ALU {
                                            (*dst) = ((*dst as u32 as i64) / (src as u32 as i64))
                                                as u32
                                                as i64;
                                        } else {
                                            // dbg!(*dst, src);
                                            // case div64-negative-imm.data
                                            // why need 0xFFFFFFFFFFFFFFFF/-10 == 1
                                            // (*dst) /= src;
                                            // case div64-negative-reg.data:
                                            // why -1/0x0fffffff6 != 0xFFFFFFFFFFFFFFFF/0x0fffffff6
                                            (*dst) = (*dst as u64).wrapping_div(src as u64) as i64;
                                        }
                                    } else {
                                        // case: div32-by-zero-reg.data wants this
                                        *dst = 0;
                                    }
                                }
                                OP::alu(AOp::OR) => {
                                    (*dst) |= src;
                                }
                                OP::alu(AOp::AND) => {
                                    (*dst) &= src;
                                }
                                OP::alu(AOp::LSH) => {
                                    if *class == Class::ALU {
                                        (*dst) = (*dst as u32).wrapping_shl(src as u32) as i64;
                                    } else {
                                        (*dst) = (*dst as u64).wrapping_shl(src as u32) as i64;
                                    }
                                    // TODO: case lsh32-reg-neg.data
                                    // 0x0000_0011
                                    // why lsh32 0x11 -4 get 0x10000000
                                }
                                OP::alu(AOp::RSH) => {
                                    if *class == Class::ALU {
                                        (*dst) = (*dst as u32).wrapping_shr(src as u32) as i64;
                                    } else {
                                        (*dst) = (*dst as u64).wrapping_shr(src as u32) as i64;
                                    }
                                }
                                OP::alu(AOp::NEG) => {
                                    (*dst) = dst.overflowing_mul(-1).0;
                                    if *class == Class::ALU64 {
                                        // (self.state.regs[ins.dst as u8 as usize], _) =
                                        // self.state.regs[ins.dst as u8 as usize].overflowing_mul(-1);
                                        // (*dst) = dst.overflowing_mul(-1).0;
                                        // self.state.regs[ins.dst as u8 as usize] =
                                        //     0xffff_ffff_ffff_ffff
                                        //         - self.state.regs[ins.dst as u8 as usize]
                                        //         + 1;
                                    } else {
                                        // self.state.regs[ins.dst as u8 as usize]  =
                                        // self.state.regs[ins.dst as u8 as usize].overflowing_mul(-1).0 as  u32  as  i64 ;
                                        // self.state.regs[ins.dst as u8 as usize] = 0xffff_ffff
                                        //     - self.state.regs[ins.dst as u8 as usize]
                                        //     + 1;
                                    }
                                }
                                OP::alu(AOp::MOD) => {
                                    if src != 0 {
                                        // case mod64.data
                                        // why 0xb1858436100dc5c8 % 0xdde263e3cbef7f3 需要转换为u64结果才对
                                        // (*dst) %= src;
                                        (*dst) = ((*dst as u64) % (src as u64)) as i64;
                                    }
                                }
                                OP::alu(AOp::XOR) => {
                                    (*dst) ^= src;
                                }
                                OP::alu(AOp::MOV) => {
                                    // mne = format!("mov {:?}, {}", ins.dst, src_desc);
                                    if *class == Class::ALU {
                                        (*dst) = src as u32 as i64;
                                    } else {
                                        (*dst) = src;
                                    }
                                }
                                OP::alu(AOp::ARSH) => {
                                    // TODO dst >>= imm (arithmetic)
                                    // (*dst) >>= src;
                                    // unsafe { *(dst as *mut u64 as *mut i64) >>= src };
                                    // dbg!(src as u32);
                                    // TODO: -16和16是一样？
                                    // /root/ebpf-emu/bpf_conformance/tests/arsh32-imm-neg.data
                                    // # %r0 == 0x80000000
                                    // arsh32 %r0, -16

                                    let sign = if *class == Class::ALU
                                        && *dst & 0x8000_0000 == 0x8000_0000
                                    {
                                        -1
                                    } else if *class == Class::ALU64
                                        && (*dst as u64) & 0x8000_0000_0000_0000
                                            == 0x8000_0000_0000_0000
                                    {
                                        -1
                                    } else {
                                        1
                                    };
                                    // case: arsh32-imm-high.data
                                    // WTF: how the shift happend
                                    // # %r0 == 0x80000000
                                    // arsh32 %r0, 48
                                    // -- result
                                    // 0xffff8000

                                    // let sign = if *dst <0 {-1} else {1};
                                    // dbg!(sign);
                                    // dbg!(&dst, &src);
                                    if *class == Class::ALU {
                                        let mut dst32 = *dst as u32 as i32;
                                        if src < 0 {
                                            dst32 = dst32.rotate_left(src.abs() as u32);
                                        } else {
                                            dst32 = dst32.rotate_right(src.abs() as u32);
                                        }
                                        (*dst) = dst32 as i64 * sign as i64
                                    } else {
                                        // for ARSH, minus means shift left
                                        if src < 0 {
                                            (*dst) = dst.rotate_left(src.abs() as u32);
                                        } else {
                                            (*dst) = dst.rotate_right(src.abs() as u32);
                                        }
                                        (*dst) = *dst as i64 * sign as i64
                                    }
                                    // if *class == Class::ALU {
                                    //     (*dst) = (*dst as i32 * sign) as u32 as i64
                                    // } else {
                                    // }
                                }
                                // Byteswap instructions class=CLASS_ALU op=BPF_END
                                // 0xd4 0b1101_0100 (imm=16) le16 dst : dst = htole16(dst)
                                // 0xd4 0b1101_0100 (imm=32) le32 dst
                                // 0xdc 0b1101_1100 (imm=16) be16 dst
                                OP::alu(AOp::END) => {
                                    // TODO
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
                                            // be64 dst: dst = htobe64(dst)
                                            match &source {
                                                Source::IMM => {
                                                    (*dst) = i64::to_le(*dst as i64) as i64
                                                }
                                                Source::SRC => {
                                                    let tmp = i64::to_be(*dst as i64) as i64;
                                                    (*dst) = tmp;
                                                }
                                            };
                                        }
                                        _ => {
                                            unreachable!("ins.imm {}", ins.imm);
                                        }
                                    }
                                }
                                _ => {
                                    unimplemented!();
                                }
                            }

                            // println!("mne: {}", mne);
                            if *class == Class::ALU && *op != OP::alu(AOp::END) {
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
                            // println!(
                            //     "{:?} dst({:?}), {:?}({:?}|{:?}), +off({:?})",
                            //     op, ins.dst, &source, ins.src, ins.imm, ins.off
                            // );
                            match &source {
                                Source::IMM => {
                                    // println!(
                                    //     "{:?} {:?}, 0x{:x}, +0x{:x}",
                                    //     op, ins.dst, ins.imm, ins.off
                                    // );
                                }
                                Source::SRC => {
                                    // println!(
                                    //     "{:?} {:?}, {:?}, +0x{:x}",
                                    //     op, ins.dst, ins.src, ins.off
                                    // );
                                }
                            };
                            // println!("jmp: {:?}", op);
                            match op {
                                OP::jmp(JOp::JA) => {
                                    // self.pc += off;
                                    self.pc = self.pc.wrapping_add_signed(off);
                                }
                                OP::jmp(JOp::JEQ) => {
                                    // println!(
                                    //     "{}: jeq dst({}), imm({}), +off({})",
                                    //     self.pc, dst, ins.imm, off
                                    // );
                                    if dst as i64 == src {
                                        // self.pc += off;
                                        // self.pc = self.pc.wrapping_add(off);
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JGT) => {
                                    if dst as i64 > src {
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JGE) => {
                                    if dst as i64 >= src {
                                        // dbg!(self.pc, off);
                                        // self.pc += off;
                                        // TODO: 到底是用wrapping还是用符号数
                                        // self.pc = self.pc.wrapping_add(off);
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JSET) => {
                                    // TODO
                                    if (dst as i64 & src) != 0 {
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JNE) => {
                                    if dst as i64 != src {
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JSGT) => {
                                    // TODO: dst as i64 > imm (signed)
                                    if dst as i64 > src {
                                        // dbg!(self.pc, off);
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JSGE) => {
                                    if dst as i64 >= src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::CALL) => {
                                    // todo!();
                                    // TODO: function call
                                    if source == &Source::IMM {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                        self.fp.push(self.pc + 1);
                                        // self.pc = ins.imm as u32;
                                        // self.instructions
                                    } else {
                                        todo!()
                                    }
                                    // self.state.register[]
                                }
                                OP::jmp(JOp::EXIT) => {
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
                                OP::jmp(JOp::JLT) => {
                                    if (dst as i64) < src {
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JLE) => {
                                    if dst as i64 <= src {
                                        // self.pc += off;
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JSLT) => {
                                    if (dst as i64) < src {
                                        self.pc = self.pc.wrapping_add_signed(off);
                                    }
                                }
                                OP::jmp(JOp::JSLE) => {
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
                    let w = match size {
                        // W
                        0x00 => 4,
                        // H
                        0x08 => 2,
                        // B
                        0x10 => 1,
                        // DW
                        0x18 => 8,
                        _ => unreachable!(),
                    };
                    let size_sign = match size {
                        // W
                        0x00 => "W",
                        // H
                        0x08 => "H",
                        // B
                        0x10 => "B",
                        // DW
                        0x18 => "DW",
                        _ => unreachable!(),
                    };
                    // let class = class;
                    let imm = ins.imm64;
                    let src = self.state.regs[ins.src as u8 as usize];
                    let dst = &mut self.state.regs[ins.dst as u8 as usize];
                    if self.DEBUG {
                        println!(
                            "{:?}[{}] {:?}, [{:?} +off]",
                            &class, size_sign, &ins.dst, &ins.src
                        );
                    }
                    match &class {
                        Class::LD | Class::LDX => {
                            // println!(
                            //     "{:?}[{}] {:?}, [{:?} +off]",
                            //     &class, size_sign, &ins.dst, &ins.src
                            // );
                            // dst_reg = *(size *) ((imm32 | src_reg) + off)
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
                            // *(size *) (dst_reg + off) = (imm32 | src_reg)
                            let mut source = match &class {
                                Class::ST => {
                                    // println!(
                                    //     "{:?}[{}] [{:?} +off], {:?}",
                                    //     &class, size_sign, &ins.dst, &ins.imm
                                    // );
                                    imm
                                }
                                Class::STX => {
                                    // println!(
                                    //     "{:?}[{}] [{:?} +off], {:?}",
                                    //     &class, size_sign, &ins.dst, &ins.src
                                    // );
                                    src
                                }
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
                                    // match size {
                                    //     // W u32
                                    //     0x00 => unsafe {
                                    //         *(dst as *mut u64 as *mut u32).offset(imm as isize) =
                                    //             source as u32
                                    //     },
                                    //     // H u16
                                    //     0x08 => unsafe {
                                    //         *(dst as *mut u64 as *mut u16).offset(imm as isize) =
                                    //             source as u16
                                    //     },
                                    //     // B u8
                                    //     0x10 => unsafe {
                                    //         *(dst as *mut u64 as *mut u8).offset(imm as isize) =
                                    //             source as u8
                                    //     },
                                    //     // DW u64
                                    //     0x18 => unsafe {
                                    //         // dbg!(123, &dst, imm);
                                    //         // *(dst as *mut u64 as *mut u64).offset(imm as isize) =
                                    //         // source as u64
                                    //     },
                                    //     _ => unreachable!(),
                                    // };
                                }
                                Mode::ATOMIC => {
                                    todo!();
                                    // STX only
                                    // atomic operations
                                    // imm use to encode atomic operations
                                    // match imm {
                                    //     ATOMIC_ADD => {
                                    //         // (*dst.offset(off)) += src;
                                    //     }
                                    //     ATOMIC_OR => {}
                                    //     ATOMIC_AND => {}
                                    //     ATOMIC_XOR => {}
                                    //     ATOMIC_FETCH => {}
                                    //     ATOMIC_XCHG => {}
                                    //     ATOMIC_CMPXCHG => {}
                                    // };
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
            // println!("=== step to end ===");
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
