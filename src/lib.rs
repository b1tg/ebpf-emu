use core::ptr::copy_nonoverlapping;
use std::collections::VecDeque;
pub fn add(left: usize, right: usize) -> usize {
    left + right
}
// #[repr(C)]
#[derive(Debug)]
#[repr(u8)]
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
}
impl From<u8> for xdp_action {
    fn from(val: u8) -> Self {
        assert!(val < 5);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const xdp_action) }
    }
}

#[derive(Debug)]
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    // data_meta: u32,
    // Below access go through struct xdp_rxq_info
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

#[derive(Debug, Clone)]
struct Instruction {
    imm: i32,      // 32-bits
    off: i16,      // 16-bits
    src: Register, // 4-bits
    dst: Register, // 4-bits
    code: Code,    // 8-bits
}

impl From<u64> for Instruction {
    fn from(ins: u64) -> Self {
        Self {
            imm: (ins >> 32) as i32,
            off: ((ins >> 16) & 0xffff) as i16,
            src: (((ins >> 12) & 0xf) as u8).into(),
            dst: (((ins >> 8) & 0xf) as u8).into(),
            code: ((ins & 0xff) as u8).into(),
        }
    }
}

// Disassembly of section xdp/github_hosts:
// 0000000000000000 <github_hosts>:
//        0:	b7 00 00 00 00 00 00 00	r0 = 0
//        1:	61 12 04 00 00 00 00 00	r2 = *(u32 *)(r1 + 4)
//        2:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0)
//        3:	bf 13 00 00 00 00 00 00	r3 = r1
//        4:	07 03 00 00 0e 00 00 00	r3 += 14
//        5:	2d 23 11 00 00 00 00 00	if r3 > r2 goto +17 <LBB0_7>
//        6:	b7 00 00 00 01 00 00 00	r0 = 1
//        7:	69 14 0c 00 00 00 00 00	r4 = *(u16 *)(r1 + 12)
//        8:	55 04 0e 00 08 00 00 00	if r4 != 8 goto +14 <LBB0_7>
//        9:	bf 14 00 00 00 00 00 00	r4 = r1
//       10:	07 04 00 00 22 00 00 00	r4 += 34
//       11:	b7 00 00 00 00 00 00 00	r0 = 0
//       12:	2d 24 0a 00 00 00 00 00	if r4 > r2 goto +10 <LBB0_7>
//       13:	b7 00 00 00 02 00 00 00	r0 = 2
//       14:	71 33 09 00 00 00 00 00	r3 = *(u8 *)(r3 + 9)
//       15:	55 03 07 00 11 00 00 00	if r3 != 17 goto +7 <LBB0_7>
//       16:	07 01 00 00 2a 00 00 00	r1 += 42
//       17:	b7 00 00 00 00 00 00 00	r0 = 0
//       18:	2d 21 04 00 00 00 00 00	if r1 > r2 goto +4 <LBB0_7>
//       19:	69 41 02 00 00 00 00 00	r1 = *(u16 *)(r4 + 2)
//       20:	b7 00 00 00 01 00 00 00	r0 = 1
//       21:	15 01 01 00 04 d2 00 00	if r1 == 53764 goto +1 <LBB0_7>
//       22:	b7 00 00 00 02 00 00 00	r0 = 2

// 00000000000000b8 <LBB0_7>:
//       23:	95 00 00 00 00 00 00 00	exit
#[test]
fn test_udp() {
    // udp dst=0x04d2 04|210
    // '0xd204' 210|04
    let ins_list = [
        0xb7000000_00000000, // r0 = 0
        0x61120400_00000000, // r2 = *(u32 *)(r1 + 4)
        0x61110000_00000000, // r1 = *(u32 *)(r1 + 0)
        0xbf130000_00000000, // r3 = r1
        0x07030000_0e000000, // r3 += 14
        0x2d231100_00000000, // if r3 > r2 goto +17 <LBB0_7>
        0xb7000000_01000000, // r0 = 1
        0x69140c00_00000000, // r4 = *(u16 *)(r1 + 12)
        0x55040e00_08000000, // if r4 != 8 goto +14 <LBB0_7>
        0xbf140000_00000000, // r4 = r1
        0x07040000_22000000, // r4 += 34
        0xb7000000_00000000, // r0 = 0
        0x2d240a00_00000000, // if r4 > r2 goto +10 <LBB0_7>
        0xb7000000_02000000, // r0 = 2
        0x71330900_00000000, // r3 = *(u8 *)(r3 + 9)
        0x55030700_11000000, // if r3 != 17 goto +7 <LBB0_7>
        0x07010000_2a000000, // r1 += 42
        0xb7000000_00000000, // r0 = 0
        0x2d210400_00000000, // if r1 > r2 goto +4 <LBB0_7>
        0x69410200_00000000, // r1 = *(u16 *)(r4 + 2)
        0xb7000000_01000000, // r0 = 1
        0x15010100_04d20000, // if r1 == 53764 goto +1 <LBB0_7>
        0xb7000000_02000000, // r0 = 2
        0x95000000_00000000, //	exit
    ]
    .map(|x| u64::from_be(x).into());
    let mut emu = Emu::default();
    emu.state.regs[0] = 0x00;
    use std::ffi::CString;
    // tcp =>443
    let tcp_443_pkg = b"\x08\x00\x27\x8d\xc0\x4d\x52\x54\x00\x12\x35\x02\x08\x00\x45\x00\x05\xd4\xf8\xd6\x00\x00\x40\x06\xbd\x0a\x6e\xf2\x44\x42\x0a\x00\x02\x0f\x01\xbb\xb2\x88\xf4\xe2\xb2\x02\xfb\x39\xeb\xc5\x50\x18\xff\xff\xbc\x54\x00\x00";
    let udp_53_pkg = b"\x08\x00\x27\x8d\xc0\x4d\x52\x54\x00\x12\x35\x02\x08\x00\x45\x00\x00\x52\x36\x04\x00\x00\x40\x11\x28\x79\x08\x08\x08\x08\x0a\x00\x02\x0f\x00\x35\xb5\x94\x00\x3e\x8b\xa8\x1a\x17\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x2e\x52\xae\x45";
    let pkg = tcp_443_pkg;
    let pkg = udp_53_pkg;
    let mut mmu = Mmu {
        memory: pkg.to_vec(),
    };
    dbg!(&pkg.len());
    // let data_start = dns_pkg.as_ptr() as *const u8 as u64;
    // println!("data_start: 0x{:x}", data_start);
    let mut ctx = xdp_md {
        data: 0,
        data_end: mmu.memory.len() as u32 - 1,
    };
    println!("ctx: 0x{:x}, 0x{:x}", &ctx.data, &ctx.data_end);
    unsafe {
        println!(
            "ctx data+2: 0x{:x}",
            mmu.read::<u8>(ctx.data_end as usize - 2)
        );
    }
    mmu.write(0x1000, &ctx.data.to_le_bytes());
    mmu.write(0x1004, &ctx.data_end.to_le_bytes());
    println!("ctx.data : 0x{:x}", mmu.read::<u32>(0x1000));
    println!("ctx.data_end : 0x{:x}", mmu.read::<u32>(0x1004));
    let ctx_ptr = &ctx as *const xdp_md as u64;
    emu.state.regs[1] = 0x1000;
    emu.state.mmu = mmu;
    emu.instructions = ins_list.to_vec();
    // println!("{:x}", raw_ins_list[0]);
    // dbg!("before", &emu);
    emu.run();
    // dbg!("after", &emu);
}
#[test]
fn test_jmp() {
    // 2d 23 01 00 00 00 00 00 if r3 > r2 goto +1 <LBB0_95>
    let ins1: Instruction = 0x0000_0000_0001_232du64.into();
    // 85 00 00 00 19 00 00 00 call 25
    let ins2: Instruction = 0x0000_0019_0000_0085u64.into();
    // 05 00 02 00 00 00 00 00 goto +2
    let ins3: Instruction = 0x0000_0000_0002_0005u64.into();
    // c7 02 00 00 20 00 00 00  r2 s>>= 32
    let ins4: Instruction = 0x0000_0020_0000_02c7u64.into();
    let mut emu = Emu::default();
    emu.state.regs[0] = 0xfe;
    // emu.instructions.push(ins1);
    // emu.instructions.push(ins2);
    // emu.instructions.push(ins3);
    emu.instructions.push(ins4);
    dbg!("before", &emu);
    emu.run();
    dbg!("after", &emu);
}
#[test]
fn test_ins() {
    // b700 0000 0000 0000
    // let ins1: u64 = 0x0000_0000_0000_00b7;
    let ins1: Instruction = 0x0000_0000_0000_00b7u64.into();
    let ins2: Instruction = 0x0000_0000_0000_0095u64.into();
    // r0 = *(u8 *)(r0 + 0)
    let ins3: Instruction = 0x0000_0000_0000_0071u64.into();
    // *(u8 *)(r5 + 0) = r2
    let ins4: Instruction = 0x0000_0000_0000_2573u64.into();
    // 73 74 0f 00 00 00 00 00 *(u8 *)(r4 + 15) = r7
    // 63 7a fc fe 00 00 00 00 *(u32 *)(r10 - 260) = r7
    let ins5: Instruction = 0x0000_0000_fefc_7a63u64.into();

    // 77 02 00 00 18 00 00 00 r2 >>= 24
    let ins6: Instruction = 0x0000_0018_0000_0277u64.into();

    let mut emu = Emu::default();
    emu.state.regs[0] = 0xfe;
    emu.instructions.push(ins1);
    emu.instructions.push(ins2);
    emu.instructions.push(ins3);
    emu.instructions.push(ins4);
    emu.instructions.push(ins5);
    emu.instructions.push(ins6);
    dbg!("before", &emu);
    emu.run();
    dbg!("after", &emu);
}

#[derive(Debug)]
struct Mmu {
    memory: Vec<u8>,
}

impl Mmu {
    fn write(&mut self, addr: usize, val: &[u8]) {
        if self.memory.len() < addr + val.len() {
            self.memory.resize(addr + val.len() + 0x1000, 0);
        }
        self.memory[addr..addr + val.len()].copy_from_slice(val)
    }
    fn read<T: std::fmt::LowerHex>(&mut self, addr: usize) -> T {
        let read_size = core::mem::size_of::<T>();
        let ptr = self.memory[addr..addr + read_size].as_ptr() as *const T;
        let res = unsafe { ptr.read_unaligned() };
        // println!(
        //     "read 0x{:x} bytes from addr 0x{:x}: 0x{:x}",
        //     read_size, addr, res
        // );
        res
    }
    fn read_ptr<T: std::fmt::LowerHex>(&mut self, addr: usize) -> *const T {
        let read_size = core::mem::size_of::<T>();
        let ptr = self.memory[addr..addr + read_size].as_ptr() as *const T;
        ptr
    }
    fn read_ptr_mut<T: std::fmt::LowerHex>(&mut self, addr: usize) -> *mut T {
        self.read_ptr::<T>(addr) as *mut T
    }
}

#[derive(Debug)]
struct State {
    regs: [u64; 11],
    mmu: Mmu,
}

#[derive(Debug)]
struct Emu {
    state: State,
    ins_count: u32,
    pc: u32,
    instructions: Vec<Instruction>,
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
        }
    }
}

impl Emu {
    fn init(&mut self, r1: usize) {
        self.state.regs[1] = r1 as u64;
    }
    fn step(&mut self) -> Option<()> {
        if let Some(ins) = self.instructions.get(self.pc as usize) {
            // Mnemonic
            let mut mne = "".to_string();
            println!("{}: {:?}", self.pc, ins);
            println!(
                "regs: r0=0x{:x}, r1=0x{:x}, r2=0x{:x}, r3=0x{:x}, r4=0x{:x}",
                self.state.regs[0],
                self.state.regs[1],
                self.state.regs[2],
                self.state.regs[3],
                self.state.regs[4]
            );
            self.pc += 1;
            match &ins.code {
                Code::AJ { op, source, class } => {
                    let (src, src_desc) = match &source {
                        Source::IMM => (ins.imm as u64, format!("0x{:x}", ins.imm)),
                        Source::SRC => (
                            self.state.regs[ins.src as u8 as usize],
                            format!("{:?}", ins.src),
                        ),
                    };
                    // dbg!(src, ins.src, self.state.regs[ins.src as u8 as usize], &source);
                    match &class {
                        Class::ALU | Class::ALU64 => {
                            let mut dst = match &class {
                                Class::ALU => {
                                    let mut dst = &mut self.state.regs[ins.dst as u8 as usize];
                                    (*dst) &= 0x0000_0000_ffff_ffff;
                                    dst
                                }
                                Class::ALU64 => &mut self.state.regs[ins.dst as u8 as usize],
                                _ => unreachable!(),
                            };
                            mne = format!("{:?} {:?}, {}", op, ins.dst, src_desc).to_lowercase();
                            match op {
                                OP::alu(AOp::ADD) => {
                                    // do we need wrapping_add ?
                                    (*dst) += src;
                                }
                                OP::alu(AOp::SUB) => {
                                    (*dst) -= src;
                                }
                                OP::alu(AOp::MUL) => {
                                    (*dst) *= src;
                                }
                                OP::alu(AOp::DIV) => {
                                    (*dst) /= src;
                                }
                                OP::alu(AOp::OR) => {
                                    (*dst) |= src;
                                }
                                OP::alu(AOp::AND) => {
                                    (*dst) &= src;
                                }
                                OP::alu(AOp::LSH) => {
                                    (*dst) <<= src;
                                }
                                OP::alu(AOp::RSH) => {
                                    (*dst) >>= src;
                                }
                                OP::alu(AOp::NEG) => {
                                    todo!();
                                    // TODO
                                    // self.state.regs[ins.dst as u8 as usize] = src;
                                }
                                OP::alu(AOp::MOD) => {
                                    (*dst) %= src;
                                }
                                OP::alu(AOp::XOR) => {
                                    (*dst) ^= src;
                                }
                                OP::alu(AOp::MOV) => {
                                    // mne = format!("mov {:?}, {}", ins.dst, src_desc);
                                    (*dst) = src;
                                }
                                OP::alu(AOp::ARSH) => {
                                    // TODO dst >>= imm (arithmetic)
                                    // (*dst) >>= src;
                                    unsafe { *(dst as *mut u64 as *mut i64) >>= src };
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
                                                    (*dst) = u16::to_le(*dst as u16) as u64
                                                }
                                                Source::SRC => {
                                                    (*dst) = u16::to_be(*dst as u16) as u64
                                                }
                                            };
                                        }
                                        32 => {
                                            match &source {
                                                Source::IMM => {
                                                    (*dst) = u32::to_le(*dst as u32) as u64
                                                }
                                                Source::SRC => {
                                                    (*dst) = u32::to_be(*dst as u32) as u64
                                                }
                                            };
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

                            match &source {
                                Source::IMM => {
                                    println!("{:?} {:?}, 0x{:x}", op, ins.dst, ins.imm);
                                }
                                Source::SRC => {
                                    println!("{:?} {:?}, {:?}", op, ins.dst, ins.src);
                                }
                            };
                            // println!("mne: {}", mne);
                        }
                        Class::JMP | Class::JMP32 => {
                            let off = ins.off as u32;
                            let mut dst = self.state.regs[ins.dst as u8 as usize];

                            // println!(
                            //     "{:?} dst({:?}), {:?}({:?}|{:?}), +off({:?})",
                            //     op, ins.dst, &source, ins.src, ins.imm, ins.off
                            // );
                            match &source {
                                Source::IMM => {
                                    println!(
                                        "{:?} {:?}, 0x{:x}, +0x{:x}",
                                        op, ins.dst, ins.imm, ins.off
                                    );
                                }
                                Source::SRC => {
                                    println!(
                                        "{:?} {:?}, {:?}, +0x{:x}",
                                        op, ins.dst, ins.src, ins.off
                                    );
                                }
                            };
                            println!("jmp: {:?}", op);
                            match op {
                                OP::jmp(JOp::JA) => {
                                    self.pc += off;
                                }
                                OP::jmp(JOp::JEQ) => {
                                    // println!("jeq dst, imm, +off");
                                    if dst == src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JGT) => {
                                    if dst > src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JGE) => {
                                    if dst >= src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JSET) => {
                                    // TODO
                                    if (dst & src) != 0 {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JNE) => {
                                    if dst != src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JSGT) => {
                                    // TODO: dst > imm (signed)
                                    if dst > src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JSGE) => {}
                                OP::jmp(JOp::CALL) => {
                                    todo!();
                                    // TODO: function call
                                    //self.pc = 0;
                                    // self.state.register[]
                                }
                                OP::jmp(JOp::EXIT) => {
                                    println!(
                                        "exit, R0={:?}(0x{:x})",
                                        xdp_action::from(self.state.regs[0] as u8),
                                        self.state.regs[0]
                                    );
                                    return None;
                                }
                                OP::jmp(JOp::JLT) => {
                                    if dst < src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JLE) => {
                                    if dst <= src {
                                        self.pc += off;
                                    }
                                }
                                OP::jmp(JOp::JSLT) => {}
                                OP::jmp(JOp::JSLE) => {}
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
                    let imm = ins.imm as u64;
                    let src = self.state.regs[ins.src as u8 as usize];
                    let mut dst = &mut self.state.regs[ins.dst as u8 as usize];

                    // println!(
                    //     "{:?}[{}] {:?}, [{:?} +off]",
                    //     &class, size_sign, &ins.dst, &ins.src
                    // );
                    match &class {
                        Class::LD | Class::LDX => {
                            println!(
                                "{:?}[{}] {:?}, [{:?} +off]",
                                &class, size_sign, &ins.dst, &ins.src
                            );
                            // dst_reg = *(size *) ((imm32 | src_reg) + off)
                            match *mode {
                                Mode::IMM => {
                                    // BPF_LD | BPF_DW | BPF_IMM
                                    // assert!(w == 0xffff_ffff);
                                    // (*dst) = imm & w;
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
                                            dst as *mut u64 as *mut u8,
                                            w,
                                        )
                                    };
                                }
                                _ => unreachable!(),
                            }
                        }
                        Class::ST | Class::STX => {
                            // *(size *) (dst_reg + off) = (imm32 | src_reg)
                            let source = match &class {
                                Class::ST => {
                                    println!(
                                        "{:?}[{}] [{:?} +off], {:?}",
                                        &class, size_sign, &ins.dst, &ins.imm
                                    );
                                    imm
                                }
                                Class::STX => {
                                    println!(
                                        "{:?}[{}] [{:?} +off], {:?}",
                                        &class, size_sign, &ins.dst, &ins.src
                                    );
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
                                            src as *mut u64 as *mut u8,
                                            self.state.mmu.read_ptr_mut::<u8>(
                                                (*dst as i64 + ins.off as i64) as usize,
                                            ),
                                            w,
                                        )
                                    };
                                    match size {
                                        // W u32
                                        0x00 => unsafe {
                                            *(dst as *mut u64 as *mut u32).offset(imm as isize) =
                                                source as u32
                                        },
                                        // H u16
                                        0x08 => unsafe {
                                            *(dst as *mut u64 as *mut u16).offset(imm as isize) =
                                                source as u16
                                        },
                                        // B u8
                                        0x10 => unsafe {
                                            *(dst as *mut u64 as *mut u8).offset(imm as isize) =
                                                source as u8
                                        },
                                        // DW u64
                                        0x18 => unsafe {
                                            *(dst as *mut u64 as *mut u64).offset(imm as isize) =
                                                source as u64
                                        },
                                        _ => unreachable!(),
                                    };
                                }
                                Mode::ATOMIC => {
                                    todo!();
                                    // STX only
                                    // atomic operations
                                    // imm use to encode atomic operations
                                    match imm {
                                        ATOMIC_ADD => {
                                            // (*dst.offset(off)) += src;
                                        }
                                        ATOMIC_OR => {}
                                        ATOMIC_AND => {}
                                        ATOMIC_XOR => {}
                                        ATOMIC_FETCH => {}
                                        ATOMIC_XCHG => {}
                                        ATOMIC_CMPXCHG => {}
                                    };
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
            println!("=== step to end ===");
            return None;
        }
    }
    fn run(&mut self) {
        loop {
            if self.step().is_none() {
                break;
            }
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

#[derive(Debug, Clone)]
enum Code {
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
        } else if [CLASS_JMP].contains(&class) {
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
            unimplemented!()
        }
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
enum Mode {
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
#[repr(u8)]
enum OP {
    alu(AOp),
    jmp(JOp),
}

#[derive(Debug, Clone)]
#[repr(u8)]
enum AOp {
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

#[derive(Debug, Clone)]
#[repr(u8)]
enum JOp {
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
// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
