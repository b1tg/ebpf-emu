pub mod emu;
pub mod ins;
pub mod mmu;

use emu::*;
use ins::*;
use mmu::*;
pub fn add(left: usize, right: usize) -> usize {
    left + right
}
// #[repr(C)]
#[derive(Debug)]
#[repr(u8)]
enum XdpAction {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
}
impl From<u8> for XdpAction {
    fn from(val: u8) -> Self {
        assert!(val < 5);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const XdpAction) }
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
fn test_stdw() {
    // memory: aa  bb  ff  ff  ff  ff  ff  ff  ff  ff  cc  dd
    // Byte code: 7a  01  02  00  11  22  33  44  79  10  02  00  00  00  00  00  95  00  00  00  00  00  00  00
    let mut emu = Emu::default();
    let mmu = Mmu {
        memory: b"\xaa\xbb\xff\xff\xff\xff\xff\xff\xff\xff\xcc\xdd".to_vec(),
    };
    emu.state.regs[1] = 0;
    emu.state.mmu = mmu;
    let ins_list = [0x7a01020011223344, 0x7910020000000000, 0x9500000000000000]
        .map(|x| u64::from_be(x).into());
    emu.instructions = ins_list.to_vec();
    emu.run();
    assert_eq!(emu.state.regs[0], 0x0000000044332211);
}

fn decode_b16(input: String) -> Vec<u8> {
    let x = input.split(" ").map(|x| u8::from_str_radix(x, 16).unwrap());
    x.collect()
}

#[ignore = "use for command line"]
#[test]
fn test_bpf_conformance() {
    // memory: aa  bb  ff  ff  ff  ff  ff  ff  ff  ff  cc  dd
    // Byte code: 7a  01  02  00  11  22  33  44  79  10  02  00  00  00  00  00  95  00  00  00  00  00  00  00
    let args: Vec<String> = std::env::args().collect();

    let memory: Vec<u8> = args[3]
        .split(" ")
        .map(|x| u8::from_str_radix(x, 16).unwrap())
        .collect();
    let arg1 = &args[4].replace(" ", "");
    let res = u64::from_str_radix(&args[5], 16).unwrap();
    let byte_code: Vec<u64> = (0..arg1.len())
        .step_by(16)
        .map(|i| u64::from_str_radix(&arg1[i..i + 16], 16).unwrap())
        .collect();
    dbg!(&memory);
    println!("{:x?}", byte_code);
    // .step_by(8).map(|x| u64::from_be_bytes(x));
    let mut emu = Emu::default();
    let mmu = Mmu {
        // memory: b"\xaa\xbb\xff\xff\xff\xff\xff\xff\xff\xff\xcc\xdd".to_vec(),
        memory: memory,
    };
    emu.state.regs[1] = 0;
    emu.state.mmu = mmu;
    // let ins_list = [
    //     0x7a01020011223344,
    //     0x7910020000000000,
    //     0x9500000000000000,
    // ].map(|x| u64::from_be(x).into());
    let ins_list: Vec<Instruction> = byte_code
        .into_iter()
        .map(|x| u64::from_be(x).into())
        .collect();
    emu.instructions = ins_list.to_vec();
    emu.run();
    // assert_eq!(emu.state.regs[0], res);
}

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
    // dbg!("before", &emu);
    emu.run();
    // dbg!("after", &emu);
}
