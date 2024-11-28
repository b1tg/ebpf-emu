use ebpf_emu::emu::Emu;
use ebpf_emu::ins::{hexs_to_instructions, hexs_to_u8s, u64s_to_instructions, Instruction};
use ebpf_emu::mmu::Mmu;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let debug = std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string()) == "1";
    if debug {
        dbg!(&args);
    }
    let mut emu = Emu::default();
    let mut mmu = Mmu {
        memory: vec![0u8; 1024],
    };
    if args.len() == 3 {
        let memory = hexs_to_u8s(&args[2]).unwrap();
        for (i, x) in memory.iter().enumerate() {
            mmu.memory[i] = *x;
        }
        if debug {
            println!("filled {} bytes memory", memory.len());
        }
        // case: mem-len.data wants this, can't found document about this:
        //  R2 = len(data)
        emu.state.regs[2] = memory.len() as _;
    }
    emu.state.regs[1] = 0;
    emu.state.regs[10] = 512; // stack
    emu.state.mmu = mmu;
    emu.instructions = hexs_to_instructions(&args[1]).unwrap();
    if debug {
        dbg!(&emu.instructions);
    }
    emu.run();
    println!("{:x}", &emu.state.regs[0]);
}
