use ebpf_emu::emu::Emu;
use ebpf_emu::ins::{hexs_to_instructions, hexs_to_u8s, u64s_to_instructions, Instruction};
use ebpf_emu::mmu::Mmu;
use std::io::BufRead;
fn main() {
    let mut line = String::new();
    let stdin = std::io::stdin();
    stdin.lock().read_line(&mut line).unwrap();
    let args: Vec<String> = std::env::args().collect();
    let debug = std::env::var("DEBUG").unwrap_or_else(|_| "0".to_string()) == "1";
    if debug {
        dbg!(&args);
    }
    let mut emu = Emu::default();
    let mut mmu = Mmu {
        memory: vec![0u8; 1024],
    };
    if args.len() == 2 {
        let memory = hexs_to_u8s(&args[1]).unwrap();
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
    let hx = if line.trim().is_empty() {
        &args[2]
    } else {
        &line
    };
    emu.instructions = hexs_to_instructions(hx).unwrap();
    if debug {
        dbg!(&emu.instructions);
    }
    emu.run();
    println!("{:x}", &emu.state.regs[0]);
}
