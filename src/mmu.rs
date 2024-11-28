#[derive(Debug)]
pub struct Mmu {
    pub memory: Vec<u8>,
}

impl Mmu {
    pub fn write(&mut self, addr: usize, val: &[u8]) {
        if self.memory.len() < addr + val.len() {
            self.memory.resize(addr + val.len() + 0x1000, 0);
        }
        self.memory[addr..addr + val.len()].copy_from_slice(val)
    }
    pub fn read<T: std::fmt::LowerHex>(&mut self, addr: usize) -> T {
        let read_size = core::mem::size_of::<T>();
        let ptr = self.memory[addr..addr + read_size].as_ptr() as *const T;
        let res = unsafe { ptr.read_unaligned() };
        // println!(
        //     "read 0x{:x} bytes from addr 0x{:x}: 0x{:x}",
        //     read_size, addr, res
        // );
        res
    }
    pub fn read_ptr<T: std::fmt::LowerHex>(&mut self, addr: usize) -> *const T {
        let read_size = core::mem::size_of::<T>();
        let ptr = self.memory[addr..addr + read_size].as_ptr() as *const T;
        ptr
    }
    pub fn read_ptr_mut<T: std::fmt::LowerHex>(&mut self, addr: usize) -> *mut T {
        self.read_ptr::<T>(addr) as *mut T
    }
}
