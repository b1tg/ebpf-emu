
all:
	cd /root/ebpf-emu && RUST_BACKTRACE=1 cargo build --bin emem
	cd /root/ebpf-emu/bpf_conformance/build && cmake --build .

test:
	cd /root/ebpf-emu/bpf_conformance/build/bin  && \
	RUST_BACKTRACE=1 ./bpf_conformance_runner --debug false --test_file_directory ../tests --plugin_path /root/ebpf-emu/target/debug/emem 
	# RUST_BACKTRACE=1 ./bpf_conformance_runner --debug true --test_file_directory ../tests --plugin_path /root/ebpf-emu/target/debug/emem --exclude_groups atomic64 

single:
	cd /root/ebpf-emu/bpf_conformance/build/bin  && \
	RUST_BACKTRACE=1 ./bpf_conformance_runner --debug true --test_file_path ../tests/lock_cmpxchg32.data --plugin_path /root/ebpf-emu/target/debug/emem  

rust:
	cd /root/ebpf-emu && RUST_BACKTRACE=1 cargo run --bin emem "" "18  00  00  00  f0  de  bc  9a  00  00  00  00  78  56  34  12  7b  0a  f8  ff  00  00  00  00  b4  01  00  00  10  32  54  76  b4  00  00  00  78  56  34  12  c3  1a  f8  ff  f1  00  00  00  b4  01  00  00  f0  de  bc  9a  5d  10  10  00  00  00  00  00  79  a0  f8  ff  00  00  00  00  18  01  00  00  f0  de  bc  9a  00  00  00  00  78  56  34  12  5d  10  0c  00  00  00  00  00  18  00  00  00  f0  de  bc  9a  00  00  00  00  78  56  34  12  7b  0a  f8  ff  00  00  00  00  b4  01  00  00  44  33  22  11  c3  1a  f8  ff  f1  00  00  00  b4  01  00  00  f0  de  bc  9a  5d  10  05  00  00  00  00  00  79  a0  f8  ff  00  00  00  00  18  01  00  00  44  33  22  11  00  00  00  00  78  56  34  12  5d  10  01  00  00  00  00  00  b7  00  00  00  00  00  00  00  95  00  00  00  00  00  00  00"
