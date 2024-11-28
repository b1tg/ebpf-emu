
all:
	cd /root/ebpf-emu && RUST_BACKTRACE=1 cargo build --bin emem
	cd /root/ebpf-emu/bpf_conformance/build && cmake --build .

test:
	cd /root/ebpf-emu/bpf_conformance/build/bin  && \
	RUST_BACKTRACE=1 ./bpf_conformance_runner --debug false --test_file_directory ../tests --plugin_path /root/ebpf-emu/target/debug/emem --exclude_groups atomic64 
	# RUST_BACKTRACE=1 ./bpf_conformance_runner --debug true --test_file_directory ../tests --plugin_path /root/ebpf-emu/target/debug/emem --exclude_groups atomic64 

single:
	cd /root/ebpf-emu/bpf_conformance/build/bin  && \
	RUST_BACKTRACE=1 ./bpf_conformance_runner --debug true --test_file_path ../tests/div64-negative-reg.data --plugin_path /root/ebpf-emu/target/debug/emem  

rust:
	cd /root/ebpf-emu && RUST_BACKTRACE=1 cargo run --bin emem "18  00  00  00  ff  ff  ff  ff  00  00  00  00  ff  ff  ff  ff  b4  01  00  00  f6  ff  ff  ff  3f  10  00  00  00  00  00  00  95  00  00  00  00  00  00  00"
