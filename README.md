
https://github.com/Alan-Jowett/bpf_conformance

- 2024/11/19 17:10
    Passed 61 out of 160 tests.
- 2024/11/19 18:24
    Passed 67 out of 160 tests.
- 2024/11/26 18:24
    Passed 100 out of 160 tests.
- 2024/11/28 17:14
    Passed 144 out of 160 tests.
- 2024/11/28 19:20
    Passed 150 out of 160 tests.    
- 2024/11/28 19:45
    Passed 160 out of 160 tests
- 2024/11/29 11:29
    Passed 176 out of 180 tests.
- 2024/11/29 14:25
    Passed 180 out of 180 tests.

https://github.com/iovisor/bpf-docs/blob/master/eBPF.md


https://docs.kernel.org/6.0/bpf/instruction-set.html

```
/root/ebpf-emu $ RUST_BACKTRACE=1 cargo run --bin emem  "b4  02  00  00  11  00  00  00  73  21  02  00  00  00  00  00  71  10  02  00  00  00  00  00  95  00  00  00  00  00  00  00  " "aa  bb  ff  cc  dd  "


/root/ebpf-emu/bpf_conformance/build $ cmake --build .
[ 55%] Built target bpf_conformance
[ 77%] Built target bpf_conformance_runner
[100%] Built target libbpf_plugin

/root/ebpf-emu/bpf_conformance/build/bin $
RUST_BACKTRACE=1 ./bpf_conformance_runner --debug true --test_file_directory ../tests --plugin_path /root/ebpf-emu/target/debug/emem --exclude_groups atomic64 



```
