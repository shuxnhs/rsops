mod lib;
use crate::lib::libbpf;

fn main() {
    libbpf::new_bpf("./trace.elf");
    libbpf::bpf_attach_kprobe();
    println!("Hello, world!");
}



