mod lib;

fn main() {
    // lib::new_bpf("/lib/modules/5.9.12-1.el7.elrepo.x86_64/build/main.elf");
    lib::bpf_attach_kprobe();
    println!("Hello, world!");
}
