mod lib;
mod module;
use lib::libbpf;
use module::bpf;
fn main() {
    libbpf::new_bpf("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    println!("------");
    bpf::parse("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    libbpf::bpf_attach_kprobe();
    println!("Hello, world!");
}
