mod lib;
mod module;
use lib::libbpf;
use module::bpf;
fn main() {
    // libbpf::new_bpf("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    // println!("------");
    let module = bpf::parse("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf").unwrap();
    println!("version :{}, license: {}", module.version, module.license);
    libbpf::bpf_attach_kprobe();
    println!("Hello, world!");
}
