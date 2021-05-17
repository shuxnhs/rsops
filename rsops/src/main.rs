mod lib;
mod load;
mod module;
mod sys;
use module::bpf;

fn main() {
    // let mut loaded = Loader::load("/opt/goproject/goebpf/src/github.com/dropbox/goebpf/examples/socket_filter/packet_counter/ebpf_prog/sock_filter.elf").expect("error loading BPF program");
    // libbpf::new_bpf("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    // println!("------");
    let module = bpf::parse("/opt/goproject/goebpf/src/github.com/dropbox/goebpf/examples/socket_filter/packet_counter/ebpf_prog/sock_filter.elf").unwrap();
    // println!("version :{}, license: {}", module.version, module.license);
    // libbpf::bpf_attach_kprobe();
    println!("load success!");
    println!("Hello, world!");
}
