mod lib;
mod load;
mod module;
mod sys;
use module::bpf;
use std::thread;
use tokio::runtime::Runtime;
fn main() {
    // let mut loaded = Loader::load("/opt/goproject/goebpf/src/github.com/dropbox/goebpf/examples/socket_filter/packet_counter/ebpf_prog/sock_filter.elf").expect("error loading BPF program");
    // libbpf::new_bpf("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    // println!("------");
    let _ = Runtime::new().unwrap().block_on(async {
        let mut mods =
            bpf::parse("/opt/rsproject/rsops/rsops/src/ebpf/ebpf_prog/sock_filter.elf").unwrap();
        for program in mods.programs.iter_mut() {
            program.load(mods.version, mods.license.clone()).unwrap();
        }
        println!("load success!");
        for sockfilr in mods.socket_filters_mut() {
            match sockfilr.attach_socket_filter("ens33") {
                Ok(_) => println!("attach success!"),
                Err(_) => println!("attach fail!"),
            };
        }

        let m = match mods.maps.get("counter") {
            None => panic!("get map panic"),
            Some(m) => m,
        };
        println!("get map success!");
        loop {
            m.lookup(0);
            //println!("lookup!");
            thread::sleep_ms(1000);
        }
    });
    // mods.
    // println!("version :{}, license: {}", module.version, module.license);
    // libbpf::bpf_attach_kprobe();
    println!("finish!");
}
