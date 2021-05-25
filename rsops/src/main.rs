mod lib;
mod load;
mod module;
mod sys;
use core::time::Duration;
use module::bpf;
use module::perf;
use module::xdp::*;
use std::net::Ipv4Addr;
use std::thread;
use tokio::runtime::Runtime;
fn main() {
    //  let mut loaded = Loader::load("/opt/goproject/goebpf/src/github.com/dropbox/goebpf/examples/socket_filter/packet_counter/ebpf_prog/sock_filter.elf").expect("error loading BPF program");
    // libbpf::new_bpf("/lib/modules/5.11.6-1.el7.elrepo.x86_64/source/main.elf");
    // println!("------");
    //xdp_attach()
    xdp_attach();
}

#[derive(Debug, Copy, Clone)]
struct perfEventItem {
    srcIp: u32,
    dstIp: u32,
    srcPort: u16,
    dstPort: u16,
}

unsafe impl ::zero::Pod for perfEventItem {}

fn intToIp(ip: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ip as u8,
        (ip >> 8) as u8,
        (ip >> 16) as u8,
        (ip >> 24) as u8,
    )
}

fn ntohs(value: u16) -> u16 {
    return ((value & 0xff) << 8) | (value >> 8);
}

fn handle_event(_cpu: i32, data: &[u8]) {
    println!("data len is {}", data.len());
    let event: perfEventItem = *zero::read(data);
    println!(
        "TCP:{}:{}-->{}:{}",
        intToIp(event.srcIp),
        ntohs(event.srcPort),
        intToIp(event.dstIp),
        ntohs(event.dstPort)
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn xdp_attach() {
    let _ = Runtime::new().unwrap().block_on(async {
        let mut mods =
            bpf::parse("/opt/rsproject/rsops/rsops/src/ebpf/xdp/ebpf_prog/xdp_dump.elf").unwrap();
        for program in mods.programs.iter_mut() {
            program.load(mods.version, mods.license.clone()).unwrap();
        }
        println!("load success!");
        for x in mods.xdps_mut() {
            match x.attach_xdp("ens33", Flags::Unset) {
                Ok(_) => println!("attach success!"),
                Err(_) => println!("attach fail!"),
            };
        }

        let m = match mods.maps.get("perfmap") {
            None => panic!("get map panic"),
            Some(m) => m,
        };
        println!("get map success!");
        let pf = perf::PerfEventBuilder::new(m)
            .sample_cb(handle_event)
            .lost_cb(handle_lost_events)
            .build()
            .unwrap();

        loop {
            pf.poll(Duration::from_millis(100)).unwrap();
        }
    });
    println!("finish!");
}

fn socket_filter() {
    let _ = Runtime::new().unwrap().block_on(async {
        let mut mods = bpf::parse(
            "/opt/rsproject/rsops/rsops/src/ebpf/socket_filter/ebpf_prog/sock_filter.elf",
        )
        .unwrap();
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
    println!("finish!");
}
