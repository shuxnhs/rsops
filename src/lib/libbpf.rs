extern crate elf;
use std::path::PathBuf;

struct Bpf {}

pub fn new_bpf(path: &str) {
    println!("path is {}!", path);
    let elfpath = PathBuf::from(path);
    let file = match elf::File::open_path(elfpath) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };
    load(file);
}

fn load(f: elf::File) {
    for val in f.sections.iter() {
        println!("val is {}!", val);
    }
}

pub fn bpf_attach_kprobe() {
    println!("bpfAttachKprobe");
}
