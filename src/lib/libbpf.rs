extern crate elf;
use std::path::PathBuf;

struct bpf {}

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
    f.sections
}

pub fn bpf_attach_kprobe() {
    println!("bpfAttachKprobe");
}
