use bpf_sys::{
    bpf_insn, bpf_map_def, bpf_probe_attach_type, bpf_probe_attach_type_BPF_PROBE_ENTRY,
    bpf_probe_attach_type_BPF_PROBE_RETURN, bpf_prog_type,
};
use goblin::elf::{Elf, SectionHeader};
use std::fs;
use std::os::unix::io::RawFd;
use std::result::*;

#[derive(Debug)]
pub enum Error {
    Section(String),
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub struct Module {
    pub programs: Vec<Program>,
    pub maps: Vec<Map>,
    pub license: String,
    pub version: u32,
}

pub enum Program {
    KProbe(KProbe),
    KRetProbe(KProbe),
    UProbe(UProbe),
    URetProbe(UProbe),
    SocketFilter(SocketFilter),
    TracePoint(TracePoint),
    XDP(XDP),
}

struct ProgramData {
    pub name: String,
    code: Vec<bpf_insn>,
    fd: Option<RawFd>,
}

/// Type to work with `kprobes` or `kretprobes`.
pub struct KProbe {
    common: ProgramData,
    attach_type: bpf_probe_attach_type,
}

/// Type to work with `uprobes` or `uretprobes`.
pub struct UProbe {
    common: ProgramData,
    attach_type: bpf_probe_attach_type,
}

/// Type to work with `socket filters`.
pub struct SocketFilter {
    common: ProgramData,
}

pub struct TracePoint {
    common: ProgramData,
}
/// Type to work with `XDP` programs.
pub struct XDP {
    common: ProgramData,
    interfaces: Vec<String>,
}

pub struct Map {
    pub name: String,
    pub kind: u32,
    fd: RawFd,
    config: bpf_map_def,
    section_data: bool,
}

pub fn parse(path: &str) {
    let bytes = fs::read(path).unwrap(); //使用 unwrap 隐式地错误处理。
    let object = Elf::parse(&bytes).unwrap();
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        let (kind, name) = get_split_section_name(&object, &shdr, shndx).unwrap(); //result
        let section_type = shdr.sh_type;
        let content = data(&bytes, &shdr);
        //  match (section_type, name) {}
        println!("val is {},{:?},{:?}!", section_type, kind, name);
    }
}

//获取 section name
fn get_split_section_name<'o>(
    object: &'o Elf<'_>,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    //let fn_err_msg = || "Section name not found";
    let fn_name = object.shdr_strtab.get_unsafe(shdr.sh_name); //Option
    let name = match fn_name {
        Some(name) => name,
        None => return Err(Error::Section(format!("Section name not found: {}", shndx))),
    };
    let mut names = name.splitn(2, '/');
    let kind = names.next();
    let name = names.next();
    Ok((kind, name))
}

#[inline]
fn data<'d>(bytes: &'d [u8], shdr: &SectionHeader) -> &'d [u8] {
    let offset = shdr.sh_offset as usize;
    let end = (shdr.sh_offset + shdr.sh_size) as usize;
    &bytes[offset..end]
}
