use bpf_sys::{
    bpf_insn, bpf_map_def, bpf_probe_attach_type, bpf_probe_attach_type_BPF_PROBE_ENTRY,
    bpf_probe_attach_type_BPF_PROBE_RETURN, bpf_prog_type, uname,
};
use goblin::elf::{section_header as hdr, Elf, SectionHeader};
use std::collections::HashMap as RSHashMap;
use std::fs;
use std::os::unix::io::RawFd;
use std::result::*;

#[derive(Debug)]
pub enum Error {
    StringConversion,
    Section(String),
    Parse(::goblin::error::Error),
    IO(::std::io::Error),
}

pub type Result<T> = ::std::result::Result<T, Error>;

impl From<::goblin::error::Error> for Error {
    fn from(e: ::goblin::error::Error) -> Error {
        Error::Parse(e)
    }
}

impl From<::std::ffi::NulError> for Error {
    fn from(_e: ::std::ffi::NulError) -> Error {
        Error::StringConversion
    }
}

impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Error {
        Error::IO(e)
    }
}

pub struct Module {
    // pub programs: Vec<Program>,
    // pub maps: Vec<Map>,
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

pub fn parse(path: &str) -> Result<Module> {
    let bytes = fs::read(path)?; //使用 unwrap 隐式地错误处理。
    let object = Elf::parse(&bytes)?;
    let mut version = 0u32;
    let mut license = String::new();
    let mut maps = RSHashMap::new();
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        let (kind, name) = get_split_section_name(&object, &shdr, shndx).unwrap(); //result
        let section_type = shdr.sh_type;
        let content = data(&bytes, &shdr);
        match (section_type, kind, name) {
            (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
            (hdr::SHT_PROGBITS, Some("license"), _) => {
                license = zero::read_str(content).to_string()
            }
            (hdr::SHT_PROGBITS, Some("maps"), Some(name)) => {
                // Maps are immediately bcc_create_map'd
                maps.insert(shndx, Map::load(name, &content)?);
            }
            _ => {}
        }
        println!("val is {},{:?},{:?}!", section_type, kind, name);
    }
    Ok(Module {
        license: license,
        version: version,
    })
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

#[inline]
fn get_version(bytes: &[u8]) -> u32 {
    let version = zero::read::<u32>(bytes);
    match version {
        0xFFFF_FFFE => uname::get_kernel_internal_version().unwrap(),
        _ => *version,
    }
}
