use bpf_sys::{
    bpf_insn, bpf_map_def, bpf_probe_attach_type, bpf_probe_attach_type_BPF_PROBE_ENTRY,
    bpf_probe_attach_type_BPF_PROBE_RETURN, bpf_prog_type, uname,
};
use goblin::elf::{section_header as hdr, Elf, SectionHeader};
use std::collections::HashMap as RSHashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::result::*;

#[derive(Debug)]
pub enum Error {
    StringConversion,
    Section(String),
    Parse(::goblin::error::Error),
    IO(::std::io::Error),
    Map,
    ProgramNotLoaded,
    ProgramAlreadyLoaded,
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

impl Program {
    #[allow(clippy::unnecessary_wraps)]
    fn new(kind: &str, name: &str, code: &[u8]) -> Result<Program> {
        let code = zero::read_array(code).to_vec();
        let name = name.to_string();

        let common = ProgramData {
            name,
            code,
            fd: None,
        };

        Ok(match kind {
            "kprobe" => Program::KProbe(KProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_ENTRY,
            }),
            "kretprobe" => Program::KProbe(KProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_RETURN,
            }),
            "uprobe" => Program::UProbe(UProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_ENTRY,
            }),
            "uretprobe" => Program::UProbe(UProbe {
                common,
                attach_type: bpf_probe_attach_type_BPF_PROBE_RETURN,
            }),
            "tracepoint" => Program::TracePoint(TracePoint { common }),
            "socketfilter" => Program::SocketFilter(SocketFilter { common }),
            "xdp" => Program::XDP(XDP {
                common,
                interfaces: Vec::new(),
            }),
            _ => return Err(Error::Section(kind.to_string())),
        })
    }
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

impl SocketFilter {
    pub fn attach_socket_filter(&mut self, interface: &str) -> Result<RawFd> {
        let fd = self.common.fd.ok_or(Error::ProgramNotLoaded)?;
        let ciface = CString::new(interface).unwrap();
        let sfd = unsafe { bpf_sys::bpf_open_raw_sock(ciface.as_ptr()) };

        if sfd < 0 {
            return Err(Error::IO(io::Error::last_os_error()));
        }

        match unsafe { bpf_sys::bpf_attach_socket(sfd, fd) } {
            0 => Ok(sfd),
            _ => Err(Error::IO(io::Error::last_os_error())),
        }
    }

    pub fn name(&self) -> String {
        self.common.name.to_string()
    }
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

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: bpf_map_def = *zero::read(code);
        Map::with_map_def(name, config)
    }

    fn with_map_def(name: &str, config: bpf_map_def) -> Result<Map> {
        let cname = CString::new(name)?;
        let fd = unsafe {
            bpf_sys::bcc_create_map(
                config.type_,
                cname.as_ptr(),
                config.key_size as i32,
                config.value_size as i32,
                config.max_entries as i32,
                config.map_flags as i32,
            )
        };
        if fd < 0 {
            return Err(Error::Map);
        }

        Ok(Map {
            name: name.to_string(),
            kind: config.type_,
            fd,
            config,
            section_data: false,
        })
    }
}

//解析elf文件
pub fn parse(path: &str) -> Result<Module> {
    let bytes = fs::read(path)?; //使用 unwrap 隐式地错误处理。
    let object = Elf::parse(&bytes)?;
    let mut version = 0u32;
    let mut license = String::new();
    let mut maps = RSHashMap::new();
    let mut programs = RSHashMap::new();
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        let (kind, name) = get_split_section_name(&object, &shdr, shndx).unwrap(); //result
        let section_type = shdr.sh_type;
        let content = data(&bytes, &shdr);
        match (section_type, kind, name) {
            (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
            (hdr::SHT_PROGBITS, Some("license"), _) => {
                license = zero::read_str(content).to_string()
            }
            (hdr::SHT_PROGBITS, Some("map"), Some(name)) => {
                // Maps are immediately bcc_create_map'd
                maps.insert(shndx, Map::load(name, &content)?);
            }
            (hdr::SHT_PROGBITS, Some(kind @ "kprobe"), Some(name))
            | (hdr::SHT_PROGBITS, Some(kind @ "kretprobe"), Some(name))
            | (hdr::SHT_PROGBITS, Some(kind @ "uprobe"), Some(name))
            | (hdr::SHT_PROGBITS, Some(kind @ "uretprobe"), Some(name))
            | (hdr::SHT_PROGBITS, Some(kind @ "xdp"), Some(name))
            | (hdr::SHT_PROGBITS, Some(kind @ "socketfilter"), Some(name)) => {
                programs.insert(shndx, Program::new(kind, name, &content)?);
            }
            _ => {}
        }
        println!("val is {},{:?},{:?}!", section_type, kind, name);
    }
    let programs = programs.drain().map(|(_, v)| v).collect();
    let maps = maps.drain().map(|(_, v)| v).collect();
    Ok(Module {
        programs,
        maps,
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
