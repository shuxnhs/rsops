use crate::module::symbols::*;
use bpf_sys::{
    bpf_insn, bpf_map_def, bpf_probe_attach_type, bpf_probe_attach_type_BPF_PROBE_ENTRY,
    bpf_probe_attach_type_BPF_PROBE_RETURN, bpf_prog_type, uname,
};
use goblin::elf::{reloc::RelocSection, section_header as hdr, Elf, SectionHeader, Sym};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::result::*;

#[cfg(target_arch = "aarch64")]
pub type DataPtr = *const u8;
#[cfg(target_arch = "aarch64")]
pub type MutDataPtr = *mut u8;

#[cfg(target_arch = "x86_64")]
pub type DataPtr = *const i8;
#[cfg(target_arch = "x86_64")]
pub type MutDataPtr = *mut i8;

#[derive(Debug)]
pub enum Error {
    StringConversion,
    Section(String),
    Parse(::goblin::error::Error),
    IO(::std::io::Error),
    Map,
    ProgramNotLoaded,
    ProgramAlreadyLoaded,
    BPF,
    Reloc,
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
    pub maps: HashMap<String, Map>, //Vec<Map>,
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

    fn to_prog_type(&self) -> bpf_prog_type {
        use Program::*;

        match self {
            KProbe(_) | KRetProbe(_) | UProbe(_) | URetProbe(_) => {
                bpf_sys::bpf_prog_type_BPF_PROG_TYPE_KPROBE
            }
            XDP(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_XDP,
            SocketFilter(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER,
            TracePoint(_) => bpf_sys::bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT,
        }
    }

    fn data(&self) -> &ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &p.common,
            UProbe(p) | URetProbe(p) => &p.common,
            XDP(p) => &p.common,
            SocketFilter(p) => &p.common,
            TracePoint(p) => &p.common,
        }
    }

    fn data_mut(&mut self) -> &mut ProgramData {
        use Program::*;

        match self {
            KProbe(p) | KRetProbe(p) => &mut p.common,
            UProbe(p) | URetProbe(p) => &mut p.common,
            XDP(p) => &mut p.common,
            SocketFilter(p) => &mut p.common,
            TracePoint(p) => &mut p.common,
        }
    }

    pub fn name(&self) -> &str {
        &self.data().name
    }

    pub fn fd(&self) -> &Option<RawFd> {
        &self.data().fd
    }

    pub fn load(&mut self, kernel_version: u32, license: String) -> Result<()> {
        if self.data().fd.is_some() {
            return Err(Error::ProgramAlreadyLoaded);
        }
        let clicense = CString::new(license)?;
        let cname = CString::new(self.data_mut().name.clone())?;
        let log_buffer: MutDataPtr =
            unsafe { libc::malloc(mem::size_of::<i8>() * 16 * 65535) as MutDataPtr };
        let buf_size = 64 * 65535_u32;

        let fd = unsafe {
            bpf_sys::bcc_prog_load(
                self.to_prog_type(),
                cname.as_ptr() as DataPtr,
                self.data_mut().code.as_ptr(),
                (self.data_mut().code.len() * mem::size_of::<bpf_insn>()) as i32,
                clicense.as_ptr() as DataPtr,
                kernel_version as u32,
                0_i32,
                log_buffer,
                buf_size,
            )
        };

        if fd < 0 {
            Err(Error::BPF)
        } else {
            self.data_mut().fd = Some(fd);
            Ok(())
        }
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

// pub struct HashMap<'a, K: Clone, V: Clone> {
//     base: &'a Map,
//     _k: PhantomData<K>,
//     _v: PhantomData<V>,
// }

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Map> {
        let config: bpf_map_def = *zero::read(code);
        Map::with_map_def(name, config)
    }

    pub fn lookup(&self, mut id: libc::c_int) {
        let mut value: MaybeUninit<libc::c_void> = MaybeUninit::uninit();
        let a = unsafe {
            bpf_sys::bpf_lookup_elem(
                self.fd,
                &mut id as *mut libc::c_int as _,
                &mut value as *mut _ as *mut _,
            )
        };
        println!("a:{}", a);
        // let v: u64 = unsafe { value.assume_init() };
        // println!("value:{}", v);
        // if a < 0 {
        //     return None;
        // }
        // Some(unsafe { value.assume_init() })
    }

    fn with_section_data(name: &str, data: &[u8], flags: u32) -> Result<Map> {
        let mut map = Map::with_map_def(
            name,
            bpf_map_def {
                type_: bpf_sys::bpf_map_type_BPF_MAP_TYPE_ARRAY,
                key_size: mem::size_of::<u32>() as u32,
                value_size: data.len() as u32,
                max_entries: 1,
                map_flags: flags,
            },
        )?;
        map.section_data = true;
        // for BSS we don't need to copy the data, it's already 0-initialized
        if name != ".bss" {
            unsafe {
                let ret = bpf_sys::bpf_update_elem(
                    map.fd,
                    &mut 0 as *mut _ as *mut _,
                    data.as_ptr() as *mut u8 as *mut _,
                    0,
                );
                if ret < 0 {
                    return Err(Error::BPF);
                }
            }
        }
        Ok(map)
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
        println!("name {} ,map fd:{}", name, fd);
        Ok(Map {
            name: name.to_string(),
            kind: config.type_,
            fd,
            config,
            section_data: false,
        })
    }
}

impl Module {
    pub fn socket_filters(&self) -> impl Iterator<Item = &SocketFilter> {
        use Program::*;
        self.programs.iter().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn socket_filters_mut(&mut self) -> impl Iterator<Item = &mut SocketFilter> {
        use Program::*;
        self.programs.iter_mut().filter_map(|prog| match prog {
            SocketFilter(p) => Some(p),
            _ => None,
        })
    }

    pub fn program(&self, name: &str) -> Option<&Program> {
        self.programs.iter().find(|p| p.name() == name)
    }
}

// pub struct MapIter<'a, 'b, K: Clone, V: Clone> {
//     map: &'a HashMap<'b, K, V>,
//     key: Option<K>,
// }

// impl<'base, K: Clone, V: Clone> HashMap<'base, K, V> {
//     pub fn new(base: &Map) -> Result<HashMap<K, V>> {
//         if mem::size_of::<K>() != base.config.key_size as usize
//             || mem::size_of::<V>() != base.config.value_size as usize
//         {
//             return Err(Error::Map);
//         }

//         Ok(HashMap {
//             base,
//             _k: PhantomData,
//             _v: PhantomData,
//         })
//     }

//     pub fn set(&self, mut key: K, mut value: V) {
//         unsafe {
//             bpf_sys::bpf_update_elem(
//                 self.base.fd,
//                 &mut key as *mut _ as *mut _,
//                 &mut value as *mut _ as *mut _,
//                 0,
//             );
//         }
//     }

//     pub fn get(&self, mut key: K) -> Option<V> {
//         let mut value = MaybeUninit::zeroed();
//         if unsafe {
//             bpf_sys::bpf_lookup_elem(
//                 self.base.fd,
//                 &mut key as *mut _ as *mut _,
//                 &mut value as *mut _ as *mut _,
//             )
//         } < 0
//         {
//             return None;
//         }
//         Some(unsafe { value.assume_init() })
//     }

//     pub fn delete(&self, mut key: K) {
//         unsafe {
//             bpf_sys::bpf_delete_elem(self.base.fd, &mut key as *mut _ as *mut _);
//         }
//     }

//     pub fn iter<'a>(&'a self) -> MapIter<'a, '_, K, V> {
//         MapIter {
//             map: self,
//             key: None,
//         }
//     }
// }

//解析elf文件
pub fn parse(path: &str) -> Result<Module> {
    let bytes = fs::read(path)?; //使用 unwrap 隐式地错误处理。
    let object = Elf::parse(&bytes)?;
    let symtab = object.syms.to_vec();
    let shdr_relocs = &object.shdr_relocs;
    let mut version = 0u32;
    let mut license = String::new();
    let mut maps: HashMap<String, Map> = HashMap::new();
    let mut rels = vec![];
    let mut programs = HashMap::new();
    println!("parse");
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        let (kind, name) = get_split_section_name(&object, &shdr, shndx).unwrap(); //result
        let section_type = shdr.sh_type;
        let content = data(&bytes, &shdr);
        match (section_type, kind, name) {
            (hdr::SHT_REL, _, _) => add_relocation(&mut rels, shndx, &shdr, shdr_relocs),
            (hdr::SHT_PROGBITS, Some("version"), _) => version = get_version(&content),
            (hdr::SHT_PROGBITS, Some("license"), _) => {
                license = zero::read_str(content).to_string()
            }
            // (hdr::SHT_PROGBITS, Some(name), None)
            //     if name == ".bss" || name.starts_with(".data") || name.starts_with(".rodata") =>
            // {
            //     // load these as ARRAY maps containing one item: the section data. Then during
            //     // relocation make instructions point inside the maps.
            //     maps.insert(
            //         shndx,
            //         Map::with_section_data(
            //             name,
            //             content,
            //             if name.starts_with(".rodata") {
            //                 bpf_sys::BPF_F_RDONLY_PROG
            //             } else {
            //                 0
            //             },
            //         )?,
            //     );
            // }
            (hdr::SHT_PROGBITS, Some("map"), Some(name)) => {
                // Maps are immediately bcc_create_map'd
                maps.insert(name.to_string(), Map::load(name, &content)?);
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

    for rel in rels.iter() {
        if programs.contains_key(&rel.target_sec_idx) {
            rel.apply(&object, &mut programs, &maps, &symtab)?;
        }
    }
    let programs = programs.drain().map(|(_, v)| v).collect();
    // let maps = maps.drain().map(|(_, v)| v).collect();
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

#[allow(dead_code)]
pub struct RelocationInfo {
    target_sec_idx: usize,
    offset: u64,
    sym_idx: usize,
}

impl RelocationInfo {
    #[inline]
    pub fn apply(
        &self,
        object: &Elf,
        programs: &mut HashMap<usize, Program>,
        maps: &HashMap<String, Map>,
        symtab: &[Sym],
    ) -> Result<()> {
        // get the program we need to apply relocations to based on the program section index
        let prog = programs.get_mut(&self.target_sec_idx).ok_or(Error::Reloc)?;
        // lookup the symbol we're relocating in the symbol table
        let sym = symtab[self.sym_idx];
        // get the map referenced by the program based on the symbol section index
        let mapname = match object.strtab.get(sym.st_name) {
            Some(Ok(mapname)) => mapname,
            Some(Err(e)) => return Err(Error::Section(e.to_string())),
            None => return Err(Error::Section(format!("name not found: {}", sym.st_name))),
        };
        println!("mapname:{}", mapname);
        let map = maps.get(mapname).ok_or(Error::Reloc)?;

        // the index of the instruction we need to patch
        let insn_idx = (self.offset / std::mem::size_of::<bpf_insn>() as u64) as usize;
        let code = &mut prog.data_mut().code;
        if map.section_data {
            code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_VALUE as u8);
            code[insn_idx + 1].imm = code[insn_idx].imm + sym.st_value as i32;
        } else {
            code[insn_idx].set_src_reg(bpf_sys::BPF_PSEUDO_MAP_FD as u8);
        }
        code[insn_idx].imm = map.fd;
        Ok(())
    }
}

#[inline]
fn add_relocation(
    rels: &mut Vec<RelocationInfo>,
    shndx: usize,
    shdr: &SectionHeader,
    shdr_relocs: &[(usize, RelocSection<'_>)],
) {
    // if unwrap blows up, something's really bad
    let section_rels = &shdr_relocs.iter().find(|(idx, _)| idx == &shndx).unwrap().1;
    rels.extend(section_rels.iter().map(|rel| RelocationInfo {
        target_sec_idx: shdr.sh_info as usize,
        sym_idx: rel.r_sym,
        offset: rel.r_offset,
    }));
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
