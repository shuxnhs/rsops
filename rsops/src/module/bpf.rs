use goblin::elf::{Elf, SectionHeader};
use std::fs;
use std::result::*;

#[derive(Debug)]
pub enum Error {
    Section(String),
}

pub type Result<T> = ::std::result::Result<T, Error>;

pub fn parse(path: &str) {
    let f = fs::read(path).unwrap(); //使用 unwrap 隐式地错误处理。
    let object = Elf::parse(&f).unwrap();
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        get_split_section_name(&object, &shdr, shndx);
        // let name = object.shdr_strtab.get_unsafe(shdr.sh_name);
        // println!("val is {},{:?}!", shndx, name);
    }
}

fn get_split_section_name<'o>(
    object: &'o Elf<'_>,
    shdr: &'o SectionHeader,
    shndx: usize,
) -> Result<(Option<&'o str>, Option<&'o str>)> {
    //let fn_err_msg = || "Section name not found";
    let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name)
        .ok_or_else(|| Error::Section(format!("Section name not found: {}", shndx)))?;
    println!("val is {:?}!", name);
    let mut names = name.splitn(2, '/');

    let kind = names.next();
    let name = names.next();

    Ok((kind, name))
}
