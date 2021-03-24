
use goblin::elf::Elf;
use std::fs;
pub fn parse(path: &str){
    let f = fs::read(path).unwrap();
    let object = Elf::parse(&f).unwrap();
    for (shndx, shdr) in object.section_headers.iter().enumerate() {
        let name = object
        .shdr_strtab
        .get_unsafe(shdr.sh_name);
        println!("val is {},{:?}!", shndx, name);
    }
}