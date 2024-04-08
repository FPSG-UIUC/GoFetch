use crypto_attacker::NATIVE_PAGE_SIZE;
// std lib
use std::process::{Command, id};
use std::str;
// Regular expression lib
use regex::Regex;
// file lib
use std::fs::File;
use std::io::Write;

fn main() {
    // Read Virtual Memory Area to get start address and end address
    let output_from_vmmap = Command::new("vmmap")
                                    .arg(format!("{}", id()))
                                    .output()
                                    .unwrap()
                                    .stdout;
    let vmmap_lines = match str::from_utf8(&output_from_vmmap) {
        Ok(v) => v.split("\n"),
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    // Traverse dynamic lib and get 256 trial range
    let mut first_flag = 0;
    let mut start_addr: u64 = 0;
    let mut end_addr: u64 = 0;
    for vmmap_line in vmmap_lines {
        if vmmap_line.contains(".dylib") || vmmap_line.contains("dyld") {
            let mut addr_range_vec = vec![];
            for lib_addr in Regex::new("[0-9a-f]{9}").unwrap().find_iter(vmmap_line) {
                let curr_addr = match u64::from_str_radix(&(lib_addr.as_str()), 16) {
                    Ok(result) => result,
                    Err(error) => panic!("Fail to parse vmmap addr {}", error)
                };
                addr_range_vec.push(curr_addr);
            }
            if addr_range_vec.len() != 2 {
                continue;
            }
            if first_flag == 0 {
                start_addr = addr_range_vec[0];
                end_addr = addr_range_vec[1];
                first_flag = 1;
            } else {
                // test if can extend search space
                if end_addr == addr_range_vec[0] {
                    end_addr = addr_range_vec[1];
                } else {
                    start_addr = addr_range_vec[0];
                    end_addr = addr_range_vec[1];
                }
            }
            // println!("start:{:#x}, end{:#x}", start_addr, end_addr);
            if (end_addr - start_addr) / NATIVE_PAGE_SIZE as u64 >= 200 {
                break;
            }
        }
        if vmmap_line.contains("Writable regions") {
            panic!("[!] Fail to get start addr / end addr for target pointer!");
        }
    }
    let victim_cl_start: u64 = start_addr;
    let victim_cl_end: u64 = end_addr;

    println!("[+] Target Pointer start frame -> {:#x}", victim_cl_start);
    println!("[+] Target Pointer end frame -> {:#x}", victim_cl_end);
    let mut dyld_space_file = File::create("dyld_space.txt").unwrap();
    write!(dyld_space_file, "{:#x}\n", victim_cl_start).unwrap();
    write!(dyld_space_file, "{:#x}\n", victim_cl_end).unwrap();
}