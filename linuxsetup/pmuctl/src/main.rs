use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use thiserror::Error;


#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("parse error")]
    Parse,
}

pub struct ThreadAffinity {
    affinity: Vec<usize>,
}

impl ThreadAffinity {
    fn pin(affinity: &[usize]) -> Self {
        let old_affinity = affinity::get_thread_affinity()
            .expect("could not get the thread affinity");

        affinity::set_thread_affinity(affinity)
            .expect("could not set the thread affinity");

        Self {
            affinity: old_affinity,
        }
    }
}

impl Drop for ThreadAffinity {
    fn drop(&mut self) {
        affinity::set_thread_affinity(&self.affinity)
            .expect("could not set the thread affinity");
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemRegister {
    MIDR_EL1,
    CLIDR_EL1,
    CSSELR_EL1,
    CCSIDR_EL1,
    SYS_APL_HID4,
    PMCR0_EL1,
}

impl SystemRegister {
    fn path(&self, core_id: usize) -> String {
        match *self {
            SystemRegister::MIDR_EL1 =>
                format!("/sys/devices/system/cpu/cpu{}/regs/identification/midr_el1", core_id),
            SystemRegister::CLIDR_EL1 |
            SystemRegister::CSSELR_EL1 |
            SystemRegister::CCSIDR_EL1 |
            SystemRegister::SYS_APL_HID4 |
            SystemRegister::PMCR0_EL1 => {
                let name = match *self {
                    SystemRegister::CLIDR_EL1 => "clidr_el1",
                    SystemRegister::CSSELR_EL1 => "csselr_el1",
                    SystemRegister::CCSIDR_EL1 => "ccsidr_el1",
                    SystemRegister::SYS_APL_HID4 => "sys_apl_hid4",
                    SystemRegister::PMCR0_EL1 => "pmcr0_el1",
                    _ => unreachable!(),
                };

                format!("/sys/kernel/apple/regs/{}", name)
            }
        }
    }
}

fn read_sys_reg(core_id: usize, reg: SystemRegister) -> Result<u64, Error> {
    let _affinity = ThreadAffinity::pin(&[core_id]);

    let file = File::open(reg.path(core_id))?;
    let reader = BufReader::new(file);
    let line = match reader.lines().next() {
        Some(line) => line?,
        _ => return Err(Error::Parse),
    };

    let without_prefix = line.trim_start_matches("0x");
    let value = u64::from_str_radix(without_prefix, 16)?;

    Ok(value)
}

fn write_sys_reg(core_id: usize, reg: SystemRegister, value: u64) -> Result<(), Error> {
    let _affinity = ThreadAffinity::pin(&[core_id]);

    fs::write(reg.path(core_id), format!("{:x}", value))?;

    Ok(())
}

fn main() -> Result<(), Error> {
    for core_id in 0..affinity::get_core_num() {
        let mut value = read_sys_reg(core_id, SystemRegister::PMCR0_EL1)?;
        value |= 1 << 30;
        write_sys_reg(core_id, SystemRegister::PMCR0_EL1, value)?;
    }

    Ok(())
}
