pub const KB: usize = 1024;
pub const MB: usize = 1024 * 1024;
pub const CACHE_LINE_SIZE_L2: usize = 128;
pub const MSB_MASK: u64 = 0x8000000000000000;
#[cfg(target_os = "macos")]
pub const MEMORY_BOUNDARY: u64 = 0x280000000;
#[cfg(target_os = "linux")]
pub const MEMORY_BOUNDARY: u64 = 0xffff00000000;
pub const PRNG_M: u64 = 8388617;

pub fn print_size(bytes: usize) {
    if bytes <= KB {
        print!("{}B", bytes);
    } else if bytes <= MB {
        print!("{}KB", bytes/KB);
    } else {
        print!("{}MB", bytes/MB);
    }
}
